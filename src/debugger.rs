use crate::breakpoint::Breakpoint;
use crate::disasm;
use crate::dwarf_info::{self, DwarfInfo};
use crate::elf_info::{ElfInfo, Symbol};
use crate::expr;
use crate::leak::{self, LeakTracker};
use crate::registers;
use anyhow::{anyhow, bail, Context, Result};
use goblin::elf::Elf;
use nix::sys::personality::{self, Persona};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execv, fork, ForkResult, Pid};
use rust_i18n::t;
use std::collections::HashMap;
use std::ffi::{c_void, CString};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};

/// 現在デバッグ対象として実行中の子プロセスの pid (無ければ 0)。
/// SIGINT 転送スレッドから読むための、プロセス全体で共有する状態。
static DEBUGGEE_PID: AtomicI32 = AtomicI32::new(0);

/// tdb 自身が SIGINT (Ctrl-C) を受け取った際、デバッグ対象プロセスにも
/// SIGINT を転送するバックグラウンドスレッドを起動する。これにより:
/// - tdb 自身は(デフォルトの「終了」ではなく)SIGINT を無視して動き続ける。
/// - `continue` 等で待機中のデバッグ対象は SIGINT を受けて ptrace 経由で
///   停止し、通常のシグナル停止として `waitpid` に報告される。
/// プログラム起動時に一度だけ呼び出す。
pub fn install_sigint_forwarder() {
    use signal_hook::consts::SIGINT;
    use signal_hook::iterator::Signals;

    let mut signals = match Signals::new([SIGINT]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", t!("dbg.sigint_setup_failed", err = e));
            return;
        }
    };
    std::thread::spawn(move || {
        for _ in signals.forever() {
            let pid = DEBUGGEE_PID.load(Ordering::SeqCst);
            if pid > 0 {
                let _ = nix::sys::signal::kill(Pid::from_raw(pid), Signal::SIGINT);
            }
        }
    });
}

pub struct Debugger {
    program: PathBuf,
    args: Vec<String>,
    elf: ElfInfo,
    dwarf: DwarfInfo,
    pid: Option<Pid>,
    /// PIE バイナリの実行時ロードベースアドレス(非PIEなら0)。
    load_bias: u64,
    breakpoints: HashMap<u64, Breakpoint>,
    /// `run` 前に指定されたシンボル名ブレークポイント。起動時に解決する。
    pending_breaks: Vec<String>,
    next_bp_id: u32,
    bp_ids: HashMap<u32, u64>,
    exited: bool,
    /// `set print pretty on|off` (GDB 同様、デフォルトは off = 1行表示)。
    print_pretty: bool,
    /// `set print elements <n>|unlimited`。文字列 (`/s`) や構造体表示の
    /// 要素数上限 (GDB のデフォルトである 200 に合わせる)。`None` は無制限。
    print_elements: Option<usize>,
    /// `leak on/off`/`leaks` で使うメモリリーク追跡状態。
    leak: LeakTracker,
    /// `nexti`/`up` が `cont()` 経由で待っている「ここで止まってほしい」
    /// 一時ブレークポイントのアドレス。メモリリーク追跡用の戻り値捕捉
    /// ブレークポイントが偶然同じアドレスになった場合に、追跡側が
    /// 勝手に実行を継続してしまわないようにするために参照する。
    skip_target: Option<u64>,
    /// ハードウェアウォッチポイント (`watch` コマンド)。x86-64 のデバッグ
    /// レジスタ DR0-DR3 に対応するため最大4つ。`None` は未使用スロット。
    /// プロセスの再起動 (`run`) では引き継がない(`break *addr` と同様)。
    watchpoints: [Option<Watchpoint>; 4],
    /// ウォッチポイントID -> DRスロット番号 (0-3)。`bp_ids`/`next_bp_id` と
    /// 番号を共有する(GDBと同様、ブレークポイントとウォッチポイントを
    /// 同じ通し番号で管理する)。
    wp_ids: HashMap<u32, usize>,
}

/// ハードウェアウォッチポイント1つ分の情報。
struct Watchpoint {
    /// 監視するメモリアドレス(実行時アドレス)。
    addr: u64,
    /// 監視する幅 (1/2/4/8バイトのいずれか)。
    len: u8,
    /// 表示用ラベル(変数名 または `*addr`)。
    label: String,
    /// 直前に観測した値。トリガー時の「旧値」として使い、その後は新しい
    /// 値で更新する。
    last_value: u64,
}

/// `step`/`next` の1回の実行(単一命令の実行、または call をまたぐ実行)の
/// 結果を分類したもの。
enum StepStop {
    Exited,
    Signaled,
    /// ブレークポイントで停止 (rip は既にブレークポイントアドレスへ補正済み)。
    Breakpoint(u64),
    /// ハードウェアウォッチポイントで停止(報告メッセージを含む)。
    Watchpoint(String),
    /// ブレークポイント以外の理由で停止した際の rip。
    Other(u64),
    Unexpected,
}

impl Debugger {
    pub fn new(program: PathBuf, args: Vec<String>) -> Result<Self> {
        let elf = ElfInfo::load(&program)?;
        let dwarf = DwarfInfo::load(&program)?;
        Ok(Debugger {
            program,
            args,
            elf,
            dwarf,
            pid: None,
            load_bias: 0,
            breakpoints: HashMap::new(),
            pending_breaks: Vec::new(),
            next_bp_id: 1,
            bp_ids: HashMap::new(),
            exited: false,
            print_pretty: false,
            print_elements: Some(200),
            leak: LeakTracker::default(),
            skip_target: None,
            watchpoints: [None, None, None, None],
            wp_ids: HashMap::new(),
        })
    }

    // ---- `set print ...` 設定 ----

    pub fn set_print_pretty(&mut self, on: bool) {
        self.print_pretty = on;
    }

    pub fn print_pretty(&self) -> bool {
        self.print_pretty
    }

    /// `n = None` は無制限 (`unlimited`)。
    pub fn set_print_elements(&mut self, n: Option<usize>) {
        self.print_elements = n;
    }

    pub fn print_elements(&self) -> Option<usize> {
        self.print_elements
    }

    pub fn is_running(&self) -> bool {
        self.pid.is_some() && !self.exited
    }

    fn pid(&self) -> Result<Pid> {
        self.pid.ok_or_else(|| anyhow!("{}", t!("dbg.not_running")))
    }

    /// デバッグ対象の終了を記録する。SIGINT 転送スレッドが古い(既に
    /// 終了した)pid に送らないよう、`DEBUGGEE_PID` も併せてクリアする。
    fn mark_exited(&mut self) {
        self.exited = true;
        DEBUGGEE_PID.store(0, Ordering::SeqCst);
    }

    /// 子プロセスを起動し、execve 直後の初回停止まで待つ。
    pub fn start(&mut self) -> Result<()> {
        if self.is_running() {
            bail!("{}", t!("dbg.already_running"));
        }
        self.breakpoints.clear();
        self.bp_ids.clear();
        self.exited = false;
        self.leak.reset_for_run();
        self.watchpoints = [None, None, None, None];
        self.wp_ids.clear();

        let path = CString::new(self.program.as_os_str().to_str().unwrap())?;
        let mut c_args: Vec<CString> = vec![path.clone()];
        for a in &self.args {
            c_args.push(CString::new(a.as_str())?);
        }

        match unsafe { fork() }.context("fork failed")? {
            ForkResult::Child => {
                ptrace::traceme().expect("PTRACE_TRACEME failed");
                // アドレス空間配置をランダム化させず、シンボル解決したアドレスを
                // そのままブレークポイントに使えるようにする。
                let _ = personality::set(Persona::ADDR_NO_RANDOMIZE);
                let err = execv(&path, &c_args).unwrap_err();
                eprintln!("execv failed: {}", err);
                std::process::exit(127);
            }
            ForkResult::Parent { child } => {
                self.pid = Some(child);
                DEBUGGEE_PID.store(child.as_raw(), Ordering::SeqCst);
                match waitpid(child, None)? {
                    WaitStatus::Stopped(_, Signal::SIGTRAP) => {}
                    other => bail!("{}", t!("dbg.unexpected_initial_stop", other = other : {:?})),
                }
            }
        }

        if self.elf.is_pie {
            self.load_bias = self.detect_load_bias()?;
        } else {
            self.load_bias = 0;
        }

        let pending: Vec<String> = self.pending_breaks.drain(..).collect();
        for spec in pending {
            if let Err(e) = self.install_breakpoint_by_spec(&spec) {
                eprintln!("{}", t!("dbg.bp_install_failed_named", spec = spec, err = e));
            }
        }

        println!(
            "{}",
            t!(
                "dbg.process_started",
                pid = self.pid()?.as_raw(),
                entry = format!("{:#x}", self.entry()),
                pie = if self.elf.is_pie { ", PIE" } else { "" }
            )
        );

        Ok(())
    }

    fn detect_load_bias(&self) -> Result<u64> {
        let pid = self.pid()?;
        let maps = fs::read_to_string(format!("/proc/{}/maps", pid.as_raw()))
            .context("failed to read /proc/pid/maps")?;
        let canon = fs::canonicalize(&self.program).unwrap_or_else(|_| self.program.clone());
        for line in maps.lines() {
            if let Some(path_part) = line.split_whitespace().last() {
                if Path::new(path_part) == canon.as_path() {
                    let addr_range = line.split_whitespace().next().unwrap_or("");
                    let start = addr_range.split('-').next().unwrap_or("0");
                    return Ok(u64::from_str_radix(start, 16).unwrap_or(0));
                }
            }
        }
        Ok(0)
    }

    fn runtime_addr(&self, link_addr: u64) -> u64 {
        link_addr + self.load_bias
    }

    // ---- ブレークポイント ----

    pub fn break_at_spec(&mut self, spec: &str) -> Result<()> {
        if let Some(hex) = spec.strip_prefix('*') {
            let addr = parse_addr(hex)?;
            return self.install_breakpoint(addr, format!("*{:#x}", addr));
        }
        if !self.is_running() {
            self.pending_breaks.push(spec.to_string());
            println!("{}", t!("dbg.pending_break_deferred", spec = spec));
            return Ok(());
        }
        self.install_breakpoint_by_spec(spec)
    }

    /// `関数名` または `ファイル名:行番号` のどちらかとして解釈しブレーク
    /// ポイントを設置する。コロンを含み、コロンの右側が数値として解釈
    /// できれば `ファイル名:行番号` として扱い、そうでなければ関数名として
    /// 扱う。
    fn install_breakpoint_by_spec(&mut self, spec: &str) -> Result<()> {
        if let Some((file_part, line_part)) = spec.rsplit_once(':') {
            if let Ok(line) = line_part.trim().parse::<u32>() {
                return self.install_breakpoint_by_location(file_part.trim(), line);
            }
        }
        self.install_breakpoint_by_name(spec)
    }

    fn install_breakpoint_by_name(&mut self, name: &str) -> Result<()> {
        let sym = self
            .elf
            .find_by_name(name)
            .ok_or_else(|| anyhow!("{}", t!("dbg.symbol_not_found", name = name)))?
            .clone();
        let entry_addr = self.runtime_addr(sym.addr);
        let addr = self.skip_prologue_addr(&sym, entry_addr);
        self.install_breakpoint(addr, name.to_string())
    }

    /// `ファイル名:行番号` にブレークポイントを設置する。指定行に実行可能な
    /// コードが無い場合(空行・宣言のみの行等)は、同じファイル内で指定行
    /// 以上の最小の行番号を持つ行に設置する(GDB と同様のフォールバック)。
    fn install_breakpoint_by_location(&mut self, file_part: &str, line: u32) -> Result<()> {
        let (link_addr, file, actual_line) = self.resolve_file_line(file_part, line)?;
        let addr = self.runtime_addr(link_addr);
        self.install_breakpoint(addr, format!("{}:{}", file.display(), actual_line))
    }

    /// `file_part`(フルパス・ファイル名・パスの末尾部分一致のいずれか、
    /// `list` の `resolve_source_file` と同じ照合ルール)に一致するファイル
    /// の行番号テーブルの中から、`line` 以上の最小の行番号を持つ行を探し、
    /// そのリンク時アドレス・ファイルパス・実際の行番号を返す。
    fn resolve_file_line(&self, file_part: &str, line: u32) -> Result<(u64, PathBuf, u32)> {
        let mut candidates: Vec<&dwarf_info::LineRow> = self
            .dwarf
            .lines()
            .iter()
            .filter(|r| {
                !r.end_sequence
                    && r.is_stmt
                    && (r.file.to_string_lossy() == file_part
                        || r.file.file_name().and_then(|f| f.to_str()) == Some(file_part)
                        || r.file.to_string_lossy().ends_with(&format!("/{}", file_part)))
            })
            .collect();
        if candidates.is_empty() {
            bail!("{}", t!("dbg.file_lineinfo_not_found", file = file_part));
        }
        candidates.sort_by_key(|r| (r.line, r.addr));
        let row = candidates.into_iter().find(|r| r.line >= line).ok_or_else(|| {
            anyhow!("{}", t!("dbg.no_code_after_line", file = file_part, line = line))
        })?;
        Ok((row.addr, row.file.clone(), row.line))
    }

    /// 関数シンボル `sym` (実行時エントリアドレス `entry_addr`) について、
    /// プロローグを過ぎた位置のアドレスを求める。DWARF 行情報があればそれを
    /// 使い、無ければ命令列を見て簡易ヒューリスティックで判定する。
    fn skip_prologue_addr(&self, sym: &Symbol, entry_addr: u64) -> u64 {
        let low = sym.addr;
        let high = if sym.size > 0 {
            low + sym.size
        } else {
            self.elf
                .symbols
                .iter()
                .map(|s| s.addr)
                .filter(|&a| a > low)
                .min()
                .unwrap_or(low + 0x1000)
        };
        if let Some(link_skip) = self.dwarf.skip_prologue(low, high) {
            return self.runtime_addr(link_skip);
        }
        match self.read_mem(entry_addr, 32) {
            Ok(bytes) if !bytes.is_empty() => disasm::skip_prologue_heuristic(&bytes, entry_addr),
            _ => entry_addr,
        }
    }

    /// 同じアドレスに2つ以上のブレークポイントを設定できないようにする
    /// (`self.breakpoints` は既にアドレスをキーにしているため、1アドレス
    /// につき1つの実体しか持てない。ここで事前にはじくことで、既存の
    /// ブレークポイントが黙って上書きされたり、`bp_ids` に同じアドレスを
    /// 指す番号が複数できたりするのを防ぐ)。
    fn install_breakpoint(&mut self, addr: u64, label: String) -> Result<()> {
        if self.breakpoints.contains_key(&addr) {
            let existing_id = self.bp_ids.iter().find(|(_, &a)| a == addr).map(|(&id, _)| id).unwrap_or(0);
            bail!("{}", t!("dbg.bp_addr_in_use", addr = format!("{:#x}", addr), id = existing_id));
        }
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        self.bp_ids.insert(id, addr);
        let mut bp = Breakpoint::new(addr);
        if self.is_running() {
            if let Some(pid) = self.pid {
                if let Err(e) = bp.enable(pid) {
                    eprintln!("{}", t!("dbg.bp_install_failed", err = e));
                }
            }
        }
        self.breakpoints.insert(addr, bp);
        println!("{}", t!("dbg.bp_set", id = id, label = label, addr = format!("{:#x}", addr)));
        Ok(())
    }

    pub fn list_breakpoints(&self) {
        if self.bp_ids.is_empty() {
            println!("{}", t!("dbg.no_breakpoints"));
            return;
        }
        for (id, addr) in self.bp_ids.iter() {
            let link_addr = addr.wrapping_sub(self.load_bias);
            let sym = self
                .elf
                .find_by_addr(link_addr)
                .map(|s| s.name.clone())
                .unwrap_or_else(|| "?".to_string());
            let enabled = self
                .breakpoints
                .get(addr)
                .map(|b| b.enabled)
                .unwrap_or(false);
            let loc = match self.dwarf.lookup(link_addr) {
                Some(row) => format!(" at {}:{}", row.file.display(), row.line),
                None => String::new(),
            };
            let inactive = if enabled { String::new() } else { t!("dbg.bp_inactive").to_string() };
            println!("{}: {:#x} <{}>{} {}", id, addr, sym, loc, inactive);
        }
    }

    /// ブレークポイント `id` を削除する。`id` がウォッチポイントのもので
    /// あれば、`delete_watchpoint` に委ねる(GDB と同様、`delete` はどちらの
    /// 種類の番号も受け付ける)。
    pub fn delete_breakpoint(&mut self, id: u32) -> Result<()> {
        if self.wp_ids.contains_key(&id) {
            return self.delete_watchpoint(id);
        }
        let addr = self
            .bp_ids
            .remove(&id)
            .ok_or_else(|| anyhow!("{}", t!("dbg.bp_not_found", id = id)))?;
        if let Some(mut bp) = self.breakpoints.remove(&addr) {
            if let Some(pid) = self.pid {
                if !self.exited {
                    bp.disable(pid)?;
                }
            }
        }
        println!("{}", t!("dbg.bp_deleted", id = id));
        Ok(())
    }

    // ---- ウォッチポイント ----

    /// 変数名を解決してアドレスとサイズ(バイト数)を返す。まず現在の PC
    /// のスコープのローカル変数/仮引数を探し、無ければグローバル変数を探す
    /// (`show globals` と同じ探索)。`watch <変数名>` から使う。
    pub fn variable_address_and_size(&self, name: &str) -> Result<(u64, u64)> {
        if let Ok((addr, var)) = self.resolve_variable(name) {
            return Ok((addr, var.ty.byte_size()));
        }
        let pid = self.pid()?;
        let regs = registers::get_regs(pid)?;
        let var = self
            .dwarf
            .globals()
            .iter()
            .find(|v| v.name == name)
            .ok_or_else(|| anyhow!("{}", t!("dbg.var_not_found", name = name)))?;
        let addr = self.eval_location(&var.location, 0, &regs)?;
        Ok((addr, var.ty.byte_size()))
    }

    /// ハードウェアウォッチポイントを設置する (`watch` コマンド)。`addr` は
    /// `len` (1/2/4/8) バイト境界に整列している必要がある(x86-64 のデバッグ
    /// レジスタの制約)。DR0-DR3 の空きスロットを探して使うため、最大4つまで。
    pub fn add_watchpoint(&mut self, addr: u64, len: u8, label: String) -> Result<()> {
        if ![1u8, 2, 4, 8].contains(&len) {
            bail!("{}", t!("dbg.watch_bad_size"));
        }
        if addr % len as u64 != 0 {
            bail!("{}", t!("dbg.watch_unaligned", addr = format!("{:#x}", addr), len = len));
        }
        let pid = self.pid()?;
        let slot = self
            .watchpoints
            .iter()
            .position(|w| w.is_none())
            .ok_or_else(|| anyhow!("{}", t!("dbg.watch_max")))?;

        let bytes = self.read_mem(addr, len as usize)?;
        let last_value = bytes_to_u64(&bytes);
        self.install_watch_slot(pid, slot, addr, len)?;

        let id = self.next_bp_id;
        self.next_bp_id += 1;
        self.wp_ids.insert(id, slot);
        self.watchpoints[slot] = Some(Watchpoint { addr, len, label: label.clone(), last_value });
        println!(
            "{}",
            t!("dbg.watch_set", id = id, label = label, addr = format!("{:#x}", addr), len = len)
        );
        Ok(())
    }

    pub fn list_watchpoints(&self) {
        if self.wp_ids.is_empty() {
            println!("{}", t!("dbg.no_watchpoints"));
            return;
        }
        let mut items: Vec<(&u32, &usize)> = self.wp_ids.iter().collect();
        items.sort_by_key(|(id, _)| **id);
        for (id, &slot) in items {
            if let Some(wp) = &self.watchpoints[slot] {
                println!(
                    "{}",
                    t!(
                        "dbg.watch_list_line",
                        id = id,
                        label = &wp.label,
                        addr = format!("{:#x}", wp.addr),
                        len = wp.len,
                        val = format!("{:#x}", wp.last_value)
                    )
                );
            }
        }
    }

    fn delete_watchpoint(&mut self, id: u32) -> Result<()> {
        let slot = self.wp_ids.remove(&id).ok_or_else(|| anyhow!("{}", t!("dbg.watch_not_found", id = id)))?;
        self.watchpoints[slot] = None;
        if let Some(pid) = self.pid {
            if !self.exited {
                self.uninstall_watch_slot(pid, slot)?;
            }
        }
        println!("{}", t!("dbg.watch_deleted", id = id));
        Ok(())
    }

    /// x86-64 の DR7 (デバッグ制御レジスタ) における `len` フィールドの符号化。
    fn dr7_len_bits(len: u8) -> u64 {
        match len {
            1 => 0b00,
            2 => 0b01,
            8 => 0b10,
            4 => 0b11,
            _ => unreachable!("呼び出し元 (add_watchpoint) でサイズを検証済み"),
        }
    }

    /// DR`slot` にアドレスを設定し、DR7 で有効化する(R/Wフィールドは書き込み
    /// 監視の `01` 固定)。
    fn install_watch_slot(&self, pid: Pid, slot: usize, addr: u64, len: u8) -> Result<()> {
        registers::write_dr(pid, slot, addr)?;
        let mut dr7 = registers::read_dr(pid, 7)?;
        const RW_WRITE: u64 = 0b01;
        let field_shift = 16 + slot * 4;
        dr7 &= !(0b1111u64 << field_shift);
        dr7 |= (RW_WRITE | (Self::dr7_len_bits(len) << 2)) << field_shift;
        dr7 |= 1 << (slot * 2); // L{slot}: ローカル有効化
        registers::write_dr(pid, 7, dr7)?;
        Ok(())
    }

    /// DR7 の該当スロットのローカル有効化ビットを落として無効化する。
    fn uninstall_watch_slot(&self, pid: Pid, slot: usize) -> Result<()> {
        let mut dr7 = registers::read_dr(pid, 7)?;
        dr7 &= !(1 << (slot * 2));
        registers::write_dr(pid, 7, dr7)?;
        registers::write_dr(pid, slot, 0)?;
        Ok(())
    }

    /// 直近の SIGTRAP がハードウェアウォッチポイントによるものかを DR6 で
    /// 調べる。該当すれば(旧値・新値を含む)報告メッセージを組み立てて
    /// 返し、`last_value` を更新したうえで DR6 をクリアする
    /// (古いステータスが次回の判定に残らないようにするため)。
    /// ウォッチポイントでなければ `None`(呼び出し元は通常の SIGTRAP 処理を
    /// 続ける)。
    fn check_watchpoint_hit(&mut self) -> Result<Option<String>> {
        let pid = self.pid()?;
        let dr6 = registers::read_dr(pid, 6)?;
        if dr6 & 0b1111 == 0 {
            return Ok(None);
        }
        let mut messages = Vec::new();
        for slot in 0..4 {
            if dr6 & (1 << slot) == 0 {
                continue;
            }
            let id = self.wp_ids.iter().find_map(|(&id, &s)| (s == slot).then_some(id));
            let Some(id) = id else { continue };
            let Some((addr, len, label, old_value)) =
                self.watchpoints[slot].as_ref().map(|wp| (wp.addr, wp.len, wp.label.clone(), wp.last_value))
            else {
                continue;
            };
            let bytes = self.read_mem(addr, len as usize)?;
            let new_value = bytes_to_u64(&bytes);
            if let Some(wp) = self.watchpoints[slot].as_mut() {
                wp.last_value = new_value;
            }
            messages.push(
                t!(
                    "dbg.watch_triggered",
                    id = id,
                    label = label,
                    addr = format!("{:#x}", addr),
                    old = format!("{:#x}", old_value),
                    new = format!("{:#x}", new_value)
                )
                .to_string(),
            );
        }
        registers::write_dr(pid, 6, 0)?;
        Ok(if messages.is_empty() { None } else { Some(messages.join("\n")) })
    }

    // ---- 実行制御 ----

    /// 現在の `rip` に有効なブレークポイントがあれば、それを一時的に元の
    /// バイトへ戻して1命令だけ実行し、書き戻す。この1命令の実行中に
    /// ハードウェアウォッチポイントが発火することがある(例えば
    /// ブレークポイントの直後の命令がちょうど監視対象への書き込みだった
    /// 場合)。その場合の報告メッセージを `Some` で返すので、呼び出し元は
    /// それをそのまま停止として報告し、本来予定していた `continue`/`step`
    /// は行わないこと(この戻り値を見ずに単に `?` だけで捨てると、
    /// ウォッチポイントのヒットを見逃してしまう)。
    fn step_over_current_breakpoint(&mut self) -> Result<Option<String>> {
        let pid = self.pid()?;
        let regs = registers::get_regs(pid)?;
        if let Some(bp) = self.breakpoints.get_mut(&regs.rip) {
            if bp.enabled {
                bp.disable(pid)?;
                ptrace::step(pid, None)?;
                match waitpid(pid, None)? {
                    WaitStatus::Exited(_, code) => {
                        self.mark_exited();
                        println!("{}", t!("dbg.process_exited", code = code));
                        return Ok(None);
                    }
                    WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                        if let Some(msg) = self.check_watchpoint_hit()? {
                            if let Some(bp) = self.breakpoints.get_mut(&regs.rip) {
                                bp.enable(pid)?;
                            }
                            return Ok(Some(msg));
                        }
                    }
                    _ => {}
                }
                if let Some(bp) = self.breakpoints.get_mut(&regs.rip) {
                    bp.enable(pid)?;
                }
            }
        }
        Ok(None)
    }

    /// ウォッチポイントのトリガー報告メッセージを表示し、現在の停止位置
    /// (ソース行/逆アセンブル)も続けて表示する。
    fn report_watchpoint(&mut self, msg: String) -> Result<()> {
        println!("{}", msg);
        let pid = self.pid()?;
        let regs = registers::get_regs(pid)?;
        self.show_stop_location(regs.rip);
        Ok(())
    }

    pub fn cont(&mut self) -> Result<()> {
        self.pid()?;
        if let Some(msg) = self.step_over_current_breakpoint()? {
            return self.report_watchpoint(msg);
        }
        if self.exited {
            return Ok(());
        }
        if self.leak.enabled {
            self.ensure_leak_breakpoints_installed();
        }
        let pid = self.pid()?;
        ptrace::cont(pid, None)?;
        let result = self.wait_and_report();
        if self.leak.enabled {
            self.uninstall_leak_breakpoints();
        }
        result
    }

    pub fn stepi(&mut self) -> Result<()> {
        self.pid()?;
        if let Some(msg) = self.step_over_current_breakpoint()? {
            return self.report_watchpoint(msg);
        }
        if self.exited {
            return Ok(());
        }
        let pid = self.pid()?;
        ptrace::step(pid, None)?;
        self.wait_and_report()
    }

    /// call 命令をまたいでステップ実行する (機械語命令単位)。
    pub fn nexti(&mut self) -> Result<()> {
        let pid = self.pid()?;
        let regs = registers::get_regs(pid)?;
        let code = self.read_mem(regs.rip, 16).unwrap_or_default();
        if let Some(len) = call_instruction_len(&code) {
            let ret_addr = regs.rip + len as u64;
            let had_bp = self.breakpoints.contains_key(&ret_addr);
            if !had_bp {
                let mut tmp = Breakpoint::new(ret_addr);
                tmp.enable(pid)?;
                self.breakpoints.insert(ret_addr, tmp);
            }
            let prev_target = self.skip_target.replace(ret_addr);
            self.cont()?;
            self.skip_target = prev_target;
            if !had_bp && !self.exited {
                if let Some(mut bp) = self.breakpoints.remove(&ret_addr) {
                    bp.disable(pid)?;
                }
            }
            Ok(())
        } else {
            self.stepi()
        }
    }

    /// 実際の機械語命令をちょうど1つだけ実行し、結果の wait 状態を返す。
    /// 現在の `rip` に有効なブレークポイントがある場合は、その `0xCC` を
    /// 一時的に元のバイトへ戻してから1命令実行し、書き戻す
    /// (`step_over_current_breakpoint` と違い、常にちょうど1命令だけ進む)。
    fn single_step_raw(&mut self) -> Result<WaitStatus> {
        let pid = self.pid()?;
        let regs = registers::get_regs(pid)?;
        let at_bp = self
            .breakpoints
            .get(&regs.rip)
            .map(|bp| bp.enabled)
            .unwrap_or(false);
        if at_bp {
            if let Some(bp) = self.breakpoints.get_mut(&regs.rip) {
                bp.disable(pid)?;
            }
        }
        ptrace::step(pid, None)?;
        let status = waitpid(pid, None)?;
        if at_bp && !matches!(status, WaitStatus::Exited(..) | WaitStatus::Signaled(..)) {
            if let Some(bp) = self.breakpoints.get_mut(&regs.rip) {
                bp.enable(pid)?;
            }
        }
        Ok(status)
    }

    /// addr のシンボル名 (関数名) を解決する。見つからなければ "??"。
    fn symbol_at(&self, runtime_addr: u64) -> String {
        self.elf
            .find_by_addr(runtime_addr.wrapping_sub(self.load_bias))
            .map(|s| s.name.clone())
            .unwrap_or_else(|| "??".to_string())
    }

    /// `waitpid` の結果を `step`/`next` 向けに分類する。プロセス終了/シグナル
    /// 終了はここでメッセージ表示と `self.exited` の更新まで行う。
    /// ブレークポイントの `int3` を踏んだ場合は `rip` をその場で補正する。
    fn classify_wait(&mut self, status: WaitStatus) -> Result<StepStop> {
        match status {
            WaitStatus::Exited(_, code) => {
                self.mark_exited();
                println!("{}", t!("dbg.process_exited", code = code));
                Ok(StepStop::Exited)
            }
            WaitStatus::Signaled(_, sig, _) => {
                self.mark_exited();
                println!("{}", t!("dbg.process_signaled", sig = sig));
                Ok(StepStop::Signaled)
            }
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                if let Some(msg) = self.check_watchpoint_hit()? {
                    return Ok(StepStop::Watchpoint(msg));
                }
                let pid = self.pid()?;
                let mut regs = registers::get_regs(pid)?;
                let bp_addr = regs.rip.wrapping_sub(1);
                if self.breakpoints.contains_key(&bp_addr) {
                    regs.rip = bp_addr;
                    registers::set_regs(pid, &regs)?;
                    // `nexti`/`up`/`next` などが内部で使う一時ブレークポイントは
                    // `bp_ids` に登録されない。ユーザーが設置した本物の
                    // ブレークポイントだけを「停止」として扱う。
                    if self.bp_ids.values().any(|&a| a == bp_addr) {
                        Ok(StepStop::Breakpoint(bp_addr))
                    } else {
                        Ok(StepStop::Other(bp_addr))
                    }
                } else {
                    Ok(StepStop::Other(regs.rip))
                }
            }
            other => {
                println!("{}", t!("dbg.unexpected_wait", other = other : {:?}));
                Ok(StepStop::Unexpected)
            }
        }
    }

    /// ソース行単位でステップイン実行する。DWARF 行情報を使い、行番号が
    /// 変わる(かつ is_stmt な)アドレスまで機械語命令を1つずつ実行する。
    /// `call` 命令も1命令として実行されるだけなので、呼び出し先に自然に
    /// ステップインする。デバッグ情報の無い関数(共有ライブラリ等)に入った
    /// 場合は、戻りアドレスまで実行してから行単位のステップを続ける。
    pub fn step_line(&mut self) -> Result<()> {
        self.pid()?;
        let pid = self.pid()?;
        let start_line = {
            let regs = registers::get_regs(pid)?;
            let link_ip = regs.rip.wrapping_sub(self.load_bias);
            self.dwarf.lookup(link_ip).map(|r| (r.file.clone(), r.line))
        };

        loop {
            let status = self.single_step_raw()?;
            match self.classify_wait(status)? {
                StepStop::Exited | StepStop::Signaled | StepStop::Unexpected => return Ok(()),
                StepStop::Breakpoint(addr) => {
                    let sym = self.symbol_at(addr);
                    println!("{}", t!("dbg.bp_hit", addr = format!("{:#x}", addr), sym = sym));
                    self.show_stop_location(addr);
                    return Ok(());
                }
                StepStop::Watchpoint(msg) => {
                    println!("{}", msg);
                    let pid = self.pid()?;
                    let regs = registers::get_regs(pid)?;
                    self.show_stop_location(regs.rip);
                    return Ok(());
                }
                StepStop::Other(rip) => {
                    let link_ip = rip.wrapping_sub(self.load_bias);
                    match self.dwarf.lookup(link_ip) {
                        Some(row) if row.is_stmt && Some((row.file.clone(), row.line)) != start_line => {
                            println!("{}:{}", row.file.display(), row.line);
                            if let Some(text) = read_source_line(&row.file, row.line) {
                                println!("{:>4}\t{}", row.line, text);
                            }
                            return Ok(());
                        }
                        Some(_) => continue,
                        None => {
                            self.finish_undebugged_frame()?;
                            if self.exited {
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
    }

    /// ソース行単位でステップオーバー実行する (`step_line` と同じだが、
    /// `call` 命令に差しかかった場合は呼び出し先には入らず、戻りアドレスに
    /// 一時ブレークポイントを置いて `continue` することで丸ごと実行する)。
    pub fn next_line(&mut self) -> Result<()> {
        self.pid()?;
        let pid = self.pid()?;
        let start_line = {
            let regs = registers::get_regs(pid)?;
            let link_ip = regs.rip.wrapping_sub(self.load_bias);
            self.dwarf.lookup(link_ip).map(|r| (r.file.clone(), r.line))
        };

        loop {
            let regs = registers::get_regs(pid)?;
            let code = self.read_mem_for_display(regs.rip, 16).unwrap_or_default();
            let (status, temp_bp) = match call_instruction_len(&code) {
                Some(len) => {
                    let ret_addr = regs.rip + len as u64;
                    match self.run_over_call(ret_addr)? {
                        Some((status, is_temp)) => (status, Some(ret_addr).filter(|_| is_temp)),
                        None => return Ok(()),
                    }
                }
                None => (self.single_step_raw()?, None),
            };

            let stop = self.classify_wait(status)?;
            // 一時ブレークポイントの削除は rip 補正 (classify_wait) の後で行う。
            // 先に消してしまうと、それが原因の SIGTRAP かどうか判定できず
            // rip がブレークポイント直後の1バイトずれた位置のままになる。
            if let Some(ret_addr) = temp_bp {
                if !matches!(stop, StepStop::Exited | StepStop::Signaled) {
                    let pid = self.pid()?;
                    if let Some(mut bp) = self.breakpoints.remove(&ret_addr) {
                        bp.disable(pid)?;
                    }
                }
            }

            match stop {
                StepStop::Exited | StepStop::Signaled | StepStop::Unexpected => return Ok(()),
                StepStop::Breakpoint(addr) => {
                    let sym = self.symbol_at(addr);
                    println!("{}", t!("dbg.bp_hit", addr = format!("{:#x}", addr), sym = sym));
                    self.show_stop_location(addr);
                    return Ok(());
                }
                StepStop::Watchpoint(msg) => {
                    println!("{}", msg);
                    let pid = self.pid()?;
                    let regs = registers::get_regs(pid)?;
                    self.show_stop_location(regs.rip);
                    return Ok(());
                }
                StepStop::Other(rip) => {
                    let link_ip = rip.wrapping_sub(self.load_bias);
                    match self.dwarf.lookup(link_ip) {
                        Some(row) if row.is_stmt && Some((row.file.clone(), row.line)) != start_line => {
                            println!("{}:{}", row.file.display(), row.line);
                            if let Some(text) = read_source_line(&row.file, row.line) {
                                println!("{:>4}\t{}", row.line, text);
                            }
                            return Ok(());
                        }
                        Some(_) => continue,
                        None => {
                            self.finish_undebugged_frame()?;
                            if self.exited {
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
    }

    /// 戻りアドレス `ret_addr` に一時ブレークポイントを置いて `continue` する
    /// (`call` をまたいで実行する処理の共通部分)。`step_over_current_breakpoint`
    /// の実行中にプロセスが終了した場合は `Ok(None)` を返す(呼び出し元は
    /// メッセージ表示済みとして扱ってよい)。それ以外の場合は wait 状態と、
    /// このブレークポイントが呼び出し元にとって一時的なもの(既存のもの
    /// ではなく今回新たに設置した)かどうかを返す。一時ブレークポイントの
    /// 削除は、呼び出し元が `rip` 補正を済ませた後に行うこと
    /// (先に削除すると、それが原因の SIGTRAP かどうか判定できなくなる)。
    fn run_over_call(&mut self, ret_addr: u64) -> Result<Option<(WaitStatus, bool)>> {
        let pid = self.pid()?;
        let had_bp = self.breakpoints.contains_key(&ret_addr);
        if !had_bp {
            let mut tmp = Breakpoint::new(ret_addr);
            tmp.enable(pid)?;
            self.breakpoints.insert(ret_addr, tmp);
        }
        if let Some(msg) = self.step_over_current_breakpoint()? {
            self.report_watchpoint(msg)?;
            return Ok(None);
        }
        if self.exited {
            return Ok(None);
        }
        let pid = self.pid()?;
        ptrace::cont(pid, None)?;
        let status = waitpid(pid, None)?;
        Ok(Some((status, !had_bp)))
    }

    /// デバッグ情報のないコードに入ってしまった際、スタックトップの
    /// 戻りアドレス(`call` 直後なのでまだ `rsp` の指す位置にある)まで
    /// 一時ブレークポイントで実行を進める。
    fn finish_undebugged_frame(&mut self) -> Result<()> {
        let pid = self.pid()?;
        let regs = registers::get_regs(pid)?;
        let ret_bytes = self.read_mem(regs.rsp, 8)?;
        let ret_addr = u64::from_ne_bytes(ret_bytes.try_into().unwrap());

        let had_bp = self.breakpoints.contains_key(&ret_addr);
        if !had_bp {
            let mut tmp = Breakpoint::new(ret_addr);
            tmp.enable(pid)?;
            self.breakpoints.insert(ret_addr, tmp);
        }
        ptrace::cont(pid, None)?;
        match waitpid(pid, None)? {
            WaitStatus::Exited(_, code) => {
                self.mark_exited();
                println!("{}", t!("dbg.process_exited", code = code));
            }
            WaitStatus::Signaled(_, sig, _) => {
                self.mark_exited();
                println!("{}", t!("dbg.process_signaled", sig = sig));
            }
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                let mut regs = registers::get_regs(pid)?;
                let hit_addr = regs.rip.wrapping_sub(1);
                if self.breakpoints.contains_key(&hit_addr) {
                    regs.rip = hit_addr;
                    registers::set_regs(pid, &regs)?;
                }
            }
            _ => {}
        }
        if !had_bp && !self.exited {
            if let Some(mut bp) = self.breakpoints.remove(&ret_addr) {
                bp.disable(pid)?;
            }
        }
        Ok(())
    }

    /// 現在の関数の呼び出し元へ戻るまで実行を再開する (rbp チェインの
    /// 戻りアドレスに一時ブレークポイントを置いて continue する)。
    pub fn up(&mut self) -> Result<()> {
        let pid = self.pid()?;
        let regs = registers::get_regs(pid)?;
        if regs.rbp == 0 {
            bail!("{}", t!("dbg.no_frame_pointer"));
        }
        let ret_addr = self.read_mem(regs.rbp + 8, 8)?;
        let ret_addr = u64::from_ne_bytes(ret_addr.try_into().unwrap());
        if ret_addr == 0 {
            bail!("{}", t!("dbg.no_caller_addr"));
        }

        let had_bp = self.breakpoints.contains_key(&ret_addr);
        if !had_bp {
            let mut tmp = Breakpoint::new(ret_addr);
            tmp.enable(pid)?;
            self.breakpoints.insert(ret_addr, tmp);
        }
        let prev_target = self.skip_target.replace(ret_addr);
        self.cont()?;
        self.skip_target = prev_target;
        if !had_bp && !self.exited {
            if let Some(mut bp) = self.breakpoints.remove(&ret_addr) {
                bp.disable(pid)?;
            }
        }
        Ok(())
    }

    /// `waitpid` の結果を報告する。メモリリーク追跡用の内部ブレークポイント
    /// (malloc 等のエントリ/戻りアドレス捕捉)を踏んだ場合は、その場で
    /// 追跡処理(`handle_leak_breakpoint`)だけを行って報告はせず、
    /// そのブレークポイントを一時的に元へ戻して1命令実行→再度 `continue`
    /// してループを続ける(ユーザーには見えない)。
    fn wait_and_report(&mut self) -> Result<()> {
        loop {
            let pid = self.pid()?;
            match waitpid(pid, None)? {
                WaitStatus::Exited(_, code) => {
                    self.mark_exited();
                    println!("{}", t!("dbg.process_exited", code = code));
                    return Ok(());
                }
                WaitStatus::Signaled(_, sig, _) => {
                    self.mark_exited();
                    println!("{}", t!("dbg.process_signaled", sig = sig));
                    return Ok(());
                }
                WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                    if let Some(msg) = self.check_watchpoint_hit()? {
                        return self.report_watchpoint(msg);
                    }
                    let mut regs = registers::get_regs(pid)?;
                    let bp_addr = regs.rip.wrapping_sub(1);
                    if self.breakpoints.contains_key(&bp_addr) {
                        regs.rip = bp_addr;
                        registers::set_regs(pid, &regs)?;
                        if self.leak.enabled && self.handle_leak_breakpoint(bp_addr)? {
                            if let Some(msg) = self.step_over_current_breakpoint()? {
                                return self.report_watchpoint(msg);
                            }
                            if self.exited {
                                return Ok(());
                            }
                            ptrace::cont(pid, None)?;
                            continue;
                        }
                        let sym = self.symbol_at(bp_addr);
                        println!("{}", t!("dbg.bp_hit", addr = format!("{:#x}", bp_addr), sym = sym));
                        self.show_stop_location(bp_addr);
                        return Ok(());
                    } else {
                        println!("{}", t!("dbg.stopped_sigtrap", rip = format!("{:#x}", regs.rip)));
                        return Ok(());
                    }
                }
                WaitStatus::Stopped(_, sig) => {
                    println!("{}", t!("dbg.stopped_signal", sig = sig));
                    return Ok(());
                }
                other => {
                    println!("{}", t!("dbg.unexpected_wait", other = other : {:?}));
                    return Ok(());
                }
            }
        }
    }

    // ---- メモリリーク検出 ----

    /// `leak on`/`leak off`。無効化時は、その場でインストール済みの
    /// 追跡用ブレークポイントを取り除く(有効化時は次回の `continue` で
    /// 遅延解決・設置する)。
    pub fn set_leak_tracking(&mut self, on: bool) {
        self.leak.enabled = on;
        if !on {
            self.uninstall_leak_breakpoints();
        }
        println!("{}", t!("dbg.leak_tracking_state", state = if on { "on" } else { "off" }));
    }

    /// 現在の追跡状態(on/off・確保/解放回数・未解決の free)を表示する。
    pub fn show_leak_status(&self) {
        println!(
            "{}",
            t!("dbg.leak_tracking_state", state = if self.leak.enabled { "on" } else { "off" })
        );
        println!(
            "{}",
            t!(
                "dbg.leak_stats",
                allocs = self.leak.total_allocs,
                frees = self.leak.total_frees,
                live = self.leak.live.len(),
                bad = self.leak.bad_frees.len()
            )
        );
    }

    /// 未解放のヒープ確保一覧を表示する (`leaks` コマンド)。
    pub fn list_leaks(&self) {
        if !self.leak.enabled {
            println!("{}", t!("dbg.leak_disabled"));
            return;
        }
        if self.leak.live.is_empty() {
            println!(
                "{}",
                t!("dbg.leak_none", allocs = self.leak.total_allocs, frees = self.leak.total_frees)
            );
        } else {
            let mut items: Vec<(&u64, &leak::LiveAlloc)> = self.leak.live.iter().collect();
            items.sort_by_key(|(addr, _)| **addr);
            let total: u64 = items.iter().map(|(_, a)| a.size).sum();
            println!("{}", t!("dbg.leak_summary", count = items.len(), total = total));
            for (addr, alloc) in items {
                let call_addr = self.runtime_addr(alloc.call_site);
                let loc = self
                    .dwarf
                    .lookup(alloc.call_site)
                    .map(|row| format!("{}:{}", row.file.display(), row.line))
                    .unwrap_or_else(|| format!("{:#x}", call_addr));
                println!(
                    "{}",
                    t!(
                        "dbg.leak_entry",
                        addr = format!("{:#018x}", addr),
                        size = alloc.size : {:>8},
                        func = alloc.func.name(),
                        loc = loc
                    )
                );
            }
        }
        if !self.leak.bad_frees.is_empty() {
            println!("{}", t!("dbg.leak_bad_frees_header", count = self.leak.bad_frees.len()));
            for p in &self.leak.bad_frees {
                println!("  {:#018x}", p);
            }
        }
    }

    /// エントリブレークポイントが未解決であれば解決し、まだ設置していない
    /// ものを設置する。`continue` のたびに呼ぶ(冪等)。
    ///
    /// `run` 直後、ユーザーがまだ一度も停止していない状態(`break main` 等を
    /// 経ていない)でいきなり `continue` した場合、この時点では ld.so が
    /// まだ起動しておらず libc がプロセスにマップされていないため、通常の
    /// 解決だけでは失敗する。その場合は実行ファイル自身のエントリポイント
    /// (`_start`)まで内部的に(ユーザーに見えない形で)一度だけ実行を
    /// 進めてから再解決する(`warm_up_to_own_entry` 参照)。1プロセスの
    /// 実行につきこの試行は1回だけ行い(`leak.warmed_up`)、失敗しても
    /// 無限に再試行はしない(例: malloc を全く使わない静的リンクバイナリ)。
    fn ensure_leak_breakpoints_installed(&mut self) {
        if self.leak.entries.is_empty() {
            let _ = self.resolve_leak_entry_points();
        }
        if self.leak.entries.is_empty() && !self.leak.warmed_up {
            self.leak.warmed_up = true;
            if matches!(self.find_libc_mapping(), Ok(None)) {
                if let Err(e) = self.warm_up_to_own_entry() {
                    eprintln!("{}", t!("dbg.leak_warmup_failed", err = e));
                }
                if !self.exited {
                    let _ = self.resolve_leak_entry_points();
                }
            }
        }
        let Some(pid) = self.pid else { return };
        let addrs: Vec<u64> = self.leak.entries.keys().copied().collect();
        for addr in addrs {
            if !self.breakpoints.contains_key(&addr) {
                let mut bp = Breakpoint::new(addr);
                if bp.enable(pid).is_ok() {
                    self.breakpoints.insert(addr, bp);
                }
            }
        }
    }

    /// libc がまだマップされていない場合に、実行ファイル自身のエントリ
    /// ポイント(`_start`)まで一時ブレークポイント + `continue` で内部的に
    /// 実行を進める。ld.so は依存する共有ライブラリ(libc を含む)の読み込みを
    /// すべて終えてから実行ファイル自身のエントリに制御を渡すため、そこに
    /// 到達すれば libc は必ずマップ済みになっている
    /// (`finish_undebugged_frame` と同じ「一時ブレークポイントを置いて
    /// 生の `waitpid` で待つ」パターン)。
    fn warm_up_to_own_entry(&mut self) -> Result<()> {
        let entry = self.entry();
        let pid = self.pid()?;
        let had_bp = self.breakpoints.contains_key(&entry);
        if !had_bp {
            let mut tmp = Breakpoint::new(entry);
            tmp.enable(pid)?;
            self.breakpoints.insert(entry, tmp);
        }
        ptrace::cont(pid, None)?;
        match waitpid(pid, None)? {
            WaitStatus::Exited(_, code) => {
                self.mark_exited();
                println!("{}", t!("dbg.process_exited", code = code));
            }
            WaitStatus::Signaled(_, sig, _) => {
                self.mark_exited();
                println!("{}", t!("dbg.process_signaled", sig = sig));
            }
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                let mut regs = registers::get_regs(pid)?;
                let hit_addr = regs.rip.wrapping_sub(1);
                if self.breakpoints.contains_key(&hit_addr) {
                    regs.rip = hit_addr;
                    registers::set_regs(pid, &regs)?;
                }
            }
            _ => {}
        }
        if !had_bp && !self.exited {
            if let Some(mut bp) = self.breakpoints.remove(&entry) {
                bp.disable(pid)?;
            }
        }
        Ok(())
    }

    /// `ensure_leak_breakpoints_installed` で設置したブレークポイントを
    /// 取り除く。ユーザーが `break` で設置した実ブレークポイントと
    /// アドレスが重複している場合はそちらを優先し、取り除かない。
    fn uninstall_leak_breakpoints(&mut self) {
        let Some(pid) = self.pid else {
            self.leak.pending.clear();
            return;
        };
        let entry_addrs: Vec<u64> = self.leak.entries.keys().copied().collect();
        for addr in entry_addrs {
            if self.bp_ids.values().any(|&a| a == addr) {
                continue;
            }
            if let Some(mut bp) = self.breakpoints.remove(&addr) {
                let _ = bp.disable(pid);
            }
        }
        let pending_addrs: Vec<u64> = self.leak.pending.keys().copied().collect();
        for addr in pending_addrs {
            if self.bp_ids.values().any(|&a| a == addr) {
                continue;
            }
            if let Some(mut bp) = self.breakpoints.remove(&addr) {
                let _ = bp.disable(pid);
            }
        }
        self.leak.pending.clear();
    }

    /// malloc/calloc/realloc/free のアドレスを解決する。まずスタティック
    /// リンクバイナリを想定して自分自身の ELF シンボルテーブルを見て
    /// (静的リンクなら定義済みシンボルとして存在する)、見つからなかった
    /// 分だけ `/proc/pid/maps` から libc の実行時ロードアドレスを求め、
    /// libc 自身の `.dynsym` を読んで解決する(動的リンクの通常のケース)。
    fn resolve_leak_entry_points(&mut self) -> Result<()> {
        let names: [(&str, leak::AllocFn); 4] = [
            ("malloc", leak::AllocFn::Malloc),
            ("calloc", leak::AllocFn::Calloc),
            ("realloc", leak::AllocFn::Realloc),
            ("free", leak::AllocFn::Free),
        ];
        let mut found: HashMap<u64, leak::AllocFn> = HashMap::new();
        let mut resolved_names: Vec<&str> = Vec::new();

        for (name, func) in &names {
            if let Some(sym) = self.elf.find_by_name(name) {
                if sym.addr != 0 {
                    found.insert(self.runtime_addr(sym.addr), *func);
                    resolved_names.push(name);
                }
            }
        }

        if resolved_names.len() < names.len() {
            if let Some((base, path)) = self.find_libc_mapping()? {
                let libc_syms = load_dynamic_symbols(&path)?;
                for (name, func) in &names {
                    if resolved_names.contains(name) {
                        continue;
                    }
                    if let Some(&val) = libc_syms.get(*name) {
                        found.insert(base + val, *func);
                    }
                }
            }
        }

        self.leak.entries = found;
        Ok(())
    }

    /// `/proc/<pid>/maps` から libc.so のマッピングを探し、その実行時
    /// ロードアドレス(先頭マッピングの開始アドレス。`detect_load_bias` と
    /// 同じ考え方)とファイルパスを返す。まだマップされていなければ `None`。
    fn find_libc_mapping(&self) -> Result<Option<(u64, PathBuf)>> {
        let pid = self.pid()?;
        let maps = fs::read_to_string(format!("/proc/{}/maps", pid.as_raw()))
            .context("failed to read /proc/pid/maps")?;
        for line in maps.lines() {
            let Some(path_part) = line.split_whitespace().last() else { continue };
            let base_name = Path::new(path_part).file_name().and_then(|f| f.to_str()).unwrap_or("");
            if base_name.starts_with("libc.so") || base_name.starts_with("libc-") {
                let addr_range = line.split_whitespace().next().unwrap_or("");
                let start = addr_range.split('-').next().unwrap_or("0");
                let base = u64::from_str_radix(start, 16).unwrap_or(0);
                return Ok(Some((base, PathBuf::from(path_part))));
            }
        }
        Ok(None)
    }

    /// ブレークポイントのヒットがメモリリーク追跡用のものであれば処理して
    /// `true` を返す(呼び出し元はユーザーへの報告をせず、静かに実行を
    /// 再開してよい)。ただし、そのアドレスがユーザーの実ブレークポイント、
    /// または `nexti`/`up` が待っている一時停止先 (`skip_target`) と
    /// 重複する場合は、追跡処理だけ済ませたうえで `false` を返し、
    /// 本来の(ユーザーに見える)停止処理に委ねる。
    fn handle_leak_breakpoint(&mut self, addr: u64) -> Result<bool> {
        if let Some(func) = self.leak.entries.get(&addr).copied() {
            self.on_alloc_entry(func)?;
            let is_user_bp = self.bp_ids.values().any(|&a| a == addr);
            return Ok(!is_user_bp);
        }
        if self.leak.pending.contains_key(&addr) {
            self.on_alloc_return(addr)?;
            let is_awaited_stop =
                self.bp_ids.values().any(|&a| a == addr) || self.skip_target == Some(addr);
            return Ok(!is_awaited_stop);
        }
        Ok(false)
    }

    /// malloc/calloc/realloc/free のエントリ(先頭アドレス)に到達した際の
    /// 処理。`free` は引数だけで完結するのでその場で解放を記録する。
    /// malloc/calloc/realloc は戻り値(確保されたポインタ)が必要なので、
    /// 戻りアドレスに一時ブレークポイントを置いて `pending` に積む。
    fn on_alloc_entry(&mut self, func: leak::AllocFn) -> Result<()> {
        let pid = self.pid()?;
        let regs = registers::get_regs(pid)?;
        let ret_bytes = self.read_mem(regs.rsp, 8)?;
        let ret_addr = u64::from_ne_bytes(ret_bytes.try_into().unwrap());
        let call_site = ret_addr.wrapping_sub(self.load_bias);

        match func {
            leak::AllocFn::Free => {
                let ptr = regs.rdi;
                if ptr != 0 {
                    if self.leak.live.remove(&ptr).is_some() {
                        self.leak.total_frees += 1;
                    } else {
                        self.leak.bad_frees.push(ptr);
                    }
                }
            }
            leak::AllocFn::Malloc | leak::AllocFn::Calloc | leak::AllocFn::Realloc => {
                let size = match func {
                    leak::AllocFn::Malloc => regs.rdi,
                    leak::AllocFn::Calloc => regs.rdi.saturating_mul(regs.rsi),
                    leak::AllocFn::Realloc => regs.rsi,
                    leak::AllocFn::Free => unreachable!(),
                };
                let old_ptr = if func == leak::AllocFn::Realloc { regs.rdi } else { 0 };
                if !self.breakpoints.contains_key(&ret_addr) {
                    let mut bp = Breakpoint::new(ret_addr);
                    bp.enable(pid)?;
                    self.breakpoints.insert(ret_addr, bp);
                }
                self.leak.pending.insert(ret_addr, leak::PendingCall { func, size, old_ptr, call_site });
            }
        }
        Ok(())
    }

    /// malloc/calloc/realloc の戻りアドレスに到達した際の処理。`rax` を
    /// 確保されたポインタとして取り込み、`live` を更新する。
    fn on_alloc_return(&mut self, addr: u64) -> Result<()> {
        let Some(pending) = self.leak.pending.remove(&addr) else {
            return Ok(());
        };
        let pid = self.pid()?;
        let regs = registers::get_regs(pid)?;
        let ptr = regs.rax;

        match pending.func {
            leak::AllocFn::Malloc | leak::AllocFn::Calloc => {
                if ptr != 0 {
                    self.leak.live.insert(
                        ptr,
                        leak::LiveAlloc { size: pending.size, func: pending.func, call_site: pending.call_site },
                    );
                    self.leak.total_allocs += 1;
                }
            }
            leak::AllocFn::Realloc => {
                if ptr != 0 {
                    if pending.old_ptr != 0 {
                        self.leak.live.remove(&pending.old_ptr);
                    }
                    self.leak.live.insert(
                        ptr,
                        leak::LiveAlloc { size: pending.size, func: pending.func, call_site: pending.call_site },
                    );
                    self.leak.total_allocs += 1;
                } else if pending.size == 0 && pending.old_ptr != 0 {
                    // realloc(ptr, 0) は多くの実装で free 相当として扱われる。
                    self.leak.live.remove(&pending.old_ptr);
                    self.leak.total_frees += 1;
                }
                // ptr == 0 かつ size != 0 は失敗: 元のブロックは変更されない
                // ため、追跡状態も変更しない。
            }
            leak::AllocFn::Free => unreachable!("free はエントリ時点で即座に処理するため pending には入らない"),
        }

        if !self.bp_ids.values().any(|&a| a == addr) {
            if let Some(mut bp) = self.breakpoints.remove(&addr) {
                bp.disable(pid)?;
            }
        }
        Ok(())
    }

    /// 停止アドレスの内容を表示する。DWARF 行情報からソースファイル/行が
    /// 分かればそのソース行を、分からなければ逆アセンブル結果を表示する。
    fn show_stop_location(&self, addr: u64) {
        let link_addr = addr.wrapping_sub(self.load_bias);
        if let Some(row) = self.dwarf.lookup(link_addr) {
            if let Some(text) = read_source_line(&row.file, row.line) {
                println!("{}:{}", row.file.display(), row.line);
                println!("{:>4}\t{}", row.line, text);
                return;
            }
        }
        match self.read_mem_for_display(addr, 16) {
            Ok(bytes) => {
                if let Some(line) = disasm::disassemble_one(&bytes, addr) {
                    println!("{}", line);
                }
            }
            Err(e) => eprintln!("{}", t!("dbg.disasm_read_failed", err = e)),
        }
    }

    /// `read_mem` と同様だが、有効なブレークポイントで書き換えられた
    /// `0xCC` バイトを元の命令バイトに戻してから返す。逆アセンブル表示用。
    fn read_mem_for_display(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut bytes = self.read_mem(addr, len)?;
        for (&bp_addr, bp) in &self.breakpoints {
            if bp.enabled && bp_addr >= addr && bp_addr < addr + len as u64 {
                bytes[(bp_addr - addr) as usize] = bp.orig_byte();
            }
        }
        Ok(bytes)
    }

    pub fn kill(&mut self) -> Result<()> {
        if let Some(pid) = self.pid {
            if !self.exited {
                let _ = ptrace::kill(pid);
                let _ = waitpid(pid, None);
            }
        }
        self.mark_exited();
        self.pid = None;
        println!("{}", t!("dbg.process_killed"));
        Ok(())
    }

    // ---- レジスタ / メモリ ----

    pub fn print_regs(&self) -> Result<()> {
        let pid = self.pid()?;
        let regs = registers::get_regs(pid)?;
        println!("{}", registers::dump(&regs));
        match registers::get_fpregs(pid) {
            Ok(fpregs) => println!("{}", registers::dump_fpregs(&fpregs)),
            Err(e) => eprintln!("{}", t!("dbg.fpregs_failed", err = e)),
        }
        Ok(())
    }

    /// `$<レジスタ名>` の値を取得する。`st0`-`st7`/`xmm0`-`xmm15` は
    /// `set_reg` の下位64bit書き込みに対応する下位64bitを返す(80bit
    /// 拡張精度としての小数値は `info registers` の `value=` を参照)。
    pub fn get_reg(&self, name: &str) -> Result<u64> {
        let pid = self.pid()?;
        if let Some(idx) = registers::parse_st_name(name) {
            let fpregs = registers::get_fpregs(pid)?;
            return Ok(registers::st_low64(&fpregs, idx));
        }
        if let Some(idx) = registers::parse_xmm_name(name) {
            let fpregs = registers::get_fpregs(pid)?;
            return Ok(registers::xmm_low64(&fpregs, idx));
        }
        let regs = registers::get_regs(pid)?;
        registers::get_by_name(&regs, name).ok_or_else(|| anyhow!("{}", t!("dbg.unknown_register", name = name)))
    }

    /// `$<レジスタ名>` への `set` を行う。`st0`-`st7`/`xmm0`-`xmm15` は
    /// `user_regs_struct` に無いため、`PTRACE_GETFPREGS`/`SETFPREGS` 相当の
    /// 別経路で扱う。`st` レジスタは浮動小数点数として意味のある唯一の型
    /// なので、式の値を `f64` として解釈し80bit拡張精度へ変換する
    /// (`print $stN` / `info registers` の表示と対応する)。`xmm` レジスタは
    /// 128bit全体の解釈が用途で変わるため、他の整数レジスタと同様に式の値を
    /// 整数として扱い、下位64bitへ書き込む(上位64bitは0にする)。
    pub fn set_reg(&self, name: &str, value: expr::Value) -> Result<()> {
        let pid = self.pid()?;
        if let Some(idx) = registers::parse_st_name(name) {
            let mut fpregs = registers::get_fpregs(pid)?;
            let bytes = registers::encode_x87_extended(value.as_f64());
            registers::set_st_bytes(&mut fpregs, idx, &bytes);
            return registers::set_fpregs(pid, &fpregs);
        }
        if let Some(idx) = registers::parse_xmm_name(name) {
            let mut fpregs = registers::get_fpregs(pid)?;
            registers::set_xmm_low64(&mut fpregs, idx, value.as_i64() as u64);
            return registers::set_fpregs(pid, &fpregs);
        }
        let mut regs = registers::get_regs(pid)?;
        if !registers::set_by_name(&mut regs, name, value.as_i64() as u64) {
            bail!("{}", t!("dbg.unknown_register", name = name));
        }
        registers::set_regs(pid, &regs)
    }

    /// DWARF 情報を使い、現在の PC のスコープにあるローカル変数/仮引数
    /// `name` の値を読み取る。`print`/`set` の式評価 (`src/expr.rs`) から
    /// 呼ばれる。
    pub fn read_variable(&self, name: &str) -> Result<expr::Value> {
        Ok(self.read_variable_typed(name)?.0)
    }

    /// `read_variable` と同じだが、ポインタ型かどうかも併せて返す
    /// (`print` が表示形式 — ポインタなら16進、それ以外は10進 — を
    /// 決めるのに使う)。
    pub fn read_variable_typed(&self, name: &str) -> Result<(expr::Value, bool)> {
        let (addr, var) = self.resolve_variable(name)?;
        let value = self.read_typed_value(addr, &var.ty)?;
        Ok((value, var.is_pointer))
    }

    /// `print` 専用の変数読み取り。式全体が単一の変数名のときだけ呼ばれ、
    /// 構造体型ならスカラー値化はせず整形済み文字列を返す
    /// (`set print pretty`/`set print elements` の対象)。
    pub fn read_for_print(&self, name: &str) -> Result<expr::PrintResult> {
        let (addr, var) = self.resolve_variable(name)?;
        if matches!(var.ty, dwarf_info::TypeInfo::Struct { .. } | dwarf_info::TypeInfo::Array { .. }) {
            return Ok(expr::PrintResult::Text(self.format_value_by_type(addr, &var.ty, 0)));
        }
        let value = self.read_typed_value(addr, &var.ty)?;
        let hint = expr::TypeHint { is_pointer: var.is_pointer, type_name: var.ty.type_name() };
        Ok(expr::PrintResult::Value(value, Some(hint)))
    }

    /// `print &name` 専用。`name` の実体アドレスを、その「〜へのポインタ」
    /// 型情報付きで返す(例: `y: int` に対する `&y` は型名 `int *`)。
    pub fn read_address_for_print(&self, name: &str) -> Result<expr::PrintResult> {
        let (addr, var) = self.resolve_variable(name)?;
        let ptr_ty = dwarf_info::TypeInfo::Pointer { pointee: Box::new(var.ty) };
        let hint = expr::TypeHint { is_pointer: true, type_name: ptr_ty.type_name() };
        Ok(expr::PrintResult::Value(expr::Value::Int(addr as i64), Some(hint)))
    }

    /// 現在の関数のローカル変数一覧を表示する (`show locals`)。
    pub fn list_locals(&self) -> Result<()> {
        self.list_scope_vars(false, &t!("dbg.no_locals"))
    }

    /// 現在の関数の仮引数一覧を表示する (`show args`)。
    pub fn list_args(&self) -> Result<()> {
        self.list_scope_vars(true, &t!("dbg.no_params"))
    }

    fn list_scope_vars(&self, want_params: bool, empty_msg: &str) -> Result<()> {
        let pid = self.pid()?;
        let regs = registers::get_regs(pid)?;
        let link_pc = regs.rip.wrapping_sub(self.load_bias);
        let Some(sub) = self.dwarf.find_subprogram(link_pc) else {
            println!("{}", t!("dbg.no_pc_function_info"));
            return Ok(());
        };
        let frame_base = self.eval_frame_base(&sub.frame_base, &regs)?;
        let mut any = false;
        for var in &sub.variables {
            if var.is_param != want_params {
                continue;
            }
            any = true;
            match self
                .eval_location(&var.location, frame_base, &regs)
                .and_then(|addr| self.format_var_value(var, addr))
            {
                Ok(s) => println!("{} = {}", var.name, s),
                Err(e) => println!("{}", t!("dbg.var_error", name = &var.name, err = format!("{:#}", e))),
            }
        }
        if !any {
            println!("{}", empty_msg);
        }
        Ok(())
    }

    /// グローバル変数(コンパイル単位直下、関数の外で宣言された変数)の
    /// 一覧を表示する (`show globals`)。関数ローカルな `static` 変数は
    /// 対象外(このツールでは扱わない単純化)。
    pub fn list_globals(&self) -> Result<()> {
        let globals = self.dwarf.globals();
        if globals.is_empty() {
            println!("{}", t!("dbg.no_globals"));
            return Ok(());
        }
        let pid = self.pid()?;
        let regs = registers::get_regs(pid)?;
        for var in globals {
            // グローバル変数の位置式 (通常 DW_OP_addr) は frame_base を
            // 使わないため 0 を渡す。
            match self
                .eval_location(&var.location, 0, &regs)
                .and_then(|addr| self.format_var_value(var, addr))
            {
                Ok(s) => println!("{} = {}", var.name, s),
                Err(e) => println!("{}", t!("dbg.var_error", name = &var.name, err = format!("{:#}", e))),
            }
        }
        Ok(())
    }

    /// `show locals`/`show args`/`show globals` で使う、1つの変数の表示
    /// 文字列を組み立てる(`print` と同じ表示ルール: `pretty on` なら
    /// 型情報付き)。
    fn format_var_value(&self, var: &dwarf_info::VarInfo, addr: u64) -> Result<String> {
        if matches!(var.ty, dwarf_info::TypeInfo::Struct { .. } | dwarf_info::TypeInfo::Array { .. }) {
            return Ok(self.format_value_by_type(addr, &var.ty, 0));
        }
        let value = self.read_typed_value(addr, &var.ty)?;
        Ok(match value {
            expr::Value::Float(f) if self.print_pretty => format!("({}){}", var.ty.type_name(), f),
            expr::Value::Float(f) => f.to_string(),
            expr::Value::Int(i) if var.is_pointer && self.print_pretty => {
                format!("({}){:#x}", var.ty.type_name(), i as u64)
            }
            expr::Value::Int(i) if var.is_pointer => format!("{:#018x} ({})", i as u64, i),
            expr::Value::Int(i) if self.print_pretty => format!("({}){}", var.ty.type_name(), i),
            expr::Value::Int(i) => i.to_string(),
        })
    }

    /// `addr` にある値を `ty` に従って表示用文字列に変換する。構造体・配列は
    /// それぞれ専用の整形関数に委譲し(それらが `pretty on` 時の型名付与も
    /// 含めて自己完結して処理する)、スカラー/ポインタはここで
    /// `(型名)値` 形式(`pretty on` の場合のみ)に整形する。
    /// `format_struct_value`/`format_array_value` の要素・メンバの表示に
    /// 共通で使う。
    fn format_value_by_type(&self, addr: u64, ty: &dwarf_info::TypeInfo, depth: usize) -> String {
        match ty {
            dwarf_info::TypeInfo::Struct { .. } => self.format_struct_value(addr, ty, depth),
            dwarf_info::TypeInfo::Array { .. } => self.format_array_value(addr, ty, depth),
            dwarf_info::TypeInfo::Pointer { .. } => match self.read_typed_value(addr, ty) {
                Ok(v) => {
                    let s = format!("{:#x}", v.as_i64() as u64);
                    if self.print_pretty {
                        format!("({}){}", ty.type_name(), s)
                    } else {
                        s
                    }
                }
                Err(_) => "?".to_string(),
            },
            _ => match self.read_typed_value(addr, ty) {
                Ok(expr::Value::Float(f)) => {
                    if self.print_pretty {
                        format!("({}){}", ty.type_name(), f)
                    } else {
                        f.to_string()
                    }
                }
                Ok(expr::Value::Int(v)) => {
                    if self.print_pretty {
                        format!("({}){}", ty.type_name(), v)
                    } else {
                        v.to_string()
                    }
                }
                Err(_) => "?".to_string(),
            },
        }
    }

    /// 構造体の値を `{a = 1, b = 2}` の形式(`set print pretty on` なら
    /// 複数行インデント表示)でフォーマットする。ポインタ型メンバは指す先を
    /// 辿らずアドレスの16進表示のみ行う(GDB の既定動作と同様)。ネストした
    /// 構造体・配列は再帰的にフォーマットする(型解決自体が
    /// `MAX_TYPE_DEPTH` で打ち切られているため、無限再帰にはならない)。
    fn format_struct_value(&self, addr: u64, ty: &dwarf_info::TypeInfo, depth: usize) -> String {
        let members = match ty {
            dwarf_info::TypeInfo::Struct { members, .. } => members,
            _ => return "?".to_string(),
        };
        let max = self.print_elements.unwrap_or(usize::MAX);
        let mut parts = Vec::new();
        for m in members.iter().take(max) {
            let member_addr = addr + m.offset;
            let value_str = self.format_value_by_type(member_addr, &m.ty, depth + 1);
            parts.push(format!("{} = {}", m.name, value_str));
        }
        if members.len() > max {
            parts.push("...".to_string());
        }
        if self.print_pretty {
            let pad = "  ".repeat(depth + 1);
            let close_pad = "  ".repeat(depth);
            format!(
                "({}) {{\n{}{}\n{}}}",
                ty.type_name(),
                pad,
                parts.join(&format!(",\n{}", pad)),
                close_pad
            )
        } else {
            format!("{{{}}}", parts.join(", "))
        }
    }

    /// 配列の値を `{1, 2, 3}` の形式(`set print pretty on` なら複数行
    /// インデント表示)でフォーマットする。要素数は `set print elements`
    /// で打ち切る。要素が構造体/配列ならネストして再帰的にフォーマットする。
    fn format_array_value(&self, addr: u64, ty: &dwarf_info::TypeInfo, depth: usize) -> String {
        let (element, count) = match ty {
            dwarf_info::TypeInfo::Array { element, count } => (element.as_ref(), *count),
            _ => return "?".to_string(),
        };
        let total = count.unwrap_or(0);
        let max = self.print_elements.map(|n| n as u64).unwrap_or(u64::MAX);
        let shown = total.min(max);
        let elem_size = element.byte_size().max(1);
        let mut parts = Vec::new();
        for i in 0..shown {
            let elem_addr = addr + i * elem_size;
            parts.push(self.format_value_by_type(elem_addr, element, depth + 1));
        }
        if total > shown {
            parts.push("...".to_string());
        }
        if self.print_pretty {
            let pad = "  ".repeat(depth + 1);
            let close_pad = "  ".repeat(depth);
            format!(
                "({}) {{\n{}{}\n{}}}",
                ty.type_name(),
                pad,
                parts.join(&format!(",\n{}", pad)),
                close_pad
            )
        } else {
            format!("{{{}}}", parts.join(", "))
        }
    }

    /// DWARF 情報を使い、現在の PC のスコープにあるローカル変数/仮引数
    /// `name` に値を書き込む。`set` の式評価 (`src/expr.rs`) から呼ばれる。
    /// 書き込みバイト数は変数の型サイズ(`DW_AT_byte_size`、最大8バイト)。
    /// 変数の型が浮動小数点数 (`float`/`double`) の場合は値を IEEE754 の
    /// ビット列に変換して書き込み、そうでなければ整数として書き込む
    /// (代入する式の値が浮動小数点数であれば、その場合は切り捨てる)。
    pub fn write_variable(&self, name: &str, value: expr::Value) -> Result<()> {
        let (addr, var) = self.resolve_variable(name)?;
        self.write_typed_value(addr, &var.ty, value)
    }

    /// ローカル変数/仮引数 `name` の実体アドレスを返す。式の `&x` (アドレス
    /// 取得演算子) から呼ばれる。
    pub fn variable_address(&self, name: &str) -> Result<u64> {
        Ok(self.resolve_variable(name)?.0)
    }

    /// `base_name->field1[i]->field2...` を評価する。`base_name` は
    /// ローカル変数/仮引数名で、各ステップの起点は(構造体/配列へのポインタ、
    /// または構造体/配列そのもの)である必要がある。式の `->`/`[]` 演算子
    /// (`src/expr.rs`) から呼ばれる。
    pub fn read_member_chain(&self, base_name: &str, steps: &[expr::ChainStep]) -> Result<expr::Value> {
        let (addr, ty) = self.resolve_member_chain(base_name, steps)?;
        self.read_typed_value(addr, &ty)
    }

    /// `read_member_chain` の書き込み版。`set base->field...=式`/
    /// `set base[i]=式` から呼ばれる。
    pub fn write_member_chain(&self, base_name: &str, steps: &[expr::ChainStep], value: expr::Value) -> Result<()> {
        let (addr, ty) = self.resolve_member_chain(base_name, steps)?;
        self.write_typed_value(addr, &ty, value)
    }

    /// `print`/`show` 用。最終ステップの型が構造体/配列なら整形済み文字列を
    /// 返し、それ以外はスカラー値+型情報を返す(`read_for_print` と同様)。
    pub fn read_chain_for_print(&self, base_name: &str, steps: &[expr::ChainStep]) -> Result<expr::PrintResult> {
        let (addr, ty) = self.resolve_member_chain(base_name, steps)?;
        if matches!(ty, dwarf_info::TypeInfo::Struct { .. } | dwarf_info::TypeInfo::Array { .. }) {
            return Ok(expr::PrintResult::Text(self.format_value_by_type(addr, &ty, 0)));
        }
        let value = self.read_typed_value(addr, &ty)?;
        let is_pointer = matches!(ty, dwarf_info::TypeInfo::Pointer { .. });
        let hint = expr::TypeHint { is_pointer, type_name: ty.type_name() };
        Ok(expr::PrintResult::Value(value, Some(hint)))
    }

    /// `base_name` から `steps` を辿り、最後のステップの (アドレス, 型) を
    /// 返す。`read_member_chain`/`write_member_chain`/`read_chain_for_print`
    /// の共通処理。
    fn resolve_member_chain(&self, base_name: &str, steps: &[expr::ChainStep]) -> Result<(u64, dwarf_info::TypeInfo)> {
        if steps.is_empty() {
            bail!("{}", t!("dbg.chain_empty"));
        }
        let (addr, var) = self.resolve_variable(base_name)?;
        // 先頭から暗黙のデリファレンスを1回済ませてしまわない: `[i]` は
        // ポインタ自身の値をベースアドレスとして使う必要があり(配列は
        // そのまま自分のアドレスを使う)、`->` はポインタなら1回だけ
        // デリファレンスする必要がある。この2つは要求するデリファレンス
        // 回数が違うため、各ステップが自分の種類に応じて自分で処理する。
        let mut cur_addr = addr;
        let mut cur_ty = var.ty;
        let mut cur_name = base_name.to_string();
        for (i, step) in steps.iter().enumerate() {
            let (step_addr, step_ty) = match step {
                expr::ChainStep::Field(field) => {
                    let (struct_addr, struct_ty) = self.deref_if_pointer(cur_addr, &cur_ty)?;
                    let members = match &struct_ty {
                        dwarf_info::TypeInfo::Struct { members, .. } => members,
                        _ => bail!(
                            "{}",
                            t!("dbg.not_struct_or_pointer", name = cur_name, field = field)
                        ),
                    };
                    let m = members
                        .iter()
                        .find(|m| &m.name == field)
                        .ok_or_else(|| anyhow!("{}", t!("dbg.member_not_found", field = field)))?;
                    (struct_addr + m.offset, m.ty.clone())
                }
                expr::ChainStep::Index(idx) => {
                    let (base_addr, element_ty) = match &cur_ty {
                        dwarf_info::TypeInfo::Array { element, .. } => (cur_addr, (**element).clone()),
                        dwarf_info::TypeInfo::Pointer { pointee } => {
                            let bytes = self.read_mem(cur_addr, 8)?;
                            let base = u64::from_ne_bytes(bytes.try_into().unwrap());
                            (base, (**pointee).clone())
                        }
                        _ => bail!(
                            "{}",
                            t!("dbg.not_array_or_pointer", name = cur_name, idx = idx)
                        ),
                    };
                    let elem_size = element_ty.byte_size().max(1);
                    let elem_addr = (base_addr as i64).wrapping_add(idx.wrapping_mul(elem_size as i64)) as u64;
                    (elem_addr, element_ty)
                }
            };
            cur_addr = step_addr;
            cur_ty = step_ty;
            cur_name = match step {
                expr::ChainStep::Field(f) => f.clone(),
                expr::ChainStep::Index(idx) => format!("[{}]", idx),
            };
            if i + 1 == steps.len() {
                return Ok((cur_addr, cur_ty));
            }
        }
        unreachable!("steps が空でなければループ内で必ず return する");
    }

    /// `ty` がポインタ型なら `addr` に格納されているポインタ値を読んで
    /// (指し示す先のアドレス, 指し示す先の型) を返す。ポインタでなければ
    /// `(addr, ty)` をそのまま返す(構造体を値として直接指している場合)。
    fn deref_if_pointer(&self, addr: u64, ty: &dwarf_info::TypeInfo) -> Result<(u64, dwarf_info::TypeInfo)> {
        match ty {
            dwarf_info::TypeInfo::Pointer { pointee } => {
                let bytes = self.read_mem(addr, 8)?;
                let ptr_val = u64::from_ne_bytes(bytes.try_into().unwrap());
                Ok((ptr_val, (**pointee).clone()))
            }
            other => Ok((addr, other.clone())),
        }
    }

    /// `addr` にある値を `ty` に従って読み取る。構造体そのもの/不明な型は
    /// 先頭8バイトを整数として返す(値としての表示や、それ以上のメンバ
    /// アクセスの連鎖には対応しない)。
    fn read_typed_value(&self, addr: u64, ty: &dwarf_info::TypeInfo) -> Result<expr::Value> {
        const DW_ATE_FLOAT: u8 = 0x04;
        const DW_ATE_SIGNED: u8 = 0x05;
        const DW_ATE_SIGNED_CHAR: u8 = 0x06;

        match ty {
            dwarf_info::TypeInfo::Base { byte_size, encoding, .. } => {
                let size = (*byte_size as usize).clamp(1, 8);
                let bytes = self.read_mem(addr, size)?;
                if *encoding == DW_ATE_FLOAT {
                    let f = if size == 4 {
                        let mut buf = [0u8; 4];
                        buf.copy_from_slice(&bytes);
                        f32::from_ne_bytes(buf) as f64
                    } else {
                        let mut buf = [0u8; 8];
                        buf[..size].copy_from_slice(&bytes);
                        f64::from_ne_bytes(buf)
                    };
                    return Ok(expr::Value::Float(f));
                }
                let mut buf = [0u8; 8];
                buf[..size].copy_from_slice(&bytes);
                let raw = u64::from_ne_bytes(buf);
                let signed = matches!(*encoding, DW_ATE_SIGNED | DW_ATE_SIGNED_CHAR);
                let value = if signed && size < 8 {
                    let shift = (8 - size) * 8;
                    ((raw << shift) as i64) >> shift
                } else {
                    raw as i64
                };
                Ok(expr::Value::Int(value))
            }
            dwarf_info::TypeInfo::Pointer { .. }
            | dwarf_info::TypeInfo::Struct { .. }
            | dwarf_info::TypeInfo::Array { .. }
            | dwarf_info::TypeInfo::Unknown => {
                let bytes = self.read_mem(addr, 8)?;
                Ok(expr::Value::Int(i64::from_ne_bytes(bytes.try_into().unwrap())))
            }
        }
    }

    /// `addr` に `value` を `ty` に従って書き込む。整数型の場合は
    /// `DW_AT_byte_size` ぶんだけ、浮動小数点数の場合は IEEE754 のビット列
    /// (4バイトなら `f32`、それ以外は `f64`)に変換して書き込む。構造体
    /// そのもの/不明な型への書き込みは対応していない。
    fn write_typed_value(&self, addr: u64, ty: &dwarf_info::TypeInfo, value: expr::Value) -> Result<()> {
        const DW_ATE_FLOAT: u8 = 0x04;
        match ty {
            dwarf_info::TypeInfo::Base { byte_size, encoding, .. } => {
                let size = (*byte_size as usize).clamp(1, 8);
                let bytes: Vec<u8> = if *encoding == DW_ATE_FLOAT {
                    if size == 4 {
                        (value.as_f64() as f32).to_ne_bytes().to_vec()
                    } else {
                        value.as_f64().to_ne_bytes()[..size].to_vec()
                    }
                } else {
                    value.as_i64().to_ne_bytes()[..size].to_vec()
                };
                self.write_mem(addr, &bytes)
            }
            dwarf_info::TypeInfo::Pointer { .. } => self.write_mem(addr, &value.as_i64().to_ne_bytes()),
            dwarf_info::TypeInfo::Struct { .. }
            | dwarf_info::TypeInfo::Array { .. }
            | dwarf_info::TypeInfo::Unknown => {
                bail!("{}", t!("dbg.write_unsupported_type"))
            }
        }
    }

    /// 変数名を現在の PC のスコープで解決し、(アドレス, 変数情報) を返す。
    fn resolve_variable(&self, name: &str) -> Result<(u64, dwarf_info::VarInfo)> {
        let pid = self.pid()?;
        let regs = registers::get_regs(pid)?;
        let link_pc = regs.rip.wrapping_sub(self.load_bias);
        let (sub, var) = self
            .dwarf
            .find_variable(link_pc, name)
            .ok_or_else(|| anyhow!("{}", t!("dbg.var_not_found", name = name)))?;
        let frame_base = self.eval_frame_base(&sub.frame_base, &regs)?;
        let addr = self.eval_location(&var.location, frame_base, &regs)?;
        Ok((addr, var.clone()))
    }

    /// `DW_AT_frame_base` の DWARF 式を評価してフレームベースアドレスを得る。
    /// `DW_OP_call_frame_cfa` は CFI を読まず、`push rbp; mov rbp,rsp` という
    /// 典型的なプロローグを前提に `rbp+16` で近似する
    /// (`backtrace`/`up` の rbp チェイン前提と同じ簡略化)。
    fn eval_frame_base(&self, expr: &[u8], regs: &registers::Regs) -> Result<u64> {
        if expr.is_empty() {
            bail!("{}", t!("dbg.no_frame_base"));
        }
        match expr[0] {
            0x9c => Ok(regs.rbp.wrapping_add(16)),
            op @ 0x70..=0x8f => {
                let offset = dwarf_info::read_sleb128(&expr[1..])
                    .ok_or_else(|| anyhow!("{}", t!("dbg.frame_base_parse_failed")))?;
                let reg_val = self.dwarf_reg_value(op - 0x70, regs)?;
                Ok((reg_val as i64).wrapping_add(offset) as u64)
            }
            op => bail!("{}", t!("dbg.unsupported_frame_base_expr", op = format!("{:#x}", op))),
        }
    }

    /// 変数の `DW_AT_location` (DWARF 式) を評価してメモリアドレスを得る。
    /// `DW_OP_fbreg`(frame_base 相対)、`DW_OP_addr`(絶対アドレス、グローバル
    /// 変数用)、`DW_OP_bregN`(レジスタ相対)に対応する。
    fn eval_location(&self, expr: &[u8], frame_base: u64, regs: &registers::Regs) -> Result<u64> {
        if expr.is_empty() {
            bail!("{}", t!("dbg.no_var_location"));
        }
        match expr[0] {
            0x91 => {
                let offset = dwarf_info::read_sleb128(&expr[1..])
                    .ok_or_else(|| anyhow!("{}", t!("dbg.var_expr_parse_failed")))?;
                Ok((frame_base as i64).wrapping_add(offset) as u64)
            }
            0x03 => {
                if expr.len() < 9 {
                    bail!("{}", t!("dbg.dw_op_addr_missing_operand"));
                }
                let addr = u64::from_le_bytes(expr[1..9].try_into().unwrap());
                Ok(self.runtime_addr(addr))
            }
            op @ 0x70..=0x8f => {
                let offset = dwarf_info::read_sleb128(&expr[1..])
                    .ok_or_else(|| anyhow!("{}", t!("dbg.var_expr_parse_failed")))?;
                let reg_val = self.dwarf_reg_value(op - 0x70, regs)?;
                Ok((reg_val as i64).wrapping_add(offset) as u64)
            }
            op => bail!("{}", t!("dbg.unsupported_var_location_expr", op = format!("{:#x}", op))),
        }
    }

    /// DWARF (x86-64 System V ABI) のレジスタ番号からレジスタ値を取得する。
    fn dwarf_reg_value(&self, dwarf_reg: u8, regs: &registers::Regs) -> Result<u64> {
        let name = match dwarf_reg {
            0 => "rax",
            1 => "rdx",
            2 => "rcx",
            3 => "rbx",
            4 => "rsi",
            5 => "rdi",
            6 => "rbp",
            7 => "rsp",
            8 => "r8",
            9 => "r9",
            10 => "r10",
            11 => "r11",
            12 => "r12",
            13 => "r13",
            14 => "r14",
            15 => "r15",
            16 => "rip",
            other => bail!("{}", t!("dbg.unsupported_dwarf_reg", other = other)),
        };
        registers::get_by_name(regs, name).ok_or_else(|| anyhow!("{}", t!("dbg.reg_get_failed", name = name)))
    }

    pub fn read_mem(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let pid = self.pid()?;
        let mut out = Vec::with_capacity(len);
        let mut cur = addr & !0x7;
        let start_pad = (addr - cur) as usize;
        while out.len() < start_pad + len {
            let word = ptrace::read(pid, cur as *mut c_void).context(t!("dbg.mem_read_failed").to_string())?;
            out.extend_from_slice(&word.to_ne_bytes());
            cur += 8;
        }
        Ok(out[start_pad..start_pad + len].to_vec())
    }

    pub fn write_mem(&self, addr: u64, data: &[u8]) -> Result<()> {
        let pid = self.pid()?;
        let mut cur = addr;
        let mut offset = 0usize;
        while offset < data.len() {
            let word_addr = cur & !0x7;
            let mut word = ptrace::read(pid, word_addr as *mut c_void)
                .context(t!("dbg.mem_read_failed").to_string())?
                .to_ne_bytes();
            let in_word_off = (cur - word_addr) as usize;
            let n = (8 - in_word_off).min(data.len() - offset);
            word[in_word_off..in_word_off + n].copy_from_slice(&data[offset..offset + n]);
            let new_word = i64::from_ne_bytes(word);
            ptrace::write(pid, word_addr as *mut c_void, new_word)
                .context(t!("dbg.mem_write_failed").to_string())?;
            cur += n as u64;
            offset += n;
        }
        Ok(())
    }

    pub fn backtrace(&self) -> Result<()> {
        let pid = self.pid()?;
        let regs = registers::get_regs(pid)?;
        let mut rip = regs.rip;
        let mut rbp = regs.rbp;
        for depth in 0..64 {
            let link_ip = rip.wrapping_sub(self.load_bias);
            let sym = self.symbol_at(rip);
            match self.dwarf.lookup(link_ip) {
                Some(row) => println!(
                    "#{:<2} {:#018x} in {} at {}:{}",
                    depth,
                    rip,
                    sym,
                    row.file.display(),
                    row.line
                ),
                None => println!("#{:<2} {:#018x} in {}", depth, rip, sym),
            }
            if rbp == 0 {
                break;
            }
            let saved_rbp = self.read_mem(rbp, 8)?;
            let ret_addr = self.read_mem(rbp + 8, 8)?;
            let saved_rbp = u64::from_ne_bytes(saved_rbp.try_into().unwrap());
            let ret_addr = u64::from_ne_bytes(ret_addr.try_into().unwrap());
            if ret_addr == 0 || saved_rbp == 0 {
                break;
            }
            rip = ret_addr;
            rbp = saved_rbp;
        }
        Ok(())
    }

    /// ELF のシンボルテーブル (関数シンボル) を一覧表示する (`syms` コマンド)。
    /// `filter` が指定されていれば、シンボル名にその文字列を含むものだけ
    /// 表示する。プロセス実行中はロードバイアスを加えた実行時アドレスを、
    /// 未実行なら ELF 上のリンク時アドレスをそのまま表示する。
    pub fn list_symbols(&self, filter: Option<&str>) {
        let symbols: Vec<&Symbol> =
            self.elf.symbols.iter().filter(|s| filter.is_none_or(|f| s.name.contains(f))).collect();
        if symbols.is_empty() {
            println!("{}", t!("dbg.no_symbols"));
            return;
        }
        for s in symbols {
            let addr = if self.is_running() { self.runtime_addr(s.addr) } else { s.addr };
            println!("{:#018x} {:>6} {}", addr, s.size, s.name);
        }
    }

    /// `.debug_line` の行番号情報を一覧表示する (`lines` コマンド)。`filter`
    /// が関数名として解決できれば、その関数のアドレス範囲内の行だけに
    /// 絞り込む(解決できなければ絞り込まず全件表示する)。終端マーカー
    /// (`end_sequence`)の行は実際のソース行ではないため表示しない。
    pub fn list_lines(&self, filter: Option<&str>) {
        let range = filter.and_then(|name| self.elf.find_by_name(name)).map(|s| (s.addr, s.addr + s.size.max(1)));
        let mut any = false;
        for row in self.dwarf.lines() {
            if row.end_sequence {
                continue;
            }
            if let Some((lo, hi)) = range {
                if row.addr < lo || row.addr >= hi {
                    continue;
                }
            }
            any = true;
            let addr = if self.is_running() { self.runtime_addr(row.addr) } else { row.addr };
            println!("{:#018x} {}:{}", addr, row.file.display(), row.line);
        }
        if !any {
            println!("{}", t!("dbg.no_lineinfo"));
        }
    }

    /// ソースコードを表示する (`list` コマンド)。`spec` の形式によって
    /// 表示位置の決め方を変える:
    /// - 指定なし: 実行中なら現在の PC の行、そうでなければ `main` 関数の行。
    /// - `*<addr>` (シンボル/アドレス指定): アドレスに対応する行番号情報を
    ///   DWARF 行テーブルから引く(実行中はランタイムアドレス、未実行なら
    ///   リンク時アドレスとして解釈する。`break *<addr>` と同じ慣習)。
    /// - 数値のみ: 行番号として扱い、直近の実行位置(または `main`)と
    ///   同じファイル内のその行を表示する。
    /// - `<ファイル>:<行番号>`: 行番号情報からファイル名が一致する行を探し、
    ///   そのファイルの指定行を表示する。
    /// - それ以外: 関数名として ELF シンボルテーブルから探し、その関数の
    ///   先頭アドレスに対応する行を表示する。
    pub fn list_source(&self, spec: Option<&str>) -> Result<()> {
        let (file, line) = match spec {
            None => self.current_source_location()?,
            Some(s) => {
                let s = s.trim();
                if let Some(hex) = s.strip_prefix('*') {
                    self.location_from_address(hex)?
                } else if let Ok(n) = s.parse::<u32>() {
                    (self.current_source_location()?.0, n)
                } else if let Some((file_part, line_part)) = s.rsplit_once(':') {
                    let n: u32 = line_part
                        .trim()
                        .parse()
                        .with_context(|| t!("dbg.line_parse_failed", s = line_part).to_string())?;
                    let file = self
                        .resolve_source_file(file_part.trim())
                        .ok_or_else(|| anyhow!("{}", t!("dbg.file_lineinfo_not_found", file = file_part)))?;
                    (file, n)
                } else {
                    self.location_from_function(s)?
                }
            }
        };
        self.show_source_window(&file, line);
        Ok(())
    }

    /// 実行中なら現在の PC の(ファイル, 行番号)、そうでなければ `main`
    /// 関数の(ファイル, 行番号)を返す。`list` の指定省略時・数値のみ
    /// 指定時のデフォルト位置決めに使う。
    fn current_source_location(&self) -> Result<(PathBuf, u32)> {
        if self.is_running() {
            let pid = self.pid()?;
            let regs = registers::get_regs(pid)?;
            let link_pc = regs.rip.wrapping_sub(self.load_bias);
            if let Some(row) = self.dwarf.lookup(link_pc) {
                return Ok((row.file.clone(), row.line));
            }
        }
        let sym = self
            .elf
            .find_by_name("main")
            .ok_or_else(|| anyhow!("{}", t!("dbg.list_no_location")))?;
        let row = self
            .dwarf
            .lookup(sym.addr)
            .ok_or_else(|| anyhow!("{}", t!("dbg.list_no_location_no_dwarf")))?;
        Ok((row.file.clone(), row.line))
    }

    /// アドレス(16進文字列)に対応する(ファイル, 行番号)を求める。
    /// 実行中はランタイムアドレス、未実行ならリンク時アドレスとして解釈する
    /// (`break *<addr>` と同じ慣習)。
    fn location_from_address(&self, hex: &str) -> Result<(PathBuf, u32)> {
        let addr = parse_addr(hex)?;
        let link_addr = if self.is_running() { addr.wrapping_sub(self.load_bias) } else { addr };
        let row = self
            .dwarf
            .lookup(link_addr)
            .ok_or_else(|| anyhow!("{}", t!("dbg.addr_lineinfo_not_found", addr = format!("{:#x}", addr))))?;
        Ok((row.file.clone(), row.line))
    }

    /// 関数名に対応する(ファイル, 行番号)を求める。ELF シンボルテーブルで
    /// アドレスを引き、そのアドレスの行番号情報を DWARF から引く。
    fn location_from_function(&self, name: &str) -> Result<(PathBuf, u32)> {
        let sym =
            self.elf.find_by_name(name).ok_or_else(|| anyhow!("{}", t!("dbg.function_not_found", name = name)))?;
        let row = self
            .dwarf
            .lookup(sym.addr)
            .ok_or_else(|| anyhow!("{}", t!("dbg.function_lineinfo_not_found", name = name)))?;
        Ok((row.file.clone(), row.line))
    }

    /// 行番号情報の中から、ファイル名(フルパス・ファイル名部分・パスの
    /// 末尾部分一致のいずれか)が `spec` に一致する最初のファイルパスを返す。
    fn resolve_source_file(&self, spec: &str) -> Option<PathBuf> {
        self.dwarf
            .lines()
            .iter()
            .find(|r| {
                !r.end_sequence
                    && (r.file.to_string_lossy() == spec
                        || r.file.file_name().and_then(|f| f.to_str()) == Some(spec)
                        || r.file.to_string_lossy().ends_with(&format!("/{}", spec)))
            })
            .map(|r| r.file.clone())
    }

    /// `file` の `center_line` を中心とした前後計10行のソースを表示する
    /// (GDB の `list` のデフォルト表示幅に合わせる)。
    fn show_source_window(&self, file: &Path, center_line: u32) {
        const WINDOW: u32 = 10;
        let center_line = center_line.max(1);
        let start = center_line.saturating_sub(WINDOW / 2 - 1).max(1);
        let end = start + WINDOW - 1;
        let Ok(content) = fs::read_to_string(file) else {
            println!("{}", t!("dbg.source_open_failed", path = file.display()));
            return;
        };
        println!("{}:", file.display());
        let mut any = false;
        for (i, text) in content.lines().enumerate() {
            let n = (i + 1) as u32;
            if n < start {
                continue;
            }
            if n > end {
                break;
            }
            println!("{:>4}\t{}", n, text);
            any = true;
        }
        if !any {
            println!("{}", t!("dbg.no_source_in_range"));
        }
    }

    pub fn program_path(&self) -> &Path {
        &self.program
    }

    pub fn entry(&self) -> u64 {
        self.runtime_addr(self.elf.entry)
    }
}

/// `path` にある共有ライブラリの ELF を読み、`.dynsym` にある関数シンボル
/// の名前 -> リンク時アドレス (`st_value`, ライブラリ自身のロードアドレス
/// 0 からの相対値) の対応表を返す。メモリリーク追跡で malloc/free 等を
/// libc から解決するのに使う。
fn load_dynamic_symbols(path: &Path) -> Result<HashMap<String, u64>> {
    let buf = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let elf = Elf::parse(&buf).context("failed to parse library ELF")?;
    let mut map = HashMap::new();
    for sym in elf.dynsyms.iter() {
        if !sym.is_function() || sym.st_value == 0 {
            continue;
        }
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            map.entry(name.to_string()).or_insert(sym.st_value);
        }
    }
    Ok(map)
}

fn read_source_line(path: &Path, line: u32) -> Option<String> {
    if line == 0 {
        return None;
    }
    let content = fs::read_to_string(path).ok()?;
    content.lines().nth((line - 1) as usize).map(|s| s.to_string())
}

fn parse_addr(s: &str) -> Result<u64> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).context(t!("dbg.addr_parse_failed").to_string())
}

/// 1/2/4/8バイトの生バイト列(リトルエンディアン)を `u64` へゼロ拡張する。
/// ウォッチポイントの値表示(`watch`/`check_watchpoint_hit`)に使う。
fn bytes_to_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf[..bytes.len()].copy_from_slice(bytes);
    u64::from_ne_bytes(buf)
}

/// 先頭が call 命令であればその命令長を返す。
/// legacy prefix / REX prefix と、E8 (call rel32) および FF /2, /3 (call r/m) に対応。
fn call_instruction_len(bytes: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 => {
                i += 1;
            }
            _ => break,
        }
    }
    if i < bytes.len() && (0x40..=0x4F).contains(&bytes[i]) {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    match bytes[i] {
        0xE8 => Some(i + 5),
        0xFF => {
            let modrm = *bytes.get(i + 1)?;
            let reg = (modrm >> 3) & 0x7;
            if reg != 2 && reg != 3 {
                return None;
            }
            let md = modrm >> 6;
            let rm = modrm & 0x7;
            let mut len = i + 2; // opcode + modrm
            let mut has_sib = false;
            if md != 3 && rm == 4 {
                has_sib = true;
                len += 1;
            }
            let disp = match md {
                0 => {
                    if rm == 5 || (has_sib && bytes.get(i + 2).map(|b| b & 0x7) == Some(5)) {
                        4
                    } else {
                        0
                    }
                }
                1 => 1,
                2 => 4,
                _ => 0,
            };
            len += disp;
            Some(len)
        }
        _ => None,
    }
}
