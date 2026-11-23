use super::Debugger;
use crate::breakpoint::Breakpoint;
use crate::leak;
use crate::registers;
use anyhow::{Context, Result};
use goblin::elf::Elf;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use rust_i18n::t;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

impl Debugger {
    /// `leak on`/`leak off`。無効化時は、その場でインストール済みの
    /// 追跡用ブレークポイントを取り除く(有効化時は次回の `continue` で
    /// 遅延解決・設置する)。
    pub fn set_leak_tracking(&mut self, on: bool) {
        self.leak.enabled = on;
        if !on {
            self.uninstall_leak_breakpoints();
        }
        println!(
            "{}",
            t!(
                "dbg.leak_tracking_state",
                state = if on { "on" } else { "off" }
            )
        );
    }

    /// 現在の追跡状態(on/off・確保/解放回数・未解決の free)を表示する。
    pub fn show_leak_status(&self) {
        println!(
            "{}",
            t!(
                "dbg.leak_tracking_state",
                state = if self.leak.enabled { "on" } else { "off" }
            )
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
                t!(
                    "dbg.leak_none",
                    allocs = self.leak.total_allocs,
                    frees = self.leak.total_frees
                )
            );
        } else {
            let mut items: Vec<(&u64, &leak::LiveAlloc)> = self.leak.live.iter().collect();
            items.sort_by_key(|(addr, _)| **addr);
            let total: u64 = items.iter().map(|(_, a)| a.size).sum();
            println!(
                "{}",
                t!("dbg.leak_summary", count = items.len(), total = total)
            );
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
            println!(
                "{}",
                t!(
                    "dbg.leak_bad_frees_header",
                    count = self.leak.bad_frees.len()
                )
            );
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
    pub(super) fn ensure_leak_breakpoints_installed(&mut self) {
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
        let Some(tid) = self.current_tid else { return };
        let addrs: Vec<u64> = self.leak.entries.keys().copied().collect();
        for addr in addrs {
            if !self.breakpoints.contains_key(&addr) {
                let mut bp = Breakpoint::new(addr);
                if bp.enable(tid).is_ok() {
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
    pub(super) fn uninstall_leak_breakpoints(&mut self) {
        let Some(tid) = self.current_tid else {
            self.leak.pending.clear();
            return;
        };
        let entry_addrs: Vec<u64> = self.leak.entries.keys().copied().collect();
        for addr in entry_addrs {
            if self.bp_ids.values().any(|&a| a == addr) {
                continue;
            }
            if let Some(mut bp) = self.breakpoints.remove(&addr) {
                let _ = bp.disable(tid);
            }
        }
        let pending_addrs: Vec<u64> = self.leak.pending.keys().copied().collect();
        for addr in pending_addrs {
            if self.bp_ids.values().any(|&a| a == addr) {
                continue;
            }
            if let Some(mut bp) = self.breakpoints.remove(&addr) {
                let _ = bp.disable(tid);
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
            let Some(path_part) = line.split_whitespace().last() else {
                continue;
            };
            let base_name = Path::new(path_part)
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or("");
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
    pub(super) fn handle_leak_breakpoint(&mut self, addr: u64) -> Result<bool> {
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
                let old_ptr = if func == leak::AllocFn::Realloc {
                    regs.rdi
                } else {
                    0
                };
                if !self.breakpoints.contains_key(&ret_addr) {
                    let mut bp = Breakpoint::new(ret_addr);
                    bp.enable(pid)?;
                    self.breakpoints.insert(ret_addr, bp);
                }
                self.leak.pending.insert(
                    ret_addr,
                    leak::PendingCall {
                        func,
                        size,
                        old_ptr,
                        call_site,
                    },
                );
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
                        leak::LiveAlloc {
                            size: pending.size,
                            func: pending.func,
                            call_site: pending.call_site,
                        },
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
                        leak::LiveAlloc {
                            size: pending.size,
                            func: pending.func,
                            call_site: pending.call_site,
                        },
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
            leak::AllocFn::Free => {
                unreachable!("free はエントリ時点で即座に処理するため pending には入らない")
            }
        }

        if !self.bp_ids.values().any(|&a| a == addr) {
            if let Some(mut bp) = self.breakpoints.remove(&addr) {
                bp.disable(pid)?;
            }
        }
        Ok(())
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
