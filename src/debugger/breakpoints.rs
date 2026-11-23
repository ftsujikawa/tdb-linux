use super::{parse_addr, source_path_matches, Debugger, Watchpoint};
use crate::breakpoint::Breakpoint;
use crate::disasm;
use crate::dwarf_info;
use crate::elf_info::Symbol;
use crate::registers;
use anyhow::{anyhow, bail, Result};
use nix::unistd::Pid;
use rust_i18n::t;
use std::path::PathBuf;

impl Debugger {
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
    pub(super) fn install_breakpoint_by_spec(&mut self, spec: &str) -> Result<()> {
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
            .filter(|r| !r.end_sequence && r.is_stmt && source_path_matches(&r.file, file_part))
            .collect();
        if candidates.is_empty() {
            bail!("{}", t!("dbg.file_lineinfo_not_found", file = file_part));
        }
        candidates.sort_by_key(|r| (r.line, r.addr));
        let row = candidates
            .into_iter()
            .find(|r| r.line >= line)
            .ok_or_else(|| {
                anyhow!(
                    "{}",
                    t!("dbg.no_code_after_line", file = file_part, line = line)
                )
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
            let existing_id = self
                .bp_ids
                .iter()
                .find(|(_, &a)| a == addr)
                .map(|(&id, _)| id)
                .unwrap_or(0);
            bail!(
                "{}",
                t!(
                    "dbg.bp_addr_in_use",
                    addr = format!("{:#x}", addr),
                    id = existing_id
                )
            );
        }
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        self.bp_ids.insert(id, addr);
        let mut bp = Breakpoint::new(addr);
        if self.is_running() {
            if let Some(tid) = self.current_tid {
                if let Err(e) = bp.enable(tid) {
                    eprintln!("{}", t!("dbg.bp_install_failed", err = e));
                }
                // 現在のプロセス以外にも既知のプロセス(fork(2) 由来の子)が
                // あれば、そちらのメモリにも同じブレークポイントを反映する
                // (ベストエフォート: 停止していないプロセスへの書き込みは
                // 失敗しうるが、無視する)。
                for &leader in &self.processes {
                    if leader != tid {
                        let _ = bp.install_in(leader);
                    }
                }
            }
        }
        self.breakpoints.insert(addr, bp);
        println!(
            "{}",
            t!(
                "dbg.bp_set",
                id = id,
                label = label,
                addr = format!("{:#x}", addr)
            )
        );
        Ok(())
    }

    pub fn list_breakpoints(&self) {
        if self.bp_ids.is_empty() {
            println!("{}", t!("dbg.no_breakpoints"));
            return;
        }
        for (id, addr) in self.bp_ids.iter() {
            let link_addr = addr.wrapping_sub(self.load_bias);
            let sym = match self.elf.find_by_addr(link_addr) {
                Some(s) if link_addr == s.addr => s.name.clone(),
                Some(s) => format!("{}+{:#x}", s.name, link_addr - s.addr),
                None => "?".to_string(),
            };
            let enabled = self
                .breakpoints
                .get(addr)
                .map(|b| b.enabled)
                .unwrap_or(false);
            let loc = match self.dwarf.lookup(link_addr) {
                Some(row) => format!(" at {}:{}", row.file.display(), row.line),
                None => String::new(),
            };
            let inactive = if enabled {
                String::new()
            } else {
                t!("dbg.bp_inactive").to_string()
            };
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
            if let Some(tid) = self.current_tid {
                if !self.exited {
                    bp.disable(tid)?;
                    for &leader in &self.processes {
                        if leader != tid {
                            let _ = bp.remove_from(leader);
                        }
                    }
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
            bail!(
                "{}",
                t!(
                    "dbg.watch_unaligned",
                    addr = format!("{:#x}", addr),
                    len = len
                )
            );
        }
        self.pid()?;
        let slot = self
            .watchpoints
            .iter()
            .position(|w| w.is_none())
            .ok_or_else(|| anyhow!("{}", t!("dbg.watch_max")))?;

        let bytes = self.read_mem(addr, len as usize)?;
        let last_value = bytes_to_u64(&bytes);
        // DR レジスタはスレッドごとの状態なので、既知の全スレッドに設置する
        // (新しく作られるスレッドには `register_thread` が同じ設定を行う)。
        // `current_tid` は確実に ptrace 停止中なのでエラーを伝播するが、
        // それ以外のスレッドはバックグラウンドで動いていて(ptrace 停止して
        // いなくて)DR レジスタの読み書きができないことがあるため、
        // ベストエフォートで無視する(そのスレッドが後で何らかの理由で
        // 停止すれば、`register_thread`/`switch_thread` 等では設置しない
        // ため、その間はそのスレッドでの発火を見逃す可能性がある)。
        let current = self.pid()?;
        self.install_watch_slot(current, slot, addr, len)?;
        for tid in self.threads.iter().copied().collect::<Vec<_>>() {
            if tid != current {
                let _ = self.install_watch_slot(tid, slot, addr, len);
            }
        }

        let id = self.next_bp_id;
        self.next_bp_id += 1;
        self.wp_ids.insert(id, slot);
        self.watchpoints[slot] = Some(Watchpoint {
            addr,
            len,
            label: label.clone(),
            last_value,
        });
        println!(
            "{}",
            t!(
                "dbg.watch_set",
                id = id,
                label = label,
                addr = format!("{:#x}", addr),
                len = len
            )
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
        let slot = self
            .wp_ids
            .remove(&id)
            .ok_or_else(|| anyhow!("{}", t!("dbg.watch_not_found", id = id)))?;
        self.watchpoints[slot] = None;
        if !self.exited {
            // 設置時と同様、バックグラウンドで動いている(ptrace 停止して
            // いない)スレッドへの解除は失敗しうるためベストエフォートとする。
            for tid in self.threads.iter().copied().collect::<Vec<_>>() {
                let _ = self.uninstall_watch_slot(tid, slot);
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
    pub(super) fn install_watch_slot(
        &self,
        pid: Pid,
        slot: usize,
        addr: u64,
        len: u8,
    ) -> Result<()> {
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
    pub(super) fn check_watchpoint_hit(&mut self) -> Result<Option<String>> {
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
            let id = self
                .wp_ids
                .iter()
                .find_map(|(&id, &s)| (s == slot).then_some(id));
            let Some(id) = id else { continue };
            let Some((addr, len, label, old_value)) = self.watchpoints[slot]
                .as_ref()
                .map(|wp| (wp.addr, wp.len, wp.label.clone(), wp.last_value))
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
        Ok(if messages.is_empty() {
            None
        } else {
            Some(messages.join("\n"))
        })
    }
}

/// 1/2/4/8バイトの生バイト列(リトルエンディアン)を `u64` へゼロ拡張する。
/// ウォッチポイントの値表示(`watch`/`check_watchpoint_hit`)に使う。
fn bytes_to_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf[..bytes.len()].copy_from_slice(bytes);
    u64::from_ne_bytes(buf)
}
