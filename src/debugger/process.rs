use super::{Debugger, DEBUGGEE_PID};
use crate::registers;
use anyhow::{anyhow, bail, Context, Result};
use nix::sys::personality::{self, Persona};
use nix::sys::ptrace;
use nix::sys::ptrace::Options;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{execv, fork, ForkResult, Pid};
use rust_i18n::t;
use std::ffi::CString;
use std::fs;
use std::path::Path;
use std::sync::atomic::Ordering;

impl Debugger {
    /// 現在フォーカスしているスレッドの tid を返す(`current_tid`)。
    /// レジスタ/メモリ/ブレークポイント等、ptrace で特定のスレッドを
    /// 指定する必要がある操作はすべてこれを経由する。マルチスレッドの
    /// デバッグ対象では、ブレークポイント/ウォッチポイントのヒットに
    /// 応じてこれが自動的に切り替わる(`thread <n>` でも手動切り替え可能)。
    /// メソッド名は歴史的経緯で `pid` のままだが、実質的には「現在の
    /// スレッドの tid」を返す。
    pub(super) fn pid(&self) -> Result<Pid> {
        self.current_tid
            .ok_or_else(|| anyhow!("{}", t!("dbg.not_running")))
    }

    /// `thread`/`lock` コマンドの引数を tid に解決する。`info threads` の
    /// 先頭列(デバッガが振った小さい番号)を主な入力として想定するが、
    /// 括弧内に表示される実際の OS の tid(pid)をそのまま渡された場合も
    /// 受け付ける(ユーザーが `info threads` の表示のどちらを指しているか
    /// 迷わずに済むようにするための救済措置)。
    fn resolve_thread_id(&self, id: u32) -> Option<Pid> {
        if let Some(&tid) = self.thread_ids.get(&id) {
            return Some(tid);
        }
        self.threads
            .iter()
            .find(|&&tid| tid.as_raw() == id as i32)
            .copied()
    }

    /// メッセージ表示用に、`tid` に対応するデバッガの小さい番号を返す
    /// (`resolve_thread_id` で生の OS tid を受け付けた場合、ユーザーが
    /// 入力した値をそのまま「id」として表示すると `info threads` の id 列と
    /// 食い違って紛らわしいため、常に正規の番号に揃える)。見つからなければ
    /// `fallback`(ユーザーの入力値)をそのまま返す。
    fn canonical_thread_id(&self, tid: Pid, fallback: u32) -> u32 {
        self.thread_ids
            .iter()
            .find(|(_, &v)| v == tid)
            .map(|(&k, _)| k)
            .unwrap_or(fallback)
    }

    /// `thread apply all <コマンド>` 用に、既知の全スレッド(`fork(2)` 由来の
    /// 別プロセスのスレッドも含む)の番号を昇順で返す。
    pub fn thread_ids_sorted(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self.thread_ids.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// `thread apply all` の実行中、対象スレッドへ一時的にフォーカスを
    /// 移す。`switch_thread` と違い `lock` 中の制限を無視する(呼び出し側が
    /// 必ず `restore_focus` で元に戻す前提の内部専用 API)。
    pub fn focus_thread_for_apply(&mut self, id: u32) -> Result<()> {
        let tid = self
            .resolve_thread_id(id)
            .ok_or_else(|| anyhow!("{}", t!("dbg.thread_not_found", id = id)))?;
        self.fixup_breakpoint_rip(tid)
            .map_err(|_| anyhow!("{}", t!("dbg.thread_not_stopped", id = id)))?;
        self.current_tid = Some(tid);
        Ok(())
    }

    /// 現在のフォーカスを返す(`thread apply all` 実行前の状態を保存するため)。
    pub fn current_focus(&self) -> Option<Pid> {
        self.current_tid
    }

    /// フォーカスを復元する(`thread apply all` 実行後、元のスレッドへ戻すため)。
    pub fn restore_focus(&mut self, tid: Option<Pid>) {
        self.current_tid = tid;
    }

    /// デバッグ対象の終了を記録する。SIGINT 転送スレッドが古い(既に
    /// 終了した)pid に送らないよう、`DEBUGGEE_PID` も併せてクリアする。
    pub(super) fn mark_exited(&mut self) {
        self.exited = true;
        DEBUGGEE_PID.store(0, Ordering::SeqCst);
    }

    /// 新規スレッド `tid` を登録する(`PTRACE_O_TRACECLONE` による自動
    /// アタッチ検出時、`wait_and_report` から呼ぶ)。既存のウォッチポイントは
    /// DR レジスタがスレッドごとの状態のため、新しいスレッドにも同じ設定を
    /// 反映する。
    pub(super) fn register_thread(&mut self, tid: Pid) {
        if self.threads.insert(tid) {
            let id = self.next_thread_id;
            self.next_thread_id += 1;
            self.thread_ids.insert(id, tid);
            self.pending_initial_stop.insert(tid);
            for (slot, wp) in self.watchpoints.iter().enumerate() {
                if let Some(wp) = wp {
                    let _ = self.install_watch_slot(tid, slot, wp.addr, wp.len);
                }
            }
        }
    }

    /// スレッド `tid` が終了した際の後始末。`current_tid` がそのスレッドを
    /// 指していた場合は、残っている別のスレッドへフォールバックする
    /// (無ければ `None`)。ロック対象のスレッドが終了した場合は、ロックも
    /// 解除して停止させていた他のスレッドを再開する(ロックしたまま
    /// 全スレッドが止まった状態で固まってしまうのを防ぐ)。
    pub(super) fn on_thread_gone(&mut self, tid: Pid) {
        self.threads.remove(&tid);
        self.thread_ids.retain(|_, &mut t| t != tid);
        self.processes.remove(&tid);
        if self.current_tid == Some(tid) {
            self.current_tid = self.threads.iter().next().copied();
        }
        if self.locked_tid == Some(tid) {
            self.locked_tid = None;
            let others: Vec<Pid> = self.threads.iter().copied().collect();
            for other in others {
                self.release_held_thread(other);
            }
        }
    }

    /// `lock` によって停止させたままにしていたスレッドを再開する。単純に
    /// `PTRACE_CONT` するだけだと、対象スレッドがブレークポイントの int3
    /// 実行直後(rip がブレークポイントアドレスの1バイト先)で止まっている
    /// 場合に、命令境界がずれたまま実行を再開してしまい SIGSEGV 等を
    /// 引き起こす。そのため、int3 直後で止まっているスレッドは rip を
    /// 戻したうえでブレークポイントを一時無効化し、シングルステップで
    /// 踏み越えてから再度有効化してから再開する
    /// (`step_over_current_breakpoint` の他スレッド版)。
    fn release_held_thread(&mut self, tid: Pid) {
        let Ok(mut regs) = registers::get_regs(tid) else {
            return;
        };
        let bp_addr = regs.rip.wrapping_sub(1);
        let was_enabled = self
            .breakpoints
            .get(&bp_addr)
            .map(|bp| bp.enabled)
            .unwrap_or(false);
        if was_enabled {
            regs.rip = bp_addr;
            if registers::set_regs(tid, &regs).is_err() {
                return;
            }
            if let Some(bp) = self.breakpoints.get_mut(&bp_addr) {
                let _ = bp.disable(tid);
            }
            if ptrace::step(tid, None).is_ok() {
                let _ = waitpid(tid, None);
            }
            if let Some(bp) = self.breakpoints.get_mut(&bp_addr) {
                let _ = bp.enable(tid);
            }
        }
        let _ = ptrace::cont(tid, None);
    }

    /// `tid` がロック中でない、またはロックされていなければ再開し、
    /// ロック中で `tid` がロック対象でなければ何もせず停止させたままにする
    /// (`wait_and_report` の各所で「内部的に静かに再開してよいか」の判定に使う)。
    pub(super) fn resume_or_hold(&self, tid: Pid) {
        if self.locked_tid.map(|locked| locked == tid).unwrap_or(true) {
            let _ = ptrace::cont(tid, None);
        }
    }

    /// `/proc/<tid>/status` の `State:` 行から、そのスレッドが現在
    /// 実行中(ptrace 停止中でない)かどうかを判定する。`lock` 実行時、
    /// 既に停止しているスレッドへ余計な `SIGSTOP` を送らないために使う。
    fn is_thread_running(tid: Pid) -> bool {
        let Ok(status) = fs::read_to_string(format!("/proc/{}/status", tid.as_raw())) else {
            return false;
        };
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("State:") {
                return matches!(
                    rest.trim().chars().next(),
                    Some('R') | Some('S') | Some('D')
                );
            }
        }
        false
    }

    /// スレッド `tid` が「ブレークポイントの int3 実行直後」(rip がブレーク
    /// ポイントアドレスの1バイト先)で停止している場合、rip をそのアドレス
    /// まで巻き戻して補正する(実際にその命令を踏み越えさせるのは呼び出し
    /// 側の責務)。`wait_and_report` を経由せず(`lock`/`thread` コマンドなど
    /// から)直接レジスタを見る際に、まだ補正されていない生の rip を
    /// 見せたり、それを起点に `continue` して命令境界がずれ SIGSEGV に
    /// なったりするのを防ぐ。
    fn fixup_breakpoint_rip(&self, tid: Pid) -> Result<registers::Regs> {
        let regs = self.peek_breakpoint_rip(tid)?;
        let _ = registers::set_regs(tid, &regs);
        Ok(regs)
    }

    /// `fixup_breakpoint_rip` の読み取り専用版。レジスタは書き換えず、
    /// 補正後の rip を含む `Regs` の値だけを返す(`info threads` などの
    /// 参照系コマンドで、対象スレッドの状態を勝手に変えたくない場合に使う)。
    fn peek_breakpoint_rip(&self, tid: Pid) -> Result<registers::Regs> {
        let mut regs = registers::get_regs(tid)?;
        let bp_addr = regs.rip.wrapping_sub(1);
        if self.breakpoints.contains_key(&bp_addr) {
            regs.rip = bp_addr;
        }
        Ok(regs)
    }

    /// スレッド `id` をロックする (`lock <n>` コマンド)。以後 `continue`/
    /// `step` 系はこのスレッドのみを実行させる。他の既知のスレッドのうち
    /// 現在実行中のものには `SIGSTOP` を送って停止させる(既に停止中の
    /// ものはそのまま)。新しく作られるスレッドも `wait_and_report` 側で
    /// 自動再開されないようになる(`resume_or_hold` を参照)。
    pub fn lock_thread(&mut self, id: u32) -> Result<()> {
        let tid = self
            .resolve_thread_id(id)
            .ok_or_else(|| anyhow!("{}", t!("dbg.thread_not_found", id = id)))?;
        let display_id = self.canonical_thread_id(tid, id);
        let regs = self
            .fixup_breakpoint_rip(tid)
            .map_err(|_| anyhow!("{}", t!("dbg.thread_not_stopped", id = display_id)))?;
        self.locked_tid = Some(tid);
        self.current_tid = Some(tid);
        for &other in &self.threads {
            if other != tid && Self::is_thread_running(other) {
                let _ = nix::sys::signal::kill(other, Signal::SIGSTOP);
            }
        }
        println!(
            "{}",
            t!("dbg.thread_locked", id = display_id, tid = tid.as_raw())
        );
        self.show_stop_location(regs.rip);
        Ok(())
    }

    /// ロックを解除する (`unlock` コマンド)。`lock` で停止させていた他の
    /// スレッドをすべて再開する。
    pub fn unlock_thread(&mut self) -> Result<()> {
        if self.locked_tid.take().is_some() {
            let others: Vec<Pid> = self
                .threads
                .iter()
                .copied()
                .filter(|&tid| Some(tid) != self.current_tid)
                .collect();
            for tid in others {
                self.release_held_thread(tid);
            }
            println!("{}", t!("dbg.thread_unlocked"));
        } else {
            println!("{}", t!("dbg.thread_not_locked"));
        }
        Ok(())
    }

    /// 実行中のスレッド一覧を表示する (`info threads`)。`lock` 中の
    /// スレッドには行末に印を付ける。`fork(2)` 由来の子プロセス(最初に
    /// 起動したプロセス自身とは異なる、独立したアドレス空間を持つもの)
    /// には別途プロセスである旨の印を付ける。
    pub fn list_threads(&self) -> Result<()> {
        self.pid()?;
        let mut items: Vec<(&u32, &Pid)> = self.thread_ids.iter().collect();
        items.sort_by_key(|(id, _)| **id);
        for (id, &tid) in items {
            let current = if Some(tid) == self.current_tid {
                "*"
            } else {
                " "
            };
            let loc = match self.peek_breakpoint_rip(tid) {
                Ok(regs) => {
                    let link_addr = regs.rip.wrapping_sub(self.load_bias);
                    let sym = match self.elf.find_by_addr(link_addr) {
                        Some(s) if link_addr == s.addr => s.name.clone(),
                        Some(s) => format!("{}+{:#x}", s.name, link_addr - s.addr),
                        None => "??".to_string(),
                    };
                    match self.dwarf.lookup(link_addr) {
                        Some(row) => format!(
                            "{:#018x} in {} at {}:{}",
                            regs.rip,
                            sym,
                            row.file.display(),
                            row.line
                        ),
                        None => format!("{:#018x} in {}", regs.rip, sym),
                    }
                }
                Err(_) => "?".to_string(),
            };
            let lock_tag = if self.locked_tid == Some(tid) {
                format!(" {}", t!("dbg.thread_list_locked_tag"))
            } else {
                String::new()
            };
            let process_tag = if Some(tid) != self.pid && self.processes.contains(&tid) {
                format!(" {}", t!("dbg.thread_list_process_tag"))
            } else {
                String::new()
            };
            println!(
                "{} {}: {} ({}){}{}",
                current,
                id,
                tid.as_raw(),
                loc,
                lock_tag,
                process_tag
            );
        }
        Ok(())
    }

    /// フォーカスするスレッドを切り替える (`thread <n>` コマンド)。対象
    /// スレッドが ptrace 停止中でない(バックグラウンドで動いている)場合は
    /// レジスタが読めないため、切り替え自体を拒否する(先にレジスタ読み取り
    /// を試し、成功した場合のみ `current_tid` を更新する。失敗後に
    /// `current_tid` を壊れた状態のまま残さないため)。`lock` 中は
    /// `current_tid` が `locked_tid` とずれると `continue` がロック対象
    /// スレッドを再開できなくなるため、ロック対象以外への切り替えは拒否する。
    pub fn switch_thread(&mut self, id: u32) -> Result<()> {
        let tid = self
            .resolve_thread_id(id)
            .ok_or_else(|| anyhow!("{}", t!("dbg.thread_not_found", id = id)))?;
        let display_id = self.canonical_thread_id(tid, id);
        if let Some(locked) = self.locked_tid {
            if locked != tid {
                bail!("{}", t!("dbg.thread_locked_cannot_switch"));
            }
        }
        let regs = self
            .fixup_breakpoint_rip(tid)
            .map_err(|_| anyhow!("{}", t!("dbg.thread_not_stopped", id = display_id)))?;
        self.current_tid = Some(tid);
        println!(
            "{}",
            t!("dbg.thread_switched", id = display_id, tid = tid.as_raw())
        );
        self.show_stop_location(regs.rip);
        Ok(())
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
        self.threads.clear();
        self.thread_ids.clear();
        self.next_thread_id = 1;
        self.pending_initial_stop.clear();
        self.locked_tid = None;
        self.processes.clear();

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
                self.current_tid = Some(child);
                DEBUGGEE_PID.store(child.as_raw(), Ordering::SeqCst);
                match waitpid(child, None)? {
                    WaitStatus::Stopped(_, Signal::SIGTRAP) => {}
                    other => bail!(
                        "{}",
                        t!("dbg.unexpected_initial_stop", other = other : {:?})
                    ),
                }
                // 新規スレッド (pthread_create 等の clone(2)) に加え、
                // fork(2)/vfork(2) による子プロセスも自動的に ptrace
                // アタッチさせ、`wait_and_report` の
                // `waitpid(None, __WALL)` で検出できるようにする。
                ptrace::setoptions(
                    child,
                    Options::PTRACE_O_TRACECLONE
                        | Options::PTRACE_O_TRACEFORK
                        | Options::PTRACE_O_TRACEVFORK,
                )
                .context("failed to set ptrace options")?;
                // `register_thread` は使わない: メインスレッドの初回停止は
                // 直前の `waitpid` で既に消化済みのため、
                // `pending_initial_stop` に入れて二重に読み飛ばしては
                // いけない。
                self.threads.insert(child);
                self.thread_ids.insert(self.next_thread_id, child);
                self.next_thread_id += 1;
                self.processes.insert(child);
            }
        }

        if self.elf.is_pie {
            self.load_bias = match self.detect_load_bias() {
                Ok(bias) => bias,
                Err(err) => {
                    self.kill()?;
                    return Err(err);
                }
            };
        } else {
            self.load_bias = 0;
        }

        let pending: Vec<String> = self.pending_breaks.drain(..).collect();
        for spec in pending {
            if let Err(e) = self.install_breakpoint_by_spec(&spec) {
                eprintln!(
                    "{}",
                    t!("dbg.bp_install_failed_named", spec = spec, err = e)
                );
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
        let path = format!("/proc/{pid}/auxv");
        let auxv = fs::read(&path).with_context(|| t!("dbg.auxv_read_failed", path = &path))?;
        // Linux x86-64 の補助ベクトルはネイティブエンディアンの u64 ペア。
        for entry in auxv.chunks_exact(16) {
            let kind = u64::from_ne_bytes(entry[..8].try_into().unwrap());
            match kind {
                libc::AT_NULL => break,
                libc::AT_ENTRY => {
                    let address = u64::from_ne_bytes(entry[8..].try_into().unwrap());
                    return address
                        .checked_sub(self.elf.entry)
                        .ok_or_else(|| anyhow!("{}", t!("dbg.invalid_pie_entry")));
                }
                _ => {}
            }
        }
        bail!("{}", t!("dbg.auxv_entry_missing", path = &path))
    }

    pub(super) fn runtime_addr(&self, link_addr: u64) -> u64 {
        link_addr + self.load_bias
    }

    pub fn kill(&mut self) -> Result<()> {
        if let Some(pid) = self.pid {
            if !self.exited {
                // `ptrace::kill`(`PTRACE_KILL`)は非推奨で信頼できないため、
                // 実際の `SIGKILL` を使う。ただし ptrace 停止中のスレッドは
                // `PTRACE_CONT` 等で一度再開されるまで、送られた致命的
                // シグナルの処理(実際の終了)が遅延することがあるため、
                // 既知の全スレッドに SIGKILL を送ったうえで、停止中のものは
                // 明示的に `PTRACE_CONT` して確実に処理させる。
                for &tid in &self.threads {
                    let _ = nix::sys::signal::kill(tid, Signal::SIGKILL);
                }
                let _ = nix::sys::signal::kill(pid, Signal::SIGKILL);
                for &tid in &self.threads {
                    let _ = ptrace::cont(tid, None);
                }
                // 既知の全スレッドの終了を刈り取る(死んでいれば `waitpid` は
                // 即座に返るはずだが、念のため上限回数付きの `__WALL` ループで
                // 無限ブロックを避ける)。
                for _ in 0..64 {
                    match waitpid(None, Some(WaitPidFlag::__WALL)) {
                        Ok(WaitStatus::Exited(..)) | Ok(WaitStatus::Signaled(..)) => continue,
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
            }
        }
        self.mark_exited();
        self.pid = None;
        self.current_tid = None;
        self.threads.clear();
        self.thread_ids.clear();
        self.pending_initial_stop.clear();
        self.locked_tid = None;
        self.processes.clear();
        println!("{}", t!("dbg.process_killed"));
        Ok(())
    }

    pub fn program_path(&self) -> &Path {
        &self.program
    }

    pub fn entry(&self) -> u64 {
        self.runtime_addr(self.elf.entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leak::AllocFn;
    use std::path::PathBuf;
    use std::process::Command;

    #[test]
    fn replaced_pie_still_resolves_entry_and_tracks_leaks() {
        let output = Command::new("mktemp").arg("-d").output().unwrap();
        assert!(output.status.success());
        let dir = PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
        let target = dir.join("leak_target");
        let replacement = dir.join("replacement");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/leak_target.c");
        let status = Command::new("gcc")
            .args(["-g", "-O0", "-fPIE", "-pie", "-o"])
            .arg(&target)
            .arg(source)
            .status()
            .unwrap();
        assert!(status.success());
        fs::copy(&target, &replacement).unwrap();

        let mut dbg = Debugger::new(target.clone(), Vec::new()).unwrap();
        dbg.set_leak_tracking(true);
        dbg.start().unwrap(); // Returns after the exec stop, before the loader runs.
        let result = (|| -> Result<_> {
            fs::rename(&replacement, &target)?;
            let maps = fs::read_to_string(format!("/proc/{}/maps", dbg.pid()?))?;
            let was_replaced = maps
                .lines()
                .any(|line| line.ends_with(&format!("{} (deleted)", target.display())));
            let original_bias = dbg.load_bias;
            dbg.load_bias = dbg.detect_load_bias()?;
            let resolved_bias = dbg.load_bias;
            dbg.cont()?;
            Ok((was_replaced, original_bias, resolved_bias, dbg.exited))
        })();
        if dbg.is_running() {
            dbg.kill().unwrap();
        }
        fs::remove_dir_all(&dir).unwrap();

        let (was_replaced, original_bias, resolved_bias, exited) = result.unwrap();
        assert!(was_replaced);
        assert_ne!(resolved_bias, 0);
        assert_eq!(resolved_bias, original_bias);
        assert!(exited);
        for (func, size) in [(AllocFn::Malloc, 200), (AllocFn::Calloc, 160)] {
            assert!(
                dbg.leak
                    .live
                    .values()
                    .any(|alloc| alloc.func == func && alloc.size == size),
                "missing {size}-byte allocation from {func:?}"
            );
        }
    }
}
