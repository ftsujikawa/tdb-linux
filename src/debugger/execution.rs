use super::Debugger;
use crate::breakpoint::Breakpoint;
use crate::registers;
use anyhow::{bail, Result};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use rust_i18n::t;

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
                    println!(
                        "{}",
                        t!("dbg.bp_hit", addr = format!("{:#x}", addr), sym = sym)
                    );
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
                        Some(row)
                            if row.is_stmt && Some((row.file.clone(), row.line)) != start_line =>
                        {
                            if !self.print_source_context(&row.file, row.line) {
                                println!("{}:{}", row.file.display(), row.line);
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
                    println!(
                        "{}",
                        t!("dbg.bp_hit", addr = format!("{:#x}", addr), sym = sym)
                    );
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
                        Some(row)
                            if row.is_stmt && Some((row.file.clone(), row.line)) != start_line =>
                        {
                            if !self.print_source_context(&row.file, row.line) {
                                println!("{}:{}", row.file.display(), row.line);
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
    /// マルチスレッドのデバッグ対象に対応するため、特定の tid ではなく
    /// `waitpid(None, __WALL)` でスレッドグループ内のどのスレッドのイベント
    /// も受け取る。呼び出し元(`cont`/`stepi`)は事前に `current_tid` だけを
    /// `continue`/`step` させているが、他のスレッドは(新規作成されたものも
    /// 含め)バックグラウンドで自由に動いているため、それらのイベントも
    /// ここで捌く必要がある:
    /// - 新規スレッド (`PTRACE_EVENT_CLONE`) は登録してそのまま `continue` する。
    /// - 新規プロセス (`PTRACE_EVENT_FORK`/`PTRACE_EVENT_VFORK`) も同様に
    ///   登録するが、独立したアドレス空間を持つため `processes` にも
    ///   加える(ブレークポイントの多重インストール対象を決めるため)。
    /// - 既知でない tid の SIGTRAP は、新規スレッド/プロセスの自動アタッチ
    ///   直後の初回停止とみなして登録し、`continue` する。
    /// - 追跡中の他のスレッドがブレークポイント/シグナルで停止した場合は、
    ///   `current_tid` をそのスレッドへ切り替えたうえで報告する
    ///   (GDB の all-stop ほど厳密ではないが、「発火したスレッドへ
    ///   フォーカスが移る」という体験は再現する)。
    fn wait_and_report(&mut self) -> Result<()> {
        loop {
            let status = waitpid(None, Some(WaitPidFlag::__WALL))?;

            if let WaitStatus::PtraceEvent(parent_tid, Signal::SIGTRAP, event) = status {
                if event == libc::PTRACE_EVENT_CLONE {
                    if let Ok(new_tid_raw) = ptrace::getevent(parent_tid) {
                        self.register_thread(Pid::from_raw(new_tid_raw as i32));
                    }
                } else if event == libc::PTRACE_EVENT_FORK || event == libc::PTRACE_EVENT_VFORK {
                    if let Ok(new_pid_raw) = ptrace::getevent(parent_tid) {
                        let new_pid = Pid::from_raw(new_pid_raw as i32);
                        self.processes.insert(new_pid);
                        self.register_thread(new_pid);
                    }
                }
                self.resume_or_hold(parent_tid);
                continue;
            }

            if let WaitStatus::Stopped(tid, _) = status {
                // 未登録なら念のため登録する(通常は CLONE イベント側で
                // 先に登録済みのはずだが、イベントが逆順で届く可能性に備える)。
                self.register_thread(tid);
                if self.pending_initial_stop.remove(&tid) {
                    // TRACECLONE による新規スレッドの自動アタッチ直後の初回
                    // 停止。カーネル/タイミングにより SIGTRAP のことも
                    // SIGSTOP のこともあるため、シグナル種別を問わず
                    // 無条件に読み飛ばす(ただし `lock` 中でロック対象外の
                    // スレッドなら、`resume_or_hold` が判断して停止させたまま
                    // にする)。
                    self.resume_or_hold(tid);
                    continue;
                }
                if self.locked_tid.map(|locked| locked != tid).unwrap_or(false) {
                    // `lock` 中でロック対象以外のスレッドの停止(`lock` 時に
                    // 送った `SIGSTOP` によるものが典型)。報告せず、
                    // 停止させたままにする(再開しない)。
                    continue;
                }
            }

            match status {
                WaitStatus::Exited(tid, code) => {
                    let was_process_leader = Some(tid) != self.pid && self.processes.contains(&tid);
                    self.on_thread_gone(tid);
                    if self.processes.is_empty() || self.threads.is_empty() {
                        self.mark_exited();
                        println!("{}", t!("dbg.process_exited", code = code));
                        return Ok(());
                    }
                    if was_process_leader {
                        println!(
                            "{}",
                            t!("dbg.child_process_exited", pid = tid.as_raw(), code = code)
                        );
                    }
                    continue;
                }
                WaitStatus::Signaled(tid, sig, _) => {
                    let was_process_leader = Some(tid) != self.pid && self.processes.contains(&tid);
                    self.on_thread_gone(tid);
                    if self.processes.is_empty() || self.threads.is_empty() {
                        self.mark_exited();
                        println!("{}", t!("dbg.process_signaled", sig = sig));
                        return Ok(());
                    }
                    if was_process_leader {
                        println!(
                            "{}",
                            t!("dbg.child_process_signaled", pid = tid.as_raw(), sig = sig)
                        );
                    }
                    continue;
                }
                WaitStatus::Stopped(tid, Signal::SIGTRAP) => {
                    self.current_tid = Some(tid);
                    let pid = tid;
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
                        println!(
                            "{}",
                            t!("dbg.bp_hit", addr = format!("{:#x}", bp_addr), sym = sym)
                        );
                        self.show_stop_location(bp_addr);
                        return Ok(());
                    } else {
                        println!(
                            "{}",
                            t!("dbg.stopped_sigtrap", rip = format!("{:#x}", regs.rip))
                        );
                        return Ok(());
                    }
                }
                WaitStatus::Stopped(tid, sig) => {
                    self.current_tid = Some(tid);
                    println!("{}", t!("dbg.stopped_signal", sig = sig));
                    // SIGINT (Ctrl-C) による停止は、GDB 同様ユーザーが実行中の
                    // デバッグ対象を一時停止させて状況を見たいという意図が
                    // 明確なため、停止した PC のソース位置(無ければ逆アセンブル)
                    // も併せて表示する。他のシグナル(クラッシュ系等)では
                    // 従来通りシグナル名のみを表示する。
                    if sig == Signal::SIGINT {
                        if let Ok(regs) = registers::get_regs(tid) {
                            self.show_stop_location(regs.rip);
                        }
                    }
                    return Ok(());
                }
                other => {
                    println!("{}", t!("dbg.unexpected_wait", other = other : {:?}));
                    return Ok(());
                }
            }
        }
    }
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
