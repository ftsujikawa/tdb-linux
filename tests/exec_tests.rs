//! 実行制御 (REQ-EXEC-*) の結合テスト。テスト仕様書 1章 (TC-EXEC-*) 対応。

#[path = "support/mod.rs"]
mod support;

use support::*;

/// TC-EXEC-01 / TC-EXEC-02: `run` でプロセスが起動し、`continue` で
/// ブレークポイントまで進んで前後7行のソース表示 (`>` マーカー付き) が出る。
#[test]
fn run_and_continue_hit_breakpoint_show_source_context() {
    let target = target_hello();
    let out = run_script(&target, &[], &["break add", "run", "continue", "quit"]);

    assert_contains(&out, "プロセスを起動しました");
    assert_contains(&out, "PIE");
    assert_contains(&out, "ブレークポイントで停止: 0x");
    assert_contains(&out, "<add>");
    assert_contains(&out, "hello.c:4");
    // 前後3行(計最大7行)、現在行に `>` マーカー。
    assert_contains(&out, "int add(int a, int b) {");
    assert_contains(&out, ">   4\t    int c = a + b;");
    assert_contains(&out, "    return c;");
}

/// TC-EXEC-03: `stepi` で1命令だけ進み、`rip` が変化する。
#[test]
fn stepi_advances_single_instruction() {
    let target = target_struct();
    let out = run_script(
        &target,
        &[],
        &["break add", "run", "continue", "info registers", "stepi", "info registers", "quit"],
    );

    let rip_lines: Vec<&str> = out.lines().filter(|l| l.trim_start().starts_with("rip ")).collect();
    assert_eq!(rip_lines.len(), 2, "expected two 'rip' lines in info registers output\n{out}");
    assert_ne!(rip_lines[0], rip_lines[1], "rip should change after stepi\n{out}");
    assert_contains(&out, "停止 (SIGTRAP)");
}

/// TC-EXEC-04: `nexti` は `call` 命令をまたいで実行する。
/// `main` で停止後、`add` の呼び出しに到達するまで `nexti` を繰り返しても
/// `add` 内部のブレークポイントには decend しない(呼び出し先の
/// ユーザーブレークポイントを踏まない)ことを確認する。
#[test]
fn nexti_steps_over_call_without_entering_callee_breakpoint() {
    let target = target_struct();
    // main の先頭から10命令ぶん nexti する(while ループ内の add 呼び出しを
    // 含む)。add 側にもブレークポイントを置いておき、そちらで「ブレーク
    // ポイントで停止」と報告されないこと (nexti がまたいで進むこと) を見る。
    let mut cmds = vec!["break main", "break add", "run", "continue"];
    let nextis = vec!["nexti"; 40];
    cmds.extend(nextis.iter().map(|s| *s));
    cmds.push("quit");
    let out = run_script(&target, &[], &cmds);

    // main 停止は1回、add (関数の先頭 <add> ちょうど) での「ブレークポイント
    // で停止」表示は出ない(nexti は call をまたぐため、add の入口に一致する
    // ブレークポイント表示が現れないはず)。
    assert_contains(&out, "ブレークポイントで停止: 0x");
    assert_contains(&out, "<main>");
    assert_not_contains(&out, "<add+0x0>");
}

/// TC-EXEC-05: `step` はソース行単位でステップインする。
#[test]
fn step_advances_source_line_and_can_step_into_call() {
    let target = target_struct();
    let out = run_script(&target, &[], &["break main", "run", "continue", "step", "step", "quit"]);

    assert_contains(&out, "target.c:19");
    assert_contains(&out, "target.c:20");
}

/// TC-EXEC-06: `next` はソース行単位でステップオーバーし、`call` を含む
/// 行でも呼び出し先には入らない。
#[test]
fn next_steps_over_call_at_source_level() {
    let target = target_struct();
    let out = run_script(
        &target,
        &[],
        &["break main", "run", "continue", "next", "next", "next", "next", "next", "next", "next", "quit"],
    );

    // main 内の行 (19 -> 26 付近) を順に辿るはずで、add 内部の行 (13,14) は
    // 出てこない(next が call をまたいで進むため、add の中には入らない)。
    assert_not_contains(&out, "target.c:13");
    assert_not_contains(&out, "target.c:14");
    assert_contains(&out, "target.c:26");
}

/// TC-EXEC-07: `up` は呼び出し元まで実行を戻す。
#[test]
fn up_returns_to_caller_frame() {
    let target = target_struct();
    let out = run_script(&target, &[], &["break add", "run", "continue", "up", "quit"]);

    assert_contains(&out, "<add>");
    assert_contains(&out, "<main>");
    assert_contains(&out, "target.c:30");
}

/// TC-EXEC-08: `kill` は実行中のプロセスを終了し、以後の操作はエラーになる。
#[test]
fn kill_terminates_process_and_blocks_further_continue() {
    let target = target_hello();
    let out = run_script(&target, &[], &["break add", "run", "continue", "kill", "continue", "quit"]);

    assert_contains(&out, "プロセスを終了しました");
    assert_contains(&out, "プロセスは実行されていません");
}

/// TC-EXEC-09: tdb 自身への SIGINT はデバッグ対象へ転送され、tdb は
/// 終了せずにシグナル停止として報告する。
#[test]
fn sigint_is_forwarded_to_debuggee_and_reported() {
    let target = target_struct(); // main() は sleep(1) を含む無限ループ
    let mut session = Session::spawn(&target, &[]);
    session.send(&["run", "continue"]);
    // continue が無限ループに入るまで少し待ってから SIGINT を送る。
    session.wait_millis(400);
    session.interrupt();
    session.wait_millis(200);
    session.send(&["kill", "quit"]);
    let out = session.finish();

    assert_contains(&out, "シグナル SIGINT を受信して停止しました");
    assert_contains(&out, "プロセスを終了しました");
}

/// TC-EXEC-10 (異常系): 未起動状態での `continue` はクラッシュせず
/// エラーメッセージを表示して REPL を継続する。
#[test]
fn continue_before_run_reports_error_without_crashing() {
    let target = target_hello();
    let out = run_script(&target, &[], &["continue", "help", "quit"]);

    assert_contains(&out, "プロセスは実行されていません");
    // 後続の `help` が実行できている = REPL が継続していることの確認。
    assert_contains(&out, "run, r");
}

#[test]
fn source_step_resumes_at_the_next_line_after_a_library_call() {
    let target = build_example("break_target", "break_target.c", &["-no-pie"]);
    let out = run_script(
        &target,
        &[],
        &["break break_target.c:15", "run", "continue", "step", "quit"],
    );
    assert_contains(&out, ">  15");
    assert_contains(&out, ">  13");
    assert_count(&out, "ブレークポイントで停止:", 1);
    assert_not_contains(&out, "エラー:");
}

#[test]
fn source_step_and_next_report_a_watchpoint_before_advancing_the_line() {
    let target = build_example("break_target", "break_target.c", &["-no-pie"]);
    for command in ["step", "next"] {
        let out = run_script(
            &target,
            &[],
            &["break add", "run", "continue", "watch sum", command, "quit"],
        );
        assert_contains(&out, "ウォッチポイント 2 がトリガーされました: sum");
        assert_contains(&out, "新値 = 0x1");
        assert_not_contains(&out, "エラー:");
    }
}

#[test]
fn continue_reports_inferior_termination_by_signal() {
    let out = run_script(
        &coverage_target(),
        &["kill"],
        &["lang en", "run", "continue", "quit"],
    );
    assert_contains(&out, "Process terminated by signal SIGKILL");
    assert_not_contains(&out, "Error:");
}

fn execution_target() -> std::path::PathBuf {
    build_example("execution_target", "execution_target.c", &["-no-pie"])
}

fn instruction_address(target: &std::path::Path, symbol: &str) -> u64 {
    let output = std::process::Command::new("nm").arg(target).output().unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let symbols = String::from_utf8(output.stdout).unwrap();
    let address = symbols
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let address = fields.next()?;
            (fields.nth(1) == Some(symbol)).then_some(address)
        })
        .unwrap_or_else(|| panic!("missing instruction label {symbol}"));
    u64::from_str_radix(address, 16).unwrap()
}

#[test]
fn watchpoint_fires_while_stepping_over_the_current_breakpoint_instruction() {
    let target = execution_target();
    let address = instruction_address(&target, "store_value");
    let breakpoint = format!("break *{address:#x}");
    for command in ["continue", "stepi", "nexti"] {
        let out = run_script(
            &target,
            &[],
            &[
                "run",
                &breakpoint,
                "continue",
                "watch *$rdi 4",
                command,
                "x/4 $rdi",
                "delete 2",
                "continue",
                "quit",
            ],
        );
        assert_count(&out, "ブレークポイントで停止:", 1);
        assert_count(&out, "ウォッチポイント 2 がトリガーされました:", 1);
        assert_contains(&out, "旧値 = 0x0");
        assert_contains(&out, "新値 = 0x11");
        assert_contains(&out, ": 11 00 00 00");
        assert_contains(&out, "[プロセスは終了しました (code=0)]");
        assert_not_contains(&out, "エラー:");
    }
}

#[test]
fn nexti_stops_at_an_existing_breakpoint_after_an_indirect_call() {
    let target = execution_target();
    let caller_entry = instruction_address(&target, "call_store");
    let call = instruction_address(&target, "indirect_call");
    let after_call = instruction_address(&target, "after_indirect_call");
    let caller_breakpoint = format!("break *{caller_entry:#x}");
    let at_return = format!("break *{after_call:#x}");
    let out = run_script(
        &target,
        &[],
        &[
            "run",
            &caller_breakpoint,
            &at_return,
            "continue",
            "delete 1",
            "stepi",
            "stepi",
            "nexti",
            "info breakpoints",
            "print/x $rip",
            "continue",
            "quit",
        ],
    );
    assert_contains(&out, &format!("停止 (SIGTRAP): rip={call:#x}"));
    assert_contains(&out, &format!("ブレークポイントで停止: {after_call:#x}"));
    assert_contains(&out, &format!("2: {after_call:#x}"));
    assert_contains(&out, &format!("$rip = {after_call:#x}"));
    assert_contains(&out, "[プロセスは終了しました (code=0)]");
    assert_not_contains(&out, "エラー:");
}

#[test]
fn source_next_reports_a_breakpoint_reached_inside_an_indirect_call() {
    let target = execution_target();
    let call = instruction_address(&target, "indirect_call");
    let store = instruction_address(&target, "store_value");
    let at_call = format!("break *{call:#x}");
    let at_store = format!("break *{store:#x}");
    let out = run_script(
        &target,
        &[],
        &[
            "run",
            &at_call,
            &at_store,
            "continue",
            "next",
            "print/x $rip",
            "quit",
        ],
    );
    assert_contains(&out, &format!("ブレークポイントで停止: {store:#x} <store_value>"));
    assert_contains(&out, &format!("$rip = {store:#x}"));
    assert_not_contains(&out, "エラー:");
}

#[test]
fn continue_reports_a_signaled_fork_child_and_waits_for_the_parent() {
    let out = run_script(
        &execution_target(),
        &["fork"],
        &["lang en", "run", "continue", "continue", "quit"],
    );
    let (before_exit, _) = out
        .split_once("Process exited (code=0)")
        .unwrap_or_else(|| panic!("missing parent exit\n{out}"));
    assert_contains(before_exit, "terminated by signal SIGKILL");
    assert_contains(before_exit, "Stopped after receiving signal SIGCHLD");
    assert_not_contains(&out, "Error:");
}

#[test]
fn next_reports_exit_when_the_call_never_returns() {
    let target = execution_target();
    let call = instruction_address(&target, "exit_call");
    let breakpoint = format!("break *{call:#x}");
    let out = run_script(
        &target,
        &["exit"],
        &[
            "lang en",
            "run",
            &breakpoint,
            "continue",
            "next",
            "print/d 7",
            "quit",
        ],
    );
    assert_contains(&out, &format!("Stopped at breakpoint: {call:#x}"));
    assert_count(&out, "Process exited (code=7)", 1);
    assert_contains(&out, "7 = 7");
    assert_not_contains(&out, "Error:");
}

#[test]
fn up_reports_missing_frame_pointer_and_missing_caller_address() {
    let target = execution_target();
    let store = instruction_address(&target, "store_value");
    let breakpoint = format!("break *{store:#x}");
    let out = run_script(
        &target,
        &[],
        &[
            "lang en",
            "run",
            &breakpoint,
            "continue",
            "set $rbp=0",
            "up",
            "set $rbp=$rdi",
            "up",
            "print/x $rip",
            "quit",
        ],
    );
    assert_contains(&out, "unable to obtain the frame pointer (rbp)");
    assert_contains(&out, "Cannot obtain the caller's address");
    assert_count(&out, "Error:", 2);
    assert_contains(&out, &format!("$rip = {store:#x}"));
}

#[test]
fn instruction_steps_at_a_call_breakpoint_stop_in_the_expected_frame() {
    let target = execution_target();
    let call = instruction_address(&target, "indirect_call");
    let callee = instruction_address(&target, "store_value");
    let return_address = instruction_address(&target, "after_indirect_call");
    let at_call = format!("break *{call:#x}");

    for (command, expected, value) in [
        ("stepi", callee, "00"),
        ("nexti", return_address, "11"),
        ("next", return_address, "11"),
    ] {
        let out = run_script(
            &target,
            &[],
            &["run", &at_call, "continue", command, "print/x $rip", "x/4 $rdi", "quit"],
        );
        assert_contains(&out, &format!("ブレークポイントで停止: {call:#x}"));
        assert_contains(&out, &format!("$rip = {expected:#x}"));
        assert_contains(&out, &format!(": {value} 00 00 00"));
        assert_not_contains(&out, "エラー:");
    }
}

#[test]
fn source_steps_at_a_call_line_enter_or_skip_the_callee() {
    let target = build_example("break_target", "break_target.c", &["-no-pie"]);
    for (command, expected, other) in [
        ("step", ">   4", ">  15"),
        ("next", ">  15", ">   4"),
    ] {
        let out = run_script(
            &target,
            &[],
            &["break break_target.c:14", "run", "continue", command, "quit"],
        );
        assert_contains(&out, ">  14");
        assert_contains(&out, expected);
        assert_not_contains(&out, other);
        assert_not_contains(&out, "エラー:");
    }
}

#[test]
fn stepping_or_continuing_from_an_exit_instruction_reports_the_exit_once() {
    let target = execution_target();
    let address = instruction_address(&target, "exit_syscall");
    let breakpoint = format!("break *{address:#x}");
    for command in ["step", "next", "continue"] {
        let out = run_script(
            &target,
            &["syscall"],
            &[
                "lang en",
                "run",
                &breakpoint,
                "continue",
                command,
                "print/d 91",
                "quit",
            ],
        );
        assert_contains(&out, &format!("Stopped at breakpoint: {address:#x}"));
        assert_count(&out, "Process exited (code=9)", 1);
        assert_contains(&out, "91 = 91");
        assert_not_contains(&out, "Error:");
    }
}

#[test]
fn step_reports_exit_when_entering_a_function_without_dwarf_that_never_returns() {
    let line = include_str!("../examples/execution_target.c")
        .lines()
        .position(|line| line.contains("step into code without DWARF"))
        .expect("missing call-site marker")
        + 1;
    let breakpoint = format!("break execution_target.c:{line}");
    let out = run_script(
        &execution_target(),
        &["syscall"],
        &[
            "lang en",
            &breakpoint,
            "run",
            "continue",
            "step",
            "print/d 92",
            "quit",
        ],
    );
    assert_contains(&out, &format!("execution_target.c:{line}"));
    assert_count(&out, "Stopped at breakpoint:", 1);
    assert_count(&out, "Process exited (code=9)", 1);
    assert_contains(&out, "92 = 92");
    assert_not_contains(&out, "Error:");
}

#[test]
fn source_step_reports_a_fault_and_leaves_the_inferior_at_the_faulting_instruction() {
    let target = execution_target();
    let address = instruction_address(&target, "illegal_instruction");
    let breakpoint = format!("break *{address:#x}");
    for command in ["step", "next"] {
        let out = run_script(
            &target,
            &["illegal"],
            &[
                "lang en",
                "run",
                &breakpoint,
                "continue",
                command,
                "print/x $rip",
                "quit",
            ],
        );
        assert_contains(&out, "SIGILL");
        assert_contains(&out, &format!("$rip = {address:#x}"));
        assert_not_contains(&out, "Process exited");
        assert_not_contains(&out, "Error:");
    }
}

#[test]
fn source_steps_report_the_next_dwarf_line_when_the_source_file_is_missing() {
    let path_map = format!(
        "-fdebug-prefix-map={}=/tdb-test-source-unavailable",
        env!("CARGO_MANIFEST_DIR")
    );
    let target = build_example(
        "break_target_missing_source",
        "break_target.c",
        &["-no-pie", &path_map],
    );
    for command in ["step", "next"] {
        let out = run_script(
            &target,
            &[],
            &[
                "lang en",
                "break break_target.c:14",
                "run",
                "continue",
                command,
                "quit",
            ],
        );
        let line = if command == "step" { 4 } else { 15 };
        assert!(
            out.lines().any(|entry| {
                entry == format!("/tdb-test-source-unavailable/examples/break_target.c:{line}")
            }),
            "{out}"
        );
        assert_not_contains(&out, "Error:");
    }
}

#[test]
fn nexti_steps_over_memory_indirect_calls_with_each_displacement_width() {
    let target = execution_target();
    let addresses = [
        "call_sib",
        "call_disp8",
        "call_disp32",
        "call_rip_relative",
        "call_no_base",
        "memory_calls_end",
    ]
    .map(|label| instruction_address(&target, label));
    let breakpoint = format!("break *{:#x}", addresses[0]);
    let mut commands = vec!["lang en", "run", &breakpoint, "continue"];
    for _ in &addresses[1..] {
        commands.extend(["nexti", "print/x $rip"]);
    }
    commands.extend(["continue", "quit"]);

    let out = run_script(&target, &["memory"], &commands);
    let actual: Vec<_> = out
        .lines()
        .filter_map(|line| line.strip_prefix("$rip = 0x"))
        .map(|addr| u64::from_str_radix(addr, 16).unwrap())
        .collect();
    assert_eq!(actual, addresses[1..], "{out}");
    assert_contains(&out, "Process exited (code=0)");
    assert_not_contains(&out, "Error:");
}

#[test]
fn source_step_reports_signal_termination_inside_an_undebugged_function() {
    let stop = coverage_target_breakpoint("step into libc without DWARF");
    let out = run_script(
        &coverage_target(),
        &["kill"],
        &["lang en", &stop, "run", "continue", "step", "quit"],
    );

    assert_count(&out, "Stopped at breakpoint:", 1);
    assert_count(&out, "Process terminated by signal SIGKILL", 1);
    assert_not_contains(&out, "Error:");
}
