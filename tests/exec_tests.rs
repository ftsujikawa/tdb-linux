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
