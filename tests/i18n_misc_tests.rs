//! 多言語対応 (REQ-I18N-*) およびヘルプ/その他 (REQ-MISC-*) の結合テスト。
//! テスト仕様書 8章・9章 (TC-I18N-*, TC-MISC-*) 対応。

#[path = "support/mod.rs"]
mod support;

use support::*;

/// TC-I18N-01: `LANG=ja_JP.UTF-8` で起動すると日本語で表示される。
#[test]
fn banner_is_japanese_when_lang_is_japanese() {
    let target = target_hello();
    let out = run_script(&target, &[], &["quit"]);
    assert_contains(&out, "コマンド一覧を表示します");
}

/// TC-I18N-02: `LANG=en_US.UTF-8` で起動すると英語で表示される。
#[test]
fn banner_is_english_when_lang_is_english() {
    let target = target_hello();
    let mut session = Session::spawn_with_env(&target, &[], &[("LANG", "en_US.UTF-8")]);
    session.send(&["quit"]);
    let out = session.finish();
    assert_contains(&out, "Type 'help' to see the list of commands.");
    assert_not_contains(&out, "コマンド一覧");
}

/// TC-I18N-03: `lang en` で実行中に表示言語を切り替えられる。
#[test]
fn lang_command_switches_language_at_runtime() {
    let target = target_hello();
    let out = run_script(&target, &[], &["lang en", "help", "quit"]);
    assert_contains(&out, "Language switched to 'en'");
    assert_contains(&out, "run, r");
    assert_not_contains(&out, "使用可能なコマンド");
}

/// TC-I18N-04: `lang` (引数省略) は現在の言語設定を表示する。
#[test]
fn lang_without_argument_shows_current_language() {
    let target = target_hello();
    let out = run_script(&target, &[], &["lang", "quit"]);
    assert_contains(&out, "ja");
}

/// TC-I18N-05 (異常系): 未知の言語コードはエラーになり、現在の言語設定は
/// 変わらない。
#[test]
fn lang_with_unknown_code_is_rejected() {
    let target = target_hello();
    let out = run_script(&target, &[], &["lang fr", "break add", "quit"]);
    assert_contains(&out, "不明な言語: 'fr'");
    // 言語は日本語のままなので、後続のメッセージも日本語で出る。
    assert_contains(&out, "未実行のため");
}

/// TC-I18N-06: 言語切り替え後のエラーメッセージも切り替わるが、
/// 識別子部分(関数名等)は翻訳されない。
#[test]
fn error_messages_translate_but_identifiers_do_not() {
    let target = target_hello();
    let out = run_script(&target, &[], &["lang en", "run", "break no_such_func_xyz", "quit"]);
    assert_contains(&out, "Error:");
    assert_contains(&out, "no_such_func_xyz");
    assert_not_contains(&out, "見つかりません");
}

/// TC-MISC-01: `help` は全コマンドの一覧を表示する。
#[test]
fn help_lists_all_commands() {
    let target = target_hello();
    let out = run_script(&target, &[], &["help", "quit"]);
    for cmd in ["run, r", "break <func>", "watch", "continue", "step", "print", "leak on|off", "quit, q"] {
        assert_contains(&out, cmd);
    }
}

/// TC-MISC-02: `quit` は実行中プロセスを `kill` してから終了する
/// (ゾンビ/取り残しプロセスを残さない)。
#[test]
fn quit_kills_running_process_before_exiting() {
    let target = target_hello();
    let out = run_script(&target, &[], &["break add", "run", "continue", "quit"]);
    assert_contains(&out, "プロセスを終了しました");
}

/// TC-MISC-03 (異常系): 未定義コマンドはエラーメッセージを表示し、
/// REPL を継続する。
#[test]
fn unknown_command_reports_error_and_continues_repl() {
    let target = target_hello();
    let out = run_script(&target, &[], &["frobnicate", "help", "quit"]);
    assert_contains(&out, "不明なコマンド: 'frobnicate'");
    assert_contains(&out, "run, r");
}

#[test]
fn incomplete_commands_report_usage_and_allow_the_next_command() {
    let out = run_script(
        &target_hello(),
        &[],
        &[
            "lang en",
            "info nope",
            "thread",
            "thread apply all",
            "lock",
            "delete",
            "leak nope",
            "show nope",
            "set",
            "set print nope",
            "x",
            "print",
            "print/d 123",
            "quit",
        ],
    );
    for expected in [
        "Usage: info ",
        "Usage: thread <",
        "Usage: thread apply all ",
        "Usage: lock ",
        "Usage: delete ",
        "Unknown argument: 'nope'",
        "Usage: show ",
        "Usage: set $",
        "Usage: set print ",
        "Usage: x/",
        "Usage: print[",
        "123 = 123",
    ] {
        assert_contains(&out, expected);
    }
}

#[test]
fn thread_apply_all_propagates_quit_without_running_queued_commands() {
    let out = run_script(
        &target_hello(),
        &[],
        &["run", "thread apply all quit", "print/d 987654"],
    );
    assert_not_contains(&out, "987654 =");
    assert_not_contains(&out, "エラー:");
}

#[test]
fn empty_input_and_eof_leave_the_repl_cleanly() {
    let out = run_script(&target_hello(), &[], &["", "  ", "print/d 7"]);
    assert_contains(&out, "7 = 7");
    assert_not_contains(&out, "エラー:");
}

#[test]
fn startup_rejects_a_missing_argument_and_a_missing_program() {
    let nonexistent = examples_dir().join("missing-tdb-test-executable");
    for (args, expected) in [
        (vec![], "Usage: tdb <program> [args...]"),
        (vec![nonexistent.as_os_str()], "Program not found:"),
    ] {
        let output = std::process::Command::new(tdb_bin())
            .args(args)
            .env("LC_ALL", "en_US.UTF-8")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_contains(&String::from_utf8_lossy(&output.stderr), expected);
    }
}

#[test]
fn explicit_lc_all_takes_precedence_over_lang() {
    let target = target_hello();
    let env = [("LANG", "ja_JP.UTF-8"), ("LC_ALL", "EN_US.UTF-8")];
    let mut session = Session::spawn_with_env(&target, &[], &env);
    session.send(&["quit"]);

    let out = session.finish();
    assert_contains(&out, "Type 'help' to see the list of commands.");
    assert_not_contains(&out, "コマンド一覧");
}
