//! ブレークポイント (REQ-BP-*) の結合テスト。テスト仕様書 2章 (TC-BP-*) 対応。

#[path = "support/mod.rs"]
mod support;

use support::*;

/// TC-BP-01: `break <func>` は関数シンボルの先頭ではなく、プロローグ
/// 通過後の位置に設置される。
#[test]
fn break_by_function_name_skips_prologue() {
    let target = target_hello();
    let out = run_script(&target, &[], &["run", "break add", "info breakpoints", "quit"]);

    assert_contains(&out, "ブレークポイント 1 を add (0x");
    // 一覧表示ではオフセット付き <add+0x...> になる(先頭に一致しない)。
    assert_contains(&out, "<add+0x");
}

/// TC-BP-02: `break <file>:<line>` でファイル名:行番号を指定できる。
#[test]
fn break_by_file_and_line() {
    let target = target_hello();
    let out = run_script(&target, &[], &["run", "break hello.c:4", "info breakpoints", "quit"]);

    // 設置メッセージのラベルは DWARF 側で解決した(フルパスの)ファイル名:
    // 行番号になる(ユーザーが入力した短縮名そのままではない)。
    assert_contains(&out, "ブレークポイント 1 を ");
    assert_contains(&out, "hello.c:4 (0x");
    assert_contains(&out, "at ");
    assert_contains(&out, "hello.c:4");
}

/// TC-BP-04: 未起動時の `break` は保留され、`run` 時に解決される。
#[test]
fn break_before_run_is_deferred_then_resolved_on_run() {
    let target = target_hello();
    let out = run_script(&target, &[], &["break add", "run", "quit"]);

    assert_contains(&out, "未実行のため");
    assert_contains(&out, "ブレークポイント 1 を add (0x");
}

/// TC-BP-06 (異常系): 同一アドレスへの重複設置は拒否され、既存の番号が
/// エラーメッセージに含まれる。
#[test]
fn duplicate_breakpoint_at_same_address_is_rejected() {
    let target = target_hello();
    let out = run_script(&target, &[], &["run", "break add", "break add", "info breakpoints", "quit"]);

    assert_contains(&out, "エラー:");
    assert_contains(&out, "ブレークポイント 1");
    // 拒否されたので2件目は追加されていない。
    assert_not_contains(&out, "ブレークポイント 2");
}

/// TC-BP-07: `info breakpoints` は番号・アドレス・関数名(+オフセット)・
/// ソース位置を表示する。
#[test]
fn info_breakpoints_lists_all_with_location() {
    let target = target_hello();
    let out = run_script(&target, &[], &["run", "break add", "break main", "info breakpoints", "quit"]);

    assert_contains(&out, "1: 0x");
    assert_contains(&out, "<add+0x");
    assert_contains(&out, "2: 0x");
    assert_contains(&out, "<main+0x");
    assert_contains(&out, "hello.c:");
}

/// TC-BP-08: `delete <n>` は指定番号のブレークポイントを一覧から取り除く。
#[test]
fn delete_removes_breakpoint_from_list() {
    let target = target_hello();
    let out = run_script(
        &target,
        &[],
        &["run", "break add", "info breakpoints", "delete 1", "info breakpoints", "quit"],
    );

    assert_contains(&out, "ブレークポイント 1 を削除しました");
    assert_contains(&out, "ブレークポイントは設定されていません");
}

/// TC-BP-10 (異常系): 存在しない関数名の指定はエラーになる(実行中)。
#[test]
fn break_unknown_function_after_run_errors() {
    let target = target_hello();
    let out = run_script(&target, &[], &["run", "break no_such_function_xyz", "quit"]);

    assert_contains(&out, "エラー: シンボル 'no_such_function_xyz' が見つかりません");
}

/// TC-BP-09: `fork(2)` 由来の子プロセスにも、`fork` 前に設置した
/// ブレークポイントが自動的に反映される。
#[test]
fn breakpoint_set_before_fork_hits_in_child_process_too() {
    let target = target_fork();
    // work() へ2回 continue する: 親・子のどちらが先でも、2回で両方到達する
    // はず(work は各プロセス1回だけ最初に呼ばれる)。
    let out = run_script(&target, &[], &["break work", "run", "continue", "continue", "info threads", "quit"]);

    assert_count(&out, "ブレークポイントで停止: 0x", 2);
    assert_contains(&out, "[プロセス]");
}

mod break_target_cases {
    use super::*;
    use std::process::Command;

    fn target() -> std::path::PathBuf {
        build_example("break_target", "break_target.c", &["-no-pie"])
    }

    #[track_caller]
    fn assert_stopped_in(output: &str, function: &str) {
        let suffix = format!(" <{function}>");
        assert!(
            output.lines().any(|line| {
                line.starts_with("ブレークポイントで停止:") && line.ends_with(&suffix)
            }),
            "{output}"
        );
    }

    #[test]
    fn deleting_and_reinstalling_breakpoint_changes_stops_in_the_same_run() {
        let out = run_target(&[
            "run",
            "break add",
            "continue",
            "delete 1",
            "break break_target.c:14",
            "continue",
            "continue",
            "break add",
            "delete 2",
            "continue",
        ]);
        let stops: Vec<_> = out
            .lines()
            .filter(|line| line.starts_with("ブレークポイントで停止:"))
            .collect();
        assert_eq!(stops.len(), 4, "{out}");
        for (stop, function) in stops.into_iter().zip(["add", "main", "main", "add"]) {
            assert_stopped_in(stop, function);
        }
        assert_contains(&out, "ブレークポイント 1 を削除しました");
        assert_not_contains(&out, "エラー:");
    }

    #[test]
    fn watchpoint_triggers_between_two_function_breakpoint_stops() {
        let out = run_target(&[
            "run",
            "break add",
            "continue",
            "watch sum",
            "continue",
            "delete 2",
            "continue",
        ]);
        let stops: Vec<_> = out
            .lines()
            .filter(|line| {
                line.starts_with("ブレークポイントで停止:")
                    || line.starts_with("ウォッチポイント 2 がトリガーされました:")
            })
            .collect();
        assert_eq!(stops.len(), 3, "{out}");
        assert_stopped_in(stops[0], "add");
        assert_contains(stops[1], "がトリガーされました: sum");
        assert_contains(&out, "新値 = 0x1");
        assert_stopped_in(stops[2], "add");
        assert_not_contains(&out, "エラー:");
    }

    fn run_target(commands: &[&str]) -> String {
        let target = target();
        let mut commands = commands.to_vec();
        commands.push("quit");
        run_script(&target, &[], &commands)
    }

    fn add_entry_address() -> u64 {
        let target = target();
        let output = Command::new("nm")
            .arg(target)
            .output()
            .expect("failed to run nm");
        assert!(output.status.success(), "nm failed: {:?}", output.stderr);
        let symbols = String::from_utf8(output.stdout).expect("nm output is not UTF-8");
        let entry = symbols
            .lines()
            .find(|line| line.ends_with(" t add"))
            .expect("missing add symbol");
        let address = entry
            .split_whitespace()
            .next()
            .expect("missing add address");
        u64::from_str_radix(address, 16).expect("invalid add address")
    }

    // 正常系

    #[test]
    fn function_breakpoint_stops_in_main() {
        let out = run_target(&["run", "break main", "continue"]);
        assert_not_contains(&out, "エラー:");
        assert_stopped_in(&out, "main");
    }

    #[test]
    fn short_break_alias_stops_in_add() {
        let out = run_target(&["run", "b add", "continue"]);
        assert_not_contains(&out, "エラー:");
        assert_stopped_in(&out, "add");
    }

    #[test]
    fn basename_breakpoint_stops_on_call_line() {
        let out = run_target(&["run", "break break_target.c:14", "continue"]);
        assert_not_contains(&out, "エラー:");
        assert_contains(&out, "ブレークポイントで停止:");
        assert_contains(&out, ">  14");
    }

    #[test]
    fn path_suffix_breakpoint_stops_on_print_line() {
        let out = run_target(&["run", "break examples/break_target.c:15", "continue"]);
        assert_not_contains(&out, "エラー:");
        assert_contains(&out, "ブレークポイントで停止:");
        assert_contains(&out, ">  15");
    }

    #[test]
    fn absolute_path_breakpoint_stops_on_call_line() {
        let location = format!(
            "break {}:14",
            examples_dir().join("break_target.c").display()
        );
        let out = run_target(&["run", &location, "continue"]);
        assert_not_contains(&out, "エラー:");
        assert_contains(&out, "ブレークポイントで停止:");
        assert_contains(&out, ">  14");
    }

    #[test]
    fn address_breakpoint_stops_at_function_entry() {
        let addr = add_entry_address();
        let command = format!("break *{addr:#x}");
        let out = run_target(&["run", &command, "continue"]);
        assert_not_contains(&out, "エラー:");
        assert_contains(&out, &format!("ブレークポイントで停止: {addr:#x} <add>"));
    }

    #[test]
    fn hex_address_without_prefix_stops_at_function_entry() {
        let addr = add_entry_address();
        let command = format!("break *{addr:x}");
        let out = run_target(&["run", &command, "continue"]);
        assert_not_contains(&out, "エラー:");
        assert_contains(&out, &format!("ブレークポイントで停止: {addr:#x} <add>"));
    }

    #[test]
    fn deferred_source_breakpoint_stops_on_requested_line() {
        let out = run_target(&["break break_target.c:15", "run", "continue"]);
        assert_not_contains(&out, "エラー:");
        assert_contains(&out, "未実行のため");
        assert_contains(&out, "ブレークポイントで停止:");
        assert_contains(&out, ">  15");
    }

    #[test]
    fn function_breakpoint_stops_on_all_three_calls() {
        let out = run_target(&[
            "run",
            "break add",
            "continue",
            "continue",
            "continue",
            "continue",
        ]);
        assert_not_contains(&out, "エラー:");
        assert_contains(&out, "i=3 total=6");
        assert_count(&out, "ブレークポイントで停止:", 3);
    }

    #[test]
    fn blank_line_breakpoint_moves_to_next_statement() {
        let out = run_target(&["run", "break break_target.c:12", "continue"]);
        assert_not_contains(&out, "エラー:");
        assert_contains(&out, "break_target.c:13 (0x");
        assert_contains(&out, ">  13");
    }

    // 異常系
    #[track_caller]
    fn assert_rejected(command: &str, diagnostic: &str) {
        let out = run_target(&["run", command, "info breakpoints"]);
        assert_contains(&out, diagnostic);
        assert_contains(&out, "ブレークポイントは設定されていません");
    }

    #[test]
    fn missing_break_argument_is_rejected() {
        assert_rejected("break", "使い方: break");
    }

    #[test]
    fn missing_hex_digits_is_rejected() {
        assert_rejected("break *", "cannot parse integer from empty string");
    }

    #[test]
    fn non_hexadecimal_address_is_rejected() {
        assert_rejected("break *0xxyz", "invalid digit");
    }

    #[test]
    fn overflowing_hexadecimal_address_is_rejected() {
        assert_rejected("break *0x10000000000000000", "too large");
    }

    #[test]
    fn non_numeric_source_line_is_rejected() {
        assert_rejected(
            "break break_target.c:abc",
            "シンボル 'break_target.c:abc' が見つかりません",
        );
    }

    #[test]
    fn negative_source_line_is_rejected() {
        assert_rejected(
            "break break_target.c:-1",
            "シンボル 'break_target.c:-1' が見つかりません",
        );
    }

    #[test]
    fn overflowing_source_line_is_rejected() {
        assert_rejected(
            "break break_target.c:4294967296",
            "シンボル 'break_target.c:4294967296' が見つかりません",
        );
    }

    #[test]
    fn unknown_source_file_is_rejected() {
        assert_rejected(
            "break no_such_break_target.c:14",
            "ファイル 'no_such_break_target.c' の行番号情報が見つかりません",
        );
    }

    #[test]
    fn data_symbol_used_as_function_is_rejected() {
        assert_rejected(
            "break __data_start",
            "シンボル '__data_start' が見つかりません",
        );
    }

    #[test]
    fn unknown_deferred_function_warns_and_keeps_valid_breakpoint() {
        let out = run_target(&[
            "break missing_break_function",
            "break add",
            "run",
            "continue",
        ]);
        assert_contains(
            &out,
            "警告: ブレークポイント 'missing_break_function' の設置に失敗しました",
        );
        assert_contains(&out, "ブレークポイント 1 を add (0x");
        assert_contains(&out, "ブレークポイントで停止:");
    }

    // 境界値

    #[test]
    fn line_zero_resolves_to_first_statement() {
        let out = run_target(&["run", "break break_target.c:0", "info breakpoints"]);
        assert_contains(&out, "break_target.c:4 (0x");
        assert_not_contains(&out, "エラー:");
    }

    #[test]
    fn first_source_statement_is_accepted() {
        let out = run_target(&["run", "break break_target.c:4", "info breakpoints"]);
        assert_contains(&out, "break_target.c:4 (0x");
        assert_not_contains(&out, "エラー:");
    }

    #[test]
    fn last_source_statement_is_accepted() {
        let out = run_target(&["run", "break break_target.c:19", "info breakpoints"]);
        assert_contains(&out, "break_target.c:19 (0x");
        assert_not_contains(&out, "エラー:");
    }

    #[test]
    fn line_after_last_statement_is_rejected() {
        assert_rejected(
            "break break_target.c:20",
            "20 行目以降に実行可能なコードが見つかりません",
        );
    }

    #[test]
    fn maximum_source_line_number_is_parsed() {
        assert_rejected(
            "break break_target.c:4294967295",
            "4294967295 行目以降に実行可能なコードが見つかりません",
        );
    }
}
