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
