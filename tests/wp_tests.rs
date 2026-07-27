//! ウォッチポイント (REQ-WP-*) の結合テスト。テスト仕様書 3章 (TC-WP-*) 対応。

#[path = "support/mod.rs"]
mod support;

use support::*;

/// TC-WP-01 / TC-WP-05: `watch <変数名>` で書き込み監視を設定でき、
/// 実際の書き込みで発火して旧値/新値が表示される。
/// `watch` は裸の変数名のみ対応(`ts->a` 等のチェーン式は不可)。
#[test]
fn watch_local_variable_triggers_on_write() {
    let target = target_struct();
    let out = run_script(&target, &[], &["break add", "run", "continue", "watch c", "continue", "quit"]);

    assert_contains(&out, "ウォッチポイント 2 を c (0x");
    assert_contains(&out, "新値 = 0x1e"); // c = a + b = 10 + 20 = 30 = 0x1e
}

/// TC-WP-03 (異常系): アライメント違反のアドレス指定はエラーになる。
#[test]
fn watch_unaligned_address_is_rejected() {
    let target = target_struct();
    let out = run_script(
        &target,
        &[],
        &["break add", "run", "continue", "watch *($rsp+1) 4", "quit"],
    );

    assert_contains(&out, "エラー:");
}

/// TC-WP-04 (異常系): ウォッチポイントは最大4つまで。5つ目はエラー。
#[test]
fn watch_rejects_fifth_watchpoint() {
    let target = target_struct();
    let out = run_script(
        &target,
        &[],
        &[
            "break add",
            "run",
            "continue",
            "watch *$rsp 1",
            "watch *($rsp+8) 1",
            "watch *($rsp+16) 1",
            "watch *($rsp+24) 1",
            "watch *($rsp+32) 1",
            "info watchpoints",
            "quit",
        ],
    );

    assert_count(&out, "ウォッチポイント", 4 /* 設定成功メッセージ */ + 1 /* info watchpoints ヘッダは別文言 */);
    assert_contains(&out, "エラー:");
}

/// TC-WP-06: `info watchpoints` は番号・ラベル・アドレス・幅・現在値を表示する。
#[test]
fn info_watchpoints_lists_configured_entries() {
    let target = target_struct();
    let out = run_script(&target, &[], &["break add", "run", "continue", "watch c", "info watchpoints", "quit"]);

    assert_contains(&out, "2: c (0x");
    assert_contains(&out, "バイト)");
    assert_contains(&out, "現在値 = 0x");
}

/// TC-WP-07: `watch` はマルチスレッド対象で複数スレッドをまたいで発火する。
#[test]
fn watch_triggers_across_multiple_threads() {
    let target = target_thread();
    let out = run_script(
        &target,
        &[],
        &["break worker", "run", "continue", "watch counter", "continue", "continue", "continue", "quit"],
    );

    assert_contains(&out, "ウォッチポイント 2 を counter");
    assert_contains(&out, "旧値");
    assert_contains(&out, "新値");
}
