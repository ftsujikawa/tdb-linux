//! メモリリーク追跡 (REQ-LEAK-*) の結合テスト。テスト仕様書 7章 (TC-LEAK-*) 対応。
//!
//! `examples/leak_target.c` は `malloc(100)` (すぐ `free`)・`malloc(200)`・
//! `calloc(10, 16)` を行い、後者2つを意図的に解放しない。glibc/ld.so が
//! 起動時に内部的に確保するメモリ等のノイズが `live`/`bad_frees` に混ざる
//! ことがある(README「実装の要点」に記載の既知の挙動)ため、本テストは
//! 「意図した2件のリークが検出されること」を確認し、ノイズの有無や総数は
//! 検証しない。

#[path = "support/mod.rs"]
mod support;

use support::*;

/// TC-LEAK-01 / TC-LEAK-02: `leak on` を有効にした状態で最後まで実行し、
/// `leak` で確保/解放回数・未解放件数を確認できる(クラッシュしない)。
#[test]
fn leak_on_tracks_allocations_without_crashing() {
    let target = target_leak();
    let out = run_script(&target, &[], &["leak on", "run", "continue", "leak", "quit"]);

    assert_contains(&out, "メモリリーク追跡: on");
    assert_contains(&out, "確保: ");
    assert_contains(&out, "解放: ");
    assert_contains(&out, "未解放: ");
}

/// TC-LEAK-03: `leaks` は未解放のヒープ確保一覧を、確保元関数名・
/// 呼び出し位置(ファイル:行番号)付きで表示する。意図した2件
/// (`malloc(200)` at leak_target.c:23, `calloc(10,16)` at leak_target.c:24)
/// が必ず含まれる。
#[test]
fn leaks_lists_the_two_intentional_leaks_with_source_location() {
    let target = target_leak();
    let out = run_script(&target, &[], &["leak on", "run", "continue", "leaks", "quit"]);

    assert_contains(&out, "未解放のヒープ確保:");
    assert_contains(&out, "200 バイト  確保元: malloc (");
    assert_contains(&out, "leak_target.c:23)");
    assert_contains(&out, "160 バイト  確保元: calloc (");
    assert_contains(&out, "leak_target.c:24)");
}

/// TC-LEAK-04 (異常系): `leak on` していない状態での `leaks` は
/// 「追跡が無効」である旨のみを表示し、クラッシュしない。
#[test]
fn leaks_without_tracking_enabled_reports_disabled() {
    let target = target_leak();
    let out = run_script(&target, &[], &["run", "continue", "leaks", "quit"]);

    assert_contains(&out, "メモリリーク追跡は無効です");
}

/// TC-LEAK-06: `leak off` は追跡を停止し、以後のフック用ブレークポイント
/// が(ユーザーへ見える形では)残らない。
#[test]
fn leak_off_disables_tracking() {
    let target = target_leak();
    let out = run_script(&target, &[], &["leak on", "leak off", "leak", "quit"]);

    assert_contains(&out, "メモリリーク追跡: off");
}
