//! 式評価 (`print`/`set`) (REQ-EXPR-*) の結合テスト。
//! テスト仕様書 6章 (TC-EXPR-*) 対応。
//!
//! `examples/target.c` の `add` にブレークポイントを置いて `continue` した
//! 後、`up` で `main` の呼び出し元フレームへ戻ることで、`x`/`y`/`ts`/
//! `ts_ptr`/`sa`/`sa_ptr`/`pm` がすべて初期化済みの状態で参照できるように
//! している。

#[path = "support/mod.rs"]
mod support;

use support::*;

/// `up` で `main` の呼び出し元フレームまで戻した状態でセッションを開く
/// 共通セットアップ。
fn spawn_in_main_after_add_call() -> Session {
    let target = target_struct();
    let mut session = Session::spawn(&target, &[]);
    session.send(&["break add", "run", "continue", "up"]);
    session.sync();
    session
}

/// TC-EXPR-01: レジスタ参照を16進+10進で表示する。
#[test]
fn print_register_shows_hex_and_decimal() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["print $rax"]);
    let out = session.sync();
    assert_contains(&out, "$rax = 0x");
    assert_contains(&out, " (");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-02: 四則演算・ビット演算の優先順位・結合性。
#[test]
fn arithmetic_precedence_and_bitwise_operators() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["print 1 + 2 * 3"]);
    assert_contains(&session.sync(), "1 + 2 * 3 = 0x0000000000000007 (7)");

    session.send(&["print (1 + 2) * 3"]);
    assert_contains(&session.sync(), "(1 + 2) * 3 = 0x0000000000000009 (9)");

    session.send(&["print 1 << 2 | 1"]);
    assert_contains(&session.sync(), "1 << 2 | 1 = 0x0000000000000005 (5)");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-03: `&<変数名>` でローカル変数の実体アドレスを取得できる。
#[test]
fn address_of_local_variable() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["print &x"]);
    let out = session.sync();
    assert_contains(&out, "&x = 0x");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-03b (異常系): `&` の直後は識別子でなければならず、`&5` は
/// 構文エラーになる。
#[test]
fn address_of_literal_is_syntax_error() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["print &5"]);
    let out = session.sync();
    assert_contains(&out, "エラー:");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-04: `*<addr式>` は型情報を持たない8バイト読み。
#[test]
fn deref_reads_eight_bytes_as_integer() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["print *&x"]);
    let out = session.sync();
    assert_contains(&out, "*&x = 0x");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-05: `->` と `.` は同義(ポインタに `.` を使っても暗黙に
/// デリファレンスされる)。連鎖の先頭は裸の変数名でなければならないため
/// (`(*ts_ptr).a` のような括弧式は不可)、`ts_ptr` に直接 `.`/`->` の
/// 両方を試して比較する。
#[test]
fn arrow_and_dot_are_equivalent_for_struct_member_access() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["print ts_ptr->a", "print ts_ptr.a"]);
    let out = session.sync();
    assert_contains(&out, "ts_ptr->a = 0");
    assert_contains(&out, "ts_ptr.a = 0");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-05b: `[]` は配列要素へアクセスでき、構造体メンバと連鎖できる。
#[test]
fn array_index_chains_with_struct_member() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["print sa[1].a"]);
    let out = session.sync();
    assert_contains(&out, "sa[1].a = 0");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-06 (異常系): 不完全な式は構文エラーとして即座に報告され、
/// tdb はクラッシュしない。
#[test]
fn incomplete_expression_is_syntax_error_without_crash() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["print 1 +", "print 1"]); // 直後のコマンドが実行できる = REPL 継続の確認
    let out = session.sync();
    assert_contains(&out, "エラー:");
    assert_contains(&out, "1 = 0x0000000000000001 (1)");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-06b (異常系/回帰確認): `lrpar` の既定エラー回復 (トークン挿入)
/// を無効化 (`RecoveryKind::None`) しているため、`i++` のような未対応の
/// 演算子を含む式でパニックしない(過去に発生していた既知不具合の再発
/// 防止確認)。
#[test]
fn unsupported_increment_operator_is_syntax_error_without_panic() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["print x++", "print 2"]);
    let out = session.sync();
    assert_contains(&out, "エラー:");
    assert_contains(&out, "2 = 0x0000000000000002 (2)");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-07: 単一の変数から始まる連鎖の結果が構造体なら整形表示する。
#[test]
fn print_struct_variable_is_formatted() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["print ts"]);
    let out = session.sync();
    assert_contains(&out, "ts = {a = 0, b = 0, c = 0}");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-07b: 配列全体も整形表示する。
#[test]
fn print_array_variable_is_formatted() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["print sa"]);
    let out = session.sync();
    assert_contains(&out, "sa = {{a = 0, b = 0, c = 0}, {a = 0, b = 0, c = 0}, {a = 0, b = 0, c = 0}}");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-08: `print *<ポインタ変数>` は型情報付きで指し示す先を読む。
#[test]
fn print_deref_of_pointer_variable_shows_pointee_struct() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["print *ts_ptr"]);
    let out = session.sync();
    assert_contains(&out, "*ts_ptr = {a = 0, b = 0, c = 0}");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-08b (異常系): ポインタ型でない変数への `print *<変数名>` は
/// エラーになる。
#[test]
fn print_deref_of_non_pointer_variable_errors() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["print *x"]);
    let out = session.sync();
    assert_contains(&out, "エラー:");
    assert_contains(&out, "ポインタ型ではない");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-09: `print/<fmt>` で表示形式を明示指定できる。
#[test]
fn print_format_specifiers() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["print/x 255", "print/o 8", "print/t 5", "print/c 65"]);
    let out = session.sync();
    assert_contains(&out, "255 = 0xff");
    assert_contains(&out, "8 = 010");
    assert_contains(&out, "5 = 101");
    assert_contains(&out, "65 = 65 'A'");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-10: `set $<reg>=<式>` でレジスタに値を設定できる。
#[test]
fn set_register_value() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["set $rax=123", "print $rax"]);
    let out = session.sync();
    assert_contains(&out, "$rax = 0x000000000000007b (123)");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-11: `set <変数名>=<式>` でローカル変数に値を設定できる。
#[test]
fn set_local_variable_value() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["set x=99", "print x"]);
    let out = session.sync();
    assert_contains(&out, "x = 99");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-11b: `set <変数名>-><メンバ>=<式>` で構造体メンバに値を設定できる。
#[test]
fn set_struct_member_via_arrow() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["set ts_ptr->a=42", "print ts_ptr->a"]);
    let out = session.sync();
    assert_contains(&out, "ts_ptr->a = 42");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-13: `set print pretty on|off` で構造体の複数行インデント表示を
/// 切り替えられる。
#[test]
fn set_print_pretty_toggles_multiline_output() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["set print pretty on", "print ts"]);
    let out_on = session.sync();
    assert_contains(&out_on, "(struct test_struct) {");
    assert_contains(&out_on, "a = (int)0,");

    session.send(&["set print pretty off", "print ts"]);
    let out_off = session.sync();
    assert_contains(&out_off, "ts = {a = 0, b = 0, c = 0}");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-14: `set print elements <n>` は表示要素数を制限し、
/// `unlimited` で解除できる。
#[test]
fn set_print_elements_limits_array_output() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["set print elements 2", "print sa"]);
    let out = session.sync();
    assert_contains(&out, "...");

    session.send(&["set print elements unlimited", "print sa"]);
    let out2 = session.sync();
    assert_contains(&out2, "sa = {{a = 0, b = 0, c = 0}, {a = 0, b = 0, c = 0}, {a = 0, b = 0, c = 0}}");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-15: `show print` は現在の `pretty`/`elements` 設定を表示する。
#[test]
fn show_print_reports_current_settings() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["show print"]);
    let out = session.sync();
    assert_contains(&out, "print pretty: off");
    assert_contains(&out, "print elements: 200"); // 既定値

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-16: `show locals`/`show args`/`show globals` はそれぞれ
/// ローカル変数・仮引数・グローバル変数の一覧を表示する。
#[test]
fn show_locals_args_globals() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["show locals", "show args", "show globals"]);
    let out = session.sync();
    assert_contains(&out, "x = 10");
    assert_contains(&out, "y = 20");
    // main() は仮引数を取らない。
    assert_contains(&out, "仮引数はありません");
    assert_contains(&out, "グローバル変数はありません");

    session.send(&["quit"]);
    session.finish();
}

/// TC-EXPR-17: `x/<n> <addr|$reg>` はメモリを16進ダンプする。
#[test]
fn examine_memory_dumps_hex_bytes() {
    let mut session = spawn_in_main_after_add_call();
    session.send(&["x/8 $rsp"]);
    let out = session.sync();
    let dump_line = out.lines().find(|l| l.trim_start().starts_with("0x") && l.contains(':')).unwrap();
    let hex_bytes = dump_line.split(':').nth(1).unwrap().split_whitespace().count();
    assert_eq!(hex_bytes, 8, "expected 8 hex bytes in dump line: {dump_line}");

    session.send(&["quit"]);
    session.finish();
}
