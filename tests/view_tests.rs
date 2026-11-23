//! スタック/シンボル/ソース表示 (REQ-VIEW-*) の結合テスト。
//! テスト仕様書 5章 (TC-VIEW-*) 対応。

#[path = "support/mod.rs"]
mod support;

use support::*;

/// TC-VIEW-01: `backtrace` は各フレームを `関数名+オフセット at file:line`
/// 形式で、フレーム番号昇順に表示する。
#[test]
fn backtrace_shows_frames_with_offset_and_source_location() {
    let target = target_hello();
    let out = run_script(&target, &[], &["break add", "run", "continue", "backtrace", "quit"]);

    assert_contains(&out, "#0  0x");
    assert_contains(&out, "in add+0x");
    assert_contains(&out, "hello.c:4");
    assert_contains(&out, "#1  0x");
    assert_contains(&out, "in main+0x");
    assert_contains(&out, "hello.c:11");
}

/// TC-VIEW-02: `syms <filter>` は部分一致で関数シンボルを絞り込む。
#[test]
fn syms_filters_by_substring() {
    let target = target_hello();
    let out = run_script(&target, &[], &["syms add", "quit"]);

    assert_contains(&out, "add");
    assert_not_contains(&out, " main\n");
    assert_not_contains(&out, " main$");
}

/// TC-VIEW-03: `lines <func>` は指定関数のアドレス範囲内の行のみに絞り込む。
#[test]
fn lines_filters_by_function_address_range() {
    let target = target_hello();
    let out = run_script(&target, &[], &["lines add", "quit"]);

    assert_contains(&out, "hello.c:3");
    assert_contains(&out, "hello.c:4");
    assert_contains(&out, "hello.c:5");
    // add は 3〜5行目のみなので、main 側の行 (8行目以降) は出てこない。
    assert_not_contains(&out, "hello.c:8");
}

/// TC-VIEW-04: `list <func>` は関数の先頭を中心に前後計10行を表示する。
#[test]
fn list_by_function_name_shows_ten_line_window() {
    let target = target_hello();
    let out = run_script(&target, &[], &["list add", "quit"]);

    assert_contains(&out, "int add(int a, int b) {");
    let line_count = out
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.chars().next().is_some_and(|c| c.is_ascii_digit())
        })
        .count();
    assert_eq!(line_count, 10, "expected exactly 10 listed source lines\n{out}");
}

/// TC-VIEW-06: `list <file>:<line>` はファイル冒頭付近を指定した場合、
/// 範囲外の行は出力されない(存在する行だけ表示する)。
#[test]
fn list_near_file_start_does_not_print_out_of_range_lines() {
    let target = target_hello();
    let out = run_script(&target, &[], &["list hello.c:1", "quit"]);

    assert_contains(&out, "1\t#include <stdio.h>");
    assert_not_contains(&out, "   0\t");
    assert_not_contains(&out, "  -1\t");
}

/// TC-VIEW-07: ブレークポイント停止時は現在行を中心に前後3行(計最大7行)、
/// 現在行の行番号の前に `>` が付く。
#[test]
fn breakpoint_stop_shows_seven_line_context_with_marker() {
    let target = target_hello();
    let out = run_script(&target, &[], &["break add", "run", "continue", "quit"]);

    assert_contains(&out, ">   4\t    int c = a + b;");
    // 現在行以外(1〜3, 5〜7行目)にはマーカーが付かない。
    assert_contains(&out, "    3\tint add(int a, int b) {");
    assert_contains(&out, "    5\t    return c;");
}

/// TC-VIEW-08: デバッグ情報のないバイナリでは、ソース表示の代わりに
/// 1命令の逆アセンブル結果が表示される。
///
/// デバッグ情報が無いため `break add` (関数名指定) 自体は使えるが、
/// プロローグ判定は命令デコードのヒューリスティックになり、停止時の
/// ソース表示は行われない(逆アセンブルへフォールバックする)。
#[test]
fn breakpoint_stop_without_debug_info_falls_back_to_disassembly() {
    let target = target_hello_nodbg();
    let out = run_script(&target, &[], &["run", "break add", "continue", "quit"]);

    assert_contains(&out, "ブレークポイントで停止");
    // ソースファイルパス:行番号の表示が出ない(逆アセンブルへフォール
    // バックしている)ことを確認する。1命令ぶんの逆アセンブル結果には
    // アドレス直後にコロンが付く (`0x...: <mnemonic> ...`)。
    assert_not_contains(&out, "hello.c:");
    assert_contains(&out, ":  ");
}

/// TC-VIEW-09: `info registers` は汎用レジスタ・rip・eflags・orig_rax・
/// セグメントレジスタ・fs_base/gs_base・x87・SSE・mxcsr を表示する。
#[test]
fn info_registers_shows_all_register_groups() {
    let target = target_hello();
    let out = run_script(&target, &[], &["break add", "run", "continue", "info registers", "quit"]);

    for field in ["rax", "rip", "eflags", "orig_rax", "cs", "fs_base", "gs_base", "st0", "xmm0", "mxcsr"] {
        assert_contains(&out, field);
    }
}

#[test]
fn integer_register_names_round_trip_and_pc_alias_reads_rip() {
    let target = target_hello();
    let registers = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15", "orig_rax",
    ];
    let mut commands = vec!["run".to_string()];
    for (index, name) in registers.iter().enumerate() {
        commands.push(format!("set ${name}={}", 100 + index));
    }
    for name in registers {
        commands.push(format!("print/d ${name}"));
    }
    for name in [
        "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs", "fs_base", "gs_base",
    ] {
        commands.push(format!("set ${name}=${name}"));
    }
    commands.extend(["print/d $pc-$rip", "quit"].map(String::from));
    let commands: Vec<_> = commands.iter().map(String::as_str).collect();
    let out = run_script(&target, &[], &commands);
    for (index, name) in registers.iter().enumerate() {
        assert_contains(&out, &format!("${name} = {}", 100 + index));
    }
    assert_contains(&out, "$pc-$rip = 0");
    assert_not_contains(&out, "エラー:");
}

#[test]
fn x87_and_xmm_registers_round_trip_and_reject_out_of_range_names() {
    let out = run_script(
        &target_hello(),
        &[],
        &[
            "run",
            "set $st0=0",
            "set $st7=-2.5",
            "set $xmm15=4660",
            "print/x $st0",
            "print/x $st7",
            "print/x $xmm15",
            "info registers",
            "print $st8",
            "set $xmm16=1",
            "quit",
        ],
    );
    for expected in [
        "$st0 = 0x0",
        "$st7 = 0xa000000000000000",
        "$xmm15 = 0x1234",
        "value=-2.5",
        "st8",
        "xmm16",
    ] {
        assert_contains(&out, expected);
    }
    assert_count(&out, "エラー:", 2);
}

#[test]
fn source_and_symbol_queries_distinguish_missing_data_and_bad_input() {
    let out = run_script(
        &target_hello_nodbg(),
        &[],
        &[
            "lang en",
            "syms this_symbol_does_not_exist",
            "lines",
            "list main",
            "list hello.c:bad",
            "list *0x0",
            "list this_function_does_not_exist",
            "quit",
        ],
    );
    assert_contains(&out, "No symbols found");
    assert_contains(&out, "No line info found");
    assert_contains(&out, "Failed to parse line number: 'bad'");
    assert_contains(&out, "this_function_does_not_exist");
    assert_count(&out, "Error:", 4);
}

#[test]
fn out_of_range_source_and_unmapped_memory_report_different_failures() {
    let out = run_script(
        &target_hello(),
        &[],
        &[
            "lang en",
            "list hello.c:9999",
            "run",
            "x/1 0x0",
            "set *0 = 65",
            "quit",
        ],
    );
    assert_contains(&out, "No source in the specified line range");
    assert_count(&out, "Memory read failed", 2);
}
