//! ELF シンボル表と動的シンボル表からの関数解決を検証する。

#[path = "support/mod.rs"]
mod support;

use std::process::Command;
use support::*;

#[test]
fn functions_from_both_symbol_tables_appear_once_and_in_address_order() {
    let target = build_example("elf_target", "elf_target.c", &["-no-pie", "-rdynamic"]);
    let out = run_script(&target, &[], &["syms", "quit"]);
    let symbols: Vec<_> = out
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let address = fields.next()?.strip_prefix("0x")?;
            let address = u64::from_str_radix(address, 16).ok()?;
            fields.next()?.parse::<u64>().ok()?;
            Some((address, fields.next()?))
        })
        .collect();

    for name in ["public_helper", "private_helper", "main"] {
        let count = symbols.iter().filter(|(_, symbol)| *symbol == name).count();
        assert_eq!(count, 1, "{name}: {out}");
    }
    assert!(
        symbols.windows(2).all(|pair| pair[0].0 <= pair[1].0),
        "{out}"
    );
    assert!(
        !symbols.iter().any(|(_, name)| *name == "elf_data"),
        "{out}"
    );
    assert_not_contains(&out, "エラー:");
}

#[test]
fn stripped_executable_can_set_and_hit_a_dynsym_only_breakpoint() {
    let target = build_example(
        "elf_target_stripped",
        "elf_target.c",
        &["-no-pie", "-rdynamic", "-Wl,--strip-all"],
    );
    let out = run_script(
        &target,
        &[],
        &[
            "syms helper",
            "break public_helper",
            "run",
            "continue",
            "continue",
            "quit",
        ],
    );

    assert_contains(&out, " public_helper");
    assert_not_contains(&out, "private_helper");
    assert_count(&out, "ブレークポイントで停止:", 1);
    assert_contains(&out, "<public_helper>");
    assert_contains(&out, "[プロセスは終了しました (code=0)]");
    assert_not_contains(&out, "エラー:");
}

#[test]
fn unreadable_and_non_elf_inputs_fail_with_distinct_diagnostics() {
    let dir = examples_dir();
    for (path, diagnostic) in [
        (dir.clone(), "failed to read"),
        (dir.join("elf_target.c"), "failed to parse ELF"),
    ] {
        let output = Command::new(tdb_bin()).arg(&path).output().unwrap();
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{}: {error}", path.display());
        assert_contains(&error, diagnostic);
    }
}
