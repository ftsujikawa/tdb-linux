mod breakpoint;
mod debugger;
mod disasm;
mod dwarf_info;
mod elf_info;
mod expr;
mod leak;
mod registers;
mod repl;

rust_i18n::i18n!("locales", fallback = "ja");

use anyhow::{bail, Result};
use debugger::Debugger;
use rust_i18n::t;
use std::path::PathBuf;

/// 表示言語の初期値を `LANG`/`LC_ALL` 環境変数から推測する。`en` で始まれば
/// 英語、それ以外(未設定含む)は日本語をデフォルトにする(このツールは
/// 元々日本語ユーザー向けのため)。`lang` コマンドで実行中に切り替えられる。
fn detect_initial_locale() -> &'static str {
    let env_lang = std::env::var("LC_ALL").or_else(|_| std::env::var("LANG")).unwrap_or_default();
    if env_lang.to_ascii_lowercase().starts_with("en") {
        "en"
    } else {
        "ja"
    }
}

fn main() -> Result<()> {
    rust_i18n::set_locale(detect_initial_locale());

    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        bail!("{}", t!("main.usage"));
    }
    let program = PathBuf::from(args.remove(0));
    if !program.exists() {
        bail!("{}", t!("main.program_not_found", path = program.display()));
    }

    let dbg = Debugger::new(program, args)?;
    debugger::install_sigint_forwarder();
    repl::run_repl(dbg);
    Ok(())
}
