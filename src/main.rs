mod breakpoint;
mod debugger;
mod disasm;
mod dwarf_info;
mod elf_info;
mod expr;
mod leak;
mod registers;
mod repl;

use anyhow::{bail, Result};
use debugger::Debugger;
use std::path::PathBuf;

fn main() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        bail!("使い方: tdb <対象プログラム> [引数...]");
    }
    let program = PathBuf::from(args.remove(0));
    if !program.exists() {
        bail!("プログラムが見つかりません: {}", program.display());
    }

    let dbg = Debugger::new(program, args)?;
    debugger::install_sigint_forwarder();
    repl::run_repl(dbg);
    Ok(())
}
