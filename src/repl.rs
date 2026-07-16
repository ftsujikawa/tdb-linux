use crate::debugger::Debugger;
use crate::expr;
use rust_i18n::t;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

pub fn run_repl(mut dbg: Debugger) {
    let mut rl = DefaultEditor::new().expect("failed to init line editor");
    println!("{}", t!("repl.banner", path = dbg.program_path().display()));
    println!("{}", t!("repl.banner_hint"));

    loop {
        let readline = rl.readline("(tdb) ");
        match readline {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(line);
                if !dispatch(&mut dbg, line) {
                    break;
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("{}", t!("repl.ctrl_c_hint"));
                continue;
            }
            Err(ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("{}", t!("repl.input_error", err = e));
                break;
            }
        }
    }
}

/// false を返したらループを終了する。
fn dispatch(dbg: &mut Debugger, line: &str) -> bool {
    let mut parts = line.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    let rest: Vec<&str> = parts.collect();

    let result = match cmd {
        "run" | "r" => dbg.start(),
        "break" | "b" => match rest.first() {
            Some(spec) => dbg.break_at_spec(spec),
            None => {
                println!("{}", t!("repl.usage_break"));
                Ok(())
            }
        },
        "info" | "i" => match rest.first().copied() {
            Some("breakpoints") | Some("b") => {
                dbg.list_breakpoints();
                Ok(())
            }
            Some("watchpoints") | Some("w") => {
                dbg.list_watchpoints();
                Ok(())
            }
            Some("registers") | Some("r") => dbg.print_regs(),
            _ => {
                println!("{}", t!("repl.usage_info"));
                Ok(())
            }
        },
        "watch" => handle_watch(dbg, &rest),
        "delete" | "d" => match rest.first().and_then(|s| s.parse::<u32>().ok()) {
            Some(id) => dbg.delete_breakpoint(id),
            None => {
                println!("{}", t!("repl.usage_delete"));
                Ok(())
            }
        },
        "continue" | "c" => dbg.cont(),
        "stepi" | "si" => dbg.stepi(),
        "nexti" | "ni" => dbg.nexti(),
        "step" | "s" => dbg.step_line(),
        "next" | "n" => dbg.next_line(),
        "up" => dbg.up(),
        "backtrace" | "bt" => dbg.backtrace(),
        "syms" => {
            dbg.list_symbols(rest.first().copied());
            Ok(())
        }
        "lines" => {
            dbg.list_lines(rest.first().copied());
            Ok(())
        }
        "list" | "l" => dbg.list_source(rest.first().copied()),
        "leak" => match rest.first().copied() {
            Some("on") => {
                dbg.set_leak_tracking(true);
                Ok(())
            }
            Some("off") => {
                dbg.set_leak_tracking(false);
                Ok(())
            }
            None => {
                dbg.show_leak_status();
                Ok(())
            }
            Some(other) => {
                println!("{}", t!("repl.leak_unknown_arg", arg = other));
                Ok(())
            }
        },
        "leaks" => {
            dbg.list_leaks();
            Ok(())
        }
        "print" | "p" => handle_print(dbg, None, &rest),
        other if other.starts_with("print/") => handle_print(dbg, Some(&other["print/".len()..]), &rest),
        other if other.starts_with("p/") => handle_print(dbg, Some(&other["p/".len()..]), &rest),
        "show" => match rest.first().copied() {
            Some("print") => {
                println!("print pretty: {}", if dbg.print_pretty() { "on" } else { "off" });
                match dbg.print_elements() {
                    Some(n) => println!("print elements: {}", n),
                    None => println!("print elements: unlimited"),
                }
                Ok(())
            }
            Some("locals") => dbg.list_locals(),
            Some("args") => dbg.list_args(),
            Some("globals") => dbg.list_globals(),
            _ => {
                println!("{}", t!("repl.usage_show"));
                Ok(())
            }
        },
        "set" => match rest.first().copied() {
            Some("print") => handle_set_print(dbg, &rest[1..]),
            Some(assign) => handle_set(dbg, assign, &rest[1..]),
            None => {
                println!("{}", t!("repl.usage_set"));
                Ok(())
            }
        },
        "kill" | "k" => dbg.kill(),
        "help" | "h" | "?" => {
            print!("{}", t!("help"));
            Ok(())
        }
        "lang" => {
            match rest.first().copied() {
                Some(l @ ("en" | "ja")) => {
                    rust_i18n::set_locale(l);
                    println!("{}", t!("repl.lang_switched", lang = l));
                }
                Some(other) => {
                    println!("{}", t!("repl.lang_unknown", arg = other));
                }
                None => {
                    println!("{}", t!("repl.lang_current", lang = &*rust_i18n::locale()));
                }
            }
            Ok(())
        }
        "quit" | "q" | "exit" => {
            if dbg.is_running() {
                let _ = dbg.kill();
            }
            return false;
        }
        other if other == "x" || other.starts_with("x/") => {
            if !rest.is_empty() {
                handle_examine(dbg, other, &rest)
            } else {
                println!("{}", t!("repl.usage_examine_bytes"));
                Ok(())
            }
        }
        other => {
            println!("{}", t!("repl.unknown_command", cmd = other));
            Ok(())
        }
    };

    if let Err(e) = result {
        println!("{}", t!("repl.error_prefix", err = format!("{:#}", e)));
    }
    true
}

/// `print`/`p` を実行する。`fmt` は `print/x` のようにコマンド名にくっついた
/// フォーマット指定(無ければ `rest` の先頭が `/x` のような形なのでそちらを
/// 見る)。フォーマット未指定時は従来通り(ポインタなら16進+10進、既知の
/// 非ポインタ型なら10進のみ、型不明なら16進+10進)。
fn handle_print(dbg: &mut Debugger, fmt: Option<&str>, rest: &[&str]) -> anyhow::Result<()> {
    let (fmt, expr_toks): (Option<char>, &[&str]) = match fmt {
        Some(f) => (f.chars().next(), rest),
        None => match rest.first().and_then(|t| t.strip_prefix('/')) {
            Some(f) => (f.chars().next(), &rest[1..]),
            None => (None, rest),
        },
    };

    if expr_toks.is_empty() {
        println!("{}", t!("repl.usage_print"));
        return Ok(());
    }
    let text = expr_toks.join(" ");
    let result = expr::eval_typed(&text, dbg)?;

    match fmt {
        None => match result {
            expr::PrintResult::Text(s) => println!("{} = {}", text, s),
            expr::PrintResult::Value(expr::Value::Float(f), hint) => match hint {
                Some(h) if dbg.print_pretty() => println!("{} = ({}){}", text, h.type_name, f),
                _ => println!("{} = {}", text, f),
            },
            expr::PrintResult::Value(expr::Value::Int(i), hint) => match hint {
                Some(h) if dbg.print_pretty() && h.is_pointer => {
                    println!("{} = ({}){:#x}", text, h.type_name, i as u64)
                }
                Some(h) if dbg.print_pretty() => println!("{} = ({}){}", text, h.type_name, i),
                Some(h) if h.is_pointer => println!("{} = {:#018x} ({})", text, i as u64, i),
                Some(_) => println!("{} = {}", text, i),
                None => println!("{} = {:#018x} ({})", text, i as u64, i),
            },
        },
        Some(f) => {
            let value = match result {
                expr::PrintResult::Text(_) => {
                    anyhow::bail!("{}", t!("repl.fmt_struct_unsupported", f = f))
                }
                expr::PrintResult::Value(v, _) => v,
            };
            let i = value.as_i64();
            match f {
                'x' => println!("{} = {:#x}", text, i as u64),
                'o' => {
                    let u = i as u64;
                    println!("{} = {}", text, if u == 0 { "0".to_string() } else { format!("0{:o}", u) });
                }
                't' => println!("{} = {:b}", text, i as u64),
                'd' | 'i' => println!("{} = {}", text, i),
                'c' => {
                    let b = (i as u64 & 0xff) as u8;
                    println!("{} = {} {}", text, i, format_char(b));
                }
                's' => {
                    let s = read_c_string(dbg, i as u64)?;
                    println!("{} = \"{}\"", text, s);
                }
                other => anyhow::bail!("{}", t!("repl.fmt_unknown", other = other)),
            }
        }
    }
    Ok(())
}

fn format_char(b: u8) -> String {
    if (0x20..=0x7e).contains(&b) {
        format!("'{}'", b as char)
    } else {
        format!("'\\x{:02x}'", b)
    }
}

/// addr からヌル終端文字列を読み取る。読み取る最大バイト数は
/// `set print elements` (既定 200、`unlimited` なら無制限) に従う。
fn read_c_string(dbg: &Debugger, addr: u64) -> anyhow::Result<String> {
    let max_len = dbg.print_elements().unwrap_or(usize::MAX);
    let mut bytes = Vec::new();
    let mut cur = addr;
    while bytes.len() < max_len {
        let chunk = dbg.read_mem(cur, 8)?;
        for &b in &chunk {
            if b == 0 {
                return Ok(String::from_utf8_lossy(&bytes).into_owned());
            }
            bytes.push(b);
            if bytes.len() >= max_len {
                break;
            }
        }
        cur += 8;
    }
    Ok(format!("{}...", String::from_utf8_lossy(&bytes)))
}

/// GDB の `set print ...` 系サブコマンド。このツールでは代表として
/// `pretty`(構造体の複数行表示)と `elements`(文字列/構造体表示の要素数
/// 上限)のみをサポートする(GDB 本家にある他の `set print` オプション
/// (`address`, `null-stop` 等)は未対応)。
fn handle_set_print(dbg: &mut Debugger, rest: &[&str]) -> anyhow::Result<()> {
    match rest {
        ["pretty", "on"] => {
            dbg.set_print_pretty(true);
            Ok(())
        }
        ["pretty", "off"] => {
            dbg.set_print_pretty(false);
            Ok(())
        }
        ["elements", "unlimited"] => {
            dbg.set_print_elements(None);
            Ok(())
        }
        ["elements", n] => {
            let n: usize =
                n.parse().map_err(|_| anyhow::anyhow!("{}", t!("repl.usage_set_print_elements")))?;
            dbg.set_print_elements(Some(n));
            Ok(())
        }
        _ => {
            println!("{}", t!("repl.usage_set_print"));
            Ok(())
        }
    }
}

fn handle_set(dbg: &mut Debugger, first_tok: &str, rest_toks: &[&str]) -> anyhow::Result<()> {
    // "set $reg=式" / "set *<addr式>=式" または " = " と区切られた形式のどちらにも対応する。
    let full = if rest_toks.is_empty() {
        first_tok.to_string()
    } else {
        format!("{} {}", first_tok, rest_toks.join(" "))
    };
    let (target, val_expr) =
        full.split_once('=').ok_or_else(|| anyhow::anyhow!("{}", t!("repl.usage_set_full")))?;
    let target = target.trim();
    let value = expr::eval(val_expr.trim(), dbg)?;

    if let Some(addr_expr) = target.strip_prefix('*') {
        let addr = expr::eval(addr_expr.trim(), dbg)?.as_i64() as u64;
        // メモリ書き換えは従来通り1バイト単位 (コードパッチ用途を想定)。
        return dbg.write_mem(addr, &[value.as_i64() as u8]);
    }

    if let Some(reg_name) = target.strip_prefix('$') {
        return dbg.set_reg(reg_name, value);
    }

    if let Some((base, steps)) = expr::parse_pure_chain(target, dbg)? {
        if !steps.is_empty() {
            return dbg.write_member_chain(&base, &steps, value);
        }
    }

    dbg.write_variable(target, value)
}

/// `watch <変数名>` は変数のアドレス・型サイズを DWARF 情報から解決し、
/// `watch *<addr式> [長さ]` は式を評価してアドレスを求める(長さ省略時は
/// 8バイト)。どちらもハードウェアウォッチポイント(書き込み監視、
/// 1/2/4/8バイトのいずれか)として設置する。
fn handle_watch(dbg: &mut Debugger, rest: &[&str]) -> anyhow::Result<()> {
    let target = rest.first().ok_or_else(|| anyhow::anyhow!("{}", t!("repl.usage_watch")))?;
    if let Some(addr_expr) = target.strip_prefix('*') {
        let addr = expr::eval(addr_expr, dbg)?.as_i64() as u64;
        let len: u8 = match rest.get(1) {
            Some(s) => {
                s.parse().map_err(|_| anyhow::anyhow!("{}", t!("repl.watch_len_parse_failed", s = s)))?
            }
            None => 8,
        };
        return dbg.add_watchpoint(addr, len, format!("*{:#x}", addr));
    }
    let (addr, size) = dbg.variable_address_and_size(target)?;
    dbg.add_watchpoint(addr, size as u8, target.to_string())
}

fn handle_examine(dbg: &Debugger, cmd: &str, rest: &[&str]) -> anyhow::Result<()> {
    let count: usize = cmd
        .split_once('/')
        .and_then(|(_, n)| n.parse().ok())
        .or_else(|| rest.first().and_then(|s| s.strip_prefix('/')).and_then(|n| n.parse().ok()))
        .unwrap_or(16);
    let addr_str = rest.last().ok_or_else(|| anyhow::anyhow!("{}", t!("repl.usage_examine_n")))?;
    let addr = if let Some(reg) = addr_str.strip_prefix('$') {
        dbg.get_reg(reg)?
    } else {
        let addr_str = addr_str.trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(addr_str, 16)?
    };
    let bytes = dbg.read_mem(addr, count)?;
    for (i, chunk) in bytes.chunks(8).enumerate() {
        print!("{:#018x}:", addr + (i * 8) as u64);
        for b in chunk {
            print!(" {:02x}", b);
        }
        println!();
    }
    Ok(())
}
