use crate::debugger::Debugger;
use crate::expr;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

const HELP: &str = "\
使用可能なコマンド:
  run, r                    プログラムを起動する
  break <func>, b <func>    関数名にブレークポイントを設定
  break *<addr>             アドレス(16進)にブレークポイントを設定
  info breakpoints, i b     ブレークポイント一覧を表示
  delete <n>, d <n>         ブレークポイント n を削除
  continue, c               実行を再開する
  stepi, si                 機械語命令を1つ実行する
  nexti, ni                 call をまたいで機械語命令を1つ実行する
  step, s                   ソース行単位でステップイン実行する(DWARF情報が必要)
  next, n                   ソース行単位でステップオーバー実行する(DWARF情報が必要)
  up                        現在の関数の呼び出し元へ戻るまで実行する
  backtrace, bt             コールスタックを表示する
  syms [絞り込み文字列]      ELFのシンボル(関数)一覧を表示する
  lines [関数名]             行番号情報(アドレス・ファイル・行番号)を表示する(DWARF情報が必要)
  info registers, i r       レジスタを表示する
  print <式>, p <式>        式を評価して表示する (例: p $rax, p x+1, p *$rsp, p &x, p ptr->field)
  print/fmt <式>            フォーマット指定して表示する (fmt: x=16進 o=8進
                              t=2進 d/i=10進 c=文字 s=文字列, 例: p/x $rax)
  set $<reg>=<式>           レジスタに式の評価値を設定する
  set <変数名>=<式>         ローカル変数/仮引数に式の評価値を設定する(DWARF情報が必要)
  set <変数名>-><メンバ>=<式>  構造体メンバに式の評価値を設定する(DWARF情報が必要)
  set print pretty on|off   構造体を複数行インデント表示するか(既定 off)
  set print elements <n>|unlimited
                            文字列(/s)/構造体表示の要素数上限(既定 200)
  show print                現在の print pretty/elements 設定を表示する
  show locals               現在の関数のローカル変数一覧を表示する(DWARF情報が必要)
  show args                 現在の関数の仮引数一覧を表示する(DWARF情報が必要)
  show globals               グローバル変数の一覧を表示する(DWARF情報が必要)
  x/<n> <addr>              メモリをバイト列として表示する
  set *<addr式>=<式>        メモリを1バイト書き換える (例: set *0x4011a0=0x90)
  kill, k                   実行中のプロセスを終了する
  help, h, ?                このヘルプを表示する
  quit, q                   デバッガを終了する
";

pub fn run_repl(mut dbg: Debugger) {
    let mut rl = DefaultEditor::new().expect("failed to init line editor");
    println!("tdb -- 簡易 Linux/C デバッガ (対象: {})", dbg.program_path().display());
    println!("'help' でコマンド一覧を表示します。");

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
                println!("(Ctrl-C: 'quit' で終了)");
                continue;
            }
            Err(ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("入力エラー: {}", e);
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
                println!("使い方: break <func> | break *<addr>");
                Ok(())
            }
        },
        "info" | "i" => match rest.first().copied() {
            Some("breakpoints") | Some("b") => {
                dbg.list_breakpoints();
                Ok(())
            }
            Some("registers") | Some("r") => dbg.print_regs(),
            _ => {
                println!("使い方: info breakpoints | info registers");
                Ok(())
            }
        },
        "delete" | "d" => match rest.first().and_then(|s| s.parse::<u32>().ok()) {
            Some(id) => dbg.delete_breakpoint(id),
            None => {
                println!("使い方: delete <番号>");
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
                println!("使い方: show print | show locals | show args | show globals");
                Ok(())
            }
        },
        "set" => match rest.first().copied() {
            Some("print") => handle_set_print(dbg, &rest[1..]),
            Some(assign) => handle_set(dbg, assign, &rest[1..]),
            None => {
                println!("使い方: set $<レジスタ名>=<値> | set print ...");
                Ok(())
            }
        },
        "kill" | "k" => dbg.kill(),
        "help" | "h" | "?" => {
            print!("{}", HELP);
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
                println!("使い方: x/<バイト数> <アドレス>");
                Ok(())
            }
        }
        other => {
            println!("不明なコマンド: '{}' ('help' を参照)", other);
            Ok(())
        }
    };

    if let Err(e) = result {
        println!("エラー: {:#}", e);
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
        println!(
            "使い方: print[/fmt] <式> (fmt: x=16進 o=8進 t=2進 d/i=10進 c=文字 s=文字列, 例: p/x $rax)"
        );
        return Ok(());
    }
    let text = expr_toks.join(" ");
    let result = expr::eval_typed(&text, dbg)?;

    match fmt {
        None => match result {
            expr::PrintResult::Struct(s) => println!("{} = {}", text, s),
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
                expr::PrintResult::Struct(_) => {
                    anyhow::bail!("構造体にはフォーマット指定 (/{}) は使えません", f)
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
                other => anyhow::bail!("不明なフォーマット指定です: /{} (x, o, t, d, i, c, s が使えます)", other),
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
            let n: usize = n
                .parse()
                .map_err(|_| anyhow::anyhow!("使い方: set print elements <数値>|unlimited"))?;
            dbg.set_print_elements(Some(n));
            Ok(())
        }
        _ => {
            println!("使い方: set print pretty on|off | set print elements <数値>|unlimited");
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
    let (target, val_expr) = full
        .split_once('=')
        .ok_or_else(|| {
            anyhow::anyhow!("使い方: set $<レジスタ名>=<式> | set *<addr式>=<式> | set <変数名>=<式> | set <変数名>-><メンバ名>=<式>")
        })?;
    let target = target.trim();
    let value = expr::eval(val_expr.trim(), dbg)?;

    if let Some(addr_expr) = target.strip_prefix('*') {
        let addr = expr::eval(addr_expr.trim(), dbg)?.as_i64() as u64;
        // メモリ書き換えは従来通り1バイト単位 (コードパッチ用途を想定)。
        return dbg.write_mem(addr, &[value.as_i64() as u8]);
    }

    if let Some(reg_name) = target.strip_prefix('$') {
        return dbg.set_reg(reg_name, value.as_i64() as u64);
    }

    if target.contains("->") {
        let parts: Vec<&str> = target.split("->").map(str::trim).collect();
        if parts.len() < 2 || parts.iter().any(|p| p.is_empty()) {
            anyhow::bail!("使い方: set <変数名>-><メンバ名>[-><メンバ名>...]=<式>");
        }
        let fields: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
        return dbg.write_member_chain(parts[0], &fields, value);
    }

    dbg.write_variable(target, value)
}

fn handle_examine(dbg: &Debugger, cmd: &str, rest: &[&str]) -> anyhow::Result<()> {
    let count: usize = cmd
        .split_once('/')
        .and_then(|(_, n)| n.parse().ok())
        .or_else(|| rest.first().and_then(|s| s.strip_prefix('/')).and_then(|n| n.parse().ok()))
        .unwrap_or(16);
    let addr_str = rest.last().ok_or_else(|| anyhow::anyhow!("使い方: x/<n> <addr>"))?;
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
