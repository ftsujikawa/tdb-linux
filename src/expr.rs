use crate::debugger::Debugger;
use anyhow::{bail, Result};
use lrlex::lrlex_mod;
use lrpar::lrpar_mod;
use rust_i18n::t;

lrlex_mod!("expr.l");
lrpar_mod!("expr.y");

// `print`/`set` で使う簡易式評価器。
// レジスタ参照 (`$rax` など)、DWARF 情報から解決するローカル変数/仮引数名
// (`x` など)、10進/16進(`0x`)整数リテラル、浮動小数点リテラル(`3.4` 等)、
// 四則演算・剰余、ビット演算 (`& | ^ ~ << >>`)、単項 `-`、メモリ参照
// (`*<addr式>`, 8バイトを読む) 、`()` による優先順位指定に対応する。
// `*` は「前に値が続くか」で二項(乗算)/単項(デリファレンス)を判別する。
// ビット演算・デリファレンスは整数のみに対応し、浮動小数点数を渡すとエラーになる。
//
// 字句解析・構文解析は `lrlex`/`lrpar` (grmtools) で生成したパーサー
// (`expr.l`/`expr.y`) が行い、構文木 (`RawExpr`) を組み立てる。実際の評価
// (`Debugger` を使ったレジスタ/メモリ/変数の読み書き) はパーサーの
// アクションでは行わず、`eval_ast` がその構文木を辿って行う
// (`Debugger` への参照をパーサーのアクションへ渡す標準的な方法が
// 不確実なため、パースと評価を分離した設計にしている)。

/// 式の評価結果。整数または浮動小数点数。
#[derive(Debug, Clone, Copy)]
pub enum Value {
    Int(i64),
    Float(f64),
}

impl Value {
    pub fn as_i64(self) -> i64 {
        match self {
            Value::Int(i) => i,
            Value::Float(f) => f as i64,
        }
    }

    pub fn as_f64(self) -> f64 {
        match self {
            Value::Int(i) => i as f64,
            Value::Float(f) => f,
        }
    }

    fn is_float(self) -> bool {
        matches!(self, Value::Float(_))
    }
}

fn require_int(v: Value, op: &str) -> Result<i64> {
    match v {
        Value::Int(i) => Ok(i),
        Value::Float(_) => bail!("{}", t!("expr.float_op_unsupported", op = op)),
    }
}

/// 二項演算を行う。どちらかが浮動小数点数なら両方を f64 に昇格して計算する。
fn numeric_binop(l: Value, r: Value, int_op: impl Fn(i64, i64) -> i64, float_op: impl Fn(f64, f64) -> f64) -> Value {
    if l.is_float() || r.is_float() {
        Value::Float(float_op(l.as_f64(), r.as_f64()))
    } else {
        Value::Int(int_op(l.as_i64(), r.as_i64()))
    }
}

/// `->field`/`.field`(構造体メンバ)または `[i]`(配列/ポインタの添字)の
/// 1ステップ。`a->b[2].c` のように混在・連鎖できる。
#[derive(Debug, Clone)]
pub enum ChainStep {
    Field(String),
    Index(i64),
}

// ---- 構文木 (grmtools が生成するパーサーのアクションが組み立てる) ----

#[derive(Debug, Clone, Copy)]
pub enum UnOp {
    Neg,
    Plus,
    Not,
}

#[derive(Debug, Clone, Copy)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
}

/// `[i]` の添字は(`arr[i+1]` のように)完全な式になりうるため、評価前の
/// 構文木のまま保持する(`ChainStep::Index` は評価後の `i64` を持つ点が
/// 異なる)。
#[derive(Debug, Clone)]
pub enum RawChainStep {
    Field(String),
    Index(Box<RawExpr>),
}

#[derive(Debug, Clone)]
pub enum RawExpr {
    Num(i64),
    Float(f64),
    Reg(String),
    Ident(String),
    Unary(UnOp, Box<RawExpr>),
    Binary(BinOp, Box<RawExpr>, Box<RawExpr>),
    Deref(Box<RawExpr>),
    AddrOf(String),
    /// 変数名に `->`/`.`/`[]` の連鎖が1つ以上続く形(連鎖が無い裸の変数名は
    /// `Ident` になる)。
    Chain(String, Vec<RawChainStep>),
}

/// `input` を字句解析・構文解析し、構文木を返す。
fn parse_to_ast(input: &str) -> Result<RawExpr> {
    let lexerdef = expr_l::lexerdef();
    let lexer = lexerdef.lexer(input);
    let (res, errs) = expr_y::parse(&lexer);
    if !errs.is_empty() {
        let msgs: Vec<String> = errs.iter().map(|e| e.pp(&lexer, &expr_y::token_epp)).collect();
        bail!("{}", t!("expr.parse_failed_grmtools", msg = msgs.join(" / ")));
    }
    res.ok_or_else(|| anyhow::anyhow!("{}", t!("expr.empty")))
}

/// 構文木を辿って実際に評価する(レジスタ/メモリ/変数へのアクセスは
/// ここで初めて発生する)。
fn eval_ast(ast: &RawExpr, dbg: &Debugger) -> Result<Value> {
    match ast {
        RawExpr::Num(n) => Ok(Value::Int(*n)),
        RawExpr::Float(f) => Ok(Value::Float(*f)),
        RawExpr::Reg(name) => Ok(Value::Int(dbg.get_reg(name)? as i64)),
        RawExpr::Ident(name) => dbg.read_variable(name),
        RawExpr::Unary(op, inner) => {
            let v = eval_ast(inner, dbg)?;
            match op {
                UnOp::Neg => Ok(match v {
                    Value::Int(i) => Value::Int(i.wrapping_neg()),
                    Value::Float(f) => Value::Float(-f),
                }),
                UnOp::Plus => Ok(v),
                UnOp::Not => Ok(Value::Int(!require_int(v, "~")?)),
            }
        }
        RawExpr::Deref(inner) => {
            let addr_val = eval_ast(inner, dbg)?;
            let addr = require_int(addr_val, &t!("expr.deref_op"))? as u64;
            let bytes = dbg.read_mem(addr, 8)?;
            Ok(Value::Int(i64::from_ne_bytes(bytes.try_into().unwrap())))
        }
        RawExpr::AddrOf(name) => Ok(Value::Int(dbg.variable_address(name)? as i64)),
        RawExpr::Binary(op, l, r) => {
            let left = eval_ast(l, dbg)?;
            let right = eval_ast(r, dbg)?;
            eval_binop(*op, left, right)
        }
        RawExpr::Chain(base, steps) => {
            let resolved = resolve_chain_steps(steps, dbg)?;
            dbg.read_member_chain(base, &resolved)
        }
    }
}

fn eval_binop(op: BinOp, l: Value, r: Value) -> Result<Value> {
    match op {
        BinOp::Add => Ok(numeric_binop(l, r, |a, b| a.wrapping_add(b), |a, b| a + b)),
        BinOp::Sub => Ok(numeric_binop(l, r, |a, b| a.wrapping_sub(b), |a, b| a - b)),
        BinOp::Mul => Ok(numeric_binop(l, r, |a, b| a.wrapping_mul(b), |a, b| a * b)),
        BinOp::Div => {
            if l.is_float() || r.is_float() {
                Ok(Value::Float(l.as_f64() / r.as_f64()))
            } else {
                let rv = r.as_i64();
                if rv == 0 {
                    bail!("{}", t!("expr.div_by_zero"));
                }
                Ok(Value::Int(l.as_i64().wrapping_div(rv)))
            }
        }
        BinOp::Rem => {
            if l.is_float() || r.is_float() {
                Ok(Value::Float(l.as_f64() % r.as_f64()))
            } else {
                let rv = r.as_i64();
                if rv == 0 {
                    bail!("{}", t!("expr.rem_by_zero"));
                }
                Ok(Value::Int(l.as_i64().wrapping_rem(rv)))
            }
        }
        BinOp::And => Ok(Value::Int(require_int(l, "&")? & require_int(r, "&")?)),
        BinOp::Or => Ok(Value::Int(require_int(l, "|")? | require_int(r, "|")?)),
        BinOp::Xor => Ok(Value::Int(require_int(l, "^")? ^ require_int(r, "^")?)),
        BinOp::Shl => {
            let rv = require_int(r, "<<")?;
            Ok(Value::Int(require_int(l, "<<")?.wrapping_shl(rv as u32)))
        }
        BinOp::Shr => {
            let rv = require_int(r, ">>")?;
            Ok(Value::Int(require_int(l, ">>")?.wrapping_shr(rv as u32)))
        }
    }
}

/// `RawChainStep` 列を、添字式を評価しつつ `ChainStep` 列(`Debugger` の
/// `read_member_chain`/`write_member_chain` が受け取る形)へ変換する。
fn resolve_chain_steps(steps: &[RawChainStep], dbg: &Debugger) -> Result<Vec<ChainStep>> {
    steps
        .iter()
        .map(|s| match s {
            RawChainStep::Field(name) => Ok(ChainStep::Field(name.clone())),
            RawChainStep::Index(expr) => Ok(ChainStep::Index(eval_ast(expr, dbg)?.as_i64())),
        })
        .collect()
}

/// `input` を式として評価する。
pub fn eval(input: &str, dbg: &Debugger) -> Result<Value> {
    let ast = parse_to_ast(input)?;
    eval_ast(&ast, dbg)
}

/// 式の DWARF 型が分かっている場合の付加情報。`print` の表示形式(ポインタ
/// なら16進、それ以外は10進)や、`set print pretty on` での型名表示に使う。
pub struct TypeHint {
    pub is_pointer: bool,
    /// 人間向けの型名 (`int`, `int *`, `struct Point` 等)。
    pub type_name: String,
}

/// `print` 専用の評価結果。式全体が単一の変数名(または `->`/`[]` の連鎖)で、
/// その型が構造体/配列の場合は `Text` として整形済みの表示文字列
/// (`set print pretty`/`set print elements` を反映済み) を返す。それ以外は
/// 従来通り `Value` を返す。`Value` に添える `Option<TypeHint>` は、式全体が
/// 単一の変数名、または `&<変数名>` の場合に限り DWARF の型情報から分かる。
/// レジスタ・リテラル・演算を含む式など、静的な型情報を持たない場合は `None`。
pub enum PrintResult {
    Value(Value, Option<TypeHint>),
    Text(String),
}

/// `eval` と同様に式を評価するが、`print` の表示形式を決めるための型情報
/// (ポインタかどうか・型名、構造体/配列なら整形済み文字列)も併せて求める。
pub fn eval_typed(input: &str, dbg: &Debugger) -> Result<PrintResult> {
    let trimmed = input.trim();
    if is_bare_ident(trimmed) {
        return dbg.read_for_print(trimmed);
    }
    if let Some(inner) = trimmed.strip_prefix('&') {
        let inner = inner.trim();
        if is_bare_ident(inner) {
            return dbg.read_address_for_print(inner);
        }
    }
    if let Some(inner) = trimmed.strip_prefix('*') {
        let inner = inner.trim();
        if is_bare_ident(inner) {
            return dbg.read_deref_for_print(inner);
        }
    }
    let ast = parse_to_ast(input)?;
    if let RawExpr::Chain(base, steps) = &ast {
        let resolved = resolve_chain_steps(steps, dbg)?;
        return dbg.read_chain_for_print(base, &resolved);
    }
    Ok(PrintResult::Value(eval_ast(&ast, dbg)?, None))
}

/// 入力全体が「変数名に `->field`/`.field`/`[式]` の連鎖だけが続く」形に
/// なっているかを判定し、そうであれば `(変数名, ステップ列)` を返す。
/// それ以外の演算子が混じっている場合や、そもそも変数名から始まっていない
/// 場合、あるいは連鎖が1つも無い裸の変数名の場合は `None`。`print`/`set` が
/// 構造体/配列を整形表示するかどうかの判定に使う(単純な `eval` では連鎖の
/// 最終結果がスカラーに変換されてしまうため)。
pub fn parse_pure_chain(input: &str, dbg: &Debugger) -> Result<Option<(String, Vec<ChainStep>)>> {
    let ast = parse_to_ast(input)?;
    match ast {
        RawExpr::Chain(base, steps) => Ok(Some((base, resolve_chain_steps(&steps, dbg)?))),
        _ => Ok(None),
    }
}

fn is_bare_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_alphanumeric() || c == '_')
}
