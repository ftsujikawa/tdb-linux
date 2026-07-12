use crate::debugger::Debugger;
use anyhow::{bail, Result};

/// `print`/`set` で使う簡易式評価器。
/// レジスタ参照 (`$rax` など)、DWARF 情報から解決するローカル変数/仮引数名
/// (`x` など)、10進/16進(`0x`)整数リテラル、浮動小数点リテラル(`3.4` 等)、
/// 四則演算・剰余、ビット演算 (`& | ^ ~ << >>`)、単項 `-`、メモリ参照
/// (`*<addr式>`, 8バイトを読む) 、`()` による優先順位指定に対応する。
/// `*` は「前に値が続くか」で二項(乗算)/単項(デリファレンス)を判別する。
/// ビット演算・デリファレンスは整数のみに対応し、浮動小数点数を渡すとエラーになる。

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
        Value::Float(_) => bail!("演算 '{}' に浮動小数点数は使えません", op),
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

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Num(i64),
    Float(f64),
    Reg(String),
    Ident(String),
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Amp,
    Pipe,
    Caret,
    Tilde,
    Shl,
    Shr,
    Arrow,
    /// `.` (構造体メンバアクセス)。このツールでは `->` と意味を区別せず、
    /// どちらも同じ `ChainStep::Field` を生成する完全な別名として扱う。
    Dot,
    LParen,
    RParen,
    LBracket,
    RBracket,
}

/// `->field`/`.field`(構造体メンバ)または `[i]`(配列/ポインタの添字)の
/// 1ステップ。`a->b[2].c` のように混在・連鎖できる。
#[derive(Debug, Clone)]
pub enum ChainStep {
    Field(String),
    Index(i64),
}

fn tokenize(input: &str) -> Result<Vec<Token>> {
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    let mut tokens = Vec::new();

    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '+' => {
                tokens.push(Token::Plus);
                i += 1;
            }
            '-' if chars.get(i + 1) == Some(&'>') => {
                tokens.push(Token::Arrow);
                i += 2;
            }
            '-' => {
                tokens.push(Token::Minus);
                i += 1;
            }
            '*' => {
                tokens.push(Token::Star);
                i += 1;
            }
            '/' => {
                tokens.push(Token::Slash);
                i += 1;
            }
            '%' => {
                tokens.push(Token::Percent);
                i += 1;
            }
            '&' => {
                tokens.push(Token::Amp);
                i += 1;
            }
            '|' => {
                tokens.push(Token::Pipe);
                i += 1;
            }
            '^' => {
                tokens.push(Token::Caret);
                i += 1;
            }
            '~' => {
                tokens.push(Token::Tilde);
                i += 1;
            }
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            '[' => {
                tokens.push(Token::LBracket);
                i += 1;
            }
            ']' => {
                tokens.push(Token::RBracket);
                i += 1;
            }
            '.' => {
                tokens.push(Token::Dot);
                i += 1;
            }
            '<' if chars.get(i + 1) == Some(&'<') => {
                tokens.push(Token::Shl);
                i += 2;
            }
            '>' if chars.get(i + 1) == Some(&'>') => {
                tokens.push(Token::Shr);
                i += 2;
            }
            '$' => {
                let start = i + 1;
                let mut j = start;
                while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
                    j += 1;
                }
                if j == start {
                    bail!("'$' の後にレジスタ名がありません");
                }
                tokens.push(Token::Reg(chars[start..j].iter().collect()));
                i = j;
            }
            _ if c.is_alphabetic() || c == '_' => {
                let start = i;
                let mut j = i;
                while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
                    j += 1;
                }
                tokens.push(Token::Ident(chars[start..j].iter().collect()));
                i = j;
            }
            _ if c.is_ascii_digit() => {
                let start = i;
                let mut j = i;
                if c == '0' && matches!(chars.get(j + 1), Some('x') | Some('X')) {
                    j += 2;
                    let hex_start = j;
                    while j < chars.len() && chars[j].is_ascii_hexdigit() {
                        j += 1;
                    }
                    let hex: String = chars[hex_start..j].iter().collect();
                    let n = i64::from_str_radix(&hex, 16)?;
                    tokens.push(Token::Num(n));
                } else {
                    while j < chars.len() && chars[j].is_ascii_digit() {
                        j += 1;
                    }
                    if chars.get(j) == Some(&'.')
                        && chars.get(j + 1).map(|c| c.is_ascii_digit()).unwrap_or(false)
                    {
                        j += 1;
                        while j < chars.len() && chars[j].is_ascii_digit() {
                            j += 1;
                        }
                        let s: String = chars[start..j].iter().collect();
                        tokens.push(Token::Float(s.parse()?));
                    } else {
                        let dec: String = chars[start..j].iter().collect();
                        tokens.push(Token::Num(dec.parse()?));
                    }
                }
                i = j;
            }
            _ => bail!("式に不正な文字があります: '{}'", c),
        }
    }
    Ok(tokens)
}

struct Parser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    dbg: &'a Debugger,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn parse_expr(&mut self) -> Result<Value> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Value> {
        let mut left = self.parse_xor()?;
        while matches!(self.peek(), Some(Token::Pipe)) {
            self.advance();
            let right = self.parse_xor()?;
            left = Value::Int(require_int(left, "|")? | require_int(right, "|")?);
        }
        Ok(left)
    }

    fn parse_xor(&mut self) -> Result<Value> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Token::Caret)) {
            self.advance();
            let right = self.parse_and()?;
            left = Value::Int(require_int(left, "^")? ^ require_int(right, "^")?);
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Value> {
        let mut left = self.parse_shift()?;
        while matches!(self.peek(), Some(Token::Amp)) {
            self.advance();
            let right = self.parse_shift()?;
            left = Value::Int(require_int(left, "&")? & require_int(right, "&")?);
        }
        Ok(left)
    }

    fn parse_shift(&mut self) -> Result<Value> {
        let mut left = self.parse_add()?;
        loop {
            match self.peek() {
                Some(Token::Shl) => {
                    self.advance();
                    let right = self.parse_add()?;
                    let r = require_int(right, "<<")?;
                    left = Value::Int(require_int(left, "<<")?.wrapping_shl(r as u32));
                }
                Some(Token::Shr) => {
                    self.advance();
                    let right = self.parse_add()?;
                    let r = require_int(right, ">>")?;
                    left = Value::Int(require_int(left, ">>")?.wrapping_shr(r as u32));
                }
                _ => break,
            }
        }
        Ok(left)
    }

    fn parse_add(&mut self) -> Result<Value> {
        let mut left = self.parse_mul()?;
        loop {
            match self.peek() {
                Some(Token::Plus) => {
                    self.advance();
                    let right = self.parse_mul()?;
                    left = numeric_binop(left, right, |a, b| a.wrapping_add(b), |a, b| a + b);
                }
                Some(Token::Minus) => {
                    self.advance();
                    let right = self.parse_mul()?;
                    left = numeric_binop(left, right, |a, b| a.wrapping_sub(b), |a, b| a - b);
                }
                _ => break,
            }
        }
        Ok(left)
    }

    fn parse_mul(&mut self) -> Result<Value> {
        let mut left = self.parse_unary()?;
        loop {
            match self.peek() {
                Some(Token::Star) => {
                    self.advance();
                    let right = self.parse_unary()?;
                    left = numeric_binop(left, right, |a, b| a.wrapping_mul(b), |a, b| a * b);
                }
                Some(Token::Slash) => {
                    self.advance();
                    let right = self.parse_unary()?;
                    if left.is_float() || right.is_float() {
                        left = Value::Float(left.as_f64() / right.as_f64());
                    } else {
                        let r = right.as_i64();
                        if r == 0 {
                            bail!("0 による除算です");
                        }
                        left = Value::Int(left.as_i64().wrapping_div(r));
                    }
                }
                Some(Token::Percent) => {
                    self.advance();
                    let right = self.parse_unary()?;
                    if left.is_float() || right.is_float() {
                        left = Value::Float(left.as_f64() % right.as_f64());
                    } else {
                        let r = right.as_i64();
                        if r == 0 {
                            bail!("0 による剰余演算です");
                        }
                        left = Value::Int(left.as_i64().wrapping_rem(r));
                    }
                }
                _ => break,
            }
        }
        Ok(left)
    }

    /// 単項演算子。`*` はここでのみ「デリファレンス」として扱われ、
    /// `parse_mul` のループ側では「乗算」として扱われる。`&` も同様に、
    /// ここでのみ「アドレス取得」として扱われ、`parse_and` のループ側では
    /// 「ビットAND」として扱われる。
    fn parse_unary(&mut self) -> Result<Value> {
        match self.peek() {
            Some(Token::Minus) => {
                self.advance();
                Ok(match self.parse_unary()? {
                    Value::Int(i) => Value::Int(i.wrapping_neg()),
                    Value::Float(f) => Value::Float(-f),
                })
            }
            Some(Token::Plus) => {
                self.advance();
                self.parse_unary()
            }
            Some(Token::Tilde) => {
                self.advance();
                let v = self.parse_unary()?;
                Ok(Value::Int(!require_int(v, "~")?))
            }
            Some(Token::Star) => {
                self.advance();
                let addr_val = self.parse_unary()?;
                let addr = require_int(addr_val, "* (デリファレンス)")? as u64;
                let bytes = self.dbg.read_mem(addr, 8)?;
                Ok(Value::Int(i64::from_ne_bytes(bytes.try_into().unwrap())))
            }
            Some(Token::Amp) => {
                self.advance();
                match self.advance() {
                    Some(Token::Ident(name)) => Ok(Value::Int(self.dbg.variable_address(&name)? as i64)),
                    _ => bail!("'&' は変数名にのみ使えます (例: &x)"),
                }
            }
            _ => self.parse_postfix(),
        }
    }

    /// 後置の `->field` / `.field` / `[式]` によるメンバ/添字アクセス連鎖
    /// (`a->b[2].c` のように混在・連鎖できる)。`Ident` の直後にそのいずれか
    /// が続く場合のみ特別扱いする。`base_name` の DWARF 型情報が必要なため、
    /// 連鎖の先頭は裸の変数名でなければならない。
    fn parse_postfix(&mut self) -> Result<Value> {
        if let Some(Token::Ident(name)) = self.peek().cloned() {
            if matches!(
                self.tokens.get(self.pos + 1),
                Some(Token::Arrow) | Some(Token::Dot) | Some(Token::LBracket)
            ) {
                self.advance(); // Ident
                let mut steps = Vec::new();
                while let Some(step) = self.try_consume_chain_step()? {
                    steps.push(step);
                }
                return self.dbg.read_member_chain(&name, &steps);
            }
        }
        self.parse_primary()
    }

    /// 現在位置が `->field` / `.field` / `[式]` ならそれを1ステップとして
    /// 消費して返す。どれでもなければ何も消費せず `None` を返す。`->` と
    /// `.` は完全な別名として同じ扱い。添字の中身は完全な式として
    /// 再帰的に評価する(`arr[i+1]` 等も可)。
    fn try_consume_chain_step(&mut self) -> Result<Option<ChainStep>> {
        match self.peek() {
            Some(Token::Arrow) | Some(Token::Dot) => {
                let op = if matches!(self.peek(), Some(Token::Arrow)) { "->" } else { "." };
                self.advance();
                match self.advance() {
                    Some(Token::Ident(field)) => Ok(Some(ChainStep::Field(field))),
                    other => bail!("'{}' の後にはメンバ名が必要です (与えられたもの: {:?})", op, other),
                }
            }
            Some(Token::LBracket) => {
                self.advance();
                let idx_val = self.parse_expr()?;
                match self.advance() {
                    Some(Token::RBracket) => Ok(Some(ChainStep::Index(idx_val.as_i64()))),
                    other => bail!("'[' に対応する ']' がありません (与えられたもの: {:?})", other),
                }
            }
            _ => Ok(None),
        }
    }

    fn parse_primary(&mut self) -> Result<Value> {
        match self.advance() {
            Some(Token::Num(n)) => Ok(Value::Int(n)),
            Some(Token::Float(f)) => Ok(Value::Float(f)),
            Some(Token::Reg(name)) => Ok(Value::Int(self.dbg.get_reg(&name)? as i64)),
            Some(Token::Ident(name)) => self.dbg.read_variable(&name),
            Some(Token::LParen) => {
                let v = self.parse_expr()?;
                match self.advance() {
                    Some(Token::RParen) => Ok(v),
                    _ => bail!("閉じ括弧 ')' がありません"),
                }
            }
            other => bail!("式を解析できません (予期しないトークン: {:?})", other),
        }
    }
}

/// `input` を式として評価する。
pub fn eval(input: &str, dbg: &Debugger) -> Result<Value> {
    let tokens = tokenize(input)?;
    if tokens.is_empty() {
        bail!("式が空です");
    }
    let mut parser = Parser { tokens, pos: 0, dbg };
    let value = parser.parse_expr()?;
    if parser.pos != parser.tokens.len() {
        bail!("式の末尾に余分な入力があります");
    }
    Ok(value)
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
    if let Some((base, steps)) = parse_pure_chain(trimmed, dbg)? {
        return dbg.read_chain_for_print(&base, &steps);
    }
    Ok(PrintResult::Value(eval(input, dbg)?, None))
}

/// 入力全体が「変数名に `->field`/`.field`/`[式]` の連鎖だけが続く」形に
/// なっているかを判定し、そうであれば `(変数名, ステップ列)` を返す。
/// それ以外の演算子が混じっている場合や、そもそも変数名から始まっていない
/// 場合は `None`。`print`/`set` が構造体/配列を整形表示するかどうかの判定
/// に使う(単純な `eval` では連鎖の最終結果がスカラーに変換されてしまう
/// ため)。
pub fn parse_pure_chain(input: &str, dbg: &Debugger) -> Result<Option<(String, Vec<ChainStep>)>> {
    let tokens = tokenize(input)?;
    if !matches!(tokens.first(), Some(Token::Ident(_))) {
        return Ok(None);
    }
    if !matches!(tokens.get(1), Some(Token::Arrow) | Some(Token::Dot) | Some(Token::LBracket)) {
        return Ok(None);
    }
    let mut parser = Parser { tokens, pos: 0, dbg };
    let Some(Token::Ident(base)) = parser.advance() else {
        unreachable!("直前に Ident であることを確認済み");
    };
    let mut steps = Vec::new();
    while let Some(step) = parser.try_consume_chain_step()? {
        steps.push(step);
    }
    if parser.pos != parser.tokens.len() {
        return Ok(None); // 末尾に演算子等が残っている場合は「純粋な連鎖」ではない
    }
    Ok(Some((base, steps)))
}

fn is_bare_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_alphanumeric() || c == '_')
}
