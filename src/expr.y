%grmtools{yacckind: Grmtools}
%start Expr
%token NUM FLOAT REG IDENT
%left '|'
%left '^'
%left '&'
%left '<<' '>>'
%left '+' '-'
%left '*' '/' '%'
%right UMINUS
%%

Expr -> RawExpr:
      Expr '|' Expr { RawExpr::Binary(BinOp::Or, Box::new($1), Box::new($3)) }
    | Expr '^' Expr { RawExpr::Binary(BinOp::Xor, Box::new($1), Box::new($3)) }
    | Expr '&' Expr { RawExpr::Binary(BinOp::And, Box::new($1), Box::new($3)) }
    | Expr '<<' Expr { RawExpr::Binary(BinOp::Shl, Box::new($1), Box::new($3)) }
    | Expr '>>' Expr { RawExpr::Binary(BinOp::Shr, Box::new($1), Box::new($3)) }
    | Expr '+' Expr { RawExpr::Binary(BinOp::Add, Box::new($1), Box::new($3)) }
    | Expr '-' Expr { RawExpr::Binary(BinOp::Sub, Box::new($1), Box::new($3)) }
    | Expr '*' Expr { RawExpr::Binary(BinOp::Mul, Box::new($1), Box::new($3)) }
    | Expr '/' Expr { RawExpr::Binary(BinOp::Div, Box::new($1), Box::new($3)) }
    | Expr '%' Expr { RawExpr::Binary(BinOp::Rem, Box::new($1), Box::new($3)) }
    | '-' Expr %prec UMINUS { RawExpr::Unary(UnOp::Neg, Box::new($2)) }
    | '+' Expr %prec UMINUS { RawExpr::Unary(UnOp::Plus, Box::new($2)) }
    | '~' Expr %prec UMINUS { RawExpr::Unary(UnOp::Not, Box::new($2)) }
    | '*' Expr %prec UMINUS { RawExpr::Deref(Box::new($2)) }
    | '&' IDENT %prec UMINUS { RawExpr::AddrOf(ident_text($lexer, $2)) }
    | '(' Expr ')' { $2 }
    | Chain { $1 }
    | IDENT { RawExpr::Ident(ident_text($lexer, $1)) }
    | NUM { RawExpr::Num(num_text($lexer, $1)) }
    | FLOAT { RawExpr::Float(float_text($lexer, $1)) }
    | REG { RawExpr::Reg(reg_text($lexer, $1)) }
    ;

Chain -> RawExpr:
      IDENT ChainSteps { RawExpr::Chain(ident_text($lexer, $1), $2) }
    ;

ChainSteps -> Vec<RawChainStep>:
      ChainStep { vec![$1] }
    | ChainSteps ChainStep { let mut v = $1; v.push($2); v }
    ;

ChainStep -> RawChainStep:
      '->' IDENT { RawChainStep::Field(ident_text($lexer, $2)) }
    | '.' IDENT { RawChainStep::Field(ident_text($lexer, $2)) }
    | '[' Expr ']' { RawChainStep::Index(Box::new($2)) }
    ;
%%

use crate::expr::{BinOp, RawChainStep, RawExpr, UnOp};

// `Debugger` への参照をパーサーのアクションへ渡す標準的な方法が不確実
// なため、このパーサーは構文木 (`RawExpr`) を組み立てるだけに留め、実際の
// 評価(レジスタ/メモリ/変数の読み書き)は `expr.rs` 側の `eval_ast` で
// 別途行う。

type LexemeResult = Result<lrlex::DefaultLexeme, lrlex::DefaultLexeme>;

fn lexeme_text<'a>(lexer: &'a dyn lrpar::NonStreamingLexer<lrlex::DefaultLexerTypes>, r: &LexemeResult) -> &'a str {
    let lexeme = r.as_ref().unwrap_or_else(|l| l);
    lexer.span_str(lexeme.span())
}

fn ident_text(lexer: &dyn lrpar::NonStreamingLexer<lrlex::DefaultLexerTypes>, r: LexemeResult) -> String {
    lexeme_text(lexer, &r).to_string()
}

fn reg_text(lexer: &dyn lrpar::NonStreamingLexer<lrlex::DefaultLexerTypes>, r: LexemeResult) -> String {
    // `$name` の `$` を除いた部分がレジスタ名。
    lexeme_text(lexer, &r)[1..].to_string()
}

fn num_text(lexer: &dyn lrpar::NonStreamingLexer<lrlex::DefaultLexerTypes>, r: LexemeResult) -> i64 {
    let s = lexeme_text(lexer, &r);
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).unwrap()
    } else {
        s.parse().unwrap()
    }
}

fn float_text(lexer: &dyn lrpar::NonStreamingLexer<lrlex::DefaultLexerTypes>, r: LexemeResult) -> f64 {
    lexeme_text(lexer, &r).parse().unwrap()
}
