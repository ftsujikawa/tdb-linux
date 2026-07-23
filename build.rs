use cfgrammar::yacc::YaccKind;
use lrlex::CTLexerBuilder;
use lrpar::RecoveryKind;

fn main() {
    // print/set/watch/x が使う式 (`src/expr.rs`) の字句解析・構文解析。
    // lrlex (`expr.l`) と lrpar (`expr.y`) を連携させ、パース結果として
    // AST (`expr.rs` 内の `RawExpr`) を組み立てる。実際の評価
    // (`Debugger` を使ったレジスタ/メモリ/変数の読み書き) はパーサーの
    // アクションでは行わず、`expr.rs` 側の `eval_ast` で別途行う。
    CTLexerBuilder::new()
        // `UMINUS` は `%prec` 専用の疑似トークンで、`expr.l` には対応する
        // 字句規則が無い(意図的)。既定では「文法にあるがレキサーに無い
        // トークン」はビルド時 panic になるため、明示的に許可する。
        .allow_missing_terms_in_lexer(true)
        .lrpar_config(|ctp| {
            ctp.yacckind(YaccKind::Grmtools)
                // 単項演算子の優先順位指定 (`%prec UMINUS`) のためだけに
                // 使う疑似トークン `UMINUS` は、通常のシフトでは使われない
                // ため「未使用トークン」警告が出る(古典的な yacc の単項
                // マイナス慣用句そのものだが、この lint には検出できない)。
                // shift/reduce 衝突の検出 (`error_on_conflicts`, 既定 true)
                // はそのまま有効にしておきたいので、警告だけをエラー扱い
                // しないようにする。
                .warnings_are_errors(false)
                // lrpar の既定のエラー回復 (CPCTPlus) は、構文エラーを
                // 「トークンの挿入/削除」で修復してパースを継続しようと
                // する。挿入されたトークンは入力中に実在しない、長さ0の
                // 偽のレキシームになるため、`expr.y` 側のアクション
                // (`num_text`/`float_text` 等、レキシームの文字列を
                // `.parse().unwrap()` する前提のコード)がそれを処理すると
                // パニックする(例: `p i++` で NUM トークンが挿入されて
                // クラッシュした)。このツールでは「式の構文エラーはその場で
                // エラーとして報告する」(黙って推測復旧しない)という、
                // 従来の手書きパーサーと同じ挙動の方が安全なので、エラー
                // 回復自体を無効化する。
                .recoverer(RecoveryKind::None)
                .grammar_in_src_dir("expr.y")
                .unwrap()
        })
        .lexer_in_src_dir("expr.l")
        .unwrap()
        .build()
        .unwrap();

    // REPL のコマンド行 (`src/repl.rs`) を「コマンド名 + 残りの引数」に
    // 分割するためだけの、文法を伴わない単体レキサー。各コマンドの引数
    // 解釈自体は従来通り `repl.rs` の Rust コードが行う。
    CTLexerBuilder::new()
        .lexer_in_src_dir("command.l")
        .unwrap()
        .build()
        .unwrap();
}
