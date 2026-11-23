use super::{parse_addr, source_path_matches, Debugger};
use crate::disasm;
use crate::dwarf_info;
use crate::elf_info::Symbol;
use crate::expr;
use crate::registers;
use anyhow::{anyhow, bail, Context, Result};
use nix::sys::ptrace;
use rust_i18n::t;
use std::ffi::c_void;
use std::fs;
use std::path::{Path, PathBuf};

impl Debugger {
    /// `center_line` を中心に前後3行(計最大7行)のソースコードを表示する。
    /// 現在行の行番号の前に `>` の印を付ける。ファイルが読めない、または
    /// 指定行が範囲外で1行も表示できない場合は何も表示せず `false` を返す
    /// (呼び出し側で逆アセンブル表示にフォールバックする)。
    pub(super) fn print_source_context(&self, file: &Path, center_line: u32) -> bool {
        const CONTEXT: u32 = 3;
        let Ok(content) = fs::read_to_string(file) else {
            return false;
        };
        let center_line = center_line.max(1);
        let start = center_line.saturating_sub(CONTEXT).max(1);
        let end = center_line + CONTEXT;
        let lines: Vec<(u32, &str)> = content
            .lines()
            .enumerate()
            .map(|(i, t)| ((i + 1) as u32, t))
            .filter(|(n, _)| *n >= start && *n <= end)
            .collect();
        if lines.is_empty() {
            return false;
        }
        println!("{}:{}", file.display(), center_line);
        for (n, text) in lines {
            let marker = if n == center_line { '>' } else { ' ' };
            println!("{}{:>4}\t{}", marker, n, text);
        }
        true
    }

    /// 停止アドレスの内容を表示する。DWARF 行情報からソースファイル/行が
    /// 分かればその周辺行(現在行の前後3行、計最大7行)を、分からなければ
    /// 逆アセンブル結果を表示する。
    pub(super) fn show_stop_location(&self, addr: u64) {
        let link_addr = addr.wrapping_sub(self.load_bias);
        if let Some(row) = self.dwarf.lookup(link_addr) {
            if self.print_source_context(&row.file, row.line) {
                return;
            }
        }
        match self.read_mem_for_display(addr, 16) {
            Ok(bytes) => {
                if let Some(line) = disasm::disassemble_one(&bytes, addr) {
                    println!("{}", line);
                }
            }
            Err(e) => eprintln!("{}", t!("dbg.disasm_read_failed", err = e)),
        }
    }

    /// `read_mem` と同様だが、有効なブレークポイントで書き換えられた
    /// `0xCC` バイトを元の命令バイトに戻してから返す。逆アセンブル表示用。
    pub(super) fn read_mem_for_display(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut bytes = self.read_mem(addr, len)?;
        for (&bp_addr, bp) in &self.breakpoints {
            if bp.enabled && bp_addr >= addr && bp_addr < addr + len as u64 {
                bytes[(bp_addr - addr) as usize] = bp.orig_byte();
            }
        }
        Ok(bytes)
    }

    pub fn print_regs(&self) -> Result<()> {
        let pid = self.pid()?;
        let regs = registers::get_regs(pid)?;
        println!("{}", registers::dump(&regs));
        match registers::get_fpregs(pid) {
            Ok(fpregs) => println!("{}", registers::dump_fpregs(&fpregs)),
            Err(e) => eprintln!("{}", t!("dbg.fpregs_failed", err = e)),
        }
        Ok(())
    }

    /// `$<レジスタ名>` の値を取得する。`st0`-`st7`/`xmm0`-`xmm15` は
    /// `set_reg` の下位64bit書き込みに対応する下位64bitを返す(80bit
    /// 拡張精度としての小数値は `info registers` の `value=` を参照)。
    pub fn get_reg(&self, name: &str) -> Result<u64> {
        let pid = self.pid()?;
        if let Some(idx) = registers::parse_st_name(name) {
            let fpregs = registers::get_fpregs(pid)?;
            return Ok(registers::st_low64(&fpregs, idx));
        }
        if let Some(idx) = registers::parse_xmm_name(name) {
            let fpregs = registers::get_fpregs(pid)?;
            return Ok(registers::xmm_low64(&fpregs, idx));
        }
        let regs = registers::get_regs(pid)?;
        registers::get_by_name(&regs, name)
            .ok_or_else(|| anyhow!("{}", t!("dbg.unknown_register", name = name)))
    }

    /// `$<レジスタ名>` への `set` を行う。`st0`-`st7`/`xmm0`-`xmm15` は
    /// `user_regs_struct` に無いため、`PTRACE_GETFPREGS`/`SETFPREGS` 相当の
    /// 別経路で扱う。`st` レジスタは浮動小数点数として意味のある唯一の型
    /// なので、式の値を `f64` として解釈し80bit拡張精度へ変換する
    /// (`print $stN` / `info registers` の表示と対応する)。`xmm` レジスタは
    /// 128bit全体の解釈が用途で変わるため、他の整数レジスタと同様に式の値を
    /// 整数として扱い、下位64bitへ書き込む(上位64bitは0にする)。
    pub fn set_reg(&self, name: &str, value: expr::Value) -> Result<()> {
        let pid = self.pid()?;
        if let Some(idx) = registers::parse_st_name(name) {
            let mut fpregs = registers::get_fpregs(pid)?;
            let bytes = registers::encode_x87_extended(value.as_f64());
            registers::set_st_bytes(&mut fpregs, idx, &bytes);
            return registers::set_fpregs(pid, &fpregs);
        }
        if let Some(idx) = registers::parse_xmm_name(name) {
            let mut fpregs = registers::get_fpregs(pid)?;
            registers::set_xmm_low64(&mut fpregs, idx, value.as_i64() as u64);
            return registers::set_fpregs(pid, &fpregs);
        }
        let mut regs = registers::get_regs(pid)?;
        if !registers::set_by_name(&mut regs, name, value.as_i64() as u64) {
            bail!("{}", t!("dbg.unknown_register", name = name));
        }
        registers::set_regs(pid, &regs)
    }

    /// DWARF 情報を使い、現在の PC のスコープにあるローカル変数/仮引数
    /// `name` の値を読み取る。`print`/`set` の式評価 (`src/expr.rs`) から
    /// 呼ばれる。
    pub fn read_variable(&self, name: &str) -> Result<expr::Value> {
        Ok(self.read_variable_typed(name)?.0)
    }

    /// `read_variable` と同じだが、ポインタ型かどうかも併せて返す
    /// (`print` が表示形式 — ポインタなら16進、それ以外は10進 — を
    /// 決めるのに使う)。
    pub fn read_variable_typed(&self, name: &str) -> Result<(expr::Value, bool)> {
        let (addr, var) = self.resolve_variable(name)?;
        let value = self.read_typed_value(addr, &var.ty)?;
        Ok((value, var.is_pointer))
    }

    /// `print` 専用の変数読み取り。式全体が単一の変数名のときだけ呼ばれ、
    /// 構造体型ならスカラー値化はせず整形済み文字列を返す
    /// (`set print pretty`/`set print elements` の対象)。
    pub fn read_for_print(&self, name: &str) -> Result<expr::PrintResult> {
        let (addr, var) = self.resolve_variable(name)?;
        self.read_print_value(addr, &var.ty, var.is_pointer)
    }

    /// `print &name` 専用。`name` の実体アドレスを、その「〜へのポインタ」
    /// 型情報付きで返す(例: `y: int` に対する `&y` は型名 `int *`)。
    pub fn read_address_for_print(&self, name: &str) -> Result<expr::PrintResult> {
        let (addr, var) = self.resolve_variable(name)?;
        let ptr_ty = dwarf_info::TypeInfo::Pointer {
            pointee: Box::new(var.ty),
        };
        let hint = expr::TypeHint {
            is_pointer: true,
            type_name: ptr_ty.type_name(),
        };
        Ok(expr::PrintResult::Value(
            expr::Value::Int(addr as i64),
            Some(hint),
        ))
    }

    /// `print *name` 専用。`name` がポインタ型のローカル変数/仮引数の場合に
    /// 限り、`*<addr式>` の生の8バイト読み(型情報なし)ではなく、DWARF の
    /// 指し示す先の型(pointee)を使って指し示す先の値を読む。指し示す先が
    /// 構造体/配列なら整形済み文字列(`set print pretty`/`set print elements`
    /// を反映)を、スカラー/ポインタなら型名付きの値を返す。`name` が
    /// ポインタ型でない場合はエラーにする(`*<変数以外の式>` は従来通り
    /// `expr::eval_ast` の `RawExpr::Deref` 経由の生の8バイト読みのまま)。
    pub fn read_deref_for_print(&self, name: &str) -> Result<expr::PrintResult> {
        let (addr, var) = self.resolve_variable(name)?;
        let pointee = match &var.ty {
            dwarf_info::TypeInfo::Pointer { pointee } => pointee.as_ref(),
            _ => bail!("{}", t!("dbg.deref_not_pointer", name = name)),
        };
        let ptr_value = self.read_typed_value(addr, &var.ty)?;
        let target_addr = ptr_value.as_i64() as u64;
        let is_pointer = matches!(pointee, dwarf_info::TypeInfo::Pointer { .. });
        self.read_print_value(target_addr, pointee, is_pointer)
    }

    /// 現在の関数のローカル変数一覧を表示する (`show locals`)。
    pub fn list_locals(&self) -> Result<()> {
        self.list_scope_vars(false, &t!("dbg.no_locals"))
    }

    /// 現在の関数の仮引数一覧を表示する (`show args`)。
    pub fn list_args(&self) -> Result<()> {
        self.list_scope_vars(true, &t!("dbg.no_params"))
    }

    fn list_scope_vars(&self, want_params: bool, empty_msg: &str) -> Result<()> {
        let pid = self.pid()?;
        let regs = registers::get_regs(pid)?;
        let link_pc = regs.rip.wrapping_sub(self.load_bias);
        let Some(sub) = self.dwarf.find_subprogram(link_pc) else {
            println!("{}", t!("dbg.no_pc_function_info"));
            return Ok(());
        };
        let frame_base = self.eval_frame_base(&sub.frame_base, &regs)?;
        let mut any = false;
        for var in &sub.variables {
            if var.is_param != want_params {
                continue;
            }
            any = true;
            match self
                .eval_location(&var.location, frame_base, &regs)
                .and_then(|addr| self.format_var_value(var, addr))
            {
                Ok(s) => println!("{} = {}", var.name, s),
                Err(e) => println!(
                    "{}",
                    t!("dbg.var_error", name = &var.name, err = format!("{:#}", e))
                ),
            }
        }
        if !any {
            println!("{}", empty_msg);
        }
        Ok(())
    }

    /// グローバル変数(コンパイル単位直下、関数の外で宣言された変数)の
    /// 一覧を表示する (`show globals`)。関数ローカルな `static` 変数は
    /// 対象外(このツールでは扱わない単純化)。
    pub fn list_globals(&self) -> Result<()> {
        let globals = self.dwarf.globals();
        if globals.is_empty() {
            println!("{}", t!("dbg.no_globals"));
            return Ok(());
        }
        let pid = self.pid()?;
        let regs = registers::get_regs(pid)?;
        for var in globals {
            // グローバル変数の位置式 (通常 DW_OP_addr) は frame_base を
            // 使わないため 0 を渡す。
            match self
                .eval_location(&var.location, 0, &regs)
                .and_then(|addr| self.format_var_value(var, addr))
            {
                Ok(s) => println!("{} = {}", var.name, s),
                Err(e) => println!(
                    "{}",
                    t!("dbg.var_error", name = &var.name, err = format!("{:#}", e))
                ),
            }
        }
        Ok(())
    }

    /// `show locals`/`show args`/`show globals` で使う、1つの変数の表示
    /// 文字列を組み立てる(`print` と同じ表示ルール: `pretty on` なら
    /// 型情報付き)。
    fn format_var_value(&self, var: &dwarf_info::VarInfo, addr: u64) -> Result<String> {
        if matches!(
            var.ty,
            dwarf_info::TypeInfo::Struct { .. } | dwarf_info::TypeInfo::Array { .. }
        ) {
            return Ok(self.format_value_by_type(addr, &var.ty, 0));
        }
        let value = self.read_typed_value(addr, &var.ty)?;
        Ok(match value {
            expr::Value::Float(f) if self.print_pretty => format!("({}){}", var.ty.type_name(), f),
            expr::Value::Float(f) => f.to_string(),
            expr::Value::Int(i) if var.is_pointer && self.print_pretty => {
                format!("({}){:#x}", var.ty.type_name(), i as u64)
            }
            expr::Value::Int(i) if var.is_pointer => format!("{:#018x} ({})", i as u64, i),
            expr::Value::Int(i) if self.print_pretty => format!("({}){}", var.ty.type_name(), i),
            expr::Value::Int(i) => i.to_string(),
        })
    }

    /// `addr` にある値を `ty` に従って表示用文字列に変換する。構造体・配列は
    /// それぞれ専用の整形関数に委譲し(それらが `pretty on` 時の型名付与も
    /// 含めて自己完結して処理する)、スカラー/ポインタはここで
    /// `(型名)値` 形式(`pretty on` の場合のみ)に整形する。
    /// `format_struct_value`/`format_array_value` の要素・メンバの表示に
    /// 共通で使う。
    fn format_value_by_type(&self, addr: u64, ty: &dwarf_info::TypeInfo, depth: usize) -> String {
        match ty {
            dwarf_info::TypeInfo::Struct { .. } => self.format_struct_value(addr, ty, depth),
            dwarf_info::TypeInfo::Array { .. } => self.format_array_value(addr, ty, depth),
            dwarf_info::TypeInfo::Pointer { .. } => match self.read_typed_value(addr, ty) {
                Ok(v) => {
                    let s = format!("{:#x}", v.as_i64() as u64);
                    if self.print_pretty {
                        format!("({}){}", ty.type_name(), s)
                    } else {
                        s
                    }
                }
                Err(_) => "?".to_string(),
            },
            _ => match self.read_typed_value(addr, ty) {
                Ok(expr::Value::Float(f)) => {
                    if self.print_pretty {
                        format!("({}){}", ty.type_name(), f)
                    } else {
                        f.to_string()
                    }
                }
                Ok(expr::Value::Int(v)) => {
                    if self.print_pretty {
                        format!("({}){}", ty.type_name(), v)
                    } else {
                        v.to_string()
                    }
                }
                Err(_) => "?".to_string(),
            },
        }
    }

    /// 構造体の値を `{a = 1, b = 2}` の形式(`set print pretty on` なら
    /// 複数行インデント表示)でフォーマットする。ポインタ型メンバは指す先を
    /// 辿らずアドレスの16進表示のみ行う(GDB の既定動作と同様)。ネストした
    /// 構造体・配列は再帰的にフォーマットする(型解決自体が
    /// `MAX_TYPE_DEPTH` で打ち切られているため、無限再帰にはならない)。
    fn format_struct_value(&self, addr: u64, ty: &dwarf_info::TypeInfo, depth: usize) -> String {
        let members = match ty {
            dwarf_info::TypeInfo::Struct { members, .. } => members,
            _ => return "?".to_string(),
        };
        let max = self.print_elements.unwrap_or(usize::MAX);
        let mut parts = Vec::new();
        for m in members.iter().take(max) {
            let member_addr = addr + m.offset;
            let value_str = self.format_value_by_type(member_addr, &m.ty, depth + 1);
            parts.push(format!("{} = {}", m.name, value_str));
        }
        if members.len() > max {
            parts.push("...".to_string());
        }
        if self.print_pretty {
            let pad = "  ".repeat(depth + 1);
            let close_pad = "  ".repeat(depth);
            format!(
                "({}) {{\n{}{}\n{}}}",
                ty.type_name(),
                pad,
                parts.join(&format!(",\n{}", pad)),
                close_pad
            )
        } else {
            format!("{{{}}}", parts.join(", "))
        }
    }

    /// 配列の値を `{1, 2, 3}` の形式(`set print pretty on` なら複数行
    /// インデント表示)でフォーマットする。要素数は `set print elements`
    /// で打ち切る。要素が構造体/配列ならネストして再帰的にフォーマットする。
    fn format_array_value(&self, addr: u64, ty: &dwarf_info::TypeInfo, depth: usize) -> String {
        let (element, count) = match ty {
            dwarf_info::TypeInfo::Array { element, count } => (element.as_ref(), *count),
            _ => return "?".to_string(),
        };
        let total = count.unwrap_or(0);
        let max = self.print_elements.map(|n| n as u64).unwrap_or(u64::MAX);
        let shown = total.min(max);
        let elem_size = element.byte_size().max(1);
        let mut parts = Vec::new();
        for i in 0..shown {
            let elem_addr = addr + i * elem_size;
            parts.push(self.format_value_by_type(elem_addr, element, depth + 1));
        }
        if total > shown {
            parts.push("...".to_string());
        }
        if self.print_pretty {
            let pad = "  ".repeat(depth + 1);
            let close_pad = "  ".repeat(depth);
            format!(
                "({}) {{\n{}{}\n{}}}",
                ty.type_name(),
                pad,
                parts.join(&format!(",\n{}", pad)),
                close_pad
            )
        } else {
            format!("{{{}}}", parts.join(", "))
        }
    }

    /// DWARF 情報を使い、現在の PC のスコープにあるローカル変数/仮引数
    /// `name` に値を書き込む。`set` の式評価 (`src/expr.rs`) から呼ばれる。
    /// 書き込みバイト数は変数の型サイズ(`DW_AT_byte_size`、最大8バイト)。
    /// 変数の型が浮動小数点数 (`float`/`double`) の場合は値を IEEE754 の
    /// ビット列に変換して書き込み、そうでなければ整数として書き込む
    /// (代入する式の値が浮動小数点数であれば、その場合は切り捨てる)。
    pub fn write_variable(&self, name: &str, value: expr::Value) -> Result<()> {
        let (addr, var) = self.resolve_variable(name)?;
        self.write_typed_value(addr, &var.ty, value)
    }

    /// ローカル変数/仮引数 `name` の実体アドレスを返す。式の `&x` (アドレス
    /// 取得演算子) から呼ばれる。
    pub fn variable_address(&self, name: &str) -> Result<u64> {
        Ok(self.resolve_variable(name)?.0)
    }

    /// `base_name->field1[i]->field2...` を評価する。`base_name` は
    /// ローカル変数/仮引数名で、各ステップの起点は(構造体/配列へのポインタ、
    /// または構造体/配列そのもの)である必要がある。式の `->`/`[]` 演算子
    /// (`src/expr.rs`) から呼ばれる。
    pub fn read_member_chain(
        &self,
        base_name: &str,
        steps: &[expr::ChainStep],
    ) -> Result<expr::Value> {
        let (addr, ty) = self.resolve_member_chain(base_name, steps)?;
        self.read_typed_value(addr, &ty)
    }

    /// `read_member_chain` の書き込み版。`set base->field...=式`/
    /// `set base[i]=式` から呼ばれる。
    pub fn write_member_chain(
        &self,
        base_name: &str,
        steps: &[expr::ChainStep],
        value: expr::Value,
    ) -> Result<()> {
        let (addr, ty) = self.resolve_member_chain(base_name, steps)?;
        self.write_typed_value(addr, &ty, value)
    }

    /// `print`/`show` 用。最終ステップの型が構造体/配列なら整形済み文字列を
    /// 返し、それ以外はスカラー値+型情報を返す(`read_for_print` と同様)。
    pub fn read_chain_for_print(
        &self,
        base_name: &str,
        steps: &[expr::ChainStep],
    ) -> Result<expr::PrintResult> {
        let (addr, ty) = self.resolve_member_chain(base_name, steps)?;
        let is_pointer = matches!(ty, dwarf_info::TypeInfo::Pointer { .. });
        self.read_print_value(addr, &ty, is_pointer)
    }

    fn read_print_value(
        &self,
        addr: u64,
        ty: &dwarf_info::TypeInfo,
        is_pointer: bool,
    ) -> Result<expr::PrintResult> {
        if matches!(
            ty,
            dwarf_info::TypeInfo::Struct { .. } | dwarf_info::TypeInfo::Array { .. }
        ) {
            return Ok(expr::PrintResult::Text(
                self.format_value_by_type(addr, ty, 0),
            ));
        }
        let value = self.read_typed_value(addr, ty)?;
        let hint = expr::TypeHint {
            is_pointer,
            type_name: ty.type_name(),
        };
        Ok(expr::PrintResult::Value(value, Some(hint)))
    }

    /// `base_name` から `steps` を辿り、最後のステップの (アドレス, 型) を
    /// 返す。`read_member_chain`/`write_member_chain`/`read_chain_for_print`
    /// の共通処理。
    fn resolve_member_chain(
        &self,
        base_name: &str,
        steps: &[expr::ChainStep],
    ) -> Result<(u64, dwarf_info::TypeInfo)> {
        if steps.is_empty() {
            bail!("{}", t!("dbg.chain_empty"));
        }
        let (addr, var) = self.resolve_variable(base_name)?;
        // 先頭から暗黙のデリファレンスを1回済ませてしまわない: `[i]` は
        // ポインタ自身の値をベースアドレスとして使う必要があり(配列は
        // そのまま自分のアドレスを使う)、`->` はポインタなら1回だけ
        // デリファレンスする必要がある。この2つは要求するデリファレンス
        // 回数が違うため、各ステップが自分の種類に応じて自分で処理する。
        let mut cur_addr = addr;
        let mut cur_ty = var.ty;
        let mut cur_name = base_name.to_string();
        for (i, step) in steps.iter().enumerate() {
            let (step_addr, step_ty) = match step {
                expr::ChainStep::Field(field) => {
                    let (struct_addr, struct_ty) = self.deref_if_pointer(cur_addr, &cur_ty)?;
                    let members = match &struct_ty {
                        dwarf_info::TypeInfo::Struct { members, .. } => members,
                        _ => bail!(
                            "{}",
                            t!("dbg.not_struct_or_pointer", name = cur_name, field = field)
                        ),
                    };
                    let m = members
                        .iter()
                        .find(|m| &m.name == field)
                        .ok_or_else(|| anyhow!("{}", t!("dbg.member_not_found", field = field)))?;
                    (struct_addr + m.offset, m.ty.clone())
                }
                expr::ChainStep::Index(idx) => {
                    let (base_addr, element_ty) = match &cur_ty {
                        dwarf_info::TypeInfo::Array { element, .. } => {
                            (cur_addr, (**element).clone())
                        }
                        dwarf_info::TypeInfo::Pointer { pointee } => {
                            let bytes = self.read_mem(cur_addr, 8)?;
                            let base = u64::from_ne_bytes(bytes.try_into().unwrap());
                            (base, (**pointee).clone())
                        }
                        _ => bail!(
                            "{}",
                            t!("dbg.not_array_or_pointer", name = cur_name, idx = idx)
                        ),
                    };
                    let elem_size = element_ty.byte_size().max(1);
                    let elem_addr =
                        (base_addr as i64).wrapping_add(idx.wrapping_mul(elem_size as i64)) as u64;
                    (elem_addr, element_ty)
                }
            };
            cur_addr = step_addr;
            cur_ty = step_ty;
            cur_name = match step {
                expr::ChainStep::Field(f) => f.clone(),
                expr::ChainStep::Index(idx) => format!("[{}]", idx),
            };
            if i + 1 == steps.len() {
                return Ok((cur_addr, cur_ty));
            }
        }
        unreachable!("steps が空でなければループ内で必ず return する");
    }

    /// `ty` がポインタ型なら `addr` に格納されているポインタ値を読んで
    /// (指し示す先のアドレス, 指し示す先の型) を返す。ポインタでなければ
    /// `(addr, ty)` をそのまま返す(構造体を値として直接指している場合)。
    fn deref_if_pointer(
        &self,
        addr: u64,
        ty: &dwarf_info::TypeInfo,
    ) -> Result<(u64, dwarf_info::TypeInfo)> {
        match ty {
            dwarf_info::TypeInfo::Pointer { pointee } => {
                let bytes = self.read_mem(addr, 8)?;
                let ptr_val = u64::from_ne_bytes(bytes.try_into().unwrap());
                Ok((ptr_val, (**pointee).clone()))
            }
            other => Ok((addr, other.clone())),
        }
    }

    /// `addr` にある値を `ty` に従って読み取る。構造体そのもの/不明な型は
    /// 先頭8バイトを整数として返す(値としての表示や、それ以上のメンバ
    /// アクセスの連鎖には対応しない)。
    fn read_typed_value(&self, addr: u64, ty: &dwarf_info::TypeInfo) -> Result<expr::Value> {
        const DW_ATE_FLOAT: u8 = 0x04;
        const DW_ATE_SIGNED: u8 = 0x05;
        const DW_ATE_SIGNED_CHAR: u8 = 0x06;

        match ty {
            dwarf_info::TypeInfo::Base {
                byte_size,
                encoding,
                ..
            } => {
                let size = (*byte_size as usize).clamp(1, 8);
                let bytes = self.read_mem(addr, size)?;
                if *encoding == DW_ATE_FLOAT {
                    let f = if size == 4 {
                        let mut buf = [0u8; 4];
                        buf.copy_from_slice(&bytes);
                        f32::from_ne_bytes(buf) as f64
                    } else {
                        let mut buf = [0u8; 8];
                        buf[..size].copy_from_slice(&bytes);
                        f64::from_ne_bytes(buf)
                    };
                    return Ok(expr::Value::Float(f));
                }
                let mut buf = [0u8; 8];
                buf[..size].copy_from_slice(&bytes);
                let raw = u64::from_ne_bytes(buf);
                let signed = matches!(*encoding, DW_ATE_SIGNED | DW_ATE_SIGNED_CHAR);
                let value = if signed && size < 8 {
                    let shift = (8 - size) * 8;
                    ((raw << shift) as i64) >> shift
                } else {
                    raw as i64
                };
                Ok(expr::Value::Int(value))
            }
            dwarf_info::TypeInfo::Pointer { .. }
            | dwarf_info::TypeInfo::Struct { .. }
            | dwarf_info::TypeInfo::Array { .. }
            | dwarf_info::TypeInfo::Unknown => {
                let bytes = self.read_mem(addr, 8)?;
                Ok(expr::Value::Int(i64::from_ne_bytes(
                    bytes.try_into().unwrap(),
                )))
            }
        }
    }

    /// `addr` に `value` を `ty` に従って書き込む。整数型の場合は
    /// `DW_AT_byte_size` ぶんだけ、浮動小数点数の場合は IEEE754 のビット列
    /// (4バイトなら `f32`、それ以外は `f64`)に変換して書き込む。構造体
    /// そのもの/不明な型への書き込みは対応していない。
    fn write_typed_value(
        &self,
        addr: u64,
        ty: &dwarf_info::TypeInfo,
        value: expr::Value,
    ) -> Result<()> {
        const DW_ATE_FLOAT: u8 = 0x04;
        match ty {
            dwarf_info::TypeInfo::Base {
                byte_size,
                encoding,
                ..
            } => {
                let size = (*byte_size as usize).clamp(1, 8);
                let bytes: Vec<u8> = if *encoding == DW_ATE_FLOAT {
                    if size == 4 {
                        (value.as_f64() as f32).to_ne_bytes().to_vec()
                    } else {
                        value.as_f64().to_ne_bytes()[..size].to_vec()
                    }
                } else {
                    value.as_i64().to_ne_bytes()[..size].to_vec()
                };
                self.write_mem(addr, &bytes)
            }
            dwarf_info::TypeInfo::Pointer { .. } => {
                self.write_mem(addr, &value.as_i64().to_ne_bytes())
            }
            dwarf_info::TypeInfo::Struct { .. }
            | dwarf_info::TypeInfo::Array { .. }
            | dwarf_info::TypeInfo::Unknown => {
                bail!("{}", t!("dbg.write_unsupported_type"))
            }
        }
    }

    /// 変数名を現在の PC のスコープで解決し、(アドレス, 変数情報) を返す。
    pub(super) fn resolve_variable(&self, name: &str) -> Result<(u64, dwarf_info::VarInfo)> {
        let pid = self.pid()?;
        let regs = registers::get_regs(pid)?;
        let link_pc = regs.rip.wrapping_sub(self.load_bias);
        let (sub, var) = self
            .dwarf
            .find_variable(link_pc, name)
            .ok_or_else(|| anyhow!("{}", t!("dbg.var_not_found", name = name)))?;
        let frame_base = self.eval_frame_base(&sub.frame_base, &regs)?;
        let addr = self.eval_location(&var.location, frame_base, &regs)?;
        Ok((addr, var.clone()))
    }

    /// `DW_AT_frame_base` の DWARF 式を評価してフレームベースアドレスを得る。
    /// `DW_OP_call_frame_cfa` は CFI を読まず、`push rbp; mov rbp,rsp` という
    /// 典型的なプロローグを前提に `rbp+16` で近似する
    /// (`backtrace`/`up` の rbp チェイン前提と同じ簡略化)。
    fn eval_frame_base(&self, expr: &[u8], regs: &registers::Regs) -> Result<u64> {
        if expr.is_empty() {
            bail!("{}", t!("dbg.no_frame_base"));
        }
        match expr[0] {
            0x9c => Ok(regs.rbp.wrapping_add(16)),
            op @ 0x70..=0x8f => {
                let offset = dwarf_info::read_sleb128(&expr[1..])
                    .ok_or_else(|| anyhow!("{}", t!("dbg.frame_base_parse_failed")))?;
                let reg_val = self.dwarf_reg_value(op - 0x70, regs)?;
                Ok((reg_val as i64).wrapping_add(offset) as u64)
            }
            op => bail!(
                "{}",
                t!("dbg.unsupported_frame_base_expr", op = format!("{:#x}", op))
            ),
        }
    }

    /// 変数の `DW_AT_location` (DWARF 式) を評価してメモリアドレスを得る。
    /// `DW_OP_fbreg`(frame_base 相対)、`DW_OP_addr`(絶対アドレス、グローバル
    /// 変数用)、`DW_OP_bregN`(レジスタ相対)に対応する。
    pub(super) fn eval_location(
        &self,
        expr: &[u8],
        frame_base: u64,
        regs: &registers::Regs,
    ) -> Result<u64> {
        if expr.is_empty() {
            bail!("{}", t!("dbg.no_var_location"));
        }
        match expr[0] {
            0x91 => {
                let offset = dwarf_info::read_sleb128(&expr[1..])
                    .ok_or_else(|| anyhow!("{}", t!("dbg.var_expr_parse_failed")))?;
                Ok((frame_base as i64).wrapping_add(offset) as u64)
            }
            0x03 => {
                if expr.len() < 9 {
                    bail!("{}", t!("dbg.dw_op_addr_missing_operand"));
                }
                let addr = u64::from_le_bytes(expr[1..9].try_into().unwrap());
                Ok(self.runtime_addr(addr))
            }
            op @ 0x70..=0x8f => {
                let offset = dwarf_info::read_sleb128(&expr[1..])
                    .ok_or_else(|| anyhow!("{}", t!("dbg.var_expr_parse_failed")))?;
                let reg_val = self.dwarf_reg_value(op - 0x70, regs)?;
                Ok((reg_val as i64).wrapping_add(offset) as u64)
            }
            op => bail!(
                "{}",
                t!(
                    "dbg.unsupported_var_location_expr",
                    op = format!("{:#x}", op)
                )
            ),
        }
    }

    /// DWARF (x86-64 System V ABI) のレジスタ番号からレジスタ値を取得する。
    fn dwarf_reg_value(&self, dwarf_reg: u8, regs: &registers::Regs) -> Result<u64> {
        let name = match dwarf_reg {
            0 => "rax",
            1 => "rdx",
            2 => "rcx",
            3 => "rbx",
            4 => "rsi",
            5 => "rdi",
            6 => "rbp",
            7 => "rsp",
            8 => "r8",
            9 => "r9",
            10 => "r10",
            11 => "r11",
            12 => "r12",
            13 => "r13",
            14 => "r14",
            15 => "r15",
            16 => "rip",
            other => bail!("{}", t!("dbg.unsupported_dwarf_reg", other = other)),
        };
        registers::get_by_name(regs, name)
            .ok_or_else(|| anyhow!("{}", t!("dbg.reg_get_failed", name = name)))
    }

    pub fn read_mem(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let pid = self.pid()?;
        let mut out = Vec::with_capacity(len);
        let mut cur = addr & !0x7;
        let start_pad = (addr - cur) as usize;
        while out.len() < start_pad + len {
            let word = ptrace::read(pid, cur as *mut c_void)
                .context(t!("dbg.mem_read_failed").to_string())?;
            out.extend_from_slice(&word.to_ne_bytes());
            cur += 8;
        }
        Ok(out[start_pad..start_pad + len].to_vec())
    }

    pub fn write_mem(&self, addr: u64, data: &[u8]) -> Result<()> {
        let pid = self.pid()?;
        let mut cur = addr;
        let mut offset = 0usize;
        while offset < data.len() {
            let word_addr = cur & !0x7;
            let mut word = ptrace::read(pid, word_addr as *mut c_void)
                .context(t!("dbg.mem_read_failed").to_string())?
                .to_ne_bytes();
            let in_word_off = (cur - word_addr) as usize;
            let n = (8 - in_word_off).min(data.len() - offset);
            word[in_word_off..in_word_off + n].copy_from_slice(&data[offset..offset + n]);
            let new_word = i64::from_ne_bytes(word);
            ptrace::write(pid, word_addr as *mut c_void, new_word)
                .context(t!("dbg.mem_write_failed").to_string())?;
            cur += n as u64;
            offset += n;
        }
        Ok(())
    }

    pub fn backtrace(&self) -> Result<()> {
        let pid = self.pid()?;
        let regs = registers::get_regs(pid)?;
        let mut rip = regs.rip;
        let mut rbp = regs.rbp;
        for depth in 0..64 {
            let link_ip = rip.wrapping_sub(self.load_bias);
            let sym = match self.elf.find_by_addr(link_ip) {
                Some(s) if link_ip == s.addr => s.name.clone(),
                Some(s) => format!("{}+{:#x}", s.name, link_ip - s.addr),
                None => "??".to_string(),
            };
            match self.dwarf.lookup(link_ip) {
                Some(row) => println!(
                    "#{:<2} {:#018x} in {} at {}:{}",
                    depth,
                    rip,
                    sym,
                    row.file.display(),
                    row.line
                ),
                None => println!("#{:<2} {:#018x} in {}", depth, rip, sym),
            }
            if rbp == 0 {
                break;
            }
            let saved_rbp = self.read_mem(rbp, 8)?;
            let ret_addr = self.read_mem(rbp + 8, 8)?;
            let saved_rbp = u64::from_ne_bytes(saved_rbp.try_into().unwrap());
            let ret_addr = u64::from_ne_bytes(ret_addr.try_into().unwrap());
            if ret_addr == 0 || saved_rbp == 0 {
                break;
            }
            rip = ret_addr;
            rbp = saved_rbp;
        }
        Ok(())
    }

    /// ELF のシンボルテーブル (関数シンボル) を一覧表示する (`syms` コマンド)。
    /// `filter` が指定されていれば、シンボル名にその文字列を含むものだけ
    /// 表示する。プロセス実行中はロードバイアスを加えた実行時アドレスを、
    /// 未実行なら ELF 上のリンク時アドレスをそのまま表示する。
    pub fn list_symbols(&self, filter: Option<&str>) {
        let symbols: Vec<&Symbol> = self
            .elf
            .symbols
            .iter()
            .filter(|s| filter.is_none_or(|f| s.name.contains(f)))
            .collect();
        if symbols.is_empty() {
            println!("{}", t!("dbg.no_symbols"));
            return;
        }
        for s in symbols {
            let addr = if self.is_running() {
                self.runtime_addr(s.addr)
            } else {
                s.addr
            };
            println!("{:#018x} {:>6} {}", addr, s.size, s.name);
        }
    }

    /// `.debug_line` の行番号情報を一覧表示する (`lines` コマンド)。`filter`
    /// が関数名として解決できれば、その関数のアドレス範囲内の行だけに
    /// 絞り込む(解決できなければ絞り込まず全件表示する)。終端マーカー
    /// (`end_sequence`)の行は実際のソース行ではないため表示しない。
    pub fn list_lines(&self, filter: Option<&str>) {
        let range = filter
            .and_then(|name| self.elf.find_by_name(name))
            .map(|s| (s.addr, s.addr + s.size.max(1)));
        let mut any = false;
        for row in self.dwarf.lines() {
            if row.end_sequence {
                continue;
            }
            if let Some((lo, hi)) = range {
                if row.addr < lo || row.addr >= hi {
                    continue;
                }
            }
            any = true;
            let addr = if self.is_running() {
                self.runtime_addr(row.addr)
            } else {
                row.addr
            };
            println!("{:#018x} {}:{}", addr, row.file.display(), row.line);
        }
        if !any {
            println!("{}", t!("dbg.no_lineinfo"));
        }
    }

    /// ソースコードを表示する (`list` コマンド)。`spec` の形式によって
    /// 表示位置の決め方を変える:
    /// - 指定なし: 実行中なら現在の PC の行、そうでなければ `main` 関数の行。
    /// - `*<addr>` (シンボル/アドレス指定): アドレスに対応する行番号情報を
    ///   DWARF 行テーブルから引く(実行中はランタイムアドレス、未実行なら
    ///   リンク時アドレスとして解釈する。`break *<addr>` と同じ慣習)。
    /// - 数値のみ: 行番号として扱い、直近の実行位置(または `main`)と
    ///   同じファイル内のその行を表示する。
    /// - `<ファイル>:<行番号>`: 行番号情報からファイル名が一致する行を探し、
    ///   そのファイルの指定行を表示する。
    /// - それ以外: 関数名として ELF シンボルテーブルから探し、その関数の
    ///   先頭アドレスに対応する行を表示する。
    pub fn list_source(&self, spec: Option<&str>) -> Result<()> {
        let (file, line) = match spec {
            None => self.current_source_location()?,
            Some(s) => {
                let s = s.trim();
                if let Some(hex) = s.strip_prefix('*') {
                    self.location_from_address(hex)?
                } else if let Ok(n) = s.parse::<u32>() {
                    (self.current_source_location()?.0, n)
                } else if let Some((file_part, line_part)) = s.rsplit_once(':') {
                    let n: u32 = line_part
                        .trim()
                        .parse()
                        .with_context(|| t!("dbg.line_parse_failed", s = line_part).to_string())?;
                    let file = self.resolve_source_file(file_part.trim()).ok_or_else(|| {
                        anyhow!("{}", t!("dbg.file_lineinfo_not_found", file = file_part))
                    })?;
                    (file, n)
                } else {
                    self.location_from_function(s)?
                }
            }
        };
        self.show_source_window(&file, line);
        Ok(())
    }

    /// 実行中なら現在の PC の(ファイル, 行番号)、そうでなければ `main`
    /// 関数の(ファイル, 行番号)を返す。`list` の指定省略時・数値のみ
    /// 指定時のデフォルト位置決めに使う。
    fn current_source_location(&self) -> Result<(PathBuf, u32)> {
        if self.is_running() {
            let pid = self.pid()?;
            let regs = registers::get_regs(pid)?;
            let link_pc = regs.rip.wrapping_sub(self.load_bias);
            if let Some(row) = self.dwarf.lookup(link_pc) {
                return Ok((row.file.clone(), row.line));
            }
        }
        let sym = self
            .elf
            .find_by_name("main")
            .ok_or_else(|| anyhow!("{}", t!("dbg.list_no_location")))?;
        let row = self
            .dwarf
            .lookup(sym.addr)
            .ok_or_else(|| anyhow!("{}", t!("dbg.list_no_location_no_dwarf")))?;
        Ok((row.file.clone(), row.line))
    }

    /// アドレス(16進文字列)に対応する(ファイル, 行番号)を求める。
    /// 実行中はランタイムアドレス、未実行ならリンク時アドレスとして解釈する
    /// (`break *<addr>` と同じ慣習)。
    fn location_from_address(&self, hex: &str) -> Result<(PathBuf, u32)> {
        let addr = parse_addr(hex)?;
        let link_addr = if self.is_running() {
            addr.wrapping_sub(self.load_bias)
        } else {
            addr
        };
        let row = self.dwarf.lookup(link_addr).ok_or_else(|| {
            anyhow!(
                "{}",
                t!("dbg.addr_lineinfo_not_found", addr = format!("{:#x}", addr))
            )
        })?;
        Ok((row.file.clone(), row.line))
    }

    /// 関数名に対応する(ファイル, 行番号)を求める。ELF シンボルテーブルで
    /// アドレスを引き、そのアドレスの行番号情報を DWARF から引く。
    fn location_from_function(&self, name: &str) -> Result<(PathBuf, u32)> {
        let sym = self
            .elf
            .find_by_name(name)
            .ok_or_else(|| anyhow!("{}", t!("dbg.function_not_found", name = name)))?;
        let row = self
            .dwarf
            .lookup(sym.addr)
            .ok_or_else(|| anyhow!("{}", t!("dbg.function_lineinfo_not_found", name = name)))?;
        Ok((row.file.clone(), row.line))
    }

    /// 行番号情報の中から、ファイル名(フルパス・ファイル名部分・パスの
    /// 末尾部分一致のいずれか)が `spec` に一致する最初のファイルパスを返す。
    fn resolve_source_file(&self, spec: &str) -> Option<PathBuf> {
        self.dwarf
            .lines()
            .iter()
            .find(|r| !r.end_sequence && source_path_matches(&r.file, spec))
            .map(|r| r.file.clone())
    }

    /// `file` の `center_line` を中心とした前後計10行のソースを表示する
    /// (GDB の `list` のデフォルト表示幅に合わせる)。
    fn show_source_window(&self, file: &Path, center_line: u32) {
        const WINDOW: u32 = 10;
        let center_line = center_line.max(1);
        let start = center_line.saturating_sub(WINDOW / 2 - 1).max(1);
        let end = start + WINDOW - 1;
        let Ok(content) = fs::read_to_string(file) else {
            println!("{}", t!("dbg.source_open_failed", path = file.display()));
            return;
        };
        println!("{}:", file.display());
        let mut any = false;
        for (i, text) in content.lines().enumerate() {
            let n = (i + 1) as u32;
            if n < start {
                continue;
            }
            if n > end {
                break;
            }
            println!("{:>4}\t{}", n, text);
            any = true;
        }
        if !any {
            println!("{}", t!("dbg.no_source_in_range"));
        }
    }
}
