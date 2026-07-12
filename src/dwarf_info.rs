use anyhow::{Context, Result};
use gimli::Reader as _;
use gimli::{EndianSlice, RunTimeEndian};
use goblin::elf::Elf;
use std::fs;
use std::path::{Path, PathBuf};

type Reader<'a> = EndianSlice<'a, RunTimeEndian>;

#[derive(Debug, Clone)]
pub struct LineRow {
    pub addr: u64,
    pub file: PathBuf,
    pub line: u32,
    pub is_stmt: bool,
    pub end_sequence: bool,
}

/// 構造体/共用体の1メンバ分の情報。
#[derive(Debug, Clone)]
pub struct MemberInfo {
    pub name: String,
    /// 構造体先頭からのバイトオフセット。
    pub offset: u64,
    pub ty: TypeInfo,
}

/// 変数/メンバの型情報。`->` によるメンバアクセスの連鎖や `[i]` による
/// 添字アクセスを辿れるように、ポインタは指し示す先の型を、構造体は
/// メンバ一覧を、配列は要素の型と要素数を保持する。
#[derive(Debug, Clone)]
pub enum TypeInfo {
    Base { byte_size: u64, encoding: u8, name: String },
    Pointer { pointee: Box<TypeInfo> },
    Struct { name: Option<String>, is_union: bool, byte_size: u64, members: Vec<MemberInfo> },
    /// `count` は要素数(不明な場合は `None`。フレキシブル配列メンバ等)。
    Array { element: Box<TypeInfo>, count: Option<u64> },
    /// 解決できなかった型(未対応の DIE 形式等)。符号なし8バイトとして扱う。
    Unknown,
}

impl TypeInfo {
    /// `print` の表示形式(16進+10進 or 10進のみ)の判定に使う。
    fn is_pointer(&self) -> bool {
        matches!(self, TypeInfo::Pointer { .. })
    }

    /// この型の値1つ分のバイトサイズ。配列の要素アドレス計算(添字の
    /// ストライド)に使う。
    pub fn byte_size(&self) -> u64 {
        match self {
            TypeInfo::Base { byte_size, .. } => *byte_size,
            TypeInfo::Pointer { .. } => 8,
            TypeInfo::Struct { byte_size, .. } => *byte_size,
            TypeInfo::Array { element, count } => element.byte_size() * count.unwrap_or(0),
            TypeInfo::Unknown => 8,
        }
    }

    /// `set print pretty on` での型情報表示に使う、人間向けの型名
    /// (`int`, `struct Point`, `struct Point *`, `int[3]` 等)。
    pub fn type_name(&self) -> String {
        match self {
            TypeInfo::Base { name, .. } => name.clone(),
            TypeInfo::Pointer { pointee } => {
                let inner = pointee.type_name();
                if inner.ends_with('*') {
                    format!("{}*", inner)
                } else {
                    format!("{} *", inner)
                }
            }
            TypeInfo::Struct { name, is_union, .. } => {
                let keyword = if *is_union { "union" } else { "struct" };
                match name {
                    Some(n) => format!("{} {}", keyword, n),
                    None => keyword.to_string(),
                }
            }
            TypeInfo::Array { element, count } => match count {
                Some(n) => format!("{}[{}]", element.type_name(), n),
                None => format!("{}[]", element.type_name()),
            },
            TypeInfo::Unknown => "?".to_string(),
        }
    }
}

/// ローカル変数/仮引数1つ分の情報。
#[derive(Debug, Clone)]
pub struct VarInfo {
    pub name: String,
    /// `DW_AT_location` の生バイト列 (DWARF 式)。
    pub location: Vec<u8>,
    /// `print` の表示形式(16進+10進 or 10進のみ)の判定に使う。
    pub is_pointer: bool,
    /// 型情報。スカラー値の読み書きにも `->` による構造体メンバアクセスにも
    /// これを使う。
    pub ty: TypeInfo,
    /// `DW_TAG_formal_parameter` (仮引数) なら true、`DW_TAG_variable`
    /// (ローカル変数) なら false。`show locals`/`show args` の絞り込みに使う。
    pub is_param: bool,
}

/// 1つの関数 (`DW_TAG_subprogram`) の情報。
pub struct SubprogramInfo {
    /// link-time アドレスでのアドレス範囲。
    pub low_pc: u64,
    pub high_pc: u64,
    /// `DW_AT_frame_base` の生バイト列 (DWARF 式)。無い場合は空。
    pub frame_base: Vec<u8>,
    pub variables: Vec<VarInfo>,
}

/// ELF から読み取った DWARF 情報。行番号テーブル(ソース行表示・プロローグ
/// 判定用)と、関数ごとのローカル変数/仮引数情報(`print`/`set` での変数
/// 参照用)、グローバル変数一覧(`show globals` 用)を保持する。
pub struct DwarfInfo {
    /// アドレス昇順にソートされた行テーブル。end_sequence 行も含む。
    rows: Vec<LineRow>,
    subprograms: Vec<SubprogramInfo>,
    /// コンパイル単位直下 (関数の外) にある変数。`show globals` で使う。
    globals: Vec<VarInfo>,
}

impl DwarfInfo {
    pub fn load(path: &Path) -> Result<DwarfInfo> {
        let buf = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        let elf = Elf::parse(&buf).context("failed to parse ELF")?;

        let endian = if elf.little_endian {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };

        let section_data = |name: &str| -> &[u8] {
            for sh in &elf.section_headers {
                if let Some(sh_name) = elf.shdr_strtab.get_at(sh.sh_name) {
                    if sh_name == name {
                        let start = sh.sh_offset as usize;
                        let end = start + sh.sh_size as usize;
                        if end <= buf.len() {
                            return &buf[start..end];
                        }
                    }
                }
            }
            &[]
        };

        let load_section = |name: &str| -> Reader<'_> { EndianSlice::new(section_data(name), endian) };

        let dwarf = gimli::Dwarf::load(|id| -> Result<Reader<'_>, gimli::Error> {
            Ok(load_section(id.name()))
        })?;

        let mut rows = Vec::new();
        let mut subprograms = Vec::new();
        let mut globals = Vec::new();
        let mut units = dwarf.units();
        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;
            let comp_dir = unit
                .comp_dir
                .as_ref()
                .and_then(|s| s.to_string().ok().map(|s| s.to_string()));
            if let Some(program) = unit.line_program.clone() {
                let mut rows_iter = program.rows();
                while let Some((header, row)) = rows_iter.next_row()? {
                    let file_path = row
                        .file(header)
                        .map(|f| resolve_file_path(&dwarf, &unit, header, f, comp_dir.as_deref()))
                        .unwrap_or_default();
                    rows.push(LineRow {
                        addr: row.address(),
                        file: file_path,
                        line: row.line().map(|l| l.get() as u32).unwrap_or(0),
                        is_stmt: row.is_stmt(),
                        end_sequence: row.end_sequence(),
                    });
                }
            }

            let mut tree = unit.entries_tree(None)?;
            let root = tree.root()?;
            walk_for_subprograms(&dwarf, &unit, root, &mut subprograms, &mut globals)?;
        }
        rows.sort_by_key(|r| r.addr);

        Ok(DwarfInfo { rows, subprograms, globals })
    }

    /// addr(link-time アドレス)を含む行情報を返す。
    pub fn lookup(&self, addr: u64) -> Option<&LineRow> {
        let idx = match self.rows.binary_search_by_key(&addr, |r| r.addr) {
            Ok(i) => {
                // 同一アドレスの行が複数ある場合、end_sequence でない最後の行を探す。
                let mut i = i;
                while i + 1 < self.rows.len() && self.rows[i + 1].addr == addr {
                    i += 1;
                }
                i
            }
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let row = &self.rows[idx];
        if row.end_sequence {
            None
        } else {
            Some(row)
        }
    }

    /// [low_pc, high_pc) 内の関数について、プロローグ終了直後と思われる
    /// アドレスを返す。関数開始アドレスの行から、行番号が変化する
    /// (または end_sequence に達する)最初の行のアドレスを採用する
    /// (GDB の skip-prologue ヒューリスティックと同様)。
    pub fn skip_prologue(&self, low_pc: u64, high_pc: u64) -> Option<u64> {
        let start_idx = match self.rows.binary_search_by_key(&low_pc, |r| r.addr) {
            Ok(i) => i,
            Err(i) => i,
        };
        if start_idx >= self.rows.len() || self.rows[start_idx].addr != low_pc {
            return None;
        }
        let first_line = self.rows[start_idx].line;
        for row in &self.rows[start_idx + 1..] {
            if row.addr >= high_pc || row.end_sequence {
                break;
            }
            if row.is_stmt && row.line != first_line {
                return Some(row.addr);
            }
        }
        None
    }

    /// pc (link-time アドレス)を含む関数の中から、名前が一致するローカル
    /// 変数/仮引数を探す。
    pub fn find_variable(&self, pc: u64, name: &str) -> Option<(&SubprogramInfo, &VarInfo)> {
        for sub in &self.subprograms {
            if pc >= sub.low_pc && pc < sub.high_pc {
                if let Some(v) = sub.variables.iter().find(|v| v.name == name) {
                    return Some((sub, v));
                }
            }
        }
        None
    }

    /// pc (link-time アドレス)を含む関数を探す。`show locals`/`show args`
    /// で現在のスコープの変数一覧を得るのに使う。
    pub fn find_subprogram(&self, pc: u64) -> Option<&SubprogramInfo> {
        self.subprograms.iter().find(|sub| pc >= sub.low_pc && pc < sub.high_pc)
    }

    /// コンパイル単位直下(関数の外)にあるグローバル変数の一覧。
    pub fn globals(&self) -> &[VarInfo] {
        &self.globals
    }

    /// `.debug_line` の行テーブル(アドレス昇順、`end_sequence` 行も含む)。
    /// `lines` コマンドで使う。
    pub fn lines(&self) -> &[LineRow] {
        &self.rows
    }
}

/// SLEB128 (符号付き可変長整数) をデコードする。DWARF 式のオペランド解析に使う。
pub fn read_sleb128(bytes: &[u8]) -> Option<i64> {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    let mut terminated = false;
    let mut last_byte = 0u8;
    for &b in bytes {
        last_byte = b;
        result |= ((b & 0x7f) as i64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            terminated = true;
            break;
        }
        if shift >= 64 {
            return None;
        }
    }
    if !terminated {
        return None;
    }
    if shift < 64 && (last_byte & 0x40) != 0 {
        result |= (-1i64).wrapping_shl(shift);
    }
    Some(result)
}

/// DIE ツリーを辿り、`DW_TAG_subprogram` を見つけるたびにアドレス範囲・
/// frame_base・(入れ子の lexical_block を含む)ローカル変数/仮引数を収集する。
/// 関数の外(コンパイル単位直下等)にある `DW_TAG_variable` はグローバル
/// 変数として `globals` に集める。
fn walk_for_subprograms<'a>(
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    node: gimli::EntriesTreeNode<Reader<'a>>,
    out: &mut Vec<SubprogramInfo>,
    globals: &mut Vec<VarInfo>,
) -> Result<()> {
    let tag = node.entry().tag();
    if tag == gimli::DW_TAG_subprogram {
        if let Some((low_pc, high_pc, frame_base)) = subprogram_shell(node.entry()) {
            let mut variables = Vec::new();
            let mut children = node.children();
            while let Some(child) = children.next()? {
                collect_vars(dwarf, unit, child, &mut variables, out, globals)?;
            }
            out.push(SubprogramInfo { low_pc, high_pc, frame_base, variables });
            return Ok(());
        }
    }
    if tag == gimli::DW_TAG_variable {
        if let Some(v) = build_var(dwarf, unit, node.entry(), false) {
            globals.push(v);
        }
        return Ok(());
    }
    let mut children = node.children();
    while let Some(child) = children.next()? {
        walk_for_subprograms(dwarf, unit, child, out, globals)?;
    }
    Ok(())
}

/// 関数の直下(および入れ子の lexical_block の中)にある変数/仮引数を集める。
/// 入れ子の関数定義に出会った場合は、外側の変数としては扱わず独立した
/// トップレベルの関数として登録する。
fn collect_vars<'a>(
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    node: gimli::EntriesTreeNode<Reader<'a>>,
    vars: &mut Vec<VarInfo>,
    subprograms: &mut Vec<SubprogramInfo>,
    globals: &mut Vec<VarInfo>,
) -> Result<()> {
    match node.entry().tag() {
        gimli::DW_TAG_variable => {
            if let Some(v) = build_var(dwarf, unit, node.entry(), false) {
                vars.push(v);
            }
        }
        gimli::DW_TAG_formal_parameter => {
            if let Some(v) = build_var(dwarf, unit, node.entry(), true) {
                vars.push(v);
            }
        }
        gimli::DW_TAG_lexical_block => {
            let mut children = node.children();
            while let Some(child) = children.next()? {
                collect_vars(dwarf, unit, child, vars, subprograms, globals)?;
            }
        }
        gimli::DW_TAG_subprogram => {
            walk_for_subprograms(dwarf, unit, node, subprograms, globals)?;
        }
        _ => {
            // その他のタグ (型情報等) の子は見ない (このツールの用途では
            // 変数はここまでの範囲にしか現れない前提の単純化)。
        }
    }
    Ok(())
}

fn subprogram_shell<R: gimli::Reader>(
    entry: &gimli::DebuggingInformationEntry<R>,
) -> Option<(u64, u64, Vec<u8>)> {
    let low_pc = match entry.attr_value(gimli::DW_AT_low_pc)? {
        gimli::AttributeValue::Addr(a) => a,
        _ => return None,
    };
    let high_pc = match entry.attr_value(gimli::DW_AT_high_pc)? {
        gimli::AttributeValue::Addr(a) => a,
        other => low_pc.wrapping_add(other.udata_value()?),
    };
    let frame_base = match entry.attr_value(gimli::DW_AT_frame_base) {
        Some(gimli::AttributeValue::Exprloc(expr)) => expr.0.to_slice().ok()?.into_owned(),
        _ => Vec::new(),
    };
    Some((low_pc, high_pc, frame_base))
}

/// DIE の `DW_AT_name` を解決する。
fn die_name<'a>(
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    entry: &gimli::DebuggingInformationEntry<Reader<'a>>,
) -> Option<String> {
    let av = entry.attr_value(gimli::DW_AT_name)?;
    dwarf.attr_string(unit, av).ok()?.to_string().ok().map(|s| s.to_string())
}

fn build_var<'a>(
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    entry: &gimli::DebuggingInformationEntry<Reader<'a>>,
    is_param: bool,
) -> Option<VarInfo> {
    let name = die_name(dwarf, unit, &entry)?;
    let location = match entry.attr_value(gimli::DW_AT_location)? {
        gimli::AttributeValue::Exprloc(expr) => expr.0.to_slice().ok()?.into_owned(),
        _ => return None,
    };
    let ty = match entry.attr_value(gimli::DW_AT_type) {
        Some(gimli::AttributeValue::UnitRef(off)) => resolve_full_type(dwarf, unit, off, 0),
        _ => TypeInfo::Unknown,
    };
    let is_pointer = ty.is_pointer();
    Some(VarInfo { name, location, is_pointer, ty, is_param })
}

/// 型解決の再帰の深さの上限。構造体が(ポインタ経由で)自分自身を含む
/// 場合(連結リスト等)、素朴に辿ると無限再帰になるため、これで打ち切る。
/// 通常の `->` の連鎖でこの深さに達することはまず無い。
const MAX_TYPE_DEPTH: u32 = 16;

/// `typedef`/`const`/`volatile`/`restrict` を辿って実体の型に到達し、
/// `TypeInfo` として返す。解決できない型・再帰が深すぎる型は
/// `TypeInfo::Unknown` とする。
fn resolve_full_type<'a>(
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    type_ref: gimli::UnitOffset,
    depth: u32,
) -> TypeInfo {
    if depth > MAX_TYPE_DEPTH {
        return TypeInfo::Unknown;
    }
    let mut offset = type_ref;
    for _ in 0..8 {
        let Ok(entry) = unit.entry(offset) else {
            return TypeInfo::Unknown;
        };
        match entry.tag() {
            gimli::DW_TAG_pointer_type => {
                let pointee = match entry.attr_value(gimli::DW_AT_type) {
                    Some(gimli::AttributeValue::UnitRef(next)) => {
                        resolve_full_type(dwarf, unit, next, depth + 1)
                    }
                    _ => TypeInfo::Unknown,
                };
                return TypeInfo::Pointer { pointee: Box::new(pointee) };
            }
            gimli::DW_TAG_base_type => {
                let byte_size = entry
                    .attr_value(gimli::DW_AT_byte_size)
                    .and_then(|v| v.udata_value())
                    .unwrap_or(4);
                // `DW_AT_encoding` は gimli では専用の `AttributeValue::Encoding(DwAte)`
                // に変換されるため、`udata_value()` では取り出せない。
                let encoding = entry
                    .attr_value(gimli::DW_AT_encoding)
                    .and_then(|v| match v {
                        gimli::AttributeValue::Encoding(e) => Some(e.0),
                        _ => None,
                    })
                    .unwrap_or(0);
                let name = die_name(dwarf, unit, &entry).unwrap_or_else(|| "?".to_string());
                return TypeInfo::Base { byte_size, encoding, name };
            }
            gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type => {
                let name = die_name(dwarf, unit, &entry);
                let is_union = entry.tag() == gimli::DW_TAG_union_type;
                let byte_size =
                    entry.attr_value(gimli::DW_AT_byte_size).and_then(|v| v.udata_value()).unwrap_or(0);
                let members = collect_members(dwarf, unit, offset, depth + 1);
                return TypeInfo::Struct { name, is_union, byte_size, members };
            }
            gimli::DW_TAG_array_type => {
                let element = match entry.attr_value(gimli::DW_AT_type) {
                    Some(gimli::AttributeValue::UnitRef(next)) => {
                        resolve_full_type(dwarf, unit, next, depth + 1)
                    }
                    _ => TypeInfo::Unknown,
                };
                // 多次元配列は `DW_TAG_array_type` 1つに複数の
                // `DW_TAG_subrange_type` (次元ごと) がぶら下がる形で
                // 表現される。外側の次元から順に「配列の配列」として
                // ネストした `TypeInfo::Array` を組み立てる。
                let dims = array_dims(unit, offset);
                let mut ty = element;
                for count in dims.into_iter().rev() {
                    ty = TypeInfo::Array { element: Box::new(ty), count };
                }
                return ty;
            }
            gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type => match entry.attr_value(gimli::DW_AT_type) {
                Some(gimli::AttributeValue::UnitRef(next)) => {
                    offset = next;
                    continue;
                }
                _ => return TypeInfo::Unknown,
            },
            _ => return TypeInfo::Unknown,
        }
    }
    TypeInfo::Unknown
}

/// `array_offset` にある `DW_TAG_array_type` DIE の直下の
/// `DW_TAG_subrange_type` (次元ごとの要素数) を、外側の次元から順に集める。
/// 要素数は `DW_AT_count` を優先し、無ければ `DW_AT_upper_bound + 1` を使う。
/// どちらも無い場合 (不完全配列型等) は `None` とする。
fn array_dims<'a>(unit: &gimli::Unit<Reader<'a>>, array_offset: gimli::UnitOffset) -> Vec<Option<u64>> {
    let mut dims = Vec::new();
    let Ok(mut tree) = unit.entries_tree(Some(array_offset)) else {
        return dims;
    };
    let Ok(root) = tree.root() else {
        return dims;
    };
    let mut children = root.children();
    while let Ok(Some(child)) = children.next() {
        let entry = child.entry();
        if entry.tag() != gimli::DW_TAG_subrange_type {
            continue;
        }
        let count = entry.attr_value(gimli::DW_AT_count).and_then(|v| v.udata_value()).or_else(|| {
            entry.attr_value(gimli::DW_AT_upper_bound).and_then(|v| v.udata_value()).map(|u| u + 1)
        });
        dims.push(count);
    }
    dims
}

/// `struct_offset` にある構造体/共用体 DIE の直下のメンバ (`DW_TAG_member`)
/// を集める。読み取りに失敗した要素は静かに読み飛ばす。
fn collect_members<'a>(
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    struct_offset: gimli::UnitOffset,
    depth: u32,
) -> Vec<MemberInfo> {
    let mut members = Vec::new();
    let Ok(mut tree) = unit.entries_tree(Some(struct_offset)) else {
        return members;
    };
    let Ok(root) = tree.root() else {
        return members;
    };
    let mut children = root.children();
    while let Ok(Some(child)) = children.next() {
        let entry = child.entry();
        if entry.tag() != gimli::DW_TAG_member {
            continue;
        }
        let Some(name) = die_name(dwarf, unit, &entry) else {
            continue;
        };
        let offset = entry
            .attr_value(gimli::DW_AT_data_member_location)
            .and_then(|v| v.udata_value())
            .unwrap_or(0);
        let ty = match entry.attr_value(gimli::DW_AT_type) {
            Some(gimli::AttributeValue::UnitRef(t)) => resolve_full_type(dwarf, unit, t, depth),
            _ => TypeInfo::Unknown,
        };
        members.push(MemberInfo { name, offset, ty });
    }
    members
}

fn resolve_file_path<'a>(
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    header: &gimli::LineProgramHeader<Reader<'a>>,
    file: &gimli::FileEntry<Reader<'a>>,
    comp_dir: Option<&str>,
) -> PathBuf {
    let name = dwarf
        .attr_string(unit, file.path_name())
        .ok()
        .and_then(|s| s.to_string().ok().map(|s| s.to_string()))
        .unwrap_or_default();

    let dir = file
        .directory(header)
        .and_then(|d| dwarf.attr_string(unit, d).ok())
        .and_then(|s| s.to_string().ok().map(|s| s.to_string()));

    let mut path = PathBuf::new();
    if let Some(dir) = &dir {
        let dir_path = Path::new(dir);
        if dir_path.is_relative() {
            if let Some(comp_dir) = comp_dir {
                path.push(comp_dir);
            }
        }
        path.push(dir_path);
    } else if let Some(comp_dir) = comp_dir {
        path.push(comp_dir);
    }
    path.push(name);
    path
}
