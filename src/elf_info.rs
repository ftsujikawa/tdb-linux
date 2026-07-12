use anyhow::{Context, Result};
use goblin::elf::Elf;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub addr: u64,
    pub size: u64,
}

pub struct ElfInfo {
    pub entry: u64,
    /// PIE (ET_DYN) かどうか。真の場合、実行時のロードアドレスにバイアスを
    /// 加算する必要がある。
    pub is_pie: bool,
    /// アドレス昇順にソートされた関数シンボル一覧。
    pub symbols: Vec<Symbol>,
}

impl ElfInfo {
    pub fn load(path: &Path) -> Result<ElfInfo> {
        let buf = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        let elf = Elf::parse(&buf).context("failed to parse ELF")?;

        let mut symbols = Vec::new();
        for sym in elf.syms.iter() {
            if !sym.is_function() || sym.st_value == 0 {
                continue;
            }
            let name = elf
                .strtab
                .get_at(sym.st_name)
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            symbols.push(Symbol {
                name,
                addr: sym.st_value,
                size: sym.st_size,
            });
        }
        // dynsym にしかシンボルが無い動的リンクバイナリにも対応する。
        for sym in elf.dynsyms.iter() {
            if !sym.is_function() || sym.st_value == 0 {
                continue;
            }
            let name = elf
                .dynstrtab
                .get_at(sym.st_name)
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            if symbols.iter().any(|s| s.addr == sym.st_value) {
                continue;
            }
            symbols.push(Symbol {
                name,
                addr: sym.st_value,
                size: sym.st_size,
            });
        }

        symbols.sort_by_key(|s| s.addr);

        Ok(ElfInfo {
            entry: elf.entry,
            is_pie: elf.header.e_type == goblin::elf::header::ET_DYN,
            symbols,
        })
    }

    pub fn find_by_name(&self, name: &str) -> Option<&Symbol> {
        self.symbols.iter().find(|s| s.name == name)
    }

    /// addr を含む(あるいは直前の)関数シンボルを返す。
    /// libc/ld.so 等、このバイナリのシンボルテーブルに存在しないアドレス
    /// (共有ライブラリ内など)に対して無関係なシンボルを誤って返さないよう、
    /// サイズ不明なシンボルについては近傍とみなせる範囲内でのみマッチさせる。
    const UNKNOWN_SIZE_FALLBACK_RANGE: u64 = 0x10000;

    pub fn find_by_addr(&self, addr: u64) -> Option<&Symbol> {
        let mut best: Option<&Symbol> = None;
        for s in &self.symbols {
            if s.addr > addr {
                break;
            }
            if addr < s.addr + s.size {
                best = Some(s);
            } else if s.size == 0 && addr - s.addr < Self::UNKNOWN_SIZE_FALLBACK_RANGE {
                best = Some(s);
            }
        }
        best
    }
}
