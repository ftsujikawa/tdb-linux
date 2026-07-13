use anyhow::Result;
use nix::sys::ptrace;
use nix::sys::ptrace::regset::NT_PRFPREG;
use nix::unistd::Pid;
use std::ffi::c_void;
use std::mem::offset_of;

pub type Regs = libc::user_regs_struct;
pub type FpRegs = libc::user_fpregs_struct;

/// `struct user` (`PTRACE_PEEKUSER`/`PTRACE_POKEUSER` が参照する領域) 内の
/// `u_debugreg` (DR0-DR7) フィールドのバイトオフセット。ウォッチポイント
/// (`watch` コマンド) の実装に使う。
const DEBUGREG_OFFSET: usize = offset_of!(libc::user, u_debugreg);

/// デバッグレジスタ DR`i` (0-7) を読む (`PTRACE_PEEKUSER` 相当)。
/// DR0-DR3 はウォッチポイントのアドレス、DR6 はステータス、DR7 は制御用。
pub fn read_dr(pid: Pid, i: usize) -> Result<u64> {
    let offset = (DEBUGREG_OFFSET + i * 8) as *mut c_void;
    Ok(ptrace::read_user(pid, offset)? as u64)
}

/// デバッグレジスタ DR`i` (0-7) に書き込む (`PTRACE_POKEUSER` 相当)。
pub fn write_dr(pid: Pid, i: usize, val: u64) -> Result<()> {
    let offset = (DEBUGREG_OFFSET + i * 8) as *mut c_void;
    ptrace::write_user(pid, offset, val as i64)?;
    Ok(())
}

pub fn get_regs(pid: Pid) -> Result<Regs> {
    Ok(ptrace::getregs(pid)?)
}

/// x87 (st0-st7) / SSE (xmm0-xmm15) レジスタを取得する
/// (`PTRACE_GETFPREGS` 相当、`user_fpregs_struct`)。
pub fn get_fpregs(pid: Pid) -> Result<FpRegs> {
    Ok(ptrace::getregset::<NT_PRFPREG>(pid)?)
}

pub fn set_regs(pid: Pid, regs: &Regs) -> Result<()> {
    ptrace::setregs(pid, *regs)?;
    Ok(())
}

pub fn set_fpregs(pid: Pid, fpregs: &FpRegs) -> Result<()> {
    ptrace::setregset::<NT_PRFPREG>(pid, *fpregs)?;
    Ok(())
}

/// レジスタ名 "st0"-"st7" をインデックス (0-7) として解析する。
pub fn parse_st_name(name: &str) -> Option<usize> {
    let n: usize = name.strip_prefix("st")?.parse().ok()?;
    (n < 8).then_some(n)
}

/// レジスタ名 "xmm0"-"xmm15" をインデックス (0-15) として解析する。
pub fn parse_xmm_name(name: &str) -> Option<usize> {
    let n: usize = name.strip_prefix("xmm")?.parse().ok()?;
    (n < 16).then_some(n)
}

/// 汎用レジスタ名 -> 値の取得。GDBに合わせた名称を採用。
pub fn get_by_name(regs: &Regs, name: &str) -> Option<u64> {
    Some(match name {
        "rax" => regs.rax,
        "rbx" => regs.rbx,
        "rcx" => regs.rcx,
        "rdx" => regs.rdx,
        "rsi" => regs.rsi,
        "rdi" => regs.rdi,
        "rbp" => regs.rbp,
        "rsp" => regs.rsp,
        "r8" => regs.r8,
        "r9" => regs.r9,
        "r10" => regs.r10,
        "r11" => regs.r11,
        "r12" => regs.r12,
        "r13" => regs.r13,
        "r14" => regs.r14,
        "r15" => regs.r15,
        "rip" | "pc" => regs.rip,
        "eflags" => regs.eflags,
        "cs" => regs.cs,
        "ss" => regs.ss,
        "ds" => regs.ds,
        "es" => regs.es,
        "fs" => regs.fs,
        "gs" => regs.gs,
        "orig_rax" => regs.orig_rax,
        "fs_base" => regs.fs_base,
        "gs_base" => regs.gs_base,
        _ => return None,
    })
}

pub fn set_by_name(regs: &mut Regs, name: &str, val: u64) -> bool {
    match name {
        "rax" => regs.rax = val,
        "rbx" => regs.rbx = val,
        "rcx" => regs.rcx = val,
        "rdx" => regs.rdx = val,
        "rsi" => regs.rsi = val,
        "rdi" => regs.rdi = val,
        "rbp" => regs.rbp = val,
        "rsp" => regs.rsp = val,
        "r8" => regs.r8 = val,
        "r9" => regs.r9 = val,
        "r10" => regs.r10 = val,
        "r11" => regs.r11 = val,
        "r12" => regs.r12 = val,
        "r13" => regs.r13 = val,
        "r14" => regs.r14 = val,
        "r15" => regs.r15 = val,
        "rip" | "pc" => regs.rip = val,
        "eflags" => regs.eflags = val,
        "cs" => regs.cs = val,
        "ss" => regs.ss = val,
        "ds" => regs.ds = val,
        "es" => regs.es = val,
        "fs" => regs.fs = val,
        "gs" => regs.gs = val,
        "orig_rax" => regs.orig_rax = val,
        "fs_base" => regs.fs_base = val,
        "gs_base" => regs.gs_base = val,
        _ => return false,
    }
    true
}

pub fn dump(regs: &Regs) -> String {
    format!(
        "rax {:#018x}  rbx {:#018x}  rcx {:#018x}  rdx {:#018x}\n\
         rsi {:#018x}  rdi {:#018x}  rbp {:#018x}  rsp {:#018x}\n\
         r8  {:#018x}  r9  {:#018x}  r10 {:#018x}  r11 {:#018x}\n\
         r12 {:#018x}  r13 {:#018x}  r14 {:#018x}  r15 {:#018x}\n\
         rip {:#018x}  eflags {:#010x}  orig_rax {:#018x}\n\
         cs {:#06x}  ss {:#06x}  ds {:#06x}  es {:#06x}  fs {:#06x}  gs {:#06x}\n\
         fs_base {:#018x}  gs_base {:#018x}",
        regs.rax,
        regs.rbx,
        regs.rcx,
        regs.rdx,
        regs.rsi,
        regs.rdi,
        regs.rbp,
        regs.rsp,
        regs.r8,
        regs.r9,
        regs.r10,
        regs.r11,
        regs.r12,
        regs.r13,
        regs.r14,
        regs.r15,
        regs.rip,
        regs.eflags,
        regs.orig_rax,
        regs.cs,
        regs.ss,
        regs.ds,
        regs.es,
        regs.fs,
        regs.gs,
        regs.fs_base,
        regs.gs_base,
    )
}

/// `st_space`(x87/MMX、`u32` 4個 = 16バイトごとに1レジスタ、実データは先頭
/// 10バイトの80bit拡張精度浮動小数点数)から `st_space` 上でのインデックス
/// `i` (0-7) のレジスタの生バイト列(メモリ上の並び順、10バイト)を取り出す。
fn st_bytes(fpregs: &FpRegs, i: usize) -> [u8; 10] {
    let words = &fpregs.st_space[i * 4..i * 4 + 4];
    let mut bytes = [0u8; 16];
    for (w, chunk) in words.iter().zip(bytes.chunks_exact_mut(4)) {
        chunk.copy_from_slice(&w.to_ne_bytes());
    }
    bytes[..10].try_into().unwrap()
}

/// インデックス `i` (0-7) の st レジスタの下位64bit(仮数部)を整数として
/// 取り出す(`print $stN` 用の簡易表示。80bit拡張精度としての小数値は
/// `info registers` の `value=` を参照)。
pub fn st_low64(fpregs: &FpRegs, i: usize) -> u64 {
    let bytes = st_bytes(fpregs, i);
    u64::from_le_bytes(bytes[0..8].try_into().unwrap())
}

/// `st_bytes` の逆: インデックス `i` (0-7) の st レジスタへ10バイトの生値を
/// 書き込む(上位6バイトは常に0にする)。
pub fn set_st_bytes(fpregs: &mut FpRegs, i: usize, bytes: &[u8; 10]) {
    let mut full = [0u8; 16];
    full[..10].copy_from_slice(bytes);
    for (w, chunk) in fpregs.st_space[i * 4..i * 4 + 4].iter_mut().zip(full.chunks_exact(4)) {
        *w = u32::from_ne_bytes(chunk.try_into().unwrap());
    }
}

/// `f64` を x87 80bit拡張精度浮動小数点数のバイト列に変換する
/// (`decode_x87_extended` の逆変換。表示側と対をなす簡易実装で、非正規化数・
/// NaN・無限大等の細かい扱いはしない)。
pub fn encode_x87_extended(value: f64) -> [u8; 10] {
    if value == 0.0 {
        return [0u8; 10];
    }
    let sign: u16 = if value.is_sign_negative() { 1 } else { 0 };
    let abs = value.abs();
    let exponent = abs.log2().floor() as i32;
    // 仮数の bit63 を明示的な整数部ビットとして持たせる(暗黙の1ビットではない)。
    let mantissa = (abs / 2f64.powi(exponent - 63)).round() as u64;
    let se: u16 = (sign << 15) | ((exponent + 16383) as u16 & 0x7fff);
    let mut bytes = [0u8; 10];
    bytes[0..8].copy_from_slice(&mantissa.to_le_bytes());
    bytes[8..10].copy_from_slice(&se.to_le_bytes());
    bytes
}

/// x87 の80bit拡張精度浮動小数点数(仮数64bit・符号1bit+指数15bit)を
/// `f64` へ変換する(表示用の簡易変換。非正規化数・NaN・無限大の細かい
/// 扱いはせず、通常の有限値をおおまかに再現できれば十分とする)。
fn decode_x87_extended(bytes: &[u8; 10]) -> f64 {
    let mantissa = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let sign_exp = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    let sign = (sign_exp >> 15) & 1;
    let exponent = (sign_exp & 0x7fff) as i32;
    if exponent == 0 && mantissa == 0 {
        return if sign == 1 { -0.0 } else { 0.0 };
    }
    // 仮数の bit63 が明示的な整数部ビット(暗黙の1ビットではない)。
    let value = (mantissa as f64) * 2f64.powi(exponent - 16383 - 63);
    if sign == 1 { -value } else { value }
}

/// `xmm_space` から `u32` 4個(16バイト)分の xmm レジスタ `i` (0-15) の
/// 生バイト列(メモリ上の並び順)を取り出す。
fn xmm_bytes(fpregs: &FpRegs, i: usize) -> [u8; 16] {
    let words = &fpregs.xmm_space[i * 4..i * 4 + 4];
    let mut bytes = [0u8; 16];
    for (w, chunk) in words.iter().zip(bytes.chunks_exact_mut(4)) {
        chunk.copy_from_slice(&w.to_ne_bytes());
    }
    bytes
}

/// インデックス `i` (0-15) の xmm レジスタの下位64bitを整数として取り出す
/// (`print $xmmN` 用。`set $xmmN=` で書き込む対象と対応する)。
pub fn xmm_low64(fpregs: &FpRegs, i: usize) -> u64 {
    let bytes = xmm_bytes(fpregs, i);
    u64::from_le_bytes(bytes[0..8].try_into().unwrap())
}

/// インデックス `i` (0-15) の xmm レジスタの下位64bitへ `val` を書き込み、
/// 上位64bitは0にする(`movq xmm, r64` と同じzero-extend。128bit全体への
/// 単一の意味付けが用途により変わるため、GP レジスタと同じ感覚で
/// `set $xmmN=<式>` できるよう下位64bitを「その」値として扱う)。
pub fn set_xmm_low64(fpregs: &mut FpRegs, i: usize, val: u64) {
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&val.to_le_bytes());
    for (w, chunk) in fpregs.xmm_space[i * 4..i * 4 + 4].iter_mut().zip(bytes.chunks_exact(4)) {
        *w = u32::from_ne_bytes(chunk.try_into().unwrap());
    }
}

/// st0-st7 / xmm0-xmm15 を表示用にフォーマットする (`info registers` から
/// 呼ぶ)。st レジスタは10バイトの生値と、80bit拡張精度からの近似 `f64` 値を
/// 両方示す。xmm レジスタは128bit全体を単一の値として解釈する意味がないため
/// (整数・単精度×4・倍精度×2 等、用途により解釈が変わる)、上位/下位64bitの
/// 生の16進値として示す。
pub fn dump_fpregs(fpregs: &FpRegs) -> String {
    let mut lines = Vec::with_capacity(24);
    for i in 0..8 {
        let bytes = st_bytes(fpregs, i);
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let value = decode_x87_extended(&bytes);
        lines.push(format!("st{:<2} raw=0x{}  value={}", i, hex, value));
    }
    for i in 0..16 {
        let bytes = xmm_bytes(fpregs, i);
        let lo = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let hi = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        lines.push(format!("xmm{:<2} 0x{:016x}{:016x}", i, hi, lo));
    }
    lines.push(format!("mxcsr {:#010x}", fpregs.mxcsr));
    lines.join("\n")
}
