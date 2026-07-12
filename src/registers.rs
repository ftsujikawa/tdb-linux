use anyhow::Result;
use nix::sys::ptrace;
use nix::unistd::Pid;

pub type Regs = libc::user_regs_struct;

pub fn get_regs(pid: Pid) -> Result<Regs> {
    Ok(ptrace::getregs(pid)?)
}

pub fn set_regs(pid: Pid, regs: &Regs) -> Result<()> {
    ptrace::setregs(pid, *regs)?;
    Ok(())
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
         rip {:#018x}  eflags {:#010x}",
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
    )
}
