use anyhow::{Context, Result};
use nix::sys::ptrace;
use nix::unistd::Pid;
use std::ffi::c_void;

const INT3: u8 = 0xCC;

/// 1つのソフトウェアブレークポイント(int3)を表す。
pub struct Breakpoint {
    pub addr: u64,
    pub enabled: bool,
    orig_byte: u8,
}

impl Breakpoint {
    pub fn new(addr: u64) -> Self {
        Breakpoint {
            addr,
            enabled: false,
            orig_byte: 0,
        }
    }

    pub fn enable(&mut self, pid: Pid) -> Result<()> {
        if self.enabled {
            return Ok(());
        }
        let word = ptrace::read(pid, self.addr as *mut c_void)
            .context("failed to read memory for breakpoint")?;
        self.orig_byte = (word & 0xff) as u8;
        let patched = (word & !0xff) | INT3 as i64;
        ptrace::write(pid, self.addr as *mut c_void, patched)
            .context("failed to write breakpoint byte")?;
        self.enabled = true;
        Ok(())
    }

    /// パッチ前の元バイトを返す。逆アセンブル表示など、実際に実行される
    /// 命令列を見せたい場面で `0xCC` の代わりに使う。
    pub fn orig_byte(&self) -> u8 {
        self.orig_byte
    }

    pub fn disable(&mut self, pid: Pid) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let word = ptrace::read(pid, self.addr as *mut c_void)
            .context("failed to read memory to restore breakpoint")?;
        let restored = (word & !0xff) | self.orig_byte as i64;
        ptrace::write(pid, self.addr as *mut c_void, restored)
            .context("failed to restore original byte")?;
        self.enabled = false;
        Ok(())
    }
}
