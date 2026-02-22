//! x86-64 register file.
//!
//! General-purpose register indices follow the ModRM/REX encoding order:
//!   0=RAX  1=RCX  2=RDX  3=RBX  4=RSP  5=RBP  6=RSI  7=RDI
//!   8=R8   9=R9  10=R10 11=R11 12=R12 13=R13 14=R14 15=R15

use crate::flags::RFLAGS_INIT;

// ── Register indices ──────────────────────────────────────────────────────────

#[allow(dead_code)]
pub mod reg {
    pub const RAX: usize = 0;
    pub const RCX: usize = 1;
    pub const RDX: usize = 2;
    pub const RBX: usize = 3;
    pub const RSP: usize = 4;
    pub const RBP: usize = 5;
    pub const RSI: usize = 6;
    pub const RDI: usize = 7;
    pub const R8:  usize = 8;
    pub const R9:  usize = 9;
    pub const R10: usize = 10;
    pub const R11: usize = 11;
    pub const R12: usize = 12;
    pub const R13: usize = 13;
    pub const R14: usize = 14;
    pub const R15: usize = 15;

    pub const NAMES: [&str; 16] = [
        "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
        "r8","r9","r10","r11","r12","r13","r14","r15",
    ];
}

// ── Segment register indices ──────────────────────────────────────────────────

pub mod sreg {
    pub const ES: usize = 0;
    pub const CS: usize = 1;
    pub const SS: usize = 2;
    pub const DS: usize = 3;
    pub const FS: usize = 4;
    pub const GS: usize = 5;
}

// ── XMM register (128-bit, SSE2 minimum in x86-64) ───────────────────────────

#[derive(Debug, Clone, Copy, Default)]
pub struct Xmm(pub [u8; 16]);

impl Xmm {
    pub fn as_u64x2(&self) -> [u64; 2] {
        [
            u64::from_le_bytes(self.0[0..8].try_into().unwrap()),
            u64::from_le_bytes(self.0[8..16].try_into().unwrap()),
        ]
    }
    pub fn as_f64x2(&self) -> [f64; 2] {
        let u = self.as_u64x2();
        [f64::from_bits(u[0]), f64::from_bits(u[1])]
    }
    pub fn from_u64(lo: u64) -> Self {
        let mut b = [0u8; 16];
        b[0..8].copy_from_slice(&lo.to_le_bytes());
        Self(b)
    }
}

// ── CPU state ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CpuState {
    /// General-purpose registers (64-bit), indexed by `reg::*` constants.
    pub gpr:    [u64; 16],
    /// Instruction pointer.
    pub rip:    u64,
    /// Flags register.
    pub rflags: u64,
    /// Segment registers (hidden base is in fs_base/gs_base).
    pub sregs:  [u16; 6],
    /// FS.base — used for thread-local storage in x86-64 ABI.
    pub fs_base: u64,
    /// GS.base — used by the kernel for per-CPU data (not modelled here).
    pub gs_base: u64,
    /// XMM registers (SSE2, mandatory in x86-64).
    pub xmm:    [Xmm; 16],
    /// x87 FPU top-of-stack pointer (0–7).
    pub fpu_top: u8,
    /// x87 FPU register stack.
    pub fpu_st:  [f64; 8],
    /// MXCSR (SSE control/status register).
    pub mxcsr:  u32,
}

impl Default for CpuState {
    fn default() -> Self {
        CpuState {
            gpr:    [0u64; 16],
            rip:    0,
            rflags: RFLAGS_INIT,
            sregs:  [0u16; 6],
            fs_base: 0,
            gs_base: 0,
            xmm:    [Xmm::default(); 16],
            fpu_top: 0,
            fpu_st:  [0f64; 8],
            mxcsr:   0x1f80, // default: all exceptions masked, round-to-nearest
        }
    }
}

impl CpuState {
    // ── GPR accessors by width ────────────────────────────────────────────

    pub fn read64(&self, idx: usize)  -> u64 { self.gpr[idx] }
    pub fn read32(&self, idx: usize)  -> u32 { self.gpr[idx] as u32 }
    pub fn read16(&self, idx: usize)  -> u16 { self.gpr[idx] as u16 }
    /// Read low or high byte; idx 4..=7 with no REX selects AH/CH/DH/BH.
    pub fn read8(&self, idx: usize, high: bool) -> u8 {
        if high { (self.gpr[idx & 3] >> 8) as u8 } else { self.gpr[idx] as u8 }
    }

    /// Write 64-bit (full register).
    pub fn write64(&mut self, idx: usize, val: u64) { self.gpr[idx] = val; }
    /// Write 32-bit: zero-extends to 64-bit (x86-64 rule).
    pub fn write32(&mut self, idx: usize, val: u32) { self.gpr[idx] = val as u64; }
    /// Write 16-bit: leaves upper 48 bits unchanged.
    pub fn write16(&mut self, idx: usize, val: u16) {
        self.gpr[idx] = (self.gpr[idx] & !0xffff) | val as u64;
    }
    /// Write 8-bit low or high byte.
    pub fn write8(&mut self, idx: usize, val: u8, high: bool) {
        if high {
            self.gpr[idx & 3] = (self.gpr[idx & 3] & !0xff00) | ((val as u64) << 8);
        } else {
            self.gpr[idx] = (self.gpr[idx] & !0xff) | val as u64;
        }
    }

    // ── Stack helpers ─────────────────────────────────────────────────────

    pub fn rsp(&self) -> u64 { self.gpr[reg::RSP] }
    pub fn set_rsp(&mut self, v: u64) { self.gpr[reg::RSP] = v; }

    pub fn push_rsp(&mut self) -> u64 {
        self.gpr[reg::RSP] = self.gpr[reg::RSP].wrapping_sub(8);
        self.gpr[reg::RSP]
    }
    pub fn pop_rsp(&mut self) -> u64 {
        let addr = self.gpr[reg::RSP];
        self.gpr[reg::RSP] = self.gpr[reg::RSP].wrapping_add(8);
        addr
    }

    // ── Flag accessors ────────────────────────────────────────────────────

    pub fn flag(&self, bit: u64) -> bool { self.rflags & bit != 0 }
    pub fn set_flag(&mut self, bit: u64, v: bool) {
        if v { self.rflags |= bit; } else { self.rflags &= !bit; }
    }
}
