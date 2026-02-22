//! AArch64 CPU emulator: register state, decoder, and interpreter.

pub mod reg;
pub mod decoder;
pub mod interpreter;

pub use decoder::{ArmInstr, ArmInstrKind, DecodeError, decode};
pub use interpreter::{ArmExecError, execute};

// ── AArch64 register state ────────────────────────────────────────────────────

/// Full AArch64 CPU state.
#[derive(Debug, Clone, Default)]
pub struct ArmCpuState {
    /// General-purpose registers X0..X30.  Index 31 is never read/written here;
    /// use `sp` for the stack pointer and treat encoding=31 as XZR in helpers.
    pub x: [u64; 31],
    /// Stack pointer (SP / WSP).
    pub sp: u64,
    /// Program counter.
    pub pc: u64,
    /// Process state / condition flags: bits [31:28] = N Z C V.
    pub pstate: u64,
    /// Thread pointer (TPIDR_EL0) — set by MSR tpidr_el0 / read by MRS.
    pub tpidr_el0: u64,
}

impl ArmCpuState {
    /// Read a 64-bit register; encoding 31 = XZR (always 0).
    #[inline(always)]
    pub fn xr(&self, idx: u8) -> u64 {
        if idx == 31 { 0 } else { self.x[idx as usize] }
    }

    /// Write a 64-bit register; encoding 31 = XZR (discard write).
    #[inline(always)]
    pub fn xw(&mut self, idx: u8, val: u64) {
        if idx != 31 { self.x[idx as usize] = val; }
    }

    /// Read as 32-bit (W register); zero-extends from lower 32 bits.
    #[inline(always)]
    pub fn wr(&self, idx: u8) -> u32 {
        self.xr(idx) as u32
    }

    /// Write a 32-bit (W register) — zero-extends to 64 bits.
    #[inline(always)]
    pub fn ww(&mut self, idx: u8, val: u32) {
        self.xw(idx, val as u64);
    }

    // ── NZCV flag helpers ────────────────────────────────────────────────────

    pub fn flag_n(&self) -> bool { (self.pstate >> 31) & 1 == 1 }
    pub fn flag_z(&self) -> bool { (self.pstate >> 30) & 1 == 1 }
    pub fn flag_c(&self) -> bool { (self.pstate >> 29) & 1 == 1 }
    pub fn flag_v(&self) -> bool { (self.pstate >> 28) & 1 == 1 }

    pub fn set_nzcv(&mut self, n: bool, z: bool, c: bool, v: bool) {
        self.pstate = (self.pstate & 0x0FFF_FFFF)
            | ((n as u64) << 31)
            | ((z as u64) << 30)
            | ((c as u64) << 29)
            | ((v as u64) << 28);
    }

    /// Evaluate an A64 condition code (4-bit cond field).
    pub fn check_cond(&self, cond: u8) -> bool {
        match cond & 0xF {
            0x0 => self.flag_z(),                                          // EQ
            0x1 => !self.flag_z(),                                         // NE
            0x2 => self.flag_c(),                                          // CS/HS
            0x3 => !self.flag_c(),                                         // CC/LO
            0x4 => self.flag_n(),                                          // MI
            0x5 => !self.flag_n(),                                         // PL
            0x6 => self.flag_v(),                                          // VS
            0x7 => !self.flag_v(),                                         // VC
            0x8 => self.flag_c() && !self.flag_z(),                        // HI
            0x9 => !self.flag_c() || self.flag_z(),                        // LS
            0xA => self.flag_n() == self.flag_v(),                         // GE
            0xB => self.flag_n() != self.flag_v(),                         // LT
            0xC => !self.flag_z() && self.flag_n() == self.flag_v(),       // GT
            0xD => self.flag_z() || self.flag_n() != self.flag_v(),        // LE
            0xE => true,                                                   // AL
            _   => true,                                                   // NV (treat as AL)
        }
    }
}
