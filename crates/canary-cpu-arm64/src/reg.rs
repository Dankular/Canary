//! AArch64 GPR indices and register constants.
//!
//! AArch64 has 31 general-purpose 64-bit registers (X0..X30), a dedicated
//! zero register (XZR), a stack pointer (SP), and a program counter (PC).
//! XZR and SP share encoding slot 31 — which one is used depends on the
//! instruction context.

// ── General-purpose register indices (X0..X30) ───────────────────────────────

pub const X0:  usize = 0;
pub const X1:  usize = 1;
pub const X2:  usize = 2;
pub const X3:  usize = 3;
pub const X4:  usize = 4;
pub const X5:  usize = 5;
pub const X6:  usize = 6;
pub const X7:  usize = 7;
pub const X8:  usize = 8;   // indirect syscall number / IP0 scratch
pub const X9:  usize = 9;
pub const X10: usize = 10;
pub const X11: usize = 11;
pub const X12: usize = 12;
pub const X13: usize = 13;
pub const X14: usize = 14;
pub const X15: usize = 15;
pub const X16: usize = 16;  // IP0 (intra-procedure-call scratch)
pub const X17: usize = 17;  // IP1
pub const X18: usize = 18;  // platform register
pub const X19: usize = 19;
pub const X20: usize = 20;
pub const X21: usize = 21;
pub const X22: usize = 22;
pub const X23: usize = 23;
pub const X24: usize = 24;
pub const X25: usize = 25;
pub const X26: usize = 26;
pub const X27: usize = 27;
pub const X28: usize = 28;
pub const X29: usize = 29;  // FP (frame pointer)
pub const X30: usize = 30;  // LR (link register)

/// Stack pointer index in ArmCpuState::sp (stored separately from x[]).
pub const SP_IDX: usize = 31;

/// Zero register — encoding 31 in most instructions reads as 0, writes discarded.
pub const XZR: usize = 31;

/// Register name table for debugging.
pub const NAMES: [&str; 32] = [
    "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
    "x8",  "x9",  "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "x30", "xzr/sp",
];
