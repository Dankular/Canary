//! x86-64 instruction decoder.
//!
//! Decodes one instruction at a time from a byte stream and produces a
//! structured `Instruction` value ready for the interpreter.
//!
//! Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual
//! Volume 2A/2B (instruction encoding chapter).

use thiserror::Error;

// ── Decoding errors ───────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("unexpected end of instruction bytes at offset {0}")]
    EndOfBytes(usize),
    #[error("unrecognised opcode 0x{0:02x}")]
    UnknownOpcode(u8),
    #[error("unrecognised two-byte opcode 0F 0x{0:02x}")]
    UnknownOpcode2(u8),
    #[error("unsupported prefix combination")]
    UnsupportedPrefix,
}

pub type DecodeResult<T> = Result<T, DecodeError>;

// ── Prefixes ──────────────────────────────────────────────────────────────────

/// Decoded legacy prefixes and REX byte.
#[derive(Debug, Clone, Default)]
pub struct Prefixes {
    /// REX byte (0 = absent).
    pub rex:   u8,
    /// 0x66 operand-size override present.
    pub osz:   bool,
    /// 0x67 address-size override present.
    pub asz:   bool,
    /// Segment override (ES/CS/SS/DS/FS/GS), None if absent.
    pub seg:   Option<u8>,
    /// LOCK prefix.
    pub lock:  bool,
    /// REP/REPNE prefix: 0=none, 0xF3=REP, 0xF2=REPNE.
    pub rep:   u8,
    /// VEX/EVEX prefix detected (future).
    pub vex:   bool,
}

impl Prefixes {
    /// REX.W — 64-bit operand override.
    pub fn rex_w(&self) -> bool { self.rex & 0x08 != 0 }
    /// REX.R — extends ModRM.reg.
    pub fn rex_r(&self) -> bool { self.rex & 0x04 != 0 }
    /// REX.X — extends SIB.index.
    pub fn rex_x(&self) -> bool { self.rex & 0x02 != 0 }
    /// REX.B — extends ModRM.rm / SIB.base / opcode reg.
    pub fn rex_b(&self) -> bool { self.rex & 0x01 != 0 }
    /// Effective operand size in bits.
    pub fn op_size(&self) -> u8 {
        if self.rex_w()          { 64 }
        else if self.osz         { 16 }
        else                     { 32 }
    }
    /// True if REX byte is present (even if 0x40).
    pub fn has_rex(&self) -> bool { self.rex != 0 }
}

// ── ModRM / SIB ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct ModRm {
    pub mod_: u8,   // 2 bits
    pub reg:  u8,   // 3 bits (after REX.R extension → 4 bits in reg_ext)
    pub rm:   u8,   // 3 bits (after REX.B extension → 4 bits in rm_ext)
}

impl ModRm {
    pub fn from_byte(b: u8) -> Self {
        ModRm { mod_: b >> 6, reg: (b >> 3) & 7, rm: b & 7 }
    }
    pub fn reg_ext(&self, rex_r: bool) -> usize { self.reg as usize | ((rex_r as usize) << 3) }
    pub fn rm_ext(&self, rex_b: bool)  -> usize { self.rm  as usize | ((rex_b as usize) << 3) }
    pub fn is_direct(&self) -> bool { self.mod_ == 3 }
}

#[derive(Debug, Clone, Copy)]
pub struct Sib {
    pub scale: u8,
    pub index: u8,
    pub base:  u8,
}
impl Sib {
    pub fn from_byte(b: u8) -> Self {
        Sib { scale: b >> 6, index: (b >> 3) & 7, base: b & 7 }
    }
}

// ── Memory operand ────────────────────────────────────────────────────────────

/// A decoded memory address expression: `base + index*scale + disp`.
#[derive(Debug, Clone)]
pub struct MemAddr {
    pub base:  Option<usize>,   // register index or None (RIP-relative if rip=true)
    pub index: Option<usize>,   // index register or None
    pub scale: u8,              // 1/2/4/8
    pub disp:  i64,
    pub rip_relative: bool,
    pub seg:   Option<u8>,      // segment override
}

// ── Operand ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Operand {
    /// General-purpose register (full 64-bit slot).
    Reg(usize),
    /// Segment register.
    SReg(usize),
    /// XMM/YMM register.
    Xmm(usize),
    /// Immediate value.
    Imm(i64),
    /// Memory operand.
    Mem(MemAddr),
}

// ── Mnemonics (subset for interpreter) ───────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mnemonic {
    // Data movement
    Mov, Movsx, Movzx, Movs, Movaps, Movups, Movsd, Movss,
    Lea, Push, Pop, Xchg, Xadd,
    // Arithmetic
    Add, Adc, Sub, Sbb, Imul, Mul, Idiv, Div, Inc, Dec, Neg, Not,
    // Logical
    And, Or, Xor, Test, Cmp,
    // Shifts / rotates
    Shl, Shr, Sar, Rol, Ror, Rcl, Rcr, Shld, Shrd,
    // Bit manipulation
    Bsf, Bsr, Bt, Bts, Btr, Btc, Popcnt, Lzcnt, Tzcnt,
    // Control flow
    Jmp, Jcc(u8 /* condition code 0..15 */), Call, Ret, RetN,
    Syscall, Int, Int3, Ud2,
    // String operations
    Scas, Cmps, Stos, Lods, Rep,
    // Flags
    Clc, Stc, Cld, Std, Cli, Sti, Cmc,
    Lahf, Sahf, Pushf, Popf,
    // Misc
    Nop, Hlt, Cpuid, Rdtsc, Xgetbv,
    // Conditionals
    Setcc(u8), Cmovcc(u8),
    // Cmpxchg / atomics
    Cmpxchg, Cmpxchg8b, Cmpxchg16b,
    Lock,
    // SSE2
    Addsd, Subsd, Mulsd, Divsd, Sqrtsd, Ucomisd, Cvtsi2sd, Cvttsd2si,
    Addss, Subss, Mulss, Divss, Sqrtss, Ucomiss, Cvtsi2ss, Cvttss2si,
    Pxor, Pand, Por, Pandn, Pcmpeqb, Pcmpeqd,
    Movdqu, Movdqa, Movq,
    Punpcklqdq, Punpckhqdq,
    // x87
    Fld, Fstp, Faddp, Fsubp, Fmulp, Fdivp, Fcompp,
    // Sign-extension
    Cbw, Cwde, Cdqe, Cwd, Cdq, Cqo,
    // Conditonal move helpers
    SysEnter, SysExit,
    // I/O port instructions
    In,   // IN AL/AX/EAX, DX
    Out,  // OUT DX, AL/AX/EAX
    // Unrecognised (will fault)
    Unknown(u8),
}

// ── Decoded instruction ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Instruction {
    pub mnemonic:  Mnemonic,
    pub op_size:   u8,          // effective operand size: 8/16/32/64
    pub addr_size: u8,          // effective address size: 32/64
    pub operands:  Vec<Operand>,
    pub prefixes:  Prefixes,
    /// Total encoded byte length (for advancing RIP).
    pub length:    u8,
}

// ── Byte reader ───────────────────────────────────────────────────────────────

struct ByteReader<'a> {
    data: &'a [u8],
    pos:  usize,
}

impl<'a> ByteReader<'a> {
    fn new(data: &'a [u8]) -> Self { ByteReader { data, pos: 0 } }
    fn read(&mut self) -> DecodeResult<u8> {
        self.data.get(self.pos).copied().map(|b| { self.pos += 1; b })
            .ok_or(DecodeError::EndOfBytes(self.pos))
    }
    fn read_i8(&mut self)  -> DecodeResult<i8>  { self.read().map(|b| b as i8) }
    fn read_u16(&mut self) -> DecodeResult<u16> {
        let lo = self.read()? as u16;
        let hi = self.read()? as u16;
        Ok(lo | (hi << 8))
    }
    fn read_i16(&mut self) -> DecodeResult<i16> { self.read_u16().map(|v| v as i16) }
    fn read_u32(&mut self) -> DecodeResult<u32> {
        let a = self.read()? as u32;
        let b = self.read()? as u32;
        let c = self.read()? as u32;
        let d = self.read()? as u32;
        Ok(a | (b<<8) | (c<<16) | (d<<24))
    }
    fn read_i32(&mut self) -> DecodeResult<i32> { self.read_u32().map(|v| v as i32) }
    fn read_u64(&mut self) -> DecodeResult<u64> {
        let lo = self.read_u32()? as u64;
        let hi = self.read_u32()? as u64;
        Ok(lo | (hi << 32))
    }
    fn read_i64(&mut self) -> DecodeResult<i64> { self.read_u64().map(|v| v as i64) }
}

// ── ModRM + SIB + displacement decoder ───────────────────────────────────────

fn decode_mem(reader: &mut ByteReader, modrm: ModRm, pfx: &Prefixes, _rip_after: u64)
    -> DecodeResult<MemAddr>
{
    let rex_b = pfx.rex_b();
    let rex_x = pfx.rex_x();

    if modrm.mod_ == 3 { panic!("decode_mem called with mod=3"); }

    // SIB present when rm==4 and mod!=3.
    let (base_reg, index_reg, scale) = if modrm.rm == 4 {
        let sib = Sib::from_byte(reader.read()?);
        let base  = Some(sib.base  as usize | ((rex_b as usize) << 3));
        let index = if sib.index == 4 { None } else { Some(sib.index as usize | ((rex_x as usize) << 3)) };
        let scale = 1u8 << sib.scale;
        (base, index, scale)
    } else {
        let rm = modrm.rm_ext(rex_b);
        (Some(rm), None, 1)
    };

    // RIP-relative addressing (mod=0, rm=5, no SIB).
    let rip_relative = modrm.mod_ == 0 && modrm.rm == 5 && modrm.rm != 4;

    let disp = match modrm.mod_ {
        0 if rip_relative => reader.read_i32()? as i64,
        0 => 0i64,
        1 => reader.read_i8()? as i64,
        2 => reader.read_i32()? as i64,
        _ => unreachable!(),
    };

    let base = if rip_relative { None } else { base_reg };
    // Handle mod=0, base=RBP/R13 (no base, 32-bit disp).
    let (base, disp) = if modrm.mod_ == 0 && !rip_relative && modrm.rm != 4 && (modrm.rm | (rex_b as u8 * 8)) == 5 {
        let d = reader.read_i32()? as i64;
        (None, d)
    } else {
        (base, disp)
    };

    Ok(MemAddr { base, index: index_reg, scale, disp, rip_relative, seg: pfx.seg })
}

fn decode_modrm_with_mem(reader: &mut ByteReader, pfx: &Prefixes, rip_after: u64)
    -> DecodeResult<(ModRm, Option<Operand>)>
{
    let byte  = reader.read()?;
    let modrm = ModRm::from_byte(byte);
    let mem   = if modrm.mod_ == 3 {
        None
    } else {
        Some(Operand::Mem(decode_mem(reader, modrm, pfx, rip_after)?))
    };
    Ok((modrm, mem))
}

// ── Immediate reader by width ─────────────────────────────────────────────────

fn read_imm(reader: &mut ByteReader, width: u8) -> DecodeResult<i64> {
    match width {
        8  => reader.read_i8().map(|v| v as i64),
        16 => reader.read_i16().map(|v| v as i64),
        32 => reader.read_i32().map(|v| v as i64),
        64 => reader.read_i64(),
        _  => unreachable!(),
    }
}

// ── Main decode function ──────────────────────────────────────────────────────

/// Decode one x86-64 instruction from `bytes` (starting at offset 0).
/// `rip` is the address of the first byte — needed for RIP-relative addressing.
pub fn decode(bytes: &[u8], rip: u64) -> DecodeResult<Instruction> {
    let mut r   = ByteReader::new(bytes);
    let mut pfx = Prefixes::default();

    // ── Phase 1: read legacy + REX prefixes ───────────────────────────────
    loop {
        let b = r.read()?;
        match b {
            0x26 => pfx.seg   = Some(0), // ES
            0x2E => pfx.seg   = Some(1), // CS
            0x36 => pfx.seg   = Some(2), // SS
            0x3E => pfx.seg   = Some(3), // DS
            0x64 => pfx.seg   = Some(4), // FS
            0x65 => pfx.seg   = Some(5), // GS
            0x66 => pfx.osz   = true,
            0x67 => pfx.asz   = true,
            0xF0 => pfx.lock  = true,
            0xF2 => pfx.rep   = 0xF2,
            0xF3 => pfx.rep   = 0xF3,
            0x40..=0x4F => { pfx.rex = b; },
            _ => {
                // Not a prefix — decode as opcode.
                let op_size   = pfx.op_size();
                let addr_size = if pfx.asz { 32 } else { 64 };

                let instr = decode_opcode(&mut r, b, &pfx, op_size, addr_size, rip)?;
                let length = r.pos as u8;
                return Ok(Instruction {
                    mnemonic:  instr.0,
                    op_size:   instr.1,
                    addr_size,
                    operands:  instr.2,
                    prefixes:  pfx,
                    length,
                });
            }
        }
    }
}

/// Returns (mnemonic, effective_op_size, operands).
fn decode_opcode(
    r:        &mut ByteReader,
    opcode:   u8,
    pfx:      &Prefixes,
    op_size:  u8,
    _addr_size: u8,
    rip:       u64,
) -> DecodeResult<(Mnemonic, u8, Vec<Operand>)> {
    use Mnemonic::*;
    use Operand::*;

    // Estimated RIP after current instruction bytes consumed so far (for
    // RIP-relative operands).  We refine this after the ModRM/displacement.
    let rip_approx = rip; // updated in callers

    macro_rules! rm_reg {
        ($mn:expr, $sz:expr) => {{
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, rip_approx)?;
            let rm  = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
            let reg = Reg(modrm.reg_ext(pfx.rex_r()));
            ($mn, $sz, vec![rm, reg])
        }};
    }
    macro_rules! reg_rm {
        ($mn:expr, $sz:expr) => {{
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, rip_approx)?;
            let rm  = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
            let reg = Reg(modrm.reg_ext(pfx.rex_r()));
            ($mn, $sz, vec![reg, rm])
        }};
    }

    Ok(match opcode {
        // ── NOP ───────────────────────────────────────────────────────────
        0x90 => (Nop, op_size, vec![]),

        // ── PUSH / POP opcode-register ───────────────────────────────────
        0x50..=0x57 => {
            let reg = (opcode & 7) as usize | ((pfx.rex_b() as usize) << 3);
            (Push, 64, vec![Reg(reg)])
        }
        0x58..=0x5F => {
            let reg = (opcode & 7) as usize | ((pfx.rex_b() as usize) << 3);
            (Pop, 64, vec![Reg(reg)])
        }

        // ── PUSH imm ──────────────────────────────────────────────────────
        0x68 => {
            let imm = r.read_i32()? as i64;
            (Push, 64, vec![Imm(imm)])
        }
        0x6A => {
            let imm = r.read_i8()? as i64;
            (Push, 64, vec![Imm(imm)])
        }

        // ── MOV reg, imm64 ────────────────────────────────────────────────
        0xB8..=0xBF => {
            let reg = (opcode & 7) as usize | ((pfx.rex_b() as usize) << 3);
            let (sz, imm) = if pfx.rex_w() {
                (64, r.read_i64()?)
            } else if pfx.osz {
                (16, r.read_i16()? as i64)
            } else {
                (32, r.read_i32()? as i64)
            };
            (Mov, sz, vec![Reg(reg), Imm(imm)])
        }
        0xB0..=0xB7 => {
            let reg = (opcode & 7) as usize;
            let imm = r.read_i8()? as i64;
            (Mov, 8, vec![Reg(reg), Imm(imm)])
        }

        // ── MOV r/m, reg ─────────────────────────────────────────────────
        0x88 => { let v = rm_reg!(Mov, 8);  v }
        0x89 => { let v = rm_reg!(Mov, op_size); v }
        // ── MOV reg, r/m ─────────────────────────────────────────────────
        0x8A => { let v = reg_rm!(Mov, 8); v }
        0x8B => { let v = reg_rm!(Mov, op_size); v }
        // ── MOV r/m, imm ─────────────────────────────────────────────────
        0xC6 => {
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, rip_approx)?;
            let dst = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
            let imm = r.read_i8()? as i64;
            (Mov, 8, vec![dst, Imm(imm)])
        }
        0xC7 => {
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, rip_approx)?;
            let dst = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
            let imm = r.read_i32()? as i64; // sign-extend to 64
            (Mov, op_size, vec![dst, Imm(imm)])
        }

        // ── LEA ──────────────────────────────────────────────────────────
        0x8D => {
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, rip_approx)?;
            let reg = Reg(modrm.reg_ext(pfx.rex_r()));
            (Lea, op_size, vec![reg, mem.unwrap()])
        }

        // ── ADD ──────────────────────────────────────────────────────────
        0x00 => { rm_reg!(Add, 8)  }
        0x01 => { rm_reg!(Add, op_size) }
        0x02 => { reg_rm!(Add, 8)  }
        0x03 => { reg_rm!(Add, op_size) }
        0x04 => { let imm = r.read_i8()? as i64; (Add, 8, vec![Reg(0), Imm(imm)]) }
        0x05 => { let imm = r.read_i32()? as i64; (Add, op_size, vec![Reg(0), Imm(imm)]) }

        // ── SUB ──────────────────────────────────────────────────────────
        0x28 => { rm_reg!(Sub, 8)  }
        0x29 => { rm_reg!(Sub, op_size) }
        0x2A => { reg_rm!(Sub, 8)  }
        0x2B => { reg_rm!(Sub, op_size) }
        0x2C => { let imm = r.read_i8()? as i64; (Sub, 8, vec![Reg(0), Imm(imm)]) }
        0x2D => { let imm = r.read_i32()? as i64; (Sub, op_size, vec![Reg(0), Imm(imm)]) }

        // ── AND ──────────────────────────────────────────────────────────
        0x20 => { rm_reg!(And, 8)  }
        0x21 => { rm_reg!(And, op_size) }
        0x22 => { reg_rm!(And, 8)  }
        0x23 => { reg_rm!(And, op_size) }
        0x24 => { let imm = r.read_i8()? as i64; (And, 8, vec![Reg(0), Imm(imm)]) }
        0x25 => { let imm = r.read_i32()? as i64; (And, op_size, vec![Reg(0), Imm(imm)]) }

        // ── OR ───────────────────────────────────────────────────────────
        0x08 => { rm_reg!(Or, 8)  }
        0x09 => { rm_reg!(Or, op_size) }
        0x0A => { reg_rm!(Or, 8)  }
        0x0B => { reg_rm!(Or, op_size) }
        0x0C => { let imm = r.read_i8()? as i64; (Or, 8, vec![Reg(0), Imm(imm)]) }
        0x0D => { let imm = r.read_i32()? as i64; (Or, op_size, vec![Reg(0), Imm(imm)]) }

        // ── XOR ──────────────────────────────────────────────────────────
        0x30 => { rm_reg!(Xor, 8)  }
        0x31 => { rm_reg!(Xor, op_size) }
        0x32 => { reg_rm!(Xor, 8)  }
        0x33 => { reg_rm!(Xor, op_size) }
        0x34 => { let imm = r.read_i8()? as i64; (Xor, 8, vec![Reg(0), Imm(imm)]) }
        0x35 => { let imm = r.read_i32()? as i64; (Xor, op_size, vec![Reg(0), Imm(imm)]) }

        // ── CMP ──────────────────────────────────────────────────────────
        0x38 => { rm_reg!(Cmp, 8)  }
        0x39 => { rm_reg!(Cmp, op_size) }
        0x3A => { reg_rm!(Cmp, 8)  }
        0x3B => { reg_rm!(Cmp, op_size) }
        0x3C => { let imm = r.read_i8()? as i64; (Cmp, 8, vec![Reg(0), Imm(imm)]) }
        0x3D => { let imm = r.read_i32()? as i64; (Cmp, op_size, vec![Reg(0), Imm(imm)]) }

        // ── TEST ─────────────────────────────────────────────────────────
        0x84 => { rm_reg!(Test, 8)  }
        0x85 => { rm_reg!(Test, op_size) }
        0xA8 => { let imm = r.read_i8()? as i64; (Test, 8, vec![Reg(0), Imm(imm)]) }
        0xA9 => { let imm = r.read_i32()? as i64; (Test, op_size, vec![Reg(0), Imm(imm)]) }

        // ── INC / DEC (register form, removed in 64-bit but kept here) ───
        0x40..=0x4F => unreachable!(), // handled as REX above

        // ── Group 1: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m, imm ────────────
        0x80 => {
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, rip_approx)?;
            let dst = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
            let imm = r.read_i8()? as i64;
            let mn = group1_mnemonic(modrm.reg);
            (mn, 8, vec![dst, Imm(imm)])
        }
        0x81 => {
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, rip_approx)?;
            let dst = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
            let imm = r.read_i32()? as i64;
            let mn = group1_mnemonic(modrm.reg);
            (mn, op_size, vec![dst, Imm(imm)])
        }
        0x83 => {
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, rip_approx)?;
            let dst = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
            let imm = r.read_i8()? as i64; // sign-extend
            let mn = group1_mnemonic(modrm.reg);
            (mn, op_size, vec![dst, Imm(imm)])
        }

        // ── Jcc short ─────────────────────────────────────────────────────
        0x70..=0x7F => {
            let cc  = opcode & 0xF;
            let rel = r.read_i8()? as i64;
            (Jcc(cc), 0, vec![Imm(rel)])
        }
        // ── JMP short / near ──────────────────────────────────────────────
        0xEB => {
            let rel = r.read_i8()? as i64;
            (Jmp, 0, vec![Imm(rel)])
        }
        0xE9 => {
            let rel = r.read_i32()? as i64;
            (Jmp, 0, vec![Imm(rel)])
        }
        // ── JMP r/m64 ─────────────────────────────────────────────────────
        0xFF => {
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, rip_approx)?;
            let dst = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
            match modrm.reg {
                0 => { let (modrm2, mem2) = decode_modrm_with_mem(r, pfx, rip_approx)?;
                       let d2 = mem2.unwrap_or_else(|| Reg(modrm2.rm_ext(pfx.rex_b())));
                       (Inc, op_size, vec![d2]) }
                1 => { let (modrm2, mem2) = decode_modrm_with_mem(r, pfx, rip_approx)?;
                       let d2 = mem2.unwrap_or_else(|| Reg(modrm2.rm_ext(pfx.rex_b())));
                       (Dec, op_size, vec![d2]) }
                2 => (Jmp,  0, vec![dst]),
                3 => (Jmp,  0, vec![dst]), // far jmp (unsupported)
                4 => (Call, 0, vec![dst]),
                5 => (Call, 0, vec![dst]), // far call
                6 => (Push, 64, vec![dst]),
                _ => (Unknown(opcode), 0, vec![]),
            }
        }

        // ── CALL rel32 ────────────────────────────────────────────────────
        0xE8 => {
            let rel = r.read_i32()? as i64;
            (Call, 0, vec![Imm(rel)])
        }
        // ── RET ───────────────────────────────────────────────────────────
        0xC3 => (Ret, 0, vec![]),
        0xC2 => { let n = r.read_u16()? as i64; (RetN, 0, vec![Imm(n)]) }

        // ── SYSCALL ──────────────────────────────────────────────────────-
        // NOTE: This opcode is 2-byte (0F 05) — handled in 0x0F dispatch below.

        // ── PUSH/POP r/m (group 1a: only PUSH here) ──────────────────────
        0x8F => {
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, rip_approx)?;
            let dst = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
            (Pop, 64, vec![dst])
        }

        // ── MOVSX / MOVZX ─────────────────────────────────────────────────
        // (full forms are 0F BE/BF/B6/B7; limited 8→op_size here)

        // ── XCHG ─────────────────────────────────────────────────────────
        0x91..=0x97 => {
            let reg = (opcode & 7) as usize | ((pfx.rex_b() as usize) << 3);
            (Xchg, op_size, vec![Reg(0), Reg(reg)])
        }

        // ── Sign extend RAX ───────────────────────────────────────────────
        0x98 => (Cwde, op_size, vec![]), // CBW / CWDE / CDQE
        0x99 => (Cdq,  op_size, vec![]), // CWD / CDQ / CQO

        // ── INT3 / INT ────────────────────────────────────────────────────
        0xCC => (Int3, 0, vec![]),
        0xCD => { let n = r.read_i8()? as i64; (Int, 0, vec![Imm(n)]) }

        // ── HLT ──────────────────────────────────────────────────────────
        0xF4 => (Hlt, 0, vec![]),

        // ── CLC/STC/CLD/STD ──────────────────────────────────────────────
        0xF8 => (Clc, 0, vec![]),
        0xF9 => (Stc, 0, vec![]),
        0xFC => (Cld, 0, vec![]),
        0xFD => (Std, 0, vec![]),

        // ── LAHF / SAHF ──────────────────────────────────────────────────
        0x9F => (Lahf, 0, vec![]),
        0x9E => (Sahf, 0, vec![]),

        // ── PUSHF / POPF ─────────────────────────────────────────────────
        0x9C => (Pushf, 64, vec![]),
        0x9D => (Popf,  64, vec![]),

        // ── Group 2 (shifts): C0/C1/D0/D1/D2/D3 ─────────────────────────
        0xC0 => { shift_group(r, pfx, 8,       Some(1))? }
        0xC1 => { shift_group(r, pfx, op_size, Some(1))? }
        0xD0 => { shift_group(r, pfx, 8,       Some(0))? } // shift by 1
        0xD1 => { shift_group(r, pfx, op_size, Some(0))? }
        0xD2 => { shift_group(r, pfx, 8,       None)?    } // shift by CL
        0xD3 => { shift_group(r, pfx, op_size, None)?    }

        // ── MUL / IMUL / DIV / IDIV (Group 3, unary forms) ───────────────
        0xF6 | 0xF7 => {
            let sz = if opcode == 0xF6 { 8 } else { op_size };
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, rip_approx)?;
            let src = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
            let mn = match modrm.reg {
                0 | 1 => { let imm = read_imm(r, sz)?; return Ok((Test, sz, vec![src, Imm(imm)])); }
                2 => Not,
                3 => Neg,
                4 => Mul,
                5 => Imul,
                6 => Div,
                7 => Idiv,
                _ => unreachable!(),
            };
            (mn, sz, vec![src])
        }

        // ── IMUL reg, r/m, imm ────────────────────────────────────────────
        0x69 => {
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, rip_approx)?;
            let src = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
            let dst = Reg(modrm.reg_ext(pfx.rex_r()));
            let imm = r.read_i32()? as i64;
            (Imul, op_size, vec![dst, src, Imm(imm)])
        }
        0x6B => {
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, rip_approx)?;
            let src = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
            let dst = Reg(modrm.reg_ext(pfx.rex_r()));
            let imm = r.read_i8()? as i64;
            (Imul, op_size, vec![dst, src, Imm(imm)])
        }

        // ── String ops ────────────────────────────────────────────────────
        0xA4 | 0xA5 => { let sz = if opcode==0xA4 { 8 } else { op_size }; (Movs, sz, vec![]) }
        0xA6 | 0xA7 => { let sz = if opcode==0xA6 { 8 } else { op_size }; (Cmps, sz, vec![]) }
        0xAA | 0xAB => { let sz = if opcode==0xAA { 8 } else { op_size }; (Stos, sz, vec![]) }
        0xAC | 0xAD => { let sz = if opcode==0xAC { 8 } else { op_size }; (Lods, sz, vec![]) }
        0xAE | 0xAF => { let sz = if opcode==0xAE { 8 } else { op_size }; (Scas, sz, vec![]) }

        // ── INC/DEC Group 4/5 (byte forms) ───────────────────────────────
        // These are covered by the 0xFF group above for 64-bit; no separate
        // 0x40-0x47 / 0x48-0x4F forms in 64-bit mode.

        // ── Two-byte escape ───────────────────────────────────────────────
        0x0F => {
            let opcode2 = r.read()?;
            decode_2byte(r, opcode2, pfx, op_size, rip_approx)?
        }

        // ── IN / OUT (port I/O) ───────────────────────────────────────────
        // 0xEC: IN AL, DX   (byte)
        // 0xED: IN AX, DX (word, if 0x66 prefix) or IN EAX, DX (dword)
        // 0xEE: OUT DX, AL  (byte)
        // 0xEF: OUT DX, AX (word, if 0x66 prefix) or OUT DX, EAX (dword)
        0xEC => (Mnemonic::In,  8,  vec![]),
        0xED => {
            let sz = if pfx.osz { 16 } else { 32 };
            (Mnemonic::In, sz, vec![])
        }
        0xEE => (Mnemonic::Out, 8,  vec![]),
        0xEF => {
            let sz = if pfx.osz { 16 } else { 32 };
            (Mnemonic::Out, sz, vec![])
        }

        // ── LEA relative to CS (far ops, rare) ───────────────────────────
        _ => (Unknown(opcode), 0, vec![]),
    })
}

fn group1_mnemonic(reg: u8) -> Mnemonic {
    use Mnemonic::*;
    match reg { 0=>Add, 1=>Or, 2=>Adc, 3=>Sbb, 4=>And, 5=>Sub, 6=>Xor, 7=>Cmp, _=>Nop }
}

fn shift_group(r: &mut ByteReader, pfx: &Prefixes, sz: u8, imm_one: Option<u8>)
    -> DecodeResult<(Mnemonic, u8, Vec<Operand>)>
{
    use Mnemonic::*; use Operand::*;
    let (modrm, mem) = decode_modrm_with_mem(r, pfx, 0)?;
    let dst = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
    let mn  = match modrm.reg { 0=>Rol, 1=>Ror, 2=>Rcl, 3=>Rcr, 4=>Shl, 5=>Shr, 7=>Sar, _=>Nop };
    let cnt = match imm_one {
        Some(0) => Imm(1),
        Some(_) => Imm(r.read_i8()? as i64),
        None    => Reg(1), // CL = reg index 1
    };
    Ok((mn, sz, vec![dst, cnt]))
}

fn decode_2byte(r: &mut ByteReader, op: u8, pfx: &Prefixes, op_size: u8, _rip: u64)
    -> DecodeResult<(Mnemonic, u8, Vec<Operand>)>
{
    use Mnemonic::*; use Operand::*;
    Ok(match op {
        0x05 => (Syscall, 0, vec![]),
        0x0B => (Ud2,     0, vec![]),
        0x31 => (Rdtsc,   0, vec![]),
        0xA2 => (Cpuid,   0, vec![]),

        // ── CMOVcc ────────────────────────────────────────────────────────
        0x40..=0x4F => {
            let cc = op & 0xF;
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, 0)?;
            let src = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
            let dst = Reg(modrm.reg_ext(pfx.rex_r()));
            (Cmovcc(cc), op_size, vec![dst, src])
        }

        // ── Jcc near ──────────────────────────────────────────────────────
        0x80..=0x8F => {
            let cc  = op & 0xF;
            let rel = r.read_i32()? as i64;
            (Jcc(cc), 0, vec![Imm(rel)])
        }

        // ── SETcc ─────────────────────────────────────────────────────────
        0x90..=0x9F => {
            let cc = op & 0xF;
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, 0)?;
            let dst = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
            (Setcc(cc), 8, vec![dst])
        }

        // ── MOVZX ─────────────────────────────────────────────────────────
        0xB6 => {
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, 0)?;
            let src = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
            let dst = Reg(modrm.reg_ext(pfx.rex_r()));
            (Movzx, op_size, vec![dst, src])
        }
        0xB7 => {
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, 0)?;
            let src = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
            let dst = Reg(modrm.reg_ext(pfx.rex_r()));
            (Movzx, op_size, vec![dst, src])
        }

        // ── MOVSX ─────────────────────────────────────────────────────────
        0xBE => {
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, 0)?;
            let src = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
            let dst = Reg(modrm.reg_ext(pfx.rex_r()));
            (Movsx, op_size, vec![dst, src])
        }
        0xBF => {
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, 0)?;
            let src = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
            let dst = Reg(modrm.reg_ext(pfx.rex_r()));
            (Movsx, op_size, vec![dst, src])
        }

        // ── IMUL reg, r/m (2-operand) ─────────────────────────────────────
        0xAF => {
            let (modrm, mem) = decode_modrm_with_mem(r, pfx, 0)?;
            let src = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
            let dst = Reg(modrm.reg_ext(pfx.rex_r()));
            (Imul, op_size, vec![dst, src])
        }

        // ── BSF / BSR ─────────────────────────────────────────────────────
        0xBC => { let (modrm, mem) = decode_modrm_with_mem(r, pfx, 0)?;
                   let src = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
                   let dst = Reg(modrm.reg_ext(pfx.rex_r()));
                   (Bsf, op_size, vec![dst, src]) }
        0xBD => { let (modrm, mem) = decode_modrm_with_mem(r, pfx, 0)?;
                   let src = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
                   let dst = Reg(modrm.reg_ext(pfx.rex_r()));
                   (Bsr, op_size, vec![dst, src]) }

        // ── XADD ─────────────────────────────────────────────────────────
        0xC0 => { let (modrm, mem) = decode_modrm_with_mem(r, pfx, 0)?;
                   let dst = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
                   let src = Reg(modrm.reg_ext(pfx.rex_r()));
                   (Xadd, 8, vec![dst, src]) }
        0xC1 => { let (modrm, mem) = decode_modrm_with_mem(r, pfx, 0)?;
                   let dst = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
                   let src = Reg(modrm.reg_ext(pfx.rex_r()));
                   (Xadd, op_size, vec![dst, src]) }

        // ── CMPXCHG ──────────────────────────────────────────────────────
        0xB0 => { let (modrm, mem) = decode_modrm_with_mem(r, pfx, 0)?;
                   let dst = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
                   let src = Reg(modrm.reg_ext(pfx.rex_r()));
                   (Cmpxchg, 8, vec![dst, src]) }
        0xB1 => { let (modrm, mem) = decode_modrm_with_mem(r, pfx, 0)?;
                   let dst = mem.unwrap_or_else(|| Reg(modrm.rm_ext(pfx.rex_b())));
                   let src = Reg(modrm.reg_ext(pfx.rex_r()));
                   (Cmpxchg, op_size, vec![dst, src]) }

        _ => (Unknown(op), 0, vec![]),
    })
}
