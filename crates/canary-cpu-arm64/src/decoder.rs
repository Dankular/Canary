//! AArch64 (A64) instruction decoder.

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct ArmInstr { pub raw: u32, pub kind: ArmInstrKind, }

#[derive(Debug, Clone)]
pub enum ArmInstrKind {
    AddImm  { rd: u8, rn: u8, imm: u64, is64: bool, setflags: bool },
    SubImm  { rd: u8, rn: u8, imm: u64, is64: bool, setflags: bool },
    AndImm  { rd: u8, rn: u8, imm: u64, is64: bool },
    OrrImm  { rd: u8, rn: u8, imm: u64, is64: bool },
    EorImm  { rd: u8, rn: u8, imm: u64, is64: bool },
    AndsImm { rd: u8, rn: u8, imm: u64, is64: bool },
    AddReg  { rd: u8, rn: u8, rm: u8, shift: u8, amount: u8, is64: bool, setflags: bool },
    SubReg  { rd: u8, rn: u8, rm: u8, shift: u8, amount: u8, is64: bool, setflags: bool },
    AndReg  { rd: u8, rn: u8, rm: u8, shift: u8, amount: u8, is64: bool, setflags: bool },
    OrrReg  { rd: u8, rn: u8, rm: u8, shift: u8, amount: u8, is64: bool },
    EorReg  { rd: u8, rn: u8, rm: u8, shift: u8, amount: u8, is64: bool },
    Lsl { rd: u8, rn: u8, rm: u8, is64: bool },
    Lsr { rd: u8, rn: u8, rm: u8, is64: bool },
    Asr { rd: u8, rn: u8, rm: u8, is64: bool },
    LslImm { rd: u8, rn: u8, shift: u8, is64: bool },
    LsrImm { rd: u8, rn: u8, shift: u8, is64: bool },
    AsrImm { rd: u8, rn: u8, shift: u8, is64: bool },
    Mul  { rd: u8, rn: u8, rm: u8, is64: bool },
    SDiv { rd: u8, rn: u8, rm: u8, is64: bool },
    UDiv { rd: u8, rn: u8, rm: u8, is64: bool },
    Csel  { rd: u8, rn: u8, rm: u8, cond: u8, is64: bool },
    Csinc { rd: u8, rn: u8, rm: u8, cond: u8, is64: bool },
    Csinv { rd: u8, rn: u8, rm: u8, cond: u8, is64: bool },
    Csneg { rd: u8, rn: u8, rm: u8, cond: u8, is64: bool },
    Rbit { rd: u8, rn: u8, is64: bool },
    Clz  { rd: u8, rn: u8, is64: bool },
    Rev  { rd: u8, rn: u8, is64: bool },
    Sxtw { rd: u8, rn: u8 },
    Uxtw { rd: u8, rn: u8 },
    Sxth { rd: u8, rn: u8, is64: bool },
    Sxtb { rd: u8, rn: u8, is64: bool },
    Movz   { rd: u8, imm16: u16, shift: u8, is64: bool },
    Movk   { rd: u8, imm16: u16, shift: u8, is64: bool },
    Movn   { rd: u8, imm16: u16, shift: u8, is64: bool },
    MovReg { rd: u8, rm: u8, is64: bool },
    Adr  { rd: u8, offset: i32 },
    Adrp { rd: u8, offset: i64 },
    B     { offset: i32 },
    Bl    { offset: i32 },
    Br    { rn: u8 },
    Blr   { rn: u8 },
    Ret   { rn: u8 },
    BCond { cond: u8, offset: i32 },
    Cbz   { rt: u8, offset: i32, is64: bool },
    Cbnz  { rt: u8, offset: i32, is64: bool },
    Tbz   { rt: u8, bit: u8, offset: i32 },
    Tbnz  { rt: u8, bit: u8, offset: i32 },
    LdrImm    { rt: u8, rn: u8, offset: i64, is64: bool },
    StrImm    { rt: u8, rn: u8, offset: i64, is64: bool },
    LdrLit    { rt: u8, offset: i32, is64: bool },
    LdrRegOff { rt: u8, rn: u8, rm: u8, extend: u8, amount: u8, is64: bool },
    StrRegOff { rt: u8, rn: u8, rm: u8, extend: u8, amount: u8, is64: bool },
    LdrhImm  { rt: u8, rn: u8, offset: i64 },
    StrhImm  { rt: u8, rn: u8, offset: i64 },
    LdrbImm  { rt: u8, rn: u8, offset: i64 },
    StrbImm  { rt: u8, rn: u8, offset: i64 },
    LdrshImm { rt: u8, rn: u8, offset: i64, is64: bool },
    LdrsbImm { rt: u8, rn: u8, offset: i64, is64: bool },
    LdrswImm { rt: u8, rn: u8, offset: i64 },
    LdrImmPost { rt: u8, rn: u8, simm: i64, is64: bool },
    LdrImmPre  { rt: u8, rn: u8, simm: i64, is64: bool },
    StrImmPost { rt: u8, rn: u8, simm: i64, is64: bool },
    StrImmPre  { rt: u8, rn: u8, simm: i64, is64: bool },
    Ldp     { rt1: u8, rt2: u8, rn: u8, offset: i64, is64: bool },
    Stp     { rt1: u8, rt2: u8, rn: u8, offset: i64, is64: bool },
    LdpPost { rt1: u8, rt2: u8, rn: u8, simm: i64, is64: bool },
    StpPre  { rt1: u8, rt2: u8, rn: u8, simm: i64, is64: bool },
    LdpPre  { rt1: u8, rt2: u8, rn: u8, simm: i64, is64: bool },
    StpPost { rt1: u8, rt2: u8, rn: u8, simm: i64, is64: bool },
    LdxrImm { rt: u8, rn: u8, is64: bool },
    StxrImm { rs: u8, rt: u8, rn: u8, is64: bool },
    Nop,
    Svc { imm: u16 },
    Mrs { rt: u8, sysreg: u32 },
    Msr { rt: u8, sysreg: u32 },
    Dmb, Dsb, Isb,
    Brk { imm: u16 },
    Unknown(u32),
}

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("not enough bytes")]
    TooShort,
}

/// Decode one A64 instruction from `data` (must be ≥ 4 bytes).
/// `pc` is the address of the instruction, used to compute PC-relative offsets.
pub fn decode(data: &[u8], _pc: u64) -> Result<ArmInstr, DecodeError> {
    if data.len() < 4 { return Err(DecodeError::TooShort); }
    let raw = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let kind = decode_raw(raw);
    Ok(ArmInstr { raw, kind })
}

// ── Sign-extend helpers ───────────────────────────────────────────────────────

fn sext(val: u32, bits: u32) -> i32 {
    let shift = 32 - bits;
    ((val << shift) as i32) >> shift
}

fn sext64(val: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((val << shift) as i64) >> shift
}

// ── Bitmask immediate decoder (DecodeBitMasks) ────────────────────────────────

fn decode_bit_mask(n: u32, imms: u32, immr: u32, is64: bool) -> Option<u64> {
    // Determine element size from N:NOT(imms)
    let combined = (n << 6) | ((!imms) & 0x3F);
    if combined == 0 { return None; }
    let len = 31 - combined.leading_zeros(); // floor(log2(combined))
    if len == 0 { return None; }

    let esize = 1u32 << len;
    let levels = esize - 1;
    let s = imms & levels;
    let r = immr & levels;

    // Build the basic element: s+1 ones in esize bits
    let welem = if s + 1 >= 64 { u64::MAX } else { (1u64 << (s + 1)) - 1 };

    // ROR(welem, r) within esize bits
    let telem = if r == 0 {
        welem
    } else {
        let mask = (1u64 << esize) - 1;
        ((welem >> r) | (welem << (esize - r))) & mask
    };

    // Replicate telem to fill 64 (or 32) bits
    let total = if is64 { 64u32 } else { 32u32 };
    let mut result = 0u64;
    let mut pos = 0u32;
    while pos < total {
        result |= telem << pos;
        pos += esize;
    }
    Some(result)
}

// ── Main decode dispatch ──────────────────────────────────────────────────────

fn decode_raw(raw: u32) -> ArmInstrKind {
    let sf   = (raw >> 31) as u8;
    let is64 = sf == 1;

    // ── NOP / system hint instructions ────────────────────────────────────
    if raw == 0xD503201F { return ArmInstrKind::Nop; }
    // Any HINT (MSR-style sys hints): top 24 bits = 0xD50320, op2 in bits[7:5]
    if raw & 0xFFFFFFE0 == 0xD503201F & 0xFFFFFFE0 { return ArmInstrKind::Nop; }

    // ── SVC ────────────────────────────────────────────────────────────────
    // 1101 0100 0000 xxxx xxxx xxxx xxx0 0001
    if raw & 0xFFE0001F == 0xD4000001 {
        return ArmInstrKind::Svc { imm: ((raw >> 5) & 0xFFFF) as u16 };
    }

    // ── BRK ────────────────────────────────────────────────────────────────
    if raw & 0xFFE0001F == 0xD4200000 {
        return ArmInstrKind::Brk { imm: ((raw >> 5) & 0xFFFF) as u16 };
    }

    // ── Barriers: DMB / DSB / ISB ──────────────────────────────────────────
    // 1101 0101 0000 0011 0011 xxxx 1001 1111
    if raw & 0xFFFFF09F == 0xD503309F {
        return match (raw >> 5) & 0x7 {
            4 => ArmInstrKind::Dsb,
            5 => ArmInstrKind::Dmb,
            6 => ArmInstrKind::Isb,
            _ => ArmInstrKind::Nop,
        };
    }

    // ── MRS (move system register to GPR) ─────────────────────────────────
    // 1101 0101 0011 xxxx xxxx xxxx xxx xxxxx
    if (raw >> 20) & 0xFFF == 0xD53 {
        let rt     = (raw & 0x1F) as u8;
        let sysreg = (raw >> 5) & 0x7FFF;
        return ArmInstrKind::Mrs { rt, sysreg };
    }

    // ── MSR (move GPR to system register) ─────────────────────────────────
    // 1101 0101 0001 xxxx xxxx xxxx xxx xxxxx
    if (raw >> 20) & 0xFFF == 0xD51 {
        let rt     = (raw & 0x1F) as u8;
        let sysreg = (raw >> 5) & 0x7FFF;
        return ArmInstrKind::Msr { rt, sysreg };
    }

    // ── BR / BLR / RET ────────────────────────────────────────────────────
    // BR:  1101 0110 0001 1111 0000 00nn nnn0 0000
    // BLR: 1101 0110 0011 1111 0000 00nn nnn0 0000
    // RET: 1101 0110 0101 1111 0000 00nn nnn0 0000
    if raw & 0xFFFFFC1F == 0xD61F0000 {
        return ArmInstrKind::Br  { rn: ((raw >> 5) & 0x1F) as u8 };
    }
    if raw & 0xFFFFFC1F == 0xD63F0000 {
        return ArmInstrKind::Blr { rn: ((raw >> 5) & 0x1F) as u8 };
    }
    if raw & 0xFFFFFC1F == 0xD65F0000 {
        return ArmInstrKind::Ret { rn: ((raw >> 5) & 0x1F) as u8 };
    }

    // ── B / BL ────────────────────────────────────────────────────────────
    // B:  000101 imm26
    // BL: 100101 imm26
    if (raw >> 26) == 0x05 {
        let imm26 = raw & 0x3FF_FFFF;
        return ArmInstrKind::B { offset: sext(imm26, 26) << 2 };
    }
    if (raw >> 26) == 0x25 {
        let imm26 = raw & 0x3FF_FFFF;
        return ArmInstrKind::Bl { offset: sext(imm26, 26) << 2 };
    }

    // ── B.cond ────────────────────────────────────────────────────────────
    // 0101 0100 imm19 0 cond
    if (raw >> 24) == 0x54 && (raw & 0x10) == 0 {
        let imm19 = (raw >> 5) & 0x7FFFF;
        let cond  = (raw & 0xF) as u8;
        return ArmInstrKind::BCond { cond, offset: sext(imm19, 19) << 2 };
    }

    // ── CBZ / CBNZ ────────────────────────────────────────────────────────
    // [30:24] = 0110100 (CBZ) / 0110101 (CBNZ);  [31]=sf
    if (raw >> 24) & 0x7F == 0x34 {
        let rt    = (raw & 0x1F) as u8;
        let imm19 = (raw >> 5) & 0x7FFFF;
        return ArmInstrKind::Cbz { rt, offset: sext(imm19, 19) << 2, is64 };
    }
    if (raw >> 24) & 0x7F == 0x35 {
        let rt    = (raw & 0x1F) as u8;
        let imm19 = (raw >> 5) & 0x7FFFF;
        return ArmInstrKind::Cbnz { rt, offset: sext(imm19, 19) << 2, is64 };
    }

    // ── TBZ / TBNZ ────────────────────────────────────────────────────────
    // [30:24] = 0110110 (TBZ) / 0110111 (TBNZ); [31]=b5
    if (raw >> 24) & 0x7F == 0x36 {
        let rt    = (raw & 0x1F) as u8;
        let b5    = (raw >> 31) as u8;
        let b40   = ((raw >> 19) & 0x1F) as u8;
        let bit   = b5 << 5 | b40;
        let imm14 = (raw >> 5) & 0x3FFF;
        return ArmInstrKind::Tbz { rt, bit, offset: sext(imm14, 14) << 2 };
    }
    if (raw >> 24) & 0x7F == 0x37 {
        let rt    = (raw & 0x1F) as u8;
        let b5    = (raw >> 31) as u8;
        let b40   = ((raw >> 19) & 0x1F) as u8;
        let bit   = b5 << 5 | b40;
        let imm14 = (raw >> 5) & 0x3FFF;
        return ArmInstrKind::Tbnz { rt, bit, offset: sext(imm14, 14) << 2 };
    }

    // ── ADR / ADRP ────────────────────────────────────────────────────────
    // [28:24] = 10000 for both; [31] differentiates
    if (raw >> 24) & 0x1F == 0x10 {
        let rd    = (raw & 0x1F) as u8;
        let immlo = (raw >> 29) & 0x3;
        let immhi = (raw >> 5) & 0x7FFFF;
        let imm21 = (immhi << 2) | immlo;
        let offset = sext(imm21, 21);
        if (raw >> 31) == 0 {
            return ArmInstrKind::Adr { rd, offset };
        } else {
            return ArmInstrKind::Adrp { rd, offset: (offset as i64) << 12 };
        }
    }

    // ── LDR literal ───────────────────────────────────────────────────────
    // [30:27] = 0110 (32-bit) or [30:27] = 0111 → covered by load/store group
    // More precisely: [29:27]=011, [26]=0, [25:24]=00 → Load register literal
    // [31:30]=opc: 00=LDR Wt, 01=LDR Xt, 10=LDRSW, 11=PRFM
    if (raw >> 27) & 0xF == 0x3 && (raw >> 26) & 1 == 0 && (raw >> 24) & 0x3 == 0 {
        let opc   = (raw >> 30) as u8 & 0x3;
        let rt    = (raw & 0x1F) as u8;
        let imm19 = (raw >> 5) & 0x7FFFF;
        let offset = sext(imm19, 19) << 2;
        return match opc {
            0 => ArmInstrKind::LdrLit { rt, offset, is64: false },
            1 => ArmInstrKind::LdrLit { rt, offset, is64: true },
            2 => ArmInstrKind::LdrswImm { rt, rn: 0xFF, offset: offset as i64 }, // LDRSW literal (rn=0xFF as sentinel)
            _ => ArmInstrKind::Nop, // PRFM
        };
    }

    // ── Data-processing immediate ─────────────────────────────────────────
    //
    // Identified by bits [28:23]: 1000xx, 1001xx, 100100, 100101, 10011x
    // More concisely: bit [28]=1 and bit [27]=0 → DP immediate
    // Exception: 10101x = branches (handled above already)

    let bits_28_23 = (raw >> 23) & 0x3F;

    // ── Add/Sub immediate: [28:24]=10001, i.e. bits_28_23 in 0x22..0x23 ──
    if bits_28_23 & 0x3E == 0x22 {
        // [31]=sf, [30:29]=opc(op:S), [28:24]=10001, [23:22]=shift, [21:10]=imm12, [9:5]=Rn, [4:0]=Rd
        let rd    = (raw & 0x1F) as u8;
        let rn    = ((raw >> 5) & 0x1F) as u8;
        let imm12 = (raw >> 10) & 0xFFF;
        let shift = (raw >> 22) & 0x3;
        let imm   = if shift == 1 { (imm12 as u64) << 12 } else { imm12 as u64 };
        let op    = (raw >> 29) & 0x3;
        return match op {
            0 => ArmInstrKind::AddImm { rd, rn, imm, is64, setflags: false },
            1 => ArmInstrKind::AddImm { rd, rn, imm, is64, setflags: true  },
            2 => ArmInstrKind::SubImm { rd, rn, imm, is64, setflags: false },
            3 => ArmInstrKind::SubImm { rd, rn, imm, is64, setflags: true  },
            _ => unreachable!(),
        };
    }

    // ── Logical immediate: [28:23]=100100 (bits_28_23 = 0x24..0x27) ──────
    if bits_28_23 & 0x3C == 0x24 {
        // [31]=sf, [30:29]=opc, [28:23]=100100, [22]=N, [21:16]=immr, [15:10]=imms, [9:5]=Rn, [4:0]=Rd
        let rd   = (raw & 0x1F) as u8;
        let rn   = ((raw >> 5) & 0x1F) as u8;
        let imms = (raw >> 10) & 0x3F;
        let immr = (raw >> 16) & 0x3F;
        let n    = (raw >> 22) & 0x1;
        let opc  = (raw >> 29) & 0x3;
        let imm  = decode_bit_mask(n, imms, immr, is64).unwrap_or(0);
        return match opc {
            0 => ArmInstrKind::AndImm  { rd, rn, imm, is64 },
            1 => ArmInstrKind::OrrImm  { rd, rn, imm, is64 },
            2 => ArmInstrKind::EorImm  { rd, rn, imm, is64 },
            3 => ArmInstrKind::AndsImm { rd, rn, imm, is64 },
            _ => unreachable!(),
        };
    }

    // ── Move wide immediate: [28:23]=100101 (bits_28_23 = 0x25) ──────────
    // (the mask 0x3F matches 0x25 exactly for bits [28:23])
    if bits_28_23 == 0x25 {
        // [31]=sf, [30:29]=opc, [28:23]=100101, [22:21]=hw, [20:5]=imm16, [4:0]=Rd
        let rd    = (raw & 0x1F) as u8;
        let imm16 = ((raw >> 5) & 0xFFFF) as u16;
        let hw    = ((raw >> 21) & 0x3) as u8;
        let shift = hw << 4; // hw * 16
        let opc   = (raw >> 29) & 0x3;
        return match opc {
            0 => ArmInstrKind::Movn { rd, imm16, shift, is64 },
            2 => ArmInstrKind::Movz { rd, imm16, shift, is64 },
            3 => ArmInstrKind::Movk { rd, imm16, shift, is64 },
            _ => ArmInstrKind::Unknown(raw),
        };
    }

    // ── Bitfield: [28:23]=100110 (bits_28_23 = 0x26) ─────────────────────
    // SBFM / BFM / UBFM — covers SXTB, SXTH, SXTW, LSL/LSR/ASR immediate forms
    if bits_28_23 == 0x26 {
        let rd   = (raw & 0x1F) as u8;
        let rn   = ((raw >> 5) & 0x1F) as u8;
        let imms = (raw >> 10) & 0x3F;
        let immr = (raw >> 16) & 0x3F;
        let opc  = (raw >> 29) & 0x3;

        // UBFM: LSL imm → imms+1 = esize-immr, imms = esize-1-shift
        // SBFM: ASR imm → imms = esize-1, immr = shift
        // LSR: UBFM imms = esize-1, immr = shift
        // SXTH: SBFM immr=0, imms=15
        // SXTB: SBFM immr=0, imms=7
        // SXTW: SBFM immr=0, imms=31
        // UXTB: UBFM immr=0, imms=7
        // UXTH: UBFM immr=0, imms=15

        // Detect convenient aliases
        let esize = if is64 { 64u32 } else { 32u32 };

        if opc == 0 {
            // SBFM
            if immr == 0 && imms == 7  { return ArmInstrKind::Sxtb { rd, rn, is64 }; }
            if immr == 0 && imms == 15 { return ArmInstrKind::Sxth { rd, rn, is64 }; }
            if immr == 0 && imms == 31 { return ArmInstrKind::Sxtw { rd, rn }; }
            // ASR immediate: imms = esize-1
            if imms == esize - 1 {
                return ArmInstrKind::AsrImm { rd, rn, shift: immr as u8, is64 };
            }
            // General SBFM — emit as AsrImm for now (common case)
            return ArmInstrKind::AsrImm { rd, rn, shift: immr as u8, is64 };
        }
        if opc == 2 {
            // UBFM
            if immr == 0 && imms == 7  { return ArmInstrKind::Uxtw { rd, rn }; } // UXTB (treat as Uxtw of low byte)
            if immr == 0 && imms == 15 { return ArmInstrKind::Uxtw { rd, rn }; } // UXTH
            if immr == 0 && imms == 31 { return ArmInstrKind::Uxtw { rd, rn }; }
            // LSR immediate: imms = esize-1, immr = shift
            if imms == esize - 1 {
                return ArmInstrKind::LsrImm { rd, rn, shift: immr as u8, is64 };
            }
            // LSL immediate: imms+1+immr = esize
            if imms + 1 + immr == esize {
                let shift = (esize - 1 - imms) as u8;
                return ArmInstrKind::LslImm { rd, rn, shift, is64 };
            }
            // General UBFM → LsrImm as approximation
            return ArmInstrKind::LsrImm { rd, rn, shift: immr as u8, is64 };
        }
        if opc == 1 {
            // BFM — treat as Nop for now (rarely generated by compilers for basic code)
            return ArmInstrKind::Nop;
        }
    }

    // ── Data-processing register ──────────────────────────────────────────
    //
    // Top-level: bit [28]=0 and bit [27]=1 and bit [25]=1 (bits [28:24] = x1x1x)
    // But the easiest is to check specific sub-encodings.

    // ── Logical shifted register: [28:24]=01010 ───────────────────────────
    if (raw >> 24) & 0x1F == 0x0A {
        let rd     = (raw & 0x1F) as u8;
        let rn     = ((raw >> 5) & 0x1F) as u8;
        let imm6   = ((raw >> 10) & 0x3F) as u8;
        let rm     = ((raw >> 16) & 0x1F) as u8;
        let shift  = ((raw >> 22) & 0x3) as u8;
        let n_bit  = (raw >> 21) & 0x1;
        let opc    = (raw >> 29) & 0x3;

        // MOV (register) alias: ORR Rd, XZR, Rm (shift=0, imm6=0, Rn=31)
        if opc == 1 && rn == 31 && imm6 == 0 && shift == 0 && n_bit == 0 {
            return ArmInstrKind::MovReg { rd, rm, is64 };
        }

        return match (opc, n_bit) {
            (0, 0) => ArmInstrKind::AndReg  { rd, rn, rm, shift, amount: imm6, is64, setflags: false },
            (0, 1) => ArmInstrKind::AndReg  { rd, rn, rm, shift, amount: imm6, is64, setflags: false }, // BIC
            (1, 0) => ArmInstrKind::OrrReg  { rd, rn, rm, shift, amount: imm6, is64 },
            (1, 1) => ArmInstrKind::OrrReg  { rd, rn, rm, shift, amount: imm6, is64 }, // ORN
            (2, 0) => ArmInstrKind::EorReg  { rd, rn, rm, shift, amount: imm6, is64 },
            (2, 1) => ArmInstrKind::EorReg  { rd, rn, rm, shift, amount: imm6, is64 }, // EON
            (3, 0) => ArmInstrKind::AndReg  { rd, rn, rm, shift, amount: imm6, is64, setflags: true }, // ANDS
            (3, 1) => ArmInstrKind::AndReg  { rd, rn, rm, shift, amount: imm6, is64, setflags: true }, // BICS
            _      => ArmInstrKind::Unknown(raw),
        };
    }

    // ── Add/Sub shifted register: [28:24]=01011 ───────────────────────────
    if (raw >> 24) & 0x1F == 0x0B && (raw >> 21) & 1 == 0 {
        let rd    = (raw & 0x1F) as u8;
        let rn    = ((raw >> 5) & 0x1F) as u8;
        let imm6  = ((raw >> 10) & 0x3F) as u8;
        let rm    = ((raw >> 16) & 0x1F) as u8;
        let shift = ((raw >> 22) & 0x3) as u8;
        let op_s  = (raw >> 29) & 0x3;
        return match op_s {
            0 => ArmInstrKind::AddReg { rd, rn, rm, shift, amount: imm6, is64, setflags: false },
            1 => ArmInstrKind::AddReg { rd, rn, rm, shift, amount: imm6, is64, setflags: true  },
            2 => ArmInstrKind::SubReg { rd, rn, rm, shift, amount: imm6, is64, setflags: false },
            3 => ArmInstrKind::SubReg { rd, rn, rm, shift, amount: imm6, is64, setflags: true  },
            _ => unreachable!(),
        };
    }

    // ── Add/Sub extended register: [28:24]=01011, bit[21]=1 ──────────────
    // Treat as AddReg/SubReg with shift=0 for simplicity
    if (raw >> 24) & 0x1F == 0x0B && (raw >> 21) & 1 == 1 {
        let rd   = (raw & 0x1F) as u8;
        let rn   = ((raw >> 5) & 0x1F) as u8;
        let rm   = ((raw >> 16) & 0x1F) as u8;
        let op_s = (raw >> 29) & 0x3;
        return match op_s {
            0 | 1 => ArmInstrKind::AddReg { rd, rn, rm, shift: 0, amount: 0, is64, setflags: op_s == 1 },
            2 | 3 => ArmInstrKind::SubReg { rd, rn, rm, shift: 0, amount: 0, is64, setflags: op_s == 3 },
            _ => unreachable!(),
        };
    }

    // ── Data-processing 2-source: [28:21]=11010110 ────────────────────────
    // UDIV, SDIV, LSLV, LSRV, ASRV, RORV
    if (raw >> 21) & 0xFF == 0xD6 && (raw >> 29) & 0x3 == 0 {
        let rd  = (raw & 0x1F) as u8;
        let rn  = ((raw >> 5) & 0x1F) as u8;
        let rm  = ((raw >> 16) & 0x1F) as u8;
        let opc = (raw >> 10) & 0x3F;
        return match opc {
            0x02 => ArmInstrKind::UDiv { rd, rn, rm, is64 },
            0x03 => ArmInstrKind::SDiv { rd, rn, rm, is64 },
            0x08 => ArmInstrKind::Lsl  { rd, rn, rm, is64 },
            0x09 => ArmInstrKind::Lsr  { rd, rn, rm, is64 },
            0x0A => ArmInstrKind::Asr  { rd, rn, rm, is64 },
            _    => ArmInstrKind::Unknown(raw),
        };
    }

    // ── Data-processing 1-source: [28:21]=11010110 opcode2=00000 ─────────
    // RBIT, REV16, REV32, REV64, CLZ, CLS
    if (raw >> 21) & 0xFF == 0xD6 && (raw >> 16) & 0x1F == 0 && (raw >> 29) & 0x3 == 2 {
        let rd  = (raw & 0x1F) as u8;
        let rn  = ((raw >> 5) & 0x1F) as u8;
        let opc = (raw >> 10) & 0x3F;
        return match opc {
            0 => ArmInstrKind::Rbit { rd, rn, is64 },
            3 | 2 => ArmInstrKind::Rev { rd, rn, is64 },
            4 => ArmInstrKind::Clz  { rd, rn, is64 },
            _ => ArmInstrKind::Unknown(raw),
        };
    }

    // ── Conditional select: [28:21]=11010100 ─────────────────────────────
    // CSEL, CSINC, CSINV, CSNEG
    if (raw >> 21) & 0xFF == 0xD4 {
        let rd   = (raw & 0x1F) as u8;
        let rn   = ((raw >> 5) & 0x1F) as u8;
        let cond = ((raw >> 12) & 0xF) as u8;
        let op2  = (raw >> 10) & 0x3;
        let rm   = ((raw >> 16) & 0x1F) as u8;
        let op   = (raw >> 30) & 0x1;
        let s    = (raw >> 29) & 0x1;
        if s == 0 {
            return match (op, op2) {
                (0, 0) => ArmInstrKind::Csel  { rd, rn, rm, cond, is64 },
                (0, 1) => ArmInstrKind::Csinc { rd, rn, rm, cond, is64 },
                (1, 0) => ArmInstrKind::Csinv { rd, rn, rm, cond, is64 },
                (1, 1) => ArmInstrKind::Csneg { rd, rn, rm, cond, is64 },
                _      => ArmInstrKind::Unknown(raw),
            };
        }
    }

    // ── Data-processing 3-source: [28:24]=11011 ──────────────────────────
    // MADD (MUL), MSUB (MNEG), SMADDL, UMADDL
    if (raw >> 24) & 0x1F == 0x1B {
        let rd  = (raw & 0x1F) as u8;
        let rn  = ((raw >> 5) & 0x1F) as u8;
        let ra  = ((raw >> 10) & 0x1F) as u8;
        let rm  = ((raw >> 16) & 0x1F) as u8;
        let o0  = (raw >> 15) & 0x1;
        // MUL = MADD with Ra=XZR, o0=0
        if ra == 31 && o0 == 0 {
            return ArmInstrKind::Mul { rd, rn, rm, is64 };
        }
        // Anything else: treat as Unknown for now
        return ArmInstrKind::Unknown(raw);
    }

    // ── Loads and Stores ──────────────────────────────────────────────────
    //
    // The load/store group is identified by bit [27]=1 and bits [25:24] variable.
    // We check specific patterns per instruction type.

    // ── Load/Store pair (STP/LDP) ─────────────────────────────────────────
    // [29:27]=101, [26]=0 for GP regs; [25:23] = opc/L
    // Signed offset:   [29:23] = 1010010 (STP), 1010011 (LDP)
    // Post-index:      [29:23] = 1010000 (STP), 1010001 (LDP)
    // Pre-index:       [29:23] = 1010110 (STP), 1010111 (LDP)
    {
        let bits_29_23 = (raw >> 23) & 0x7F;
        let rt1  = (raw & 0x1F) as u8;
        let rn   = ((raw >> 5) & 0x1F) as u8;
        let rt2  = ((raw >> 10) & 0x1F) as u8;
        let imm7 = (raw >> 15) & 0x7F;
        let sf_b = (raw >> 31) as u8;
        let pair_is64 = sf_b == 1;
        let scale = if pair_is64 { 3u32 } else { 2u32 };
        let simm  = sext64(imm7 as u64, 7) << scale;

        match bits_29_23 {
            0x52 => return ArmInstrKind::Stp     { rt1, rt2, rn, offset: simm, is64: pair_is64 },
            0x53 => return ArmInstrKind::Ldp     { rt1, rt2, rn, offset: simm, is64: pair_is64 },
            0x50 => return ArmInstrKind::StpPost { rt1, rt2, rn, simm,         is64: pair_is64 },
            0x51 => return ArmInstrKind::LdpPost { rt1, rt2, rn, simm,         is64: pair_is64 },
            0x56 => return ArmInstrKind::StpPre  { rt1, rt2, rn, simm,         is64: pair_is64 },
            0x57 => return ArmInstrKind::LdpPre  { rt1, rt2, rn, simm,         is64: pair_is64 },
            _ => {}
        }
    }

    // ── Load/Store exclusive: LDXR / STXR ────────────────────────────────
    // LDXR: 1x001000010111110111110000xxxxx  (top bits encode size)
    if raw & 0xBFFFF000 == 0x085F7C00 {
        let rt = (raw & 0x1F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let size64 = (raw >> 30) & 1 == 1;
        return ArmInstrKind::LdxrImm { rt, rn, is64: size64 };
    }
    // STXR: 1x001000000xxxxx011111xxxxxxxxxx
    if raw & 0xBFE07C00 == 0x08007C00 {
        let rt = (raw & 0x1F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rs = ((raw >> 16) & 0x1F) as u8;
        let size64 = (raw >> 30) & 1 == 1;
        return ArmInstrKind::StxrImm { rs, rt, rn, is64: size64 };
    }

    // ── Load/Store register (unsigned offset / post/pre / register offset) ─
    // [29:27]=111; [26]=0 for GP; [25:24] select addressing mode
    // size [31:30], opc [23:22] determine width and sign-extension

    // Helper: decode size+opc for regular load/stores
    let size = (raw >> 30) & 0x3;
    let vr   = (raw >> 26) & 0x1; // 0=GP, 1=FP/SIMD
    let bits_29_27 = (raw >> 27) & 0x7;

    if bits_29_27 == 0x7 && vr == 0 {
        let rt   = (raw & 0x1F) as u8;
        let rn   = ((raw >> 5) & 0x1F) as u8;
        let opc  = (raw >> 22) & 0x3;
        let mode = (raw >> 24) & 0x3;

        match mode {
            // ── Unsigned offset (imm12): [25:24]=01 ──────────────────────
            0x1 => {
                let imm12 = (raw >> 10) & 0xFFF;
                let offset = (imm12 << size) as i64;
                return decode_ls_unsigned(rt, rn, offset, size, opc, raw);
            }
            // ── Register offset: [25:24]=10, bit[21]=1 ───────────────────
            0x2 if (raw >> 21) & 1 == 1 => {
                let rm     = ((raw >> 16) & 0x1F) as u8;
                let extend = ((raw >> 13) & 0x7) as u8;
                let amount = ((raw >> 12) & 0x1) as u8;
                return decode_ls_reg(rt, rn, rm, extend, amount, size, opc, raw);
            }
            // ── Unscaled/pre/post: [25:24]=00 or [25:24]=10,bit21=0 ──────
            0x0 | 0x2 => {
                let imm9   = (raw >> 12) & 0x1FF;
                let simm9  = sext64(imm9 as u64, 9);
                let idx    = (raw >> 10) & 0x3;
                return decode_ls_prepost(rt, rn, simm9, idx, size, opc, raw);
            }
            _ => {}
        }
    }

    ArmInstrKind::Unknown(raw)
}

// ── Load/Store decode helpers ─────────────────────────────────────────────────

fn decode_ls_unsigned(rt: u8, rn: u8, offset: i64, size: u32, opc: u32, raw: u32) -> ArmInstrKind {
    match (size, opc) {
        (3, 0) => ArmInstrKind::StrImm    { rt, rn, offset, is64: true  },
        (3, 1) => ArmInstrKind::LdrImm    { rt, rn, offset, is64: true  },
        (2, 0) => ArmInstrKind::StrImm    { rt, rn, offset, is64: false },
        (2, 1) => ArmInstrKind::LdrImm    { rt, rn, offset, is64: false },
        (1, 0) => ArmInstrKind::StrhImm   { rt, rn, offset },
        (1, 1) => ArmInstrKind::LdrhImm   { rt, rn, offset },
        (1, 2) => ArmInstrKind::LdrshImm  { rt, rn, offset, is64: true  },
        (1, 3) => ArmInstrKind::LdrshImm  { rt, rn, offset, is64: false },
        (0, 0) => ArmInstrKind::StrbImm   { rt, rn, offset },
        (0, 1) => ArmInstrKind::LdrbImm   { rt, rn, offset },
        (0, 2) => ArmInstrKind::LdrsbImm  { rt, rn, offset, is64: true  },
        (0, 3) => ArmInstrKind::LdrsbImm  { rt, rn, offset, is64: false },
        (2, 2) => ArmInstrKind::LdrswImm  { rt, rn, offset },
        _      => ArmInstrKind::Unknown(raw),
    }
}

fn decode_ls_reg(rt: u8, rn: u8, rm: u8, extend: u8, amount: u8,
                 size: u32, opc: u32, raw: u32) -> ArmInstrKind {
    let is64 = match (size, opc) {
        (3, 1) | (3, 0) => true,
        _ => false,
    };
    match (size, opc) {
        (_, 0) => ArmInstrKind::StrRegOff { rt, rn, rm, extend, amount, is64 },
        (_, 1) => ArmInstrKind::LdrRegOff { rt, rn, rm, extend, amount, is64 },
        _      => ArmInstrKind::Unknown(raw),
    }
}

fn decode_ls_prepost(rt: u8, rn: u8, simm9: i64, idx: u32, size: u32, opc: u32, raw: u32) -> ArmInstrKind {
    // idx: 0b00=unscaled, 0b01=post-index, 0b10=unprivileged, 0b11=pre-index
    let is64 = size == 3;
    match idx {
        0x1 => match (size, opc) {
            (3, 0) | (2, 0) | (1, 0) | (0, 0) =>
                ArmInstrKind::StrImmPost { rt, rn, simm: simm9, is64 },
            (3, 1) | (2, 1) | (1, 1) | (0, 1) =>
                ArmInstrKind::LdrImmPost { rt, rn, simm: simm9, is64 },
            _ => ArmInstrKind::Unknown(raw),
        },
        0x3 => match (size, opc) {
            (3, 0) | (2, 0) | (1, 0) | (0, 0) =>
                ArmInstrKind::StrImmPre { rt, rn, simm: simm9, is64 },
            (3, 1) | (2, 1) | (1, 1) | (0, 1) =>
                ArmInstrKind::LdrImmPre { rt, rn, simm: simm9, is64 },
            _ => ArmInstrKind::Unknown(raw),
        },
        0x0 => {
            // STUR/LDUR (unscaled) — treat as regular LDR/STR with raw offset
            match (size, opc) {
                (3, 0) | (2, 0) | (1, 0) | (0, 0) =>
                    ArmInstrKind::StrImm { rt, rn, offset: simm9, is64 },
                (3, 1) | (2, 1) | (1, 1) | (0, 1) =>
                    ArmInstrKind::LdrImm { rt, rn, offset: simm9, is64 },
                _ => ArmInstrKind::Unknown(raw),
            }
        }
        _ => ArmInstrKind::Unknown(raw),
    }
}
