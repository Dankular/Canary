//! x86-64 interpreter — executes one decoded instruction at a time.

use canary_memory::GuestMemory;
use thiserror::Error;

use crate::{
    decoder::{Instruction, Mnemonic, Operand, MemAddr},
    flags::{self, *},
    registers::{CpuState, reg},
};

#[derive(Debug, Error)]
pub enum ExecError {
    #[error("memory error: {0}")]
    Mem(#[from] canary_memory::MemError),
    #[error("division by zero")]
    DivideByZero,
    #[error("SYSCALL trap")]
    Syscall,
    #[error("illegal instruction (UD2 / unknown)")]
    IllegalInstruction,
    #[error("HLT instruction")]
    Halt,
    #[error("INT {0}")]
    Int(u8),
    #[error("unimplemented instruction: {0:?}")]
    Unimplemented(String),
    #[error("I/O port: dir={dir} port={port:#06x} size={size} val={val:#010x}")]
    IoPort { dir: u8, port: u16, size: u8, val: u32 },
}

pub type ExecResult<T> = Result<T, ExecError>;

// ── Address computation ───────────────────────────────────────────────────────

pub fn compute_addr(cpu: &CpuState, ma: &MemAddr, next_rip: u64) -> u64 {
    let base = if ma.rip_relative {
        next_rip
    } else {
        ma.base.map(|r| cpu.gpr[r]).unwrap_or(0)
    };
    let index = ma.index.map(|r| cpu.gpr[r].wrapping_mul(ma.scale as u64)).unwrap_or(0);
    let linear = base.wrapping_add(index).wrapping_add(ma.disp as u64);
    // Apply FS/GS segment base for TLS-relative accesses (x86-64 ABI).
    // Decoder stores: FS=4 (prefix 0x64), GS=5 (prefix 0x65).
    // CS/DS/ES/SS have base 0 in 64-bit mode and are left as-is.
    match ma.seg {
        Some(4) => linear.wrapping_add(cpu.fs_base), // FS override
        Some(5) => linear.wrapping_add(cpu.gs_base), // GS override
        _       => linear,
    }
}

// ── Operand read ──────────────────────────────────────────────────────────────

pub fn read_op(cpu: &CpuState, mem: &GuestMemory, op: &Operand, sz: u8, next_rip: u64)
    -> ExecResult<u64>
{
    Ok(match op {
        Operand::Reg(r) => match sz {
            8  => cpu.read8(*r, false) as u64,
            16 => cpu.read16(*r) as u64,
            32 => cpu.read32(*r) as u64,
            _  => cpu.read64(*r),
        },
        Operand::Imm(v) => *v as u64,
        Operand::Mem(ma) => {
            let addr = compute_addr(cpu, ma, next_rip);
            match sz {
                8  => mem.read_u8(addr)?  as u64,
                16 => mem.read_u16(addr)? as u64,
                32 => mem.read_u32(addr)? as u64,
                _  => mem.read_u64(addr)?,
            }
        }
        Operand::Xmm(r) => {
            let bytes = &cpu.xmm[*r].0;
            u64::from_le_bytes(bytes[0..8].try_into().unwrap())
        }
        _ => 0,
    })
}

// ── Operand write ─────────────────────────────────────────────────────────────

pub fn write_op(cpu: &mut CpuState, mem: &mut GuestMemory, op: &Operand, sz: u8, val: u64, next_rip: u64)
    -> ExecResult<()>
{
    match op {
        Operand::Reg(r) => match sz {
            8  => cpu.write8(*r, val as u8, false),
            16 => cpu.write16(*r, val as u16),
            32 => cpu.write32(*r, val as u32), // zero-extends
            _  => cpu.write64(*r, val),
        },
        Operand::Mem(ma) => {
            let addr = compute_addr(cpu, ma, next_rip);
            match sz {
                8  => mem.write_u8(addr,  val as u8)?,
                16 => mem.write_u16(addr, val as u16)?,
                32 => mem.write_u32(addr, val as u32)?,
                _  => mem.write_u64(addr, val)?,
            }
        }
        _ => {}
    }
    Ok(())
}

// ── XMM 128-bit helpers ───────────────────────────────────────────────────────

/// Read 128 bits from an XMM register or memory operand into a byte array.
fn read_xmm128(cpu: &CpuState, mem: &GuestMemory, op: &Operand, next_rip: u64)
    -> ExecResult<[u8; 16]>
{
    match op {
        Operand::Xmm(r) => Ok(cpu.xmm[*r].0),
        Operand::Mem(ma) => {
            let addr = compute_addr(cpu, ma, next_rip);
            let lo = mem.read_u64(addr)?;
            let hi = mem.read_u64(addr.wrapping_add(8))?;
            let mut b = [0u8; 16];
            b[0..8].copy_from_slice(&lo.to_le_bytes());
            b[8..16].copy_from_slice(&hi.to_le_bytes());
            Ok(b)
        }
        _ => Ok([0u8; 16]),
    }
}

/// Write 128 bits to an XMM register or memory operand.
fn write_xmm128(cpu: &mut CpuState, mem: &mut GuestMemory, op: &Operand,
                val: [u8; 16], next_rip: u64) -> ExecResult<()>
{
    match op {
        Operand::Xmm(r) => { cpu.xmm[*r].0 = val; Ok(()) }
        Operand::Mem(ma) => {
            let addr = compute_addr(cpu, ma, next_rip);
            let lo = u64::from_le_bytes(val[0..8].try_into().unwrap());
            let hi = u64::from_le_bytes(val[8..16].try_into().unwrap());
            mem.write_u64(addr, lo)?;
            mem.write_u64(addr.wrapping_add(8), hi)?;
            Ok(())
        }
        _ => Ok(()),
    }
}

// ── Condition code evaluation ─────────────────────────────────────────────────

pub fn eval_cc(rflags: u64, cc: u8) -> bool {
    let cf = rflags & CF != 0;
    let pf = rflags & PF != 0;
    let zf = rflags & ZF != 0;
    let sf = rflags & SF != 0;
    let of = rflags & OF != 0;
    match cc & 0xF {
        0x0 => of,                   // O
        0x1 => !of,                  // NO
        0x2 => cf,                   // B / C / NAE
        0x3 => !cf,                  // AE / NB / NC
        0x4 => zf,                   // E / Z
        0x5 => !zf,                  // NE / NZ
        0x6 => cf || zf,             // BE / NA
        0x7 => !cf && !zf,           // A / NBE
        0x8 => sf,                   // S
        0x9 => !sf,                  // NS
        0xA => pf,                   // P / PE
        0xB => !pf,                  // NP / PO
        0xC => sf != of,             // L / NGE
        0xD => sf == of,             // GE / NL
        0xE => zf || (sf != of),     // LE / NG
        0xF => !zf && (sf == of),    // G / NLE
        _   => false,
    }
}

// ── Mask helper ───────────────────────────────────────────────────────────────

fn mask(sz: u8) -> u64 { flags::mask_for(sz) }

// ── Main execute function ─────────────────────────────────────────────────────

/// Execute one instruction.  Returns `Ok(())` on success, or an error that the
/// caller must handle (syscall, halt, illegal instruction, etc.).
pub fn execute(
    instr:    &Instruction,
    cpu:      &mut CpuState,
    mem:      &mut GuestMemory,
) -> ExecResult<()> {
    use Mnemonic::*;

    // Advance RIP before execution so RIP-relative operands are computed
    // relative to the *next* instruction (x86 semantics).
    let next_rip = cpu.rip.wrapping_add(instr.length as u64);
    let sz = instr.op_size;
    let ops = &instr.operands;

    macro_rules! read {
        ($op:expr) => { read_op(cpu, mem, $op, sz, next_rip)? }
    }
    macro_rules! write {
        ($op:expr, $val:expr) => { write_op(cpu, mem, $op, sz, $val, next_rip)? }
    }

    match &instr.mnemonic {
        // ── NOP ───────────────────────────────────────────────────────────
        Nop => {}

        // ── MOV ──────────────────────────────────────────────────────────
        Mov => {
            let val = read!(&ops[1]);
            write!(&ops[0], val);
        }
        Movzx => {
            // source is smaller; destination is op_size
            let src_sz = match &ops[1] {
                Operand::Mem(_) => if sz == 32 || sz == 64 { 16 } else { 8 },
                _ => 8,
            };
            let val = read_op(cpu, mem, &ops[1], src_sz, next_rip)? & mask(src_sz);
            write!(&ops[0], val);
        }
        Movsx => {
            let src_sz: u8 = if sz == 64 { 32 } else { 8 };
            let val = read_op(cpu, mem, &ops[1], src_sz, next_rip)?;
            let sign_bit = 1u64 << (src_sz - 1);
            let extended = if val & sign_bit != 0 {
                val | !mask(src_sz)
            } else {
                val & mask(src_sz)
            };
            write!(&ops[0], extended);
        }

        // MOVSXD r64/r32, r/m32 (opcode 0x63 in 64-bit mode):
        // Always reads 32-bit source; sign-extends to 64 when sz==64, else 32-bit (zero-extends).
        Movsxd => {
            let val = read_op(cpu, mem, &ops[1], 32, next_rip)?;
            let extended = if sz == 64 {
                (val as u32) as i32 as i64 as u64  // sign-extend 32→64
            } else {
                val & 0xFFFF_FFFF                  // zero-extend 32→32 (r32 write)
            };
            write!(&ops[0], extended);
        }

        // ── LEA ──────────────────────────────────────────────────────────
        Lea => {
            let Operand::Mem(ref ma) = ops[1] else { cpu.rip = next_rip; return Ok(()); };
            let addr = compute_addr(cpu, ma, next_rip);
            write!(&ops[0], addr & mask(sz));
        }

        // ── PUSH ─────────────────────────────────────────────────────────
        Push => {
            let val = read!(&ops[0]);
            let rsp = cpu.push_rsp();
            mem.write_u64(rsp, val)?;
        }

        // ── POP ──────────────────────────────────────────────────────────
        Pop => {
            let rsp = cpu.pop_rsp();
            let val = mem.read_u64(rsp)?;
            write!(&ops[0], val);
        }

        // ── ENTER / LEAVE ─────────────────────────────────────────────────
        Enter => {
            // ENTER alloc_size, level — for level=0 (common case):
            //   push RBP; RBP = RSP; RSP -= alloc_size
            let alloc_size = if let Operand::Imm(n) = ops[0] { n as u64 } else { 0 };
            let rbp = cpu.gpr[reg::RBP];
            let rsp = cpu.push_rsp();
            mem.write_u64(rsp, rbp)?;
            cpu.gpr[reg::RBP] = cpu.gpr[reg::RSP];
            cpu.gpr[reg::RSP] = cpu.gpr[reg::RSP].wrapping_sub(alloc_size);
        }
        Leave => {
            // RSP = RBP; pop RBP
            cpu.gpr[reg::RSP] = cpu.gpr[reg::RBP];
            let rsp = cpu.pop_rsp();
            cpu.gpr[reg::RBP] = mem.read_u64(rsp)?;
        }

        // ── XCHG ─────────────────────────────────────────────────────────
        Xchg => {
            let a = read!(&ops[0]);
            let b = read!(&ops[1]);
            write!(&ops[0], b);
            write!(&ops[1], a);
        }

        // ── ADD ──────────────────────────────────────────────────────────
        Add => {
            let dst = read!(&ops[0]);
            let src = read!(&ops[1]);
            let res = flags::add_flags(&mut cpu.rflags, dst, src, 0, sz);
            write!(&ops[0], res);
        }

        // ── ADC ──────────────────────────────────────────────────────────
        Adc => {
            let dst   = read!(&ops[0]);
            let src   = read!(&ops[1]);
            let carry = if cpu.rflags & CF != 0 { 1 } else { 0 };
            let res   = flags::add_flags(&mut cpu.rflags, dst, src, carry, sz);
            write!(&ops[0], res);
        }

        // ── SUB ──────────────────────────────────────────────────────────
        Sub => {
            let dst = read!(&ops[0]);
            let src = read!(&ops[1]);
            let res = flags::sub_flags(&mut cpu.rflags, dst, src, 0, sz);
            write!(&ops[0], res);
        }

        // ── SBB ──────────────────────────────────────────────────────────
        Sbb => {
            let dst    = read!(&ops[0]);
            let src    = read!(&ops[1]);
            let borrow = if cpu.rflags & CF != 0 { 1 } else { 0 };
            let res    = flags::sub_flags(&mut cpu.rflags, dst, src, borrow, sz);
            write!(&ops[0], res);
        }

        // ── AND ──────────────────────────────────────────────────────────
        And => {
            let res = read!(&ops[0]) & read!(&ops[1]);
            flags::update_szp(&mut cpu.rflags, res, sz);
            cpu.rflags &= !(CF | OF);
            write!(&ops[0], res & mask(sz));
        }

        // ── OR ───────────────────────────────────────────────────────────
        Or => {
            let res = read!(&ops[0]) | read!(&ops[1]);
            flags::update_szp(&mut cpu.rflags, res, sz);
            cpu.rflags &= !(CF | OF);
            write!(&ops[0], res & mask(sz));
        }

        // ── XOR ──────────────────────────────────────────────────────────
        Xor => {
            let res = read!(&ops[0]) ^ read!(&ops[1]);
            flags::update_szp(&mut cpu.rflags, res, sz);
            cpu.rflags &= !(CF | OF);
            write!(&ops[0], res & mask(sz));
        }

        // ── NOT ──────────────────────────────────────────────────────────
        Not => {
            let val = !read!(&ops[0]) & mask(sz);
            write!(&ops[0], val);
        }

        // ── NEG ──────────────────────────────────────────────────────────
        Neg => {
            let val = read!(&ops[0]);
            let res = flags::sub_flags(&mut cpu.rflags, 0, val, 0, sz);
            write!(&ops[0], res);
        }

        // ── CMP ──────────────────────────────────────────────────────────
        Cmp => {
            let dst = read!(&ops[0]);
            let src = read!(&ops[1]);
            flags::sub_flags(&mut cpu.rflags, dst, src, 0, sz);
        }

        // ── TEST ─────────────────────────────────────────────────────────
        Test => {
            let res = read!(&ops[0]) & read!(&ops[1]);
            flags::update_szp(&mut cpu.rflags, res, sz);
            cpu.rflags &= !(CF | OF);
        }

        // ── INC / DEC ────────────────────────────────────────────────────
        Inc => {
            let dst = read!(&ops[0]);
            let old_cf = cpu.rflags & CF;
            let res = flags::add_flags(&mut cpu.rflags, dst, 1, 0, sz);
            cpu.rflags = (cpu.rflags & !CF) | old_cf; // INC doesn't affect CF
            write!(&ops[0], res);
        }
        Dec => {
            let dst = read!(&ops[0]);
            let old_cf = cpu.rflags & CF;
            let res = flags::sub_flags(&mut cpu.rflags, dst, 1, 0, sz);
            cpu.rflags = (cpu.rflags & !CF) | old_cf;
            write!(&ops[0], res);
        }

        // ── IMUL ─────────────────────────────────────────────────────────
        Imul => {
            match ops.len() {
                1 => {
                    // IMUL r/m: RDX:RAX = RAX * src (signed)
                    let src = read!(&ops[0]) as i64;
                    let rax = cpu.read64(reg::RAX) as i64;
                    let res = (rax as i128).wrapping_mul(src as i128);
                    cpu.write64(reg::RAX, res as u64);
                    cpu.write64(reg::RDX, (res >> 64) as u64);
                    let overflow = (res as i64 as i128) != res;
                    flags::set_flag(&mut cpu.rflags, CF | OF, overflow);
                }
                2 => {
                    let dst_val = read!(&ops[0]) as i64;
                    let src_val = read!(&ops[1]) as i64;
                    let res = (dst_val as i128).wrapping_mul(src_val as i128);
                    write!(&ops[0], res as u64 & mask(sz));
                    let overflow = (res as i64 as i128) != res;
                    flags::set_flag(&mut cpu.rflags, CF | OF, overflow);
                }
                3 => {
                    let src = read!(&ops[1]) as i64;
                    let imm = if let Operand::Imm(v) = ops[2] { v } else { 0 };
                    let res = (src as i128).wrapping_mul(imm as i128);
                    write!(&ops[0], res as u64 & mask(sz));
                    let overflow = (res as i64 as i128) != res;
                    flags::set_flag(&mut cpu.rflags, CF | OF, overflow);
                }
                _ => {}
            }
        }

        // ── MUL ──────────────────────────────────────────────────────────
        Mul => {
            let src = read!(&ops[0]);
            let rax = cpu.read64(reg::RAX);
            let res = (rax as u128).wrapping_mul(src as u128);
            cpu.write64(reg::RAX, res as u64);
            cpu.write64(reg::RDX, (res >> 64) as u64);
            let overflow = res >> sz != 0;
            flags::set_flag(&mut cpu.rflags, CF | OF, overflow);
        }

        // ── DIV / IDIV ────────────────────────────────────────────────────
        Div => {
            let divisor = read!(&ops[0]);
            if divisor == 0 { return Err(ExecError::DivideByZero); }
            let rdx = cpu.read64(reg::RDX);
            let rax = cpu.read64(reg::RAX);
            let dividend = ((rdx as u128) << 64) | rax as u128;
            let quot = dividend / divisor as u128;
            let rem  = dividend % divisor as u128;
            cpu.write64(reg::RAX, quot as u64);
            cpu.write64(reg::RDX, rem  as u64);
        }
        Idiv => {
            let divisor = read!(&ops[0]) as i64;
            if divisor == 0 { return Err(ExecError::DivideByZero); }
            let rdx = cpu.read64(reg::RDX) as i64;
            let rax = cpu.read64(reg::RAX) as i64;
            let dividend = ((rdx as i128) << 64) | rax as i128;
            let quot = dividend / divisor as i128;
            let rem  = dividend % divisor as i128;
            cpu.write64(reg::RAX, quot as u64);
            cpu.write64(reg::RDX, rem  as u64);
        }

        // ── Shifts ───────────────────────────────────────────────────────
        Shl | Shr | Sar => {
            let val   = read!(&ops[0]);
            let cnt   = (read_op(cpu, mem, &ops[1], 8, next_rip)? & 63) as u8;
            let m     = mask(sz);
            let res   = match &instr.mnemonic {
                Shl => val.wrapping_shl(cnt as u32),
                Shr => (val & m).wrapping_shr(cnt as u32),
                Sar => ((val as i64).wrapping_shr(cnt as u32)) as u64,
                _   => unreachable!(),
            };
            if cnt > 0 {
                let last_shifted_out = match &instr.mnemonic {
                    Shl => (val >> (sz - cnt)) & 1,
                    _   => (val >> (cnt - 1)) & 1,
                };
                flags::set_flag(&mut cpu.rflags, CF, last_shifted_out != 0);
                flags::update_szp(&mut cpu.rflags, res, sz);
                if cnt == 1 {
                    let sf = res >> (sz - 1) & 1;
                    flags::set_flag(&mut cpu.rflags, OF, match &instr.mnemonic {
                        Shl => sf != last_shifted_out,
                        Sar => false,
                        Shr => val >> (sz - 1) != 0,
                        _   => false,
                    });
                }
            }
            write!(&ops[0], res & m);
        }
        Rol | Ror => {
            let val = read!(&ops[0]) & mask(sz);
            let cnt = (read_op(cpu, mem, &ops[1], 8, next_rip)? % sz as u64) as u32;
            let res = match &instr.mnemonic {
                Rol => val.rotate_left(cnt),
                Ror => val.rotate_right(cnt),
                _   => unreachable!(),
            } & mask(sz);
            write!(&ops[0], res);
            if cnt > 0 {
                let cf_bit = if matches!(instr.mnemonic, Rol) { res & 1 } else { res >> (sz-1) & 1 };
                flags::set_flag(&mut cpu.rflags, CF, cf_bit != 0);
            }
        }

        // ── BSF / BSR ─────────────────────────────────────────────────────
        Bsf => {
            let src = read!(&ops[1]) & mask(sz);
            if src == 0 {
                flags::set_flag(&mut cpu.rflags, ZF, true);
            } else {
                write!(&ops[0], src.trailing_zeros() as u64);
                flags::set_flag(&mut cpu.rflags, ZF, false);
            }
        }
        Bsr => {
            let src = read!(&ops[1]) & mask(sz);
            if src == 0 {
                flags::set_flag(&mut cpu.rflags, ZF, true);
            } else {
                write!(&ops[0], (sz as u64 - 1) - src.leading_zeros() as u64);
                flags::set_flag(&mut cpu.rflags, ZF, false);
            }
        }

        // ── Jcc ──────────────────────────────────────────────────────────
        Jcc(cc) => {
            if eval_cc(cpu.rflags, *cc) {
                if let Operand::Imm(rel) = ops[0] {
                    cpu.rip = next_rip.wrapping_add(rel as u64);
                    return Ok(());
                }
            }
        }

        // ── JMP ──────────────────────────────────────────────────────────
        Jmp => {
            let target = match &ops[0] {
                Operand::Imm(rel)  => next_rip.wrapping_add(*rel as u64),
                Operand::Reg(r)    => cpu.gpr[*r],
                Operand::Mem(ma)   => {
                    let addr = compute_addr(cpu, ma, next_rip);
                    mem.read_u64(addr)?
                }
                _ => next_rip,
            };
            cpu.rip = target;
            return Ok(());
        }

        // ── CALL ─────────────────────────────────────────────────────────
        Call => {
            let target = match &ops[0] {
                Operand::Imm(rel)  => next_rip.wrapping_add(*rel as u64),
                Operand::Reg(r)    => cpu.gpr[*r],
                Operand::Mem(ma)   => {
                    let addr = compute_addr(cpu, ma, next_rip);
                    mem.read_u64(addr)?
                }
                _ => next_rip,
            };
            let rsp = cpu.push_rsp();
            mem.write_u64(rsp, next_rip)?;
            cpu.rip = target;
            return Ok(());
        }

        // ── RET ──────────────────────────────────────────────────────────
        Ret => {
            let rsp = cpu.pop_rsp();
            let target = mem.read_u64(rsp)?;
            cpu.rip = target;
            return Ok(());
        }
        RetN => {
            let rsp = cpu.pop_rsp();
            let target = mem.read_u64(rsp)?;
            if let Operand::Imm(n) = ops[0] {
                cpu.gpr[reg::RSP] = cpu.gpr[reg::RSP].wrapping_add(n as u64);
            }
            cpu.rip = target;
            return Ok(());
        }

        // ── SYSCALL ──────────────────────────────────────────────────────
        Syscall => {
            // Store next RIP in RCX (Linux syscall ABI).
            cpu.gpr[reg::RCX] = next_rip;
            // R11 = RFLAGS.
            cpu.gpr[reg::R11] = cpu.rflags;
            cpu.rip = next_rip;
            return Err(ExecError::Syscall);
        }

        // ── INT / INT3 ───────────────────────────────────────────────────
        Int3 => { cpu.rip = next_rip; return Err(ExecError::Int(3)); }
        Int  => {
            if let Operand::Imm(n) = ops[0] {
                cpu.rip = next_rip;
                return Err(ExecError::Int(n as u8));
            }
        }

        // ── HLT ──────────────────────────────────────────────────────────
        Hlt => { cpu.rip = next_rip; return Err(ExecError::Halt); }

        // ── Ud2 ──────────────────────────────────────────────────────────
        Ud2 => { cpu.rip = next_rip; return Err(ExecError::IllegalInstruction); }
        Unknown(op) => {
            log::error!("canary: unknown opcode byte {:#04x} @ rip={:#x}", op, cpu.rip);
            cpu.rip = next_rip;
            return Err(ExecError::IllegalInstruction);
        }

        // ── CMOVcc ───────────────────────────────────────────────────────
        Cmovcc(cc) => {
            if eval_cc(cpu.rflags, *cc) {
                let val = read!(&ops[1]);
                write!(&ops[0], val);
            }
        }

        // ── SETcc ────────────────────────────────────────────────────────
        Setcc(cc) => {
            let val = if eval_cc(cpu.rflags, *cc) { 1u64 } else { 0 };
            write_op(cpu, mem, &ops[0], 8, val, next_rip)?;
        }

        // ── CMPXCHG ──────────────────────────────────────────────────────
        Cmpxchg => {
            let acc = cpu.read64(reg::RAX) & mask(sz);
            let dst = read!(&ops[0]);
            if acc == dst {
                flags::set_flag(&mut cpu.rflags, ZF, true);
                let src = read!(&ops[1]);
                write!(&ops[0], src);
            } else {
                flags::set_flag(&mut cpu.rflags, ZF, false);
                cpu.write64(reg::RAX, dst);
            }
        }

        // ── XADD ─────────────────────────────────────────────────────────
        Xadd => {
            let dst = read!(&ops[0]);
            let src = read!(&ops[1]);
            write!(&ops[1], dst);
            let res = flags::add_flags(&mut cpu.rflags, dst, src, 0, sz);
            write!(&ops[0], res);
        }

        // ── CBW / CWDE / CDQE (opcode 0x98): sign-extend into RAX only ──
        // Does NOT touch RDX — that is for CDQ/CQO (opcode 0x99).
        Cwde | Cbw | Cdqe => {
            let rax = cpu.read64(reg::RAX);
            let extended = match sz {
                16 => (rax & 0xff) as i8 as i64 as u64,    // CBW:  AL  → AX
                64 => (rax as u32) as i32 as i64 as u64,   // CDQE: EAX → RAX
                _  => (rax as u16) as i16 as i64 as u64,   // CWDE: AX  → EAX
            };
            cpu.write64(reg::RAX, extended);
        }

        // ── CWD / CDQ / CQO (opcode 0x99): sign-extend RAX into RDX ─────
        Cdq | Cqo | Cwd => {
            let rax = cpu.read64(reg::RAX);
            let sign = match sz {
                16 => if rax & 0x8000 != 0 { u64::from(u16::MAX) } else { 0 }, // CWD: AX→DX
                64 => (rax as i64 >> 63) as u64,                                // CQO: RAX→RDX
                _  => if rax & 0x8000_0000 != 0 { u64::from(u32::MAX) } else { 0 }, // CDQ: EAX→EDX
            };
            cpu.write64(reg::RDX, sign);
        }

        // ── Flags ────────────────────────────────────────────────────────
        Clc => { cpu.rflags &= !CF; }
        Stc => { cpu.rflags |=  CF; }
        Cld => { cpu.rflags &= !DF; }
        Std => { cpu.rflags |=  DF; }
        Cli => { cpu.rflags &= !IF; }
        Sti => { cpu.rflags |=  IF; }
        Cmc => { cpu.rflags ^=  CF; }

        Lahf => {
            let ah = (cpu.rflags & 0xFF) as u8;
            cpu.gpr[reg::RAX] = (cpu.gpr[reg::RAX] & !0xFF00) | ((ah as u64) << 8);
        }
        Sahf => {
            let ah = (cpu.gpr[reg::RAX] >> 8) as u8;
            cpu.rflags = (cpu.rflags & !0xFF) | ah as u64;
        }
        Pushf => {
            let rsp = cpu.push_rsp();
            mem.write_u64(rsp, cpu.rflags & 0x00FF_FFFF)?;
        }
        Popf => {
            let rsp = cpu.pop_rsp();
            let v = mem.read_u64(rsp)?;
            cpu.rflags = (cpu.rflags & !0x00FF_FFFF) | (v & 0x00FF_FFFF);
        }

        // ── CPUID ────────────────────────────────────────────────────────
        Cpuid => {
            let leaf = cpu.gpr[reg::RAX] as u32;
            let (eax, ebx, ecx, edx) = emulate_cpuid(leaf);
            cpu.write32(reg::RAX, eax);
            cpu.write32(reg::RBX, ebx);
            cpu.write32(reg::RCX, ecx);
            cpu.write32(reg::RDX, edx);
        }

        // ── RDTSC ────────────────────────────────────────────────────────
        Rdtsc => {
            // Return a fake but monotonically-increasing TSC.
            static TSC: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let tsc = TSC.fetch_add(1000, std::sync::atomic::Ordering::Relaxed);
            cpu.write32(reg::RAX, tsc as u32);
            cpu.write32(reg::RDX, (tsc >> 32) as u32);
        }

        // ── RDTSCP ───────────────────────────────────────────────────────
        Rdtscp => {
            // Like RDTSC but also writes IA32_TSC_AUX (processor ID) into ECX.
            static TSC2: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let tsc = TSC2.fetch_add(1000, std::sync::atomic::Ordering::Relaxed);
            cpu.write32(reg::RAX, tsc as u32);
            cpu.write32(reg::RDX, (tsc >> 32) as u32);
            cpu.write32(reg::RCX, 0); // processor ID = 0 (single core)
        }

        // ── XGETBV ───────────────────────────────────────────────────────
        Xgetbv => {
            // Read Extended Control Register XCR[ECX] into EDX:EAX.
            // We advertise XCR0 = 0x3 (x87 + SSE state saved by OS) which
            // tells glibc that SSE is available but AVX (bit 2) is not,
            // preventing it from emitting YMM instructions we don't support.
            let xcr = cpu.gpr[reg::RCX] as u32;
            let (edx, eax): (u32, u32) = match xcr {
                0 => (0, 0x3), // XCR0: FPU (bit 0) + SSE (bit 1) only
                _ => (0, 0),
            };
            cpu.write32(reg::RAX, eax);
            cpu.write32(reg::RDX, edx);
        }

        // ── String instructions ───────────────────────────────────────────
        Movs => {
            let dir    = if cpu.rflags & DF != 0 { u64::MAX } else { 1 };
            let _src   = cpu.gpr[reg::RSI];
            let _dst   = cpu.gpr[reg::RDI];
            let count  = if instr.prefixes.rep != 0 { cpu.gpr[reg::RCX] } else { 1 };
            let stride = (sz / 8) as u64;
            for _ in 0..count {
                let val = match sz {
                    8  => mem.read_u8(cpu.gpr[reg::RSI])?  as u64,
                    16 => mem.read_u16(cpu.gpr[reg::RSI])? as u64,
                    32 => mem.read_u32(cpu.gpr[reg::RSI])? as u64,
                    _  => mem.read_u64(cpu.gpr[reg::RSI])?,
                };
                match sz {
                    8  => mem.write_u8( cpu.gpr[reg::RDI], val as u8)?,
                    16 => mem.write_u16(cpu.gpr[reg::RDI], val as u16)?,
                    32 => mem.write_u32(cpu.gpr[reg::RDI], val as u32)?,
                    _  => mem.write_u64(cpu.gpr[reg::RDI], val)?,
                }
                cpu.gpr[reg::RSI] = cpu.gpr[reg::RSI].wrapping_add(stride.wrapping_mul(dir));
                cpu.gpr[reg::RDI] = cpu.gpr[reg::RDI].wrapping_add(stride.wrapping_mul(dir));
            }
            if instr.prefixes.rep != 0 { cpu.gpr[reg::RCX] = 0; }
        }

        Stos => {
            let dir   = if cpu.rflags & DF != 0 { u64::MAX } else { 1 };
            let val   = cpu.gpr[reg::RAX];
            let count = if instr.prefixes.rep != 0 { cpu.gpr[reg::RCX] } else { 1 };
            let stride = (sz / 8) as u64;
            for _ in 0..count {
                match sz {
                    8  => mem.write_u8( cpu.gpr[reg::RDI], val as u8)?,
                    16 => mem.write_u16(cpu.gpr[reg::RDI], val as u16)?,
                    32 => mem.write_u32(cpu.gpr[reg::RDI], val as u32)?,
                    _  => mem.write_u64(cpu.gpr[reg::RDI], val)?,
                }
                cpu.gpr[reg::RDI] = cpu.gpr[reg::RDI].wrapping_add(stride.wrapping_mul(dir));
            }
            if instr.prefixes.rep != 0 { cpu.gpr[reg::RCX] = 0; }
        }

        Scas => {
            let dir    = if cpu.rflags & DF != 0 { u64::MAX } else { 1 };
            let acc    = cpu.gpr[reg::RAX] & mask(sz);
            let stride = (sz / 8) as u64;
            let count  = if instr.prefixes.rep != 0 { cpu.gpr[reg::RCX] } else { 1 };
            let mut remaining = count;
            while remaining > 0 {
                let val = match sz {
                    8  => mem.read_u8(cpu.gpr[reg::RDI])?  as u64,
                    16 => mem.read_u16(cpu.gpr[reg::RDI])? as u64,
                    32 => mem.read_u32(cpu.gpr[reg::RDI])? as u64,
                    _  => mem.read_u64(cpu.gpr[reg::RDI])?,
                };
                flags::sub_flags(&mut cpu.rflags, acc, val, 0, sz);
                cpu.gpr[reg::RDI] = cpu.gpr[reg::RDI].wrapping_add(stride.wrapping_mul(dir));
                remaining -= 1;
                if instr.prefixes.rep == 0xF3 && cpu.rflags & ZF != 0 { break; } // REPE
                if instr.prefixes.rep == 0xF2 && cpu.rflags & ZF == 0 { break; } // REPNE
            }
            if instr.prefixes.rep != 0 { cpu.gpr[reg::RCX] = remaining; }
        }

        // ── OUT DX, AL/AX/EAX ────────────────────────────────────────────
        Out => {
            let port = cpu.read32(reg::RDX) as u16;
            let val = match instr.op_size {
                8  => cpu.read8(reg::RAX, false) as u32,
                16 => cpu.read16(reg::RAX) as u32,
                _  => cpu.read32(reg::RAX),
            };
            cpu.rip = next_rip;
            return Err(ExecError::IoPort { dir: 1, port, size: instr.op_size, val });
        }

        // ── IN AL/AX/EAX, DX ─────────────────────────────────────────────
        In => {
            let port = cpu.read32(reg::RDX) as u16;
            cpu.rip = next_rip;
            return Err(ExecError::IoPort { dir: 0, port, size: instr.op_size, val: 0 });
        }

        // ── SSE2 packed-integer XMM operations ───────────────────────────

        Pxor => {
            let src = read_xmm128(cpu, mem, &ops[1], next_rip)?;
            let n = match &ops[0] { Operand::Xmm(n) => *n, _ => 0 };
            for i in 0..16 { cpu.xmm[n].0[i] ^= src[i]; }
        }
        Por => {
            let src = read_xmm128(cpu, mem, &ops[1], next_rip)?;
            let n = match &ops[0] { Operand::Xmm(n) => *n, _ => 0 };
            for i in 0..16 { cpu.xmm[n].0[i] |= src[i]; }
        }
        Pand => {
            let src = read_xmm128(cpu, mem, &ops[1], next_rip)?;
            let n = match &ops[0] { Operand::Xmm(n) => *n, _ => 0 };
            for i in 0..16 { cpu.xmm[n].0[i] &= src[i]; }
        }
        Pandn => {
            let src = read_xmm128(cpu, mem, &ops[1], next_rip)?;
            let n = match &ops[0] { Operand::Xmm(n) => *n, _ => 0 };
            for i in 0..16 { cpu.xmm[n].0[i] = !cpu.xmm[n].0[i] & src[i]; }
        }
        Pcmpeqb => {
            // Each byte: 0xFF if equal, 0x00 if not.
            let src = read_xmm128(cpu, mem, &ops[1], next_rip)?;
            let n = match &ops[0] { Operand::Xmm(n) => *n, _ => 0 };
            let dst = cpu.xmm[n].0;
            for i in 0..16 { cpu.xmm[n].0[i] = if dst[i] == src[i] { 0xFF } else { 0x00 }; }
        }
        Movdqa | Movdqu | Movaps | Movups => {
            let src = read_xmm128(cpu, mem, &ops[1], next_rip)?;
            write_xmm128(cpu, mem, &ops[0], src, next_rip)?;
        }
        Movd => {
            // MOVD xmm, r/m32: zero-extend 32-bit value into XMM, upper 96 bits = 0.
            let val = read_op(cpu, mem, &ops[1], 32, next_rip)?;
            let n = match &ops[0] { Operand::Xmm(n) => *n, _ => 0 };
            cpu.xmm[n].0 = [0u8; 16];
            cpu.xmm[n].0[0..4].copy_from_slice(&(val as u32).to_le_bytes());
        }
        Movq => {
            // MOVQ XMM←XMM/m64/r64: load 64b into XMM low, zero high 64b.
            // MOVQ m64/r64←XMM: store XMM low 64b.
            match (&ops[0], &ops[1]) {
                (Operand::Xmm(d), Operand::Xmm(s)) => {
                    let low: [u8; 8] = cpu.xmm[*s].0[0..8].try_into().unwrap();
                    cpu.xmm[*d].0 = [0u8; 16];
                    cpu.xmm[*d].0[0..8].copy_from_slice(&low);
                }
                (Operand::Xmm(d), _) => {
                    let val = read_op(cpu, mem, &ops[1], 64, next_rip)?;
                    cpu.xmm[*d].0 = [0u8; 16];
                    cpu.xmm[*d].0[0..8].copy_from_slice(&val.to_le_bytes());
                }
                (_, Operand::Xmm(s)) => {
                    let val = u64::from_le_bytes(cpu.xmm[*s].0[0..8].try_into().unwrap());
                    write_op(cpu, mem, &ops[0], 64, val, next_rip)?;
                }
                _ => {}
            }
        }
        Movhps => {
            // MOVHPS XMM,m64: load m64 into XMM high 64b, keep low unchanged.
            // MOVHPS m64,XMM: store XMM high 64b to memory.
            // MOVLHPS XMM1,XMM2 (reg-reg): XMM1.high = XMM2.low.
            match (&ops[0], &ops[1]) {
                (Operand::Xmm(d), Operand::Xmm(s)) => {
                    // MOVLHPS: dst.high = src.low
                    let low: [u8; 8] = cpu.xmm[*s].0[0..8].try_into().unwrap();
                    cpu.xmm[*d].0[8..16].copy_from_slice(&low);
                }
                (Operand::Xmm(d), _) => {
                    // MOVHPS load: XMM.high = m64, keep XMM.low
                    let val = read_op(cpu, mem, &ops[1], 64, next_rip)?;
                    cpu.xmm[*d].0[8..16].copy_from_slice(&val.to_le_bytes());
                }
                (_, Operand::Xmm(s)) => {
                    // MOVHPS store: m64 = XMM.high
                    let val = u64::from_le_bytes(cpu.xmm[*s].0[8..16].try_into().unwrap());
                    write_op(cpu, mem, &ops[0], 64, val, next_rip)?;
                }
                _ => {}
            }
        }
        Pmovmskb => {
            // Extract the MSB of each of the 16 bytes in XMM into a 16-bit mask in r32.
            let n = match &ops[1] { Operand::Xmm(n) => *n, _ => 0 };
            let mut mask = 0u32;
            for i in 0..16 { if cpu.xmm[n].0[i] & 0x80 != 0 { mask |= 1 << i; } }
            write_op(cpu, mem, &ops[0], 32, mask as u64, next_rip)?;
        }
        Punpcklbw => {
            // Interleave low 8 bytes of dst and src: [d0,s0,d1,s1,...,d7,s7]
            let src = read_xmm128(cpu, mem, &ops[1], next_rip)?;
            let n = match &ops[0] { Operand::Xmm(n) => *n, _ => 0 };
            let dst = cpu.xmm[n].0;
            let mut result = [0u8; 16];
            for i in 0..8 { result[i*2] = dst[i]; result[i*2+1] = src[i]; }
            cpu.xmm[n].0 = result;
        }
        Punpcklwd => {
            // Interleave low 4 words of dst and src: [d0,s0,d1,s1,d2,s2,d3,s3] (words)
            let src = read_xmm128(cpu, mem, &ops[1], next_rip)?;
            let n = match &ops[0] { Operand::Xmm(n) => *n, _ => 0 };
            let dst = cpu.xmm[n].0;
            let mut result = [0u8; 16];
            for i in 0..4 {
                result[i*4]   = dst[i*2];   result[i*4+1] = dst[i*2+1];
                result[i*4+2] = src[i*2];   result[i*4+3] = src[i*2+1];
            }
            cpu.xmm[n].0 = result;
        }
        Pshufd => {
            // Shuffle 4 dwords within XMM using imm8: bits[2k+1:2k] = source index for dst dword k.
            let src = read_xmm128(cpu, mem, &ops[1], next_rip)?;
            let imm = match &ops[2] { Operand::Imm(v) => *v as u8, _ => 0 };
            let n = match &ops[0] { Operand::Xmm(n) => *n, _ => 0 };
            let mut result = [0u8; 16];
            for i in 0..4usize {
                let sel = ((imm >> (i * 2)) & 3) as usize;
                result[i*4..i*4+4].copy_from_slice(&src[sel*4..sel*4+4]);
            }
            cpu.xmm[n].0 = result;
        }

        // ── Unimplemented — continue for now ─────────────────────────────
        _ => {
            // Log and skip rather than crashing for unimplemented insns.
            log::warn!("unimplemented: {:?} @ {:#x}", instr.mnemonic, cpu.rip);
        }
    }

    cpu.rip = next_rip;
    Ok(())
}

// ── CPUID emulation ───────────────────────────────────────────────────────────

fn emulate_cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    match leaf {
        0 => {
            // Max basic leaf = 7, vendor = "GenuineIntel" (fake)
            (7, 0x756e6547, 0x6c65746e, 0x49656e69)
        }
        1 => {
            // Family 6, Model 15.  Deliberately omit SSE2 (and higher) so
            // that ld-linux uses its scalar RELA relocation loop.  The SSE2
            // vectorised loop uses MOVDQA/PADDQ/MOVQ-xmm which we stub as
            // Nop; leaving SSE2 advertised causes relocations to be silently
            // skipped, producing null-pointer crashes when ld-linux calls
            // through unpatched GOT entries.  Scalar relocation uses only
            // standard 64-bit instructions and works correctly.
            // MMX/FXSR/SSE are also cleared: glibc ifunc resolvers for those
            // paths can emit 0F-prefixed instructions we haven't implemented.
            let ecx: u32 = 0; // No SSE3, SSSE3, SSE4.x, POPCNT, AVX, OSXSAVE
            let edx: u32 = (1 << 0)  // FPU
                         | (1 << 4)  // TSC
                         | (1 << 6)  // PAE
                         | (1 << 8)  // CX8
                         | (1 << 15) // CMOV
                         | (1 << 19) // CLFSH
                         // SSE, SSE2, MMX, FXSR intentionally NOT set —
                         // forces scalar code paths in ld-linux and glibc.
                         ;
            // EAX = Family 6, Model 15 (Core 2 era), Stepping 0.
            // Stepping bits 3:0 MUST be 0: ld-linux stores EAX&0xf into a
            // stack slot that it later uses as a string pointer, and the
            // null-check (TEST R14,R14; JZ) only skips the dereference when
            // the value is zero.  Stepping 0xF (15) caused "address 0xf not
            // mapped" at RIP=0x10006daa inside _dl_important_hwcaps.
            (0x0006_0F00, 0x0100_0800, ecx, edx)
        }
        7 => {
            // Extended features; FSGSBASE in EBX bit 0
            (0, 1, 0, 0)
        }
        0x8000_0000 => (0x8000_0001, 0, 0, 0), // Max extended leaf
        0x8000_0001 => {
            // LAHF64 support in ECX bit 0
            (0, 0, 1, 0)
        }
        _ => (0, 0, 0, 0),
    }
}
