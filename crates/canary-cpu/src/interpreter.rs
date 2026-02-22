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
    base.wrapping_add(index).wrapping_add(ma.disp as u64)
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
        Ud2 | Unknown(_) => { cpu.rip = next_rip; return Err(ExecError::IllegalInstruction); }

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

        // ── CWD / CDQ / CQO ──────────────────────────────────────────────
        Cwde | Cdq | Cqo | Cwd | Cbw | Cdqe => {
            let rax = cpu.read64(reg::RAX);
            let sign = match sz {
                16 => (rax & 0xff) as i8 as i64 as u64,
                32 => (rax as u16) as i16 as i64 as u64,
                64 => (rax as u32) as i32 as i64 as u64,
                _  => (rax as i64 >> 63) as u64,
            };
            cpu.write64(reg::RDX, if (sign as i64) < 0 { u64::MAX } else { 0 });
            // Also sign-extend RAX for CWDE/CDQE
            if matches!(instr.mnemonic, Cwde | Cdqe | Cbw) {
                cpu.write64(reg::RAX, sign);
            }
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
            // Family 6, Model 15 (Core 2 Duo); ECX: SSE3/SSSE3/SSE4.1/SSE4.2/POPCNT
            let ecx: u32 = (1 << 0)  // SSE3
                         | (1 << 9)  // SSSE3
                         | (1 << 19) // SSE4.1
                         | (1 << 20) // SSE4.2
                         | (1 << 23) // POPCNT
                         ;
            let edx: u32 = (1 << 0)  // FPU
                         | (1 << 4)  // TSC
                         | (1 << 6)  // PAE
                         | (1 << 8)  // CX8
                         | (1 << 15) // CMOV
                         | (1 << 19) // CLFSH
                         | (1 << 23) // MMX
                         | (1 << 24) // FXSR
                         | (1 << 25) // SSE
                         | (1 << 26) // SSE2
                         ;
            (0x0006_0F0F, 0x0100_0800, ecx, edx)
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
