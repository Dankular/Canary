//! AArch64 instruction interpreter.

use canary_memory::GuestMemory;
use crate::{ArmCpuState, decoder::{ArmInstr, ArmInstrKind}};

#[derive(Debug)]
pub enum ArmExecError {
    /// SVC instruction — caller should dispatch the syscall.
    Syscall,
    /// BRK/HLT — halt execution.
    Halt,
    /// Unrecognised or unimplemented instruction.
    IllegalInstruction,
    /// Memory fault at address.
    MemFault(u64),
}

impl std::fmt::Display for ArmExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ArmExecError::Syscall              => write!(f, "syscall"),
            ArmExecError::Halt                 => write!(f, "halt"),
            ArmExecError::IllegalInstruction   => write!(f, "illegal instruction"),
            ArmExecError::MemFault(a)          => write!(f, "memory fault @ {a:#x}"),
        }
    }
}

/// Execute one instruction.  Returns `Ok(())` on success, `Err` otherwise.
/// On success, `cpu.pc` has been advanced to the next instruction.
pub fn execute(instr: &ArmInstr, cpu: &mut ArmCpuState, mem: &mut GuestMemory)
    -> Result<(), ArmExecError>
{
    let pc = cpu.pc;

    match &instr.kind {

        // ── NOP / barriers (treat as no-op) ──────────────────────────────
        ArmInstrKind::Nop | ArmInstrKind::Dmb | ArmInstrKind::Dsb | ArmInstrKind::Isb => {}

        // ── SVC ───────────────────────────────────────────────────────────
        ArmInstrKind::Svc { .. } => {
            cpu.pc = pc.wrapping_add(4);
            return Err(ArmExecError::Syscall);
        }

        // ── BRK ───────────────────────────────────────────────────────────
        ArmInstrKind::Brk { .. } => {
            return Err(ArmExecError::Halt);
        }

        // ── System register accesses ──────────────────────────────────────

        // TPIDR_EL0 sysreg encoding: op0=3,op1=3,CRn=13,CRm=0,op2=2 → 0x5E82
        ArmInstrKind::Mrs { rt, sysreg } => {
            let val = if *sysreg == 0x5E82 {
                cpu.tpidr_el0
            } else {
                0 // unknown sysregs read as 0
            };
            cpu.xw(*rt, val);
        }
        ArmInstrKind::Msr { rt, sysreg } => {
            if *sysreg == 0x5E82 {
                cpu.tpidr_el0 = cpu.xr(*rt);
            }
            // other MSRs silently discarded
        }

        // ── PC-relative addressing ────────────────────────────────────────

        ArmInstrKind::Adr { rd, offset } => {
            cpu.xw(*rd, pc.wrapping_add(*offset as i64 as u64));
        }
        ArmInstrKind::Adrp { rd, offset } => {
            let base = pc & !0xFFF;
            cpu.xw(*rd, base.wrapping_add(*offset as u64));
        }

        // ── Branches ─────────────────────────────────────────────────────

        ArmInstrKind::B { offset } => {
            cpu.pc = pc.wrapping_add(*offset as i64 as u64);
            return Ok(());
        }
        ArmInstrKind::Bl { offset } => {
            cpu.xw(30, pc.wrapping_add(4));
            cpu.pc = pc.wrapping_add(*offset as i64 as u64);
            return Ok(());
        }
        ArmInstrKind::Br { rn } => {
            cpu.pc = cpu.xr(*rn);
            return Ok(());
        }
        ArmInstrKind::Blr { rn } => {
            let target = cpu.xr(*rn);
            cpu.xw(30, pc.wrapping_add(4));
            cpu.pc = target;
            return Ok(());
        }
        ArmInstrKind::Ret { rn } => {
            cpu.pc = cpu.xr(*rn);
            return Ok(());
        }
        ArmInstrKind::BCond { cond, offset } => {
            if cpu.check_cond(*cond) {
                cpu.pc = pc.wrapping_add(*offset as i64 as u64);
                return Ok(());
            }
        }
        ArmInstrKind::Cbz { rt, offset, is64 } => {
            let val = if *is64 { cpu.xr(*rt) } else { cpu.wr(*rt) as u64 };
            if val == 0 {
                cpu.pc = pc.wrapping_add(*offset as i64 as u64);
                return Ok(());
            }
        }
        ArmInstrKind::Cbnz { rt, offset, is64 } => {
            let val = if *is64 { cpu.xr(*rt) } else { cpu.wr(*rt) as u64 };
            if val != 0 {
                cpu.pc = pc.wrapping_add(*offset as i64 as u64);
                return Ok(());
            }
        }
        ArmInstrKind::Tbz { rt, bit, offset } => {
            if (cpu.xr(*rt) >> *bit) & 1 == 0 {
                cpu.pc = pc.wrapping_add(*offset as i64 as u64);
                return Ok(());
            }
        }
        ArmInstrKind::Tbnz { rt, bit, offset } => {
            if (cpu.xr(*rt) >> *bit) & 1 != 0 {
                cpu.pc = pc.wrapping_add(*offset as i64 as u64);
                return Ok(());
            }
        }

        // ── Arithmetic immediate ──────────────────────────────────────────

        ArmInstrKind::AddImm { rd, rn, imm, is64, setflags } => {
            let a = reg_read(cpu, *rn, *is64, true);
            let b = *imm;
            let (res, flags) = add_with_flags(a, b, *is64);
            reg_write(cpu, *rd, res, *is64, false);
            if *setflags { cpu.set_nzcv(flags.0, flags.1, flags.2, flags.3); }
        }
        ArmInstrKind::SubImm { rd, rn, imm, is64, setflags } => {
            let a = reg_read(cpu, *rn, *is64, true);
            let b = *imm;
            let (res, flags) = sub_with_flags(a, b, *is64);
            reg_write(cpu, *rd, res, *is64, false);
            if *setflags { cpu.set_nzcv(flags.0, flags.1, flags.2, flags.3); }
        }

        // ── Arithmetic register ───────────────────────────────────────────

        ArmInstrKind::AddReg { rd, rn, rm, shift, amount, is64, setflags } => {
            let a = reg_read(cpu, *rn, *is64, true);
            let b = apply_shift(cpu.xr(*rm), *shift, *amount as u32, *is64);
            let (res, flags) = add_with_flags(a, b, *is64);
            reg_write(cpu, *rd, res, *is64, false);
            if *setflags { cpu.set_nzcv(flags.0, flags.1, flags.2, flags.3); }
        }
        ArmInstrKind::SubReg { rd, rn, rm, shift, amount, is64, setflags } => {
            let a = reg_read(cpu, *rn, *is64, true);
            let b = apply_shift(cpu.xr(*rm), *shift, *amount as u32, *is64);
            let (res, flags) = sub_with_flags(a, b, *is64);
            reg_write(cpu, *rd, res, *is64, false);
            if *setflags { cpu.set_nzcv(flags.0, flags.1, flags.2, flags.3); }
        }

        // ── Logical ───────────────────────────────────────────────────────

        ArmInstrKind::AndImm { rd, rn, imm, is64 } => {
            let res = reg_read(cpu, *rn, *is64, false) & imm;
            reg_write(cpu, *rd, res, *is64, false);
        }
        ArmInstrKind::OrrImm { rd, rn, imm, is64 } => {
            let res = reg_read(cpu, *rn, *is64, false) | imm;
            reg_write(cpu, *rd, res, *is64, false);
        }
        ArmInstrKind::EorImm { rd, rn, imm, is64 } => {
            let res = reg_read(cpu, *rn, *is64, false) ^ imm;
            reg_write(cpu, *rd, res, *is64, false);
        }
        ArmInstrKind::AndsImm { rd, rn, imm, is64 } => {
            let res = reg_read(cpu, *rn, *is64, false) & imm;
            reg_write(cpu, *rd, res, *is64, false);
            set_logical_flags(cpu, res, *is64);
        }
        ArmInstrKind::AndReg { rd, rn, rm, shift, amount, is64, setflags } => {
            let a = reg_read(cpu, *rn, *is64, false);
            let b = apply_shift(cpu.xr(*rm), *shift, *amount as u32, *is64);
            let res = a & b;
            reg_write(cpu, *rd, res, *is64, false);
            if *setflags { set_logical_flags(cpu, res, *is64); }
        }
        ArmInstrKind::OrrReg { rd, rn, rm, shift, amount, is64 } => {
            let a = reg_read(cpu, *rn, *is64, false);
            let b = apply_shift(cpu.xr(*rm), *shift, *amount as u32, *is64);
            reg_write(cpu, *rd, a | b, *is64, false);
        }
        ArmInstrKind::EorReg { rd, rn, rm, shift, amount, is64 } => {
            let a = reg_read(cpu, *rn, *is64, false);
            let b = apply_shift(cpu.xr(*rm), *shift, *amount as u32, *is64);
            reg_write(cpu, *rd, a ^ b, *is64, false);
        }

        // ── Shifts ───────────────────────────────────────────────────────

        ArmInstrKind::Lsl { rd, rn, rm, is64 } => {
            let shift = (cpu.xr(*rm) & if *is64 { 63 } else { 31 }) as u32;
            let res = reg_read(cpu, *rn, *is64, false) << shift;
            reg_write(cpu, *rd, res, *is64, false);
        }
        ArmInstrKind::Lsr { rd, rn, rm, is64 } => {
            let shift = (cpu.xr(*rm) & if *is64 { 63 } else { 31 }) as u32;
            let res = reg_read(cpu, *rn, *is64, false) >> shift;
            reg_write(cpu, *rd, res, *is64, false);
        }
        ArmInstrKind::Asr { rd, rn, rm, is64 } => {
            let shift = (cpu.xr(*rm) & if *is64 { 63 } else { 31 }) as u32;
            let res = if *is64 {
                ((reg_read(cpu, *rn, true, false) as i64) >> shift) as u64
            } else {
                (((reg_read(cpu, *rn, false, false) as i32) >> shift) as u64) & 0xFFFFFFFF
            };
            reg_write(cpu, *rd, res, *is64, false);
        }
        ArmInstrKind::LslImm { rd, rn, shift, is64 } => {
            let val = reg_read(cpu, *rn, *is64, false) << *shift;
            reg_write(cpu, *rd, val, *is64, false);
        }
        ArmInstrKind::LsrImm { rd, rn, shift, is64 } => {
            let val = reg_read(cpu, *rn, *is64, false) >> *shift;
            reg_write(cpu, *rd, val, *is64, false);
        }
        ArmInstrKind::AsrImm { rd, rn, shift, is64 } => {
            let val = if *is64 {
                ((reg_read(cpu, *rn, true, false) as i64) >> *shift) as u64
            } else {
                (((reg_read(cpu, *rn, false, false) as i32) >> *shift) as u64) & 0xFFFF_FFFF
            };
            reg_write(cpu, *rd, val, *is64, false);
        }

        // ── Multiply / divide ─────────────────────────────────────────────

        ArmInstrKind::Mul { rd, rn, rm, is64 } => {
            let a = reg_read(cpu, *rn, *is64, false);
            let b = reg_read(cpu, *rm, *is64, false);
            reg_write(cpu, *rd, a.wrapping_mul(b), *is64, false);
        }
        ArmInstrKind::UDiv { rd, rn, rm, is64 } => {
            let a = reg_read(cpu, *rn, *is64, false);
            let b = reg_read(cpu, *rm, *is64, false);
            reg_write(cpu, *rd, if b == 0 { 0 } else { a.wrapping_div(b) }, *is64, false);
        }
        ArmInstrKind::SDiv { rd, rn, rm, is64 } => {
            let a = reg_read(cpu, *rn, *is64, false);
            let b = reg_read(cpu, *rm, *is64, false);
            let res = if b == 0 {
                0
            } else if *is64 {
                ((a as i64).wrapping_div(b as i64)) as u64
            } else {
                (((a as u32) as i32).wrapping_div((b as u32) as i32) as u64) & 0xFFFF_FFFF
            };
            reg_write(cpu, *rd, res, *is64, false);
        }

        // ── Bit operations ────────────────────────────────────────────────

        ArmInstrKind::Rbit { rd, rn, is64 } => {
            let v = reg_read(cpu, *rn, *is64, false);
            let res = if *is64 { v.reverse_bits() } else { (v as u32).reverse_bits() as u64 };
            reg_write(cpu, *rd, res, *is64, false);
        }
        ArmInstrKind::Clz { rd, rn, is64 } => {
            let v = reg_read(cpu, *rn, *is64, false);
            let res = if *is64 { v.leading_zeros() as u64 } else { (v as u32).leading_zeros() as u64 };
            reg_write(cpu, *rd, res, *is64, false);
        }
        ArmInstrKind::Rev { rd, rn, is64 } => {
            let v = reg_read(cpu, *rn, *is64, false);
            let res = if *is64 { v.swap_bytes() } else { (v as u32).swap_bytes() as u64 };
            reg_write(cpu, *rd, res, *is64, false);
        }

        // ── Sign/zero extension ───────────────────────────────────────────

        ArmInstrKind::Sxtw { rd, rn } => {
            let val = cpu.wr(*rn) as i32 as i64 as u64;
            cpu.xw(*rd, val);
        }
        ArmInstrKind::Uxtw { rd, rn } => {
            let val = cpu.wr(*rn) as u64;
            cpu.xw(*rd, val);
        }
        ArmInstrKind::Sxth { rd, rn, is64 } => {
            let val = (cpu.xr(*rn) as i16) as i64 as u64;
            reg_write(cpu, *rd, val, *is64, false);
        }
        ArmInstrKind::Sxtb { rd, rn, is64 } => {
            let val = (cpu.xr(*rn) as i8) as i64 as u64;
            reg_write(cpu, *rd, val, *is64, false);
        }

        // ── MOV variants ─────────────────────────────────────────────────

        ArmInstrKind::MovReg { rd, rm, is64 } => {
            let val = reg_read(cpu, *rm, *is64, false);
            reg_write(cpu, *rd, val, *is64, false);
        }
        ArmInstrKind::Movz { rd, imm16, shift, is64 } => {
            let val = (*imm16 as u64) << *shift;
            reg_write(cpu, *rd, val, *is64, false);
        }
        ArmInstrKind::Movn { rd, imm16, shift, is64 } => {
            let val = !((*imm16 as u64) << *shift);
            reg_write(cpu, *rd, val, *is64, false);
        }
        ArmInstrKind::Movk { rd, imm16, shift, is64 } => {
            let old = cpu.xr(*rd);
            let mask = !(0xFFFFu64 << *shift);
            let val = (old & mask) | ((*imm16 as u64) << *shift);
            reg_write(cpu, *rd, val, *is64, false);
        }

        // ── Conditional select ────────────────────────────────────────────

        ArmInstrKind::Csel { rd, rn, rm, cond, is64 } => {
            let val = if cpu.check_cond(*cond) {
                reg_read(cpu, *rn, *is64, false)
            } else {
                reg_read(cpu, *rm, *is64, false)
            };
            reg_write(cpu, *rd, val, *is64, false);
        }
        ArmInstrKind::Csinc { rd, rn, rm, cond, is64 } => {
            let val = if cpu.check_cond(*cond) {
                reg_read(cpu, *rn, *is64, false)
            } else {
                reg_read(cpu, *rm, *is64, false).wrapping_add(1)
            };
            reg_write(cpu, *rd, val, *is64, false);
        }
        ArmInstrKind::Csinv { rd, rn, rm, cond, is64 } => {
            let val = if cpu.check_cond(*cond) {
                reg_read(cpu, *rn, *is64, false)
            } else {
                !reg_read(cpu, *rm, *is64, false)
            };
            reg_write(cpu, *rd, val, *is64, false);
        }
        ArmInstrKind::Csneg { rd, rn, rm, cond, is64 } => {
            let val = if cpu.check_cond(*cond) {
                reg_read(cpu, *rn, *is64, false)
            } else {
                (reg_read(cpu, *rm, *is64, false) as i64).wrapping_neg() as u64
            };
            reg_write(cpu, *rd, val, *is64, false);
        }

        // ── Loads ─────────────────────────────────────────────────────────

        ArmInstrKind::LdrLit { rt, offset, is64 } => {
            let addr = pc.wrapping_add(*offset as i64 as u64);
            if *is64 {
                let v = mem.read_u64(addr).map_err(|_| ArmExecError::MemFault(addr))?;
                cpu.xw(*rt, v);
            } else {
                let v = mem.read_u32(addr).map_err(|_| ArmExecError::MemFault(addr))?;
                cpu.ww(*rt, v);
            }
        }

        ArmInstrKind::LdrImm { rt, rn, offset, is64 } => {
            let base = rn_sp(cpu, *rn);
            let addr = base.wrapping_add(*offset as u64);
            if *is64 {
                let v = mem.read_u64(addr).map_err(|_| ArmExecError::MemFault(addr))?;
                cpu.xw(*rt, v);
            } else {
                let v = mem.read_u32(addr).map_err(|_| ArmExecError::MemFault(addr))?;
                cpu.ww(*rt, v);
            }
        }
        ArmInstrKind::StrImm { rt, rn, offset, is64 } => {
            let base = rn_sp(cpu, *rn);
            let addr = base.wrapping_add(*offset as u64);
            if *is64 {
                mem.write_u64(addr, cpu.xr(*rt)).map_err(|_| ArmExecError::MemFault(addr))?;
            } else {
                mem.write_u32(addr, cpu.wr(*rt)).map_err(|_| ArmExecError::MemFault(addr))?;
            }
        }
        ArmInstrKind::LdrImmPost { rt, rn, simm, is64 } => {
            let base = rn_sp(cpu, *rn);
            if *is64 {
                let v = mem.read_u64(base).map_err(|_| ArmExecError::MemFault(base))?;
                cpu.xw(*rt, v);
            } else {
                let v = mem.read_u32(base).map_err(|_| ArmExecError::MemFault(base))?;
                cpu.ww(*rt, v);
            }
            rn_sp_write(cpu, *rn, base.wrapping_add(*simm as u64));
        }
        ArmInstrKind::StrImmPost { rt, rn, simm, is64 } => {
            let base = rn_sp(cpu, *rn);
            if *is64 {
                mem.write_u64(base, cpu.xr(*rt)).map_err(|_| ArmExecError::MemFault(base))?;
            } else {
                mem.write_u32(base, cpu.wr(*rt)).map_err(|_| ArmExecError::MemFault(base))?;
            }
            rn_sp_write(cpu, *rn, base.wrapping_add(*simm as u64));
        }
        ArmInstrKind::LdrImmPre { rt, rn, simm, is64 } => {
            let addr = rn_sp(cpu, *rn).wrapping_add(*simm as u64);
            rn_sp_write(cpu, *rn, addr);
            if *is64 {
                let v = mem.read_u64(addr).map_err(|_| ArmExecError::MemFault(addr))?;
                cpu.xw(*rt, v);
            } else {
                let v = mem.read_u32(addr).map_err(|_| ArmExecError::MemFault(addr))?;
                cpu.ww(*rt, v);
            }
        }
        ArmInstrKind::StrImmPre { rt, rn, simm, is64 } => {
            let addr = rn_sp(cpu, *rn).wrapping_add(*simm as u64);
            rn_sp_write(cpu, *rn, addr);
            if *is64 {
                mem.write_u64(addr, cpu.xr(*rt)).map_err(|_| ArmExecError::MemFault(addr))?;
            } else {
                mem.write_u32(addr, cpu.wr(*rt)).map_err(|_| ArmExecError::MemFault(addr))?;
            }
        }

        ArmInstrKind::LdrhImm { rt, rn, offset } => {
            let addr = rn_sp(cpu, *rn).wrapping_add(*offset as u64);
            let v = mem.read_u16(addr).map_err(|_| ArmExecError::MemFault(addr))?;
            cpu.xw(*rt, v as u64);
        }
        ArmInstrKind::StrhImm { rt, rn, offset } => {
            let addr = rn_sp(cpu, *rn).wrapping_add(*offset as u64);
            mem.write_u16(addr, cpu.xr(*rt) as u16).map_err(|_| ArmExecError::MemFault(addr))?;
        }
        ArmInstrKind::LdrbImm { rt, rn, offset } => {
            let addr = rn_sp(cpu, *rn).wrapping_add(*offset as u64);
            let v = mem.read_u8(addr).map_err(|_| ArmExecError::MemFault(addr))?;
            cpu.xw(*rt, v as u64);
        }
        ArmInstrKind::StrbImm { rt, rn, offset } => {
            let addr = rn_sp(cpu, *rn).wrapping_add(*offset as u64);
            mem.write_u8(addr, cpu.xr(*rt) as u8).map_err(|_| ArmExecError::MemFault(addr))?;
        }
        ArmInstrKind::LdrshImm { rt, rn, offset, is64 } => {
            let addr = rn_sp(cpu, *rn).wrapping_add(*offset as u64);
            let v = mem.read_u16(addr).map_err(|_| ArmExecError::MemFault(addr))? as i16 as i64 as u64;
            reg_write(cpu, *rt, v, *is64, false);
        }
        ArmInstrKind::LdrsbImm { rt, rn, offset, is64 } => {
            let addr = rn_sp(cpu, *rn).wrapping_add(*offset as u64);
            let v = mem.read_u8(addr).map_err(|_| ArmExecError::MemFault(addr))? as i8 as i64 as u64;
            reg_write(cpu, *rt, v, *is64, false);
        }
        ArmInstrKind::LdrswImm { rt, rn, offset } => {
            let addr = rn_sp(cpu, *rn).wrapping_add(*offset as u64);
            let v = mem.read_u32(addr).map_err(|_| ArmExecError::MemFault(addr))? as i32 as i64 as u64;
            cpu.xw(*rt, v);
        }

        ArmInstrKind::LdrRegOff { rt, rn, rm, extend, amount, is64 } => {
            let base   = rn_sp(cpu, *rn);
            let offset = apply_extend(cpu.xr(*rm), *extend, *amount);
            let addr   = base.wrapping_add(offset);
            if *is64 {
                let v = mem.read_u64(addr).map_err(|_| ArmExecError::MemFault(addr))?;
                cpu.xw(*rt, v);
            } else {
                let v = mem.read_u32(addr).map_err(|_| ArmExecError::MemFault(addr))?;
                cpu.ww(*rt, v);
            }
        }
        ArmInstrKind::StrRegOff { rt, rn, rm, extend, amount, is64 } => {
            let base   = rn_sp(cpu, *rn);
            let offset = apply_extend(cpu.xr(*rm), *extend, *amount);
            let addr   = base.wrapping_add(offset);
            if *is64 {
                mem.write_u64(addr, cpu.xr(*rt)).map_err(|_| ArmExecError::MemFault(addr))?;
            } else {
                mem.write_u32(addr, cpu.wr(*rt)).map_err(|_| ArmExecError::MemFault(addr))?;
            }
        }

        // ── Pair loads/stores ─────────────────────────────────────────────

        ArmInstrKind::Ldp { rt1, rt2, rn, offset, is64 } => {
            let base  = rn_sp(cpu, *rn);
            let addr  = base.wrapping_add(*offset as u64);
            let size  = if *is64 { 8u64 } else { 4 };
            ldp_exec(cpu, mem, *rt1, *rt2, addr, size, *is64)?;
        }
        ArmInstrKind::Stp { rt1, rt2, rn, offset, is64 } => {
            let base  = rn_sp(cpu, *rn);
            let addr  = base.wrapping_add(*offset as u64);
            let size  = if *is64 { 8u64 } else { 4 };
            stp_exec(cpu, mem, *rt1, *rt2, addr, size, *is64)?;
        }
        ArmInstrKind::LdpPost { rt1, rt2, rn, simm, is64 } => {
            let base = rn_sp(cpu, *rn);
            let size = if *is64 { 8u64 } else { 4 };
            ldp_exec(cpu, mem, *rt1, *rt2, base, size, *is64)?;
            rn_sp_write(cpu, *rn, base.wrapping_add(*simm as u64));
        }
        ArmInstrKind::StpPost { rt1, rt2, rn, simm, is64 } => {
            let base = rn_sp(cpu, *rn);
            let size = if *is64 { 8u64 } else { 4 };
            stp_exec(cpu, mem, *rt1, *rt2, base, size, *is64)?;
            rn_sp_write(cpu, *rn, base.wrapping_add(*simm as u64));
        }
        ArmInstrKind::LdpPre { rt1, rt2, rn, simm, is64 } => {
            let addr = rn_sp(cpu, *rn).wrapping_add(*simm as u64);
            rn_sp_write(cpu, *rn, addr);
            let size = if *is64 { 8u64 } else { 4 };
            ldp_exec(cpu, mem, *rt1, *rt2, addr, size, *is64)?;
        }
        ArmInstrKind::StpPre { rt1, rt2, rn, simm, is64 } => {
            let addr = rn_sp(cpu, *rn).wrapping_add(*simm as u64);
            rn_sp_write(cpu, *rn, addr);
            let size = if *is64 { 8u64 } else { 4 };
            stp_exec(cpu, mem, *rt1, *rt2, addr, size, *is64)?;
        }

        // ── Exclusive loads/stores (simplified: no reservation tracking) ──

        ArmInstrKind::LdxrImm { rt, rn, is64 } => {
            let addr = rn_sp(cpu, *rn);
            if *is64 {
                let v = mem.read_u64(addr).map_err(|_| ArmExecError::MemFault(addr))?;
                cpu.xw(*rt, v);
            } else {
                let v = mem.read_u32(addr).map_err(|_| ArmExecError::MemFault(addr))?;
                cpu.ww(*rt, v);
            }
        }
        ArmInstrKind::StxrImm { rs, rt, rn, is64 } => {
            let addr = rn_sp(cpu, *rn);
            if *is64 {
                mem.write_u64(addr, cpu.xr(*rt)).map_err(|_| ArmExecError::MemFault(addr))?;
            } else {
                mem.write_u32(addr, cpu.wr(*rt)).map_err(|_| ArmExecError::MemFault(addr))?;
            }
            cpu.xw(*rs, 0); // indicate success
        }

        // ── Unknown / unimplemented ───────────────────────────────────────
        ArmInstrKind::Unknown(_) => {
            return Err(ArmExecError::IllegalInstruction);
        }
    }

    cpu.pc = pc.wrapping_add(4);
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Read a register, optionally masking to 32-bit.
/// `use_sp`: encoding 31 = SP (stack pointer) instead of XZR.
fn reg_read(cpu: &ArmCpuState, idx: u8, is64: bool, use_sp: bool) -> u64 {
    let val = if use_sp && idx == 31 { cpu.sp } else { cpu.xr(idx) };
    if is64 { val } else { val & 0xFFFF_FFFF }
}

/// Write a register.  If `is64=false`, zero-extends to 64 bits.
/// `use_sp`: encoding 31 = SP (never applicable for dest in arithmetic).
fn reg_write(cpu: &mut ArmCpuState, idx: u8, val: u64, is64: bool, use_sp: bool) {
    let v = if is64 { val } else { val & 0xFFFF_FFFF };
    if use_sp && idx == 31 { cpu.sp = v; } else { cpu.xw(idx, v); }
}

/// Read Rn, treating encoding 31 as SP (common for load/store base).
fn rn_sp(cpu: &ArmCpuState, rn: u8) -> u64 {
    if rn == 31 { cpu.sp } else { cpu.xr(rn) }
}

/// Write Rn, treating encoding 31 as SP.
fn rn_sp_write(cpu: &mut ArmCpuState, rn: u8, val: u64) {
    if rn == 31 { cpu.sp = val; } else { cpu.xw(rn, val); }
}

/// Apply a shift operation to a 64-bit value.
fn apply_shift(val: u64, shift_type: u8, amount: u32, is64: bool) -> u64 {
    let bits = if is64 { 64u32 } else { 32u32 };
    let amount = amount & (bits - 1);
    let v = if is64 { val } else { val & 0xFFFF_FFFF };
    let res = match shift_type & 0x3 {
        0 => v << amount,                               // LSL
        1 => v >> amount,                               // LSR
        2 => if is64 {                                  // ASR
                 ((v as i64) >> amount) as u64
             } else {
                 ((v as i32) >> amount) as u64 & 0xFFFF_FFFF
             },
        3 => v.rotate_right(amount),                    // ROR
        _ => unreachable!(),
    };
    if is64 { res } else { res & 0xFFFF_FFFF }
}

/// Apply an extend operation (for load/store register offset addressing).
fn apply_extend(val: u64, extend: u8, amount: u8) -> u64 {
    let shift = amount as u32;
    match extend & 0x7 {
        2 => (val as u32 as u64) << shift,          // UXTW
        3 => val << shift,                           // LSL / UXTX
        6 => ((val as u32 as i32) as i64 as u64) << shift, // SXTW
        7 => ((val as i64 as u64)) << shift,         // SXTX
        _ => val << shift,
    }
}

/// Add two values, returning (result, (N, Z, C, V)) flags.
fn add_with_flags(a: u64, b: u64, is64: bool) -> (u64, (bool, bool, bool, bool)) {
    if is64 {
        let (res, carry) = a.overflowing_add(b);
        let overflow = (!(a ^ b) & (a ^ res)) >> 63 == 1;
        let n = res >> 63 == 1;
        let z = res == 0;
        (res, (n, z, carry, overflow))
    } else {
        let a32 = a as u32;
        let b32 = b as u32;
        let (res32, carry) = a32.overflowing_add(b32);
        let overflow = (!(a32 ^ b32) & (a32 ^ res32)) >> 31 == 1;
        let res = res32 as u64;
        (res, (res32 >> 31 == 1, res32 == 0, carry, overflow))
    }
}

/// Subtract two values, returning (result, (N, Z, C, V)) flags.
fn sub_with_flags(a: u64, b: u64, is64: bool) -> (u64, (bool, bool, bool, bool)) {
    // SUB uses inverted carry (C=1 if no borrow, i.e. a>=b unsigned)
    add_with_flags(a, (!b).wrapping_add(1), is64)
}

/// Set NZCV after a logical operation (C=0, V=0).
fn set_logical_flags(cpu: &mut ArmCpuState, result: u64, is64: bool) {
    let n = if is64 { result >> 63 == 1 } else { result >> 31 == 1 };
    let z = if is64 { result == 0 } else { result as u32 == 0 };
    cpu.set_nzcv(n, z, false, false);
}

/// Execute LDP (load pair).
fn ldp_exec(cpu: &mut ArmCpuState, mem: &mut GuestMemory,
            rt1: u8, rt2: u8, addr: u64, size: u64, is64: bool)
    -> Result<(), ArmExecError>
{
    if is64 {
        let v1 = mem.read_u64(addr).map_err(|_| ArmExecError::MemFault(addr))?;
        let v2 = mem.read_u64(addr + size).map_err(|_| ArmExecError::MemFault(addr + size))?;
        cpu.xw(rt1, v1);
        cpu.xw(rt2, v2);
    } else {
        let v1 = mem.read_u32(addr).map_err(|_| ArmExecError::MemFault(addr))?;
        let v2 = mem.read_u32(addr + size).map_err(|_| ArmExecError::MemFault(addr + size))?;
        cpu.ww(rt1, v1);
        cpu.ww(rt2, v2);
    }
    Ok(())
}

/// Execute STP (store pair).
fn stp_exec(cpu: &mut ArmCpuState, mem: &mut GuestMemory,
            rt1: u8, rt2: u8, addr: u64, size: u64, is64: bool)
    -> Result<(), ArmExecError>
{
    if is64 {
        mem.write_u64(addr, cpu.xr(rt1)).map_err(|_| ArmExecError::MemFault(addr))?;
        mem.write_u64(addr + size, cpu.xr(rt2)).map_err(|_| ArmExecError::MemFault(addr + size))?;
    } else {
        mem.write_u32(addr, cpu.wr(rt1)).map_err(|_| ArmExecError::MemFault(addr))?;
        mem.write_u32(addr + size, cpu.wr(rt2)).map_err(|_| ArmExecError::MemFault(addr + size))?;
    }
    Ok(())
}
