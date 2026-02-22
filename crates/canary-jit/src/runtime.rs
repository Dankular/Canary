//! Block execution: iterate over a `JitBlock`'s pre-decoded instructions and
//! execute each one via the interpreter, returning a `JitResult` that tells
//! the caller how the block ended.

use canary_cpu::{
    interpreter::{execute, ExecError},
    registers::CpuState,
};
use canary_memory::GuestMemory;

use crate::block::{is_block_terminal, JitBlock};

// ── JitResult ─────────────────────────────────────────────────────────────────

/// Outcome of executing a `JitBlock`.
#[derive(Debug)]
pub enum JitResult {
    /// Block completed normally (no control-flow change detected by the JIT
    /// layer).  `next_rip` is the fallthrough address set by the interpreter.
    Continue(u64),

    /// Block ended with a branch (conditional or unconditional jump / call /
    /// ret).  `cpu.rip` has already been updated to the branch target by the
    /// interpreter.
    Branch(u64),

    /// Block ended with a SYSCALL instruction.  The caller must dispatch the
    /// syscall and then continue execution from `cpu.rip` (which the
    /// interpreter already advanced to the instruction after SYSCALL).
    Syscall(u64),

    /// Block ended with HLT — the emulated program wants to stop.
    Halt,

    /// An instruction in the block caused an unrecoverable error.
    Fault(String),
}

// ── Block execution ───────────────────────────────────────────────────────────

/// Execute all instructions in `block` sequentially, updating `cpu` and `mem`.
///
/// The interpreter is responsible for updating `cpu.rip` after each
/// instruction (including for branch targets).  This function just drives the
/// loop and translates `ExecError` variants into `JitResult`.
pub fn execute_block(
    block: &mut JitBlock,
    cpu: &mut CpuState,
    mem: &mut GuestMemory,
) -> JitResult {
    // Point RIP at the block entry so the interpreter starts from the right
    // place (the interpreter advances RIP internally before executing each
    // instruction, matching x86 semantics for RIP-relative addressing).
    cpu.rip = block.entry_rip;

    for instr in &block.instrs {
        // Remember whether this instruction is a control-flow terminal so we
        // can return the right JitResult variant even on Ok(()).
        let is_terminal = is_block_terminal(instr);

        match execute(instr, cpu, mem) {
            Ok(()) => {
                // The interpreter updated cpu.rip to the next sequential
                // instruction (or to a branch target for Jcc/Jmp/Call/Ret
                // — those return Ok(()) after setting rip).
                if is_terminal {
                    // The instruction was a control-flow change (e.g. Jcc not
                    // taken falls through with Ok; taken also falls through
                    // with Ok after the interpreter updates rip).
                    return JitResult::Branch(cpu.rip);
                }
                // Otherwise keep executing the remaining instructions in the
                // block.
            }
            Err(ExecError::Syscall) => {
                // cpu.rip has been set to the instruction after SYSCALL by the
                // interpreter.
                return JitResult::Syscall(cpu.rip);
            }
            Err(ExecError::Halt) => {
                return JitResult::Halt;
            }
            Err(ExecError::DivideByZero) => {
                return JitResult::Fault(format!(
                    "divide by zero @ {:#x}",
                    instr_rip(cpu, instr)
                ));
            }
            Err(ExecError::IllegalInstruction) => {
                return JitResult::Fault(format!(
                    "illegal instruction @ {:#x}",
                    instr_rip(cpu, instr)
                ));
            }
            Err(ExecError::Int(n)) => {
                return JitResult::Fault(format!(
                    "INT {} @ {:#x}",
                    n,
                    instr_rip(cpu, instr)
                ));
            }
            Err(ExecError::Mem(e)) => {
                return JitResult::Fault(format!("memory fault: {e}"));
            }
            Err(ExecError::Unimplemented(s)) => {
                // Non-fatal: log and keep going (matches interpreter behaviour).
                log::warn!("JIT: unimplemented instruction: {s}");
            }
        }
    }

    // All instructions in the block executed without hitting a terminal error.
    JitResult::Continue(cpu.rip)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Best-effort: recover the RIP of the faulting instruction.  After a fault
/// `cpu.rip` has already been advanced by the interpreter (it sets rip to
/// next_rip before returning errors for most instructions), so we back-calculate
/// from the instruction length.
fn instr_rip(cpu: &CpuState, instr: &canary_cpu::decoder::Instruction) -> u64 {
    cpu.rip.wrapping_sub(instr.length as u64)
}
