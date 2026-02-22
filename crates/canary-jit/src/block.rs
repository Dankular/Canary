//! Basic-block extraction: decode a contiguous sequence of x86-64 instructions
//! ending at the first control-flow instruction, then store the result as a
//! `JitBlock`.

use canary_cpu::decoder::{decode, Instruction, Mnemonic};
use canary_memory::GuestMemory;

// ── JitTier ───────────────────────────────────────────────────────────────────

/// Compilation tier for a cached basic block.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum JitTier {
    /// Tier-0: decoded instruction list, replayed via interpreter.
    Interpreted,
    /// Tier-1: emitted WASM bytecode, compiled by the browser JIT.
    Compiled,
}

// ── JitBlock ──────────────────────────────────────────────────────────────────

/// A pre-decoded basic block ready for cached execution.
#[derive(Debug)]
pub struct JitBlock {
    /// Guest RIP of the first instruction in this block.
    pub entry_rip: u64,

    /// Instructions in sequential execution order.
    pub instrs: Vec<Instruction>,

    /// RIP of the instruction *after* the last one in this block.
    ///
    /// `Some(rip)` when the block ends with a conditional branch (or a block
    /// size limit was hit) — the fallthrough address when the branch is not
    /// taken.
    ///
    /// `None` when the block ends with an unconditional transfer (JMP, CALL,
    /// RET, SYSCALL, HLT, UD2) — there is no static fallthrough.
    pub fallthrough: Option<u64>,

    /// Number of times this block has been entered via the JIT cache.
    pub hit_count: u32,

    /// Compilation tier for this block.
    pub tier: JitTier,
}

// ── Terminal-instruction predicates ──────────────────────────────────────────

/// Returns `true` when `instr` ends a basic block (i.e. can change RIP in a
/// way that makes the next sequential instruction unreachable or unknown).
pub fn is_block_terminal(instr: &Instruction) -> bool {
    matches!(
        instr.mnemonic,
        Mnemonic::Jmp
            | Mnemonic::Jcc(_)
            | Mnemonic::Call
            | Mnemonic::Ret
            | Mnemonic::RetN
            | Mnemonic::Syscall
            | Mnemonic::Int
            | Mnemonic::Int3
            | Mnemonic::Hlt
            | Mnemonic::Ud2
            | Mnemonic::Unknown(_)
    )
}

/// Returns `true` when the block-terminal instruction is an *unconditional*
/// transfer — meaning there is no static fallthrough address.
fn is_unconditional_terminal(instr: &Instruction) -> bool {
    matches!(
        instr.mnemonic,
        Mnemonic::Jmp
            | Mnemonic::Call
            | Mnemonic::Ret
            | Mnemonic::RetN
            | Mnemonic::Syscall
            | Mnemonic::Hlt
            | Mnemonic::Ud2
            | Mnemonic::Unknown(_)
    )
}

// ── Block compilation ─────────────────────────────────────────────────────────

/// Maximum number of instructions to include in a single basic block.
const MAX_BLOCK_INSTRS: usize = 64;

/// Decode a basic block starting at `entry_rip` from `mem`.
///
/// Returns `None` if the very first instruction cannot be decoded (unmapped
/// memory, unknown opcode at the entry point, etc.).  Subsequent decode
/// failures simply terminate the block at the last successfully decoded
/// instruction.
pub fn compile_block(entry_rip: u64, mem: &GuestMemory) -> Option<JitBlock> {
    let mut instrs: Vec<Instruction> = Vec::with_capacity(16);
    let mut rip = entry_rip;

    loop {
        // Try to read up to 15 bytes (maximum x86-64 instruction length).
        // Fall back to 1 byte so we can still decode single-byte instructions
        // that live at the very end of a mapped page.
        let bytes = match mem.read_bytes(rip, 15) {
            Ok(b) => b,
            Err(_) => match mem.read_bytes(rip, 1) {
                Ok(b) => b,
                Err(_) => {
                    // Cannot read memory at rip — stop here.
                    if instrs.is_empty() {
                        return None; // can't form a block at all
                    }
                    break;
                }
            },
        };

        let instr = match decode(bytes, rip) {
            Ok(i) => i,
            Err(_) => {
                if instrs.is_empty() {
                    return None; // first instruction is not decodable
                }
                break;
            }
        };

        let next_rip = rip.wrapping_add(instr.length as u64);
        let terminal = is_block_terminal(&instr);
        instrs.push(instr);
        rip = next_rip;

        if terminal || instrs.len() >= MAX_BLOCK_INSTRS {
            break;
        }
    }

    // Determine whether there is a static fallthrough address.
    let fallthrough = {
        let last = instrs.last().expect("instrs is non-empty");
        if is_unconditional_terminal(last) {
            None
        } else {
            // Either a Jcc (conditional) or a size-limited non-terminal block:
            // the fallthrough is the RIP just past the last instruction.
            Some(rip)
        }
    };

    Some(JitBlock {
        entry_rip,
        instrs,
        fallthrough,
        hit_count: 0,
        tier: JitTier::Interpreted,
    })
}
