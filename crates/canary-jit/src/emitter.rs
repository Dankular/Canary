//! WASM bytecode emitter for JIT Tier-1.
//!
//! Each basic block is compiled to a self-contained WASM module with one
//! exported function:
//!
//! ```text
//! (func (export "run") (param $reg_ptr i32) (param $mem_ptr i32) (result i32)
//!   ...body...
//! )
//! ```
//!
//! The function reads/writes the 16 GPRs + RIP from a flat i64[17] array
//! located at `reg_ptr` inside imported memory "env"/"memory":
//!
//!   slot 0  = RAX  … slot 15 = R15  slot 16 = RIP
//!
//! Returns: 0 = normal fall-through, 1 = syscall, 2 = branch/end.
//!
//! If any instruction in the block is not yet supported, `emit_block` returns
//! `None` and the caller falls back to the Tier-0 interpreter.

use wasm_encoder::{
    CodeSection, EntityType, ExportKind, ExportSection, Function, FunctionSection,
    ImportSection, MemArg, MemoryType, Module, TypeSection, ValType,
};

use crate::block::JitBlock;
use canary_cpu::decoder::{Mnemonic, Operand};
use canary_cpu::registers::reg;

// ── Layout constants ─────────────────────────────────────────────────────────

/// Bytes between consecutive register slots in the flat array (each slot is i64).
const REG_STRIDE: u64 = 8;

/// Index of RIP in the flat register array.
const RIP_IDX: usize = 16;

// ── Local variable indices inside the emitted WASM function ──────────────────

/// param 0: reg_ptr — base address of the i64[17] register array (i32)
const LOCAL_REG_PTR: u32 = 0;
/// param 1: mem_ptr — unused for now, reserved for future memory helpers (i32)
// const LOCAL_MEM_PTR: u32 = 1;
/// local 2: temp_i64 — scratch register used by store_reg_from_stack
const LOCAL_TEMP_I64: u32 = 2;

// ── Public API ────────────────────────────────────────────────────────────────

/// Emit a complete WASM module for one basic block.
///
/// Returns the binary WASM bytes, or `None` if any instruction in the block
/// is not yet supported by the Tier-1 emitter (caller falls back to Tier-0).
pub fn emit_block(block: &JitBlock) -> Option<Vec<u8>> {
    BlockEmitter.emit(block)
}

// ── Emitter implementation ────────────────────────────────────────────────────

struct BlockEmitter;

impl BlockEmitter {
    fn emit(self, block: &JitBlock) -> Option<Vec<u8>> {
        let mut module = Module::new();

        // ── Type section ─────────────────────────────────────────────────
        // type 0: func(i32, i32) -> i32
        let mut types = TypeSection::new();
        types
            .ty()
            .function(vec![ValType::I32, ValType::I32], vec![ValType::I32]);
        module.section(&types);

        // ── Import section ────────────────────────────────────────────────
        // Import the host WebAssembly memory so the emitted function can read
        // and write the guest register file and guest RAM through it.
        let mut imports = ImportSection::new();
        imports.import(
            "env",
            "memory",
            EntityType::Memory(MemoryType {
                minimum: 1,
                maximum: None,
                memory64: false,
                shared: false,
                page_size_log2: None,
            }),
        );
        module.section(&imports);

        // ── Function section ──────────────────────────────────────────────
        // One function body, referencing type 0.
        // Note: the imported memory counts in the import index space but NOT
        // in the function index space, so our first function is still index 0.
        let mut funcs = FunctionSection::new();
        funcs.function(0);
        module.section(&funcs);

        // ── Export section ────────────────────────────────────────────────
        let mut exports = ExportSection::new();
        exports.export("run", ExportKind::Func, 0);
        module.section(&exports);

        // ── Code section ─────────────────────────────────────────────────
        // Locals (beyond the two i32 params):
        //   local 2: i64  — scratch for store_reg_from_stack
        //   local 3: i32  — scratch (reserved)
        let mut func = Function::new([(1u32, ValType::I64), (1u32, ValType::I32)]);

        let mut exit_reason: i32 = 0;

        {
            let mut sink = func.instructions();

            for instr in &block.instrs {
                if !emit_instr(&mut sink, instr) {
                    // Unsupported instruction — signal caller to fall back.
                    return None;
                }

                // Detect block terminals and set the appropriate exit code.
                match instr.mnemonic {
                    Mnemonic::Syscall => {
                        exit_reason = 1;
                        break;
                    }
                    Mnemonic::Hlt
                    | Mnemonic::Jmp
                    | Mnemonic::Call
                    | Mnemonic::Ret
                    | Mnemonic::RetN => {
                        exit_reason = 2;
                        break;
                    }
                    Mnemonic::Jcc(_) => {
                        exit_reason = 2;
                        break;
                    }
                    _ => {}
                }
            }

            // Return exit_reason.
            sink.i32_const(exit_reason).end();
        }

        let mut codes = CodeSection::new();
        codes.function(&func);
        module.section(&codes);

        Some(module.finish())
    }
}

// ── Per-instruction emitter ───────────────────────────────────────────────────

/// Emit WASM instructions for a single x86-64 instruction into `sink`.
///
/// Returns `true` on success, `false` if the instruction is not yet supported.
fn emit_instr(
    sink: &mut wasm_encoder::InstructionSink<'_>,
    instr: &canary_cpu::decoder::Instruction,
) -> bool {
    use Mnemonic::*;

    match instr.mnemonic {
        // ── NOP ───────────────────────────────────────────────────────────
        Nop => {
            sink.nop();
            true
        }

        // ── MOV reg, imm ─────────────────────────────────────────────────
        Mov if has_reg(&instr.operands, 0) && has_imm(&instr.operands, 1) => {
            let dst = reg_idx(&instr.operands[0]);
            let imm = imm_val(&instr.operands[1]);
            store_reg_const(sink, dst, imm);
            true
        }

        // ── MOV reg, reg ─────────────────────────────────────────────────
        Mov if has_reg(&instr.operands, 0) && has_reg(&instr.operands, 1) => {
            let dst = reg_idx(&instr.operands[0]);
            let src = reg_idx(&instr.operands[1]);
            load_reg(sink, src);
            store_reg_from_stack(sink, dst);
            true
        }

        // ── ADD reg, imm (64-bit) ─────────────────────────────────────────
        Add if has_reg(&instr.operands, 0)
            && has_imm(&instr.operands, 1)
            && instr.op_size == 64 =>
        {
            let dst = reg_idx(&instr.operands[0]);
            let imm = imm_val(&instr.operands[1]);
            load_reg(sink, dst);
            sink.i64_const(imm).i64_add();
            store_reg_from_stack(sink, dst);
            true
        }

        // ── SUB reg, imm (64-bit) ─────────────────────────────────────────
        Sub if has_reg(&instr.operands, 0)
            && has_imm(&instr.operands, 1)
            && instr.op_size == 64 =>
        {
            let dst = reg_idx(&instr.operands[0]);
            let imm = imm_val(&instr.operands[1]);
            load_reg(sink, dst);
            sink.i64_const(imm).i64_sub();
            store_reg_from_stack(sink, dst);
            true
        }

        // ── XOR reg, reg ─────────────────────────────────────────────────
        Xor if has_reg(&instr.operands, 0) && has_reg(&instr.operands, 1) => {
            let dst = reg_idx(&instr.operands[0]);
            let src = reg_idx(&instr.operands[1]);
            load_reg(sink, dst);
            load_reg(sink, src);
            sink.i64_xor();
            store_reg_from_stack(sink, dst);
            true
        }

        // ── PUSH reg ─────────────────────────────────────────────────────
        Push if has_reg(&instr.operands, 0) => {
            let src = reg_idx(&instr.operands[0]);

            // RSP -= 8
            load_reg(sink, reg::RSP);
            sink.i64_const(8).i64_sub();
            store_reg_from_stack(sink, reg::RSP);

            // mem[RSP] = src  (i64 store at the new stack pointer)
            // The address operand for WASM i64.store must be an i32.
            load_reg(sink, reg::RSP);   // i64 — guest virtual address
            sink.i32_wrap_i64();        // truncate to i32 (identity for 32-bit WASM address space)
            load_reg(sink, src);        // value to store
            sink.i64_store(MemArg {
                offset: 0,
                align: 3, // 8-byte aligned
                memory_index: 0,
            });
            true
        }

        // ── SYSCALL: update RIP to instruction-after, signal exit_reason 1 ─
        // The actual RIP advance is done by the interpreter's Syscall handler;
        // we just need to ensure the emitted block returns exit_reason=1 so the
        // host can dispatch the syscall.  No WASM instructions needed here
        // beyond the terminal detection above.
        Syscall => true,

        // ── Everything else: unsupported ──────────────────────────────────
        _ => false,
    }
}

// ── Register-access helpers ───────────────────────────────────────────────────

/// Emit code that pushes `gpr[reg_idx]` (i64) onto the WASM operand stack.
fn load_reg(sink: &mut wasm_encoder::InstructionSink<'_>, reg_idx: usize) {
    sink.local_get(LOCAL_REG_PTR).i64_load(MemArg {
        offset: (reg_idx as u64) * REG_STRIDE,
        align: 3,
        memory_index: 0,
    });
}

/// Emit code that pops an i64 from the WASM operand stack and writes it to
/// `gpr[reg_idx]`.  Uses LOCAL_TEMP_I64 as a scratch local.
fn store_reg_from_stack(sink: &mut wasm_encoder::InstructionSink<'_>, reg_idx: usize) {
    sink.local_set(LOCAL_TEMP_I64) // stash value
        .local_get(LOCAL_REG_PTR)  // base ptr
        .local_get(LOCAL_TEMP_I64) // reload value
        .i64_store(MemArg {
            offset: (reg_idx as u64) * REG_STRIDE,
            align: 3,
            memory_index: 0,
        });
}

/// Emit code that stores a compile-time constant i64 into `gpr[reg_idx]`.
fn store_reg_const(sink: &mut wasm_encoder::InstructionSink<'_>, reg_idx: usize, val: i64) {
    sink.local_get(LOCAL_REG_PTR)
        .i64_const(val)
        .i64_store(MemArg {
            offset: (reg_idx as u64) * REG_STRIDE,
            align: 3,
            memory_index: 0,
        });
}

// ── Operand helpers ───────────────────────────────────────────────────────────

fn has_reg(ops: &[Operand], idx: usize) -> bool {
    matches!(ops.get(idx), Some(Operand::Reg(_)))
}

fn has_imm(ops: &[Operand], idx: usize) -> bool {
    matches!(ops.get(idx), Some(Operand::Imm(_)))
}

fn reg_idx(op: &Operand) -> usize {
    match op {
        Operand::Reg(r) => *r,
        _ => panic!("emitter: reg_idx on non-Reg operand"),
    }
}

fn imm_val(op: &Operand) -> i64 {
    match op {
        Operand::Imm(v) => *v,
        _ => panic!("emitter: imm_val on non-Imm operand"),
    }
}

// suppress unused-import warning for RIP_IDX when only SYSCALL uses it
#[allow(dead_code)]
const _RIP_IDX: usize = RIP_IDX;
