//! canary-jit — soft basic-block JIT cache for the Canary x86-64 emulator.
//!
//! # Strategy ("Tier-0 / Soft JIT")
//!
//! Rather than emitting real machine code or WASM bytecode, this tier:
//!
//! 1. Decodes a basic block (up to 64 instructions) starting at the current RIP.
//! 2. Stores the `Vec<Instruction>` in a `HashMap<u64, JitBlock>` keyed by
//!    entry RIP.
//! 3. On a cache hit, re-executes the pre-decoded instruction list via the
//!    interpreter, avoiding the decode overhead on every iteration of a hot
//!    loop — which is typically the dominant cost.
//!
//! A Tier-1 JIT can replace `execute_block` with genuine WASM bytecode
//! emission without changing the public API.

pub mod block;
pub mod runtime;

use std::collections::HashMap;

use canary_cpu::registers::CpuState;
use canary_memory::GuestMemory;

pub use block::JitBlock;
pub use runtime::JitResult;

// ── JitCache ──────────────────────────────────────────────────────────────────

/// A cache mapping entry RIP addresses to pre-decoded basic blocks.
pub struct JitCache {
    blocks: HashMap<u64, JitBlock>,
    /// Maximum number of cached blocks before the oldest entries are evicted.
    max_blocks: usize,
}

impl JitCache {
    /// Create a new, empty JIT cache.
    pub fn new() -> Self {
        JitCache {
            blocks: HashMap::new(),
            max_blocks: 8192,
        }
    }

    /// Look up a cached block by entry RIP.
    pub fn get_mut(&mut self, rip: u64) -> Option<&mut JitBlock> {
        self.blocks.get_mut(&rip)
    }

    /// Decode and cache a new basic block starting at `entry_rip`.
    ///
    /// Returns `None` if the block cannot be decoded (unmapped memory, unknown
    /// opcode, etc.).  The returned reference borrows `self` immutably.
    pub fn compile(
        &mut self,
        entry_rip: u64,
        mem: &GuestMemory,
    ) -> Option<&JitBlock> {
        // Evict randomly when the cache is full to bound memory use.
        if self.blocks.len() >= self.max_blocks {
            // Remove an arbitrary entry — O(1) with HashMap.
            if let Some(key) = self.blocks.keys().next().copied() {
                self.blocks.remove(&key);
            }
        }

        let block = block::compile_block(entry_rip, mem)?;
        self.blocks.insert(entry_rip, block);
        self.blocks.get(&entry_rip)
    }

    /// Execute a cached basic block, updating `cpu` and `mem` in place.
    ///
    /// Returns a `JitResult` describing how the block ended.
    pub fn execute_block(
        block: &mut JitBlock,
        cpu: &mut CpuState,
        mem: &mut GuestMemory,
    ) -> JitResult {
        runtime::execute_block(block, cpu, mem)
    }

    /// Invalidate all cached blocks whose entry RIP falls within
    /// `[guest_start, guest_start + length)`.
    ///
    /// Call this from `mprotect(PROT_NONE)` and from any self-modifying-code
    /// write paths so stale decoded blocks are not re-used after the underlying
    /// bytes have changed.
    pub fn invalidate_range(&mut self, guest_start: u64, length: u64) {
        let guest_end = guest_start.saturating_add(length);
        self.blocks.retain(|&rip, _| rip < guest_start || rip >= guest_end);
    }

    /// Return the number of blocks currently in the cache.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
}

impl Default for JitCache {
    fn default() -> Self {
        Self::new()
    }
}
