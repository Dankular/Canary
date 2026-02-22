//! Thread management types for the Canary emulator.
//!
//! Each `clone(CLONE_VM | CLONE_THREAD)` allocates a new `ThreadId` and records
//! a `Thread` entry in the `ThreadTable`.  In the WASM execution model each
//! thread maps to a Web Worker sharing the same `SharedArrayBuffer`-backed
//! linear memory.

use canary_cpu::registers::CpuState;
use std::collections::HashMap;

// ── Thread ID ─────────────────────────────────────────────────────────────────

pub type ThreadId = u32;

// ── Thread state ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThreadState {
    Running,
    /// Thread is sleeping on a futex at this guest virtual address.
    FutexWait(u64),
    /// Thread has exited with this status code.
    Zombie(i32),
}

// ── Thread record ─────────────────────────────────────────────────────────────

pub struct Thread {
    pub tid:   ThreadId,
    pub state: ThreadState,
    /// Each spawned thread has its own register file.  The main thread's
    /// registers live in `CanaryRuntime::cpu`; this field is used for any
    /// additional threads allocated through `clone`.
    pub cpu:   CpuState,
    /// Per-thread signal mask.
    pub sigmask: u64,
    /// Guest VA to clear (write 0 as u32) when the thread exits
    /// (CLONE_CHILD_CLEARTID).  0 = not set.
    pub clear_child_tid: u64,
    /// Guest VA where the new TID is written at spawn time
    /// (CLONE_CHILD_SETTID).  0 = not set.
    pub set_child_tid: u64,
}

// ── Thread table ──────────────────────────────────────────────────────────────

pub struct ThreadTable {
    threads:  HashMap<ThreadId, Thread>,
    next_tid: ThreadId,
}

impl ThreadTable {
    /// Create a new thread table.  `main_tid` is the TID of the main thread
    /// (typically 1); the next allocated TID will be `main_tid + 1`.
    pub fn new(main_tid: ThreadId) -> Self {
        ThreadTable {
            threads:  HashMap::new(),
            next_tid: main_tid + 1,
        }
    }

    /// Allocate the next available TID and advance the counter.
    pub fn alloc_tid(&mut self) -> ThreadId {
        let tid = self.next_tid;
        self.next_tid += 1;
        tid
    }

    /// Insert a thread into the table (replaces any existing entry with the
    /// same TID).
    pub fn insert(&mut self, t: Thread) {
        self.threads.insert(t.tid, t);
    }

    /// Look up a thread by TID, returning a mutable reference.
    pub fn get_mut(&mut self, tid: ThreadId) -> Option<&mut Thread> {
        self.threads.get_mut(&tid)
    }

    /// Iterate mutably over all threads.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Thread> {
        self.threads.values_mut()
    }

    /// Remove a thread from the table.
    pub fn remove(&mut self, tid: ThreadId) -> Option<Thread> {
        self.threads.remove(&tid)
    }

    /// Number of threads currently tracked.
    pub fn len(&self) -> usize {
        self.threads.len()
    }

    /// True if no threads are tracked.
    pub fn is_empty(&self) -> bool {
        self.threads.is_empty()
    }
}
