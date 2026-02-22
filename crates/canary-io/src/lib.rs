//! I/O port emulation for Canary.
//!
//! Port 0x7860 is the WebX GPU IPC channel.
//! All other ports return 0xFF (not present) for IN, and silently ignore OUT.

use std::collections::VecDeque;

/// Direction of an I/O port access.
#[derive(Debug, Clone, Copy)]
pub enum IoDir { In, Out }

/// A pending I/O port write from the guest, waiting for JS to process.
#[derive(Debug, Clone)]
pub struct IoPendingWrite {
    pub port: u16,
    pub size: u8,   // 1, 2, or 4
    pub val:  u32,
}

/// A pending I/O port read response from JS back to the guest.
#[derive(Debug, Clone)]
pub struct IoPendingRead {
    pub port: u16,
    pub size: u8,
    pub val:  u32,
}

/// I/O port state.
pub struct IoCtx {
    /// Outbound writes queued by guest — delivered to JS.
    pub pending_writes: VecDeque<IoPendingWrite>,
    /// Inbound read responses queued by JS — consumed by guest IN.
    pub pending_reads:  VecDeque<IoPendingRead>,
}

impl IoCtx {
    pub fn new() -> Self {
        IoCtx {
            pending_writes: VecDeque::new(),
            pending_reads:  VecDeque::new(),
        }
    }

    /// Called when the guest executes OUT port, val.
    /// Queues the write for JS to process.
    pub fn guest_out(&mut self, port: u16, size: u8, val: u32) {
        self.pending_writes.push_back(IoPendingWrite { port, size, val });
    }

    /// Called when the guest executes IN port.
    /// Returns a queued read response from JS, or 0xFF if none available.
    pub fn guest_in(&mut self, port: u16, size: u8) -> u32 {
        if let Some(resp) = self.pending_reads.front() {
            if resp.port == port && resp.size == size {
                return self.pending_reads.pop_front().unwrap().val;
            }
        }
        // No response ready: return 0xFF (busy/not-present)
        match size {
            1 => 0xFF,
            2 => 0xFFFF,
            _ => 0xFFFF_FFFF,
        }
    }

    /// Drain all pending writes for JS consumption.
    pub fn drain_writes(&mut self) -> Vec<IoPendingWrite> {
        self.pending_writes.drain(..).collect()
    }

    /// JS pushes a read response (data from browser to guest).
    pub fn push_read_response(&mut self, port: u16, size: u8, val: u32) {
        self.pending_reads.push_back(IoPendingRead { port, size, val });
    }
}

impl Default for IoCtx {
    fn default() -> Self {
        Self::new()
    }
}
