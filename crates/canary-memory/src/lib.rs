//! Virtual memory manager for a 64-bit Linux process running inside WASM.
//!
//! # Design
//!
//! WebAssembly's linear memory is a flat byte array indexed by a 32-bit
//! offset.  Guest x86-64 processes, however, use 64-bit virtual addresses.
//!
//! We handle this by maintaining a *segment table*: a list of (guest_start,
//! wasm_offset, length, prot) records.  When the interpreter reads or writes
//! a guest address, it calls `translate()` to get the WASM index.
//!
//! For practicality we bias the guest address space so that all segments fit
//! below 4 GiB (the typical size of a WASM linear memory):
//!
//! * Text/data segments start at guest 0x0040_0000 → index 0x0040_0000
//! * mmap-able region starts above the binary.
//! * Stack lives at guest 0xBF00_0000 → index 0xBF00_0000.
//!
//! This works for the vast majority of x86-64 user-space programs that do not
//! require addresses above 4 GiB.

use thiserror::Error;
use std::collections::BTreeMap;

// ── Page size ─────────────────────────────────────────────────────────────────

pub const PAGE_SIZE: u64 = 4096;
pub const PAGE_MASK: u64 = PAGE_SIZE - 1;

pub fn page_align_down(addr: u64) -> u64 { addr & !PAGE_MASK }
pub fn page_align_up(addr: u64)   -> u64 { (addr + PAGE_MASK) & !PAGE_MASK }

// ── Protection flags ──────────────────────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Prot: u8 {
        const NONE  = 0b000;
        const READ  = 0b001;
        const WRITE = 0b010;
        const EXEC  = 0b100;
    }
}

// ── Map flags ─────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MapFlags: u32 {
        const SHARED    = 0x01;
        const PRIVATE   = 0x02;
        const FIXED     = 0x10;
        const ANONYMOUS = 0x20;
        const GROWSDOWN = 0x100;
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum MemError {
    #[error("out of memory")]
    OutOfMemory,
    #[error("address 0x{0:x} not mapped")]
    NotMapped(u64),
    #[error("address 0x{0:x} not readable")]
    NotReadable(u64),
    #[error("address 0x{0:x} not writable")]
    NotWritable(u64),
    #[error("address 0x{0:x} not executable")]
    NotExecutable(u64),
    #[error("mmap fixed address 0x{0:x} conflicts")]
    FixedConflict(u64),
    #[error("unaligned address 0x{0:x}")]
    Unaligned(u64),
    #[error("wasm memory access out of bounds")]
    WasmBounds,
}

pub type MemResult<T> = Result<T, MemError>;

// ── Mapping record ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Mapping {
    /// Guest virtual address (page-aligned start).
    pub guest_start: u64,
    /// Length in bytes (page-aligned).
    pub length:      u64,
    /// Protection.
    pub prot:        Prot,
    /// Offset into `GuestMemory::data` where this mapping lives.
    pub wasm_offset: u32,
}

// ── Guest memory ──────────────────────────────────────────────────────────────

pub struct GuestMemory {
    /// The raw backing store — this is what would be the WASM linear memory.
    /// In a real WASM build this would be a pointer to `memory.buffer`.
    pub data: Vec<u8>,

    /// Page table: guest_start → Mapping, ordered for range queries.
    mappings: BTreeMap<u64, Mapping>,

    /// Next available WASM offset for new allocations.
    _wasm_alloc_ptr: u32,

    /// Next available guest address for anonymous mmap.
    mmap_brk: u64,

    /// Current program break (brk syscall).
    pub program_brk: u64,
}

/// Layout constants for the guest address space.
pub mod layout {
    /// Lowest guest address ever used (below ELF base for ET_EXEC).
    pub const GUEST_BASE:       u64 = 0x0010_0000;
    /// Typical ELF load address for ET_EXEC / base for ET_DYN.
    pub const ELF_BASE:         u64 = 0x0040_0000;
    /// Load address for the dynamic interpreter (ld-linux.so.2).
    /// Placed at 256 MiB, safely above typical ELF text + BSS.
    pub const INTERP_BASE:      u64 = 0x1000_0000;
    /// Start of the mmap / heap region (grows upward).
    /// Placed above INTERP_BASE + generous space for interpreter.
    pub const MMAP_START:       u64 = 0x2000_0000;
    /// Stack base (grows downward from this address).
    pub const STACK_TOP:        u64 = 0xBFFF_F000;
    /// Stack size (8 MiB default).
    pub const STACK_SIZE:       u64 = 8 * 1024 * 1024;
    /// Total WASM linear memory to allocate (3 GiB).
    pub const TOTAL_WASM_BYTES: usize = 0xC000_0000;
}

impl GuestMemory {
    /// Create a new guest memory.  The backing store starts empty and grows
    /// lazily as pages are mapped — no up-front multi-GiB allocation.
    pub fn new(_total_bytes: usize) -> Self {
        GuestMemory {
            data:           Vec::new(),
            mappings:       BTreeMap::new(),
            _wasm_alloc_ptr: 0,
            mmap_brk:       layout::MMAP_START,
            program_brk:    layout::MMAP_START,
        }
    }

    /// Grow the backing store to cover `[0, end)` if necessary.
    fn ensure_capacity(&mut self, end: usize) {
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    /// Find the mapping that contains `guest_addr`, if any.
    pub fn find_mapping(&self, guest_addr: u64) -> Option<&Mapping> {
        // BTreeMap::range gives us all entries with key <= guest_addr.
        self.mappings
            .range(..=guest_addr)
            .next_back()
            .map(|(_, m)| m)
            .filter(|m| guest_addr < m.guest_start + m.length)
    }

    /// Translate a guest virtual address to a WASM data index.
    pub fn translate(&self, guest_addr: u64, prot: Prot) -> MemResult<usize> {
        let m = self.find_mapping(guest_addr)
                    .ok_or(MemError::NotMapped(guest_addr))?;
        if prot.contains(Prot::READ)  && !m.prot.contains(Prot::READ)  { return Err(MemError::NotReadable(guest_addr));  }
        if prot.contains(Prot::WRITE) && !m.prot.contains(Prot::WRITE) { return Err(MemError::NotWritable(guest_addr));  }
        if prot.contains(Prot::EXEC)  && !m.prot.contains(Prot::EXEC)  { return Err(MemError::NotExecutable(guest_addr)); }
        let wasm_idx = m.wasm_offset as u64 + (guest_addr - m.guest_start);
        Ok(wasm_idx as usize)
    }

    /// Allocate a contiguous block in WASM memory (internal).
    #[allow(dead_code)]
    fn wasm_alloc(&mut self, bytes: u64) -> MemResult<u32> {
        let start = self._wasm_alloc_ptr;
        let end   = start.checked_add(bytes as u32).ok_or(MemError::OutOfMemory)?;
        if end as usize > self.data.len() { return Err(MemError::OutOfMemory); }
        self._wasm_alloc_ptr = end;
        Ok(start)
    }

    // ── Public API ────────────────────────────────────────────────────────

    /// Map a region of guest memory.
    ///
    /// If `MapFlags::FIXED` is set, the guest address must be page-aligned and
    /// must not overlap any existing mapping (or the existing mapping will be
    /// silently replaced).
    pub fn mmap(
        &mut self,
        guest_hint: u64,
        length:     u64,
        prot:       Prot,
        flags:      MapFlags,
    ) -> MemResult<u64> {
        if length == 0 { return Err(MemError::OutOfMemory); }
        let length = page_align_up(length);

        let guest_start = if flags.contains(MapFlags::FIXED) {
            if guest_hint & PAGE_MASK != 0 { return Err(MemError::Unaligned(guest_hint)); }
            // Remove any existing mappings in this range.
            self.munmap(guest_hint, length).ok();
            guest_hint
        } else {
            // Pick the next available address in the mmap region.
            let addr = page_align_up(self.mmap_brk);
            self.mmap_brk = addr + length;
            addr
        };

        // Identity-map: guest VA == WASM byte index.
        // This keeps loader_write(), brk(), and all callers consistent.
        let wasm_offset = guest_start as u32;
        let idx = guest_start as usize;
        let end = idx.checked_add(length as usize).ok_or(MemError::OutOfMemory)?;
        self.ensure_capacity(end);
        self.data[idx..idx + length as usize].fill(0);

        self.mappings.insert(guest_start, Mapping { guest_start, length, prot, wasm_offset });
        Ok(guest_start)
    }

    /// Unmap a region.
    pub fn munmap(&mut self, guest_start: u64, length: u64) -> MemResult<()> {
        let guest_start = page_align_down(guest_start);
        let length      = page_align_up(length);
        let guest_end   = guest_start + length;
        // Collect overlapping keys.
        let keys: Vec<u64> = self.mappings
            .range(..guest_end)
            .filter(|(_, m)| m.guest_start + m.length > guest_start)
            .map(|(k, _)| *k)
            .collect();
        for k in keys { self.mappings.remove(&k); }
        Ok(())
    }

    /// Change protection on a mapped region.
    pub fn mprotect(&mut self, guest_start: u64, length: u64, prot: Prot) -> MemResult<()> {
        let guest_end = guest_start + length;
        let keys: Vec<u64> = self.mappings
            .range(..guest_end)
            .filter(|(_, m)| m.guest_start + m.length > guest_start)
            .map(|(k, _)| *k)
            .collect();
        for k in keys {
            if let Some(m) = self.mappings.get_mut(&k) { m.prot = prot; }
        }
        Ok(())
    }

    // ── Typed reads ───────────────────────────────────────────────────────

    pub fn read_bytes(&self, guest_addr: u64, len: usize) -> MemResult<&[u8]> {
        let idx = self.translate(guest_addr, Prot::READ)?;
        self.data.get(idx..idx + len).ok_or(MemError::WasmBounds)
    }

    pub fn write_bytes_at(&mut self, guest_addr: u64, src: &[u8]) -> MemResult<()> {
        let idx = self.translate(guest_addr, Prot::WRITE)?;
        let dst = self.data.get_mut(idx..idx + src.len()).ok_or(MemError::WasmBounds)?;
        dst.copy_from_slice(src);
        Ok(())
    }

    pub fn read_u8(&self, addr: u64)   -> MemResult<u8>  { Ok(self.read_bytes(addr, 1)?[0]) }
    pub fn read_u16(&self, addr: u64)  -> MemResult<u16> { Ok(u16::from_le_bytes(self.read_bytes(addr, 2)?.try_into().unwrap())) }
    pub fn read_u32(&self, addr: u64)  -> MemResult<u32> { Ok(u32::from_le_bytes(self.read_bytes(addr, 4)?.try_into().unwrap())) }
    pub fn read_u64(&self, addr: u64)  -> MemResult<u64> { Ok(u64::from_le_bytes(self.read_bytes(addr, 8)?.try_into().unwrap())) }
    pub fn read_i8(&self, addr: u64)   -> MemResult<i8>  { Ok(self.read_u8(addr)?  as i8)  }
    pub fn read_i16(&self, addr: u64)  -> MemResult<i16> { Ok(self.read_u16(addr)? as i16) }
    pub fn read_i32(&self, addr: u64)  -> MemResult<i32> { Ok(self.read_u32(addr)? as i32) }
    pub fn read_i64(&self, addr: u64)  -> MemResult<i64> { Ok(self.read_u64(addr)? as i64) }

    pub fn write_u8(&mut self,  addr: u64, v: u8)  -> MemResult<()> { self.write_bytes_at(addr, &[v]) }
    pub fn write_u16(&mut self, addr: u64, v: u16) -> MemResult<()> { self.write_bytes_at(addr, &v.to_le_bytes()) }
    pub fn write_u32(&mut self, addr: u64, v: u32) -> MemResult<()> { self.write_bytes_at(addr, &v.to_le_bytes()) }
    pub fn write_u64(&mut self, addr: u64, v: u64) -> MemResult<()> { self.write_bytes_at(addr, &v.to_le_bytes()) }

    /// Read a NUL-terminated C string from guest memory.
    pub fn read_cstr(&self, guest_addr: u64) -> MemResult<String> {
        let mut s = Vec::new();
        let mut addr = guest_addr;
        loop {
            let b = self.read_u8(addr)?;
            if b == 0 { break; }
            s.push(b);
            addr += 1;
        }
        Ok(String::from_utf8_lossy(&s).into_owned())
    }

    // ── ELF loader impl of GuestMemory trait ─────────────────────────────

    /// Directly write bytes (bypassing prot checks) for the ELF loader.
    pub fn loader_write(&mut self, guest_addr: u64, src: &[u8]) {
        let idx = guest_addr as usize;
        self.ensure_capacity(idx + src.len());
        self.data[idx..idx + src.len()].copy_from_slice(src);
    }

    pub fn loader_zero(&mut self, guest_addr: u64, len: usize) {
        let idx = guest_addr as usize;
        self.ensure_capacity(idx + len);
        self.data[idx..idx + len].fill(0);
    }

    // ── Program break (heap) ──────────────────────────────────────────────

    /// Adjust the program break.  Returns the new break address.
    pub fn brk(&mut self, new_brk: u64) -> u64 {
        if new_brk == 0 || new_brk < self.program_brk {
            return self.program_brk;
        }
        let old_brk = self.program_brk;
        let new_brk = page_align_up(new_brk);
        // Allocate extra pages if needed.
        if new_brk > old_brk {
            let idx = old_brk as usize;
            let len = (new_brk - old_brk) as usize;
            self.ensure_capacity(idx + len);
            self.data[idx..idx + len].fill(0);
            self.program_brk = new_brk;
        }
        self.program_brk
    }
}

// ── ElfLoader trait ───────────────────────────────────────────────────────────
//
// Abstracts over the memory back-end used by the ELF loader.
// Defined here (in canary-memory) so that:
//   * canary-elf can depend on canary-memory and use the trait,
//   * canary-memory can provide the impl for GuestMemory — all without
//     creating a circular dependency.

pub trait ElfLoader {
    fn write_bytes(&mut self, guest_addr: u64, data: &[u8]);
    fn zero_bytes(&mut self, guest_addr: u64, len: usize);
}

impl ElfLoader for GuestMemory {
    fn write_bytes(&mut self, guest_addr: u64, data: &[u8]) {
        self.loader_write(guest_addr, data);
    }
    fn zero_bytes(&mut self, guest_addr: u64, len: usize) {
        self.loader_zero(guest_addr, len);
    }
}

