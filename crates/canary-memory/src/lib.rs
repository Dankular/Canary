//! Virtual memory manager for a 64-bit Linux process running inside WASM.
//!
//! # Design (v2 — page-table based)
//!
//! Instead of identity-mapping guest VAs to WASM byte indices (which required
//! up to 3 GiB of backing store just for a stack at 0xBFFF_F000), we now use
//! a software page table:
//!
//! * Physical frames are allocated sequentially from `data: Vec<u8>`.
//!   Frame N occupies `data[N * PAGE_SIZE .. (N+1) * PAGE_SIZE]`.
//! * A `HashMap<u64, u32>` maps page-number (guest_va >> 12) to frame index.
//! * Only pages that are actually mapped consume physical frames.
//! * The backing store grows lazily; a program that uses 4 MiB of real memory
//!   will cause ~4 MiB of WASM allocation, regardless of where its VAs live.
//!
//! This allows the full 47-bit x86-64 user VA space (e.g. stack at
//! 0x0000_7FFF_FFFF_F000, mmap regions anywhere) with no 4 GiB constraint.

use thiserror::Error;
use std::collections::{BTreeMap, HashMap};

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
    /// Kept for API compatibility; unused in the new page-table design.
    pub wasm_offset: u32,
}

// ── Layout constants ──────────────────────────────────────────────────────────

/// Layout constants for the guest address space.
pub mod layout {
    /// Lowest guest address ever used (below ELF base for ET_EXEC).
    pub const GUEST_BASE:       u64 = 0x0010_0000;
    /// Typical ELF load address for ET_EXEC / base for ET_DYN.
    pub const ELF_BASE:         u64 = 0x0040_0000;
    /// Load address for the dynamic interpreter (ld-linux.so.2).
    pub const INTERP_BASE:      u64 = 0x1000_0000;
    /// Start of the mmap / heap region (grows upward).
    pub const MMAP_START:       u64 = 0x2000_0000;
    /// Stack top: standard Linux x86-64 default (128 TiB mark).
    pub const STACK_TOP:        u64 = 0x0000_7FFF_FFFF_F000;
    /// Stack size (8 MiB default).
    pub const STACK_SIZE:       u64 = 8 * 1024 * 1024;
    /// Unused in new design (kept so existing callers compile).
    pub const TOTAL_WASM_BYTES: usize = 0;
}

// ── Guest memory ──────────────────────────────────────────────────────────────

pub struct GuestMemory {
    /// Physical frame storage.  Frame N is at data[N*PAGE_SIZE..(N+1)*PAGE_SIZE].
    /// Not pub: callers must go through the API.
    data: Vec<u8>,

    /// Number of frames allocated so far.
    frame_count: u32,

    /// Page table: page_number (guest_va >> 12) → frame index.
    page_table: HashMap<u64, u32>,

    /// Mapping metadata for mmap/munmap/mprotect tracking.
    mappings: BTreeMap<u64, Mapping>,

    /// Next guest VA for anonymous mmap allocation.
    mmap_brk: u64,

    /// Current program break (brk syscall).
    pub program_brk: u64,
}

impl GuestMemory {
    /// Create a new guest memory.  `_total_bytes` is accepted for API
    /// compatibility but ignored — the backing store grows lazily.
    pub fn new(_total_bytes: usize) -> Self {
        GuestMemory {
            data:        Vec::with_capacity(64 * 1024 * 1024),
            frame_count: 0,
            page_table:  HashMap::new(),
            mappings:    BTreeMap::new(),
            mmap_brk:    layout::MMAP_START,
            program_brk: layout::MMAP_START,
        }
    }

    // ── Frame allocator ───────────────────────────────────────────────────

    /// Allocate a new zeroed physical frame and return its index.
    fn alloc_frame(&mut self) -> u32 {
        let idx = self.frame_count;
        self.frame_count += 1;
        let new_len = self.frame_count as usize * PAGE_SIZE as usize;
        if new_len > self.data.len() {
            self.data.resize(new_len, 0);
        }
        idx
    }

    /// Return the frame index for `page_num`, allocating one if absent.
    fn get_or_alloc_frame(&mut self, page_num: u64) -> u32 {
        if let Some(&frame) = self.page_table.get(&page_num) {
            return frame;
        }
        let frame = self.alloc_frame();
        self.page_table.insert(page_num, frame);
        frame
    }

    // ── Translation ───────────────────────────────────────────────────────

    /// Translate `guest_addr` to a byte index into `self.data`, checking `prot`.
    fn translate_inner(&self, guest_addr: u64, prot: Prot) -> MemResult<usize> {
        let page_num = guest_addr >> 12;
        let page_off = (guest_addr & PAGE_MASK) as usize;

        let frame = self.page_table.get(&page_num)
            .ok_or(MemError::NotMapped(guest_addr))?;

        // Check protection via the Mapping metadata.
        let m = self.find_mapping(guest_addr)
            .ok_or(MemError::NotMapped(guest_addr))?;
        if prot.contains(Prot::READ)  && !m.prot.contains(Prot::READ)  {
            return Err(MemError::NotReadable(guest_addr));
        }
        if prot.contains(Prot::WRITE) && !m.prot.contains(Prot::WRITE) {
            return Err(MemError::NotWritable(guest_addr));
        }
        if prot.contains(Prot::EXEC)  && !m.prot.contains(Prot::EXEC)  {
            return Err(MemError::NotExecutable(guest_addr));
        }

        Ok(*frame as usize * PAGE_SIZE as usize + page_off)
    }

    /// Public translation (same signature as before).
    pub fn translate(&self, guest_addr: u64, prot: Prot) -> MemResult<usize> {
        self.translate_inner(guest_addr, prot)
    }

    // ── Mapping lookup ────────────────────────────────────────────────────

    /// Find the mapping that contains `guest_addr`, if any.
    pub fn find_mapping(&self, guest_addr: u64) -> Option<&Mapping> {
        self.mappings
            .range(..=guest_addr)
            .next_back()
            .map(|(_, m)| m)
            .filter(|m| guest_addr < m.guest_start + m.length)
    }

    // ── mmap / munmap / mprotect / mremap ─────────────────────────────────

    /// Map a region of guest memory.
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
            if guest_hint & PAGE_MASK != 0 {
                return Err(MemError::Unaligned(guest_hint));
            }
            // Remove any existing mapping at this range first.
            self.munmap(guest_hint, length).ok();
            guest_hint
        } else {
            let addr = page_align_up(self.mmap_brk);
            self.mmap_brk = addr + length;
            addr
        };

        // Allocate physical frames and zero them.
        let num_pages = length / PAGE_SIZE;
        for i in 0..num_pages {
            let page_num = (guest_start >> 12) + i;
            let frame = self.get_or_alloc_frame(page_num);
            let start = frame as usize * PAGE_SIZE as usize;
            self.data[start..start + PAGE_SIZE as usize].fill(0);
        }

        // wasm_offset is kept at 0; it is unused in the page-table design.
        self.mappings.insert(guest_start, Mapping {
            guest_start,
            length,
            prot,
            wasm_offset: 0,
        });

        Ok(guest_start)
    }

    /// Unmap a region.
    pub fn munmap(&mut self, guest_start: u64, length: u64) -> MemResult<()> {
        let guest_start = page_align_down(guest_start);
        let length      = page_align_up(length);
        let guest_end   = guest_start + length;

        // Free page table entries (frames are not reclaimed — fragmentation
        // management is deferred to a future compacting GC).
        let num_pages = length / PAGE_SIZE;
        for i in 0..num_pages {
            self.page_table.remove(&((guest_start >> 12) + i));
        }

        // Remove mapping records that overlap [guest_start, guest_end).
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

    /// Remap a region (glibc malloc uses this heavily).
    ///
    /// Implements the semantics of Linux `mremap(2)`:
    /// * Shrink: unmap the tail pages and return `old_addr`.
    /// * Grow in-place: if the pages immediately after `old_addr + old_size`
    ///   are free, extend there.
    /// * Move (MREMAP_MAYMOVE): allocate a fresh region, copy content, unmap
    ///   the old region.
    pub fn mremap(
        &mut self,
        old_addr: u64,
        old_size: u64,
        new_size: u64,
        flags:    u32,
    ) -> MemResult<u64> {
        const MREMAP_MAYMOVE: u32 = 1;

        let old_size = page_align_up(old_size);
        let new_size = page_align_up(new_size);

        if new_size == 0 { return Err(MemError::OutOfMemory); }

        // Shrink: just unmap the tail.
        if new_size <= old_size {
            if new_size < old_size {
                self.munmap(old_addr + new_size, old_size - new_size)?;
                // Update mapping record length.
                if let Some(m) = self.mappings.get_mut(&old_addr) {
                    m.length = new_size;
                }
            }
            return Ok(old_addr);
        }

        // Grow: try to extend in-place first.
        let old_end = old_addr + old_size;
        let ext_pages = (new_size - old_size) / PAGE_SIZE;
        let start_ext_page = old_end >> 12;
        let can_extend = (0..ext_pages)
            .all(|i| !self.page_table.contains_key(&(start_ext_page + i)));

        if can_extend {
            let prot = self.find_mapping(old_addr)
                .map(|m| m.prot)
                .unwrap_or(Prot::READ | Prot::WRITE);
            for i in 0..ext_pages {
                let frame = self.get_or_alloc_frame(start_ext_page + i);
                let idx = frame as usize * PAGE_SIZE as usize;
                self.data[idx..idx + PAGE_SIZE as usize].fill(0);
            }
            if let Some(m) = self.mappings.get_mut(&old_addr) {
                m.length = new_size;
            } else {
                // No mapping record existed — insert one.
                self.mappings.insert(old_addr, Mapping {
                    guest_start: old_addr,
                    length: new_size,
                    prot,
                    wasm_offset: 0,
                });
            }
            return Ok(old_addr);
        }

        // Must move.
        if flags & MREMAP_MAYMOVE == 0 {
            return Err(MemError::OutOfMemory);
        }

        let prot = self.find_mapping(old_addr)
            .map(|m| m.prot)
            .unwrap_or(Prot::READ | Prot::WRITE);

        // Allocate a new region.
        let new_addr = self.mmap(
            0,
            new_size,
            prot,
            MapFlags::PRIVATE | MapFlags::ANONYMOUS,
        )?;

        // Copy old pages into new region.
        let copy_pages = old_size / PAGE_SIZE;
        for i in 0..copy_pages {
            let old_page = (old_addr >> 12) + i;
            let new_page = (new_addr >> 12) + i;
            if let Some(&old_frame) = self.page_table.get(&old_page) {
                let old_idx = old_frame as usize * PAGE_SIZE as usize;
                // Copy via a temporary buffer to avoid aliasing issues.
                let buf: Vec<u8> = self.data[old_idx..old_idx + PAGE_SIZE as usize].to_vec();
                let new_frame = self.get_or_alloc_frame(new_page);
                let new_idx = new_frame as usize * PAGE_SIZE as usize;
                self.data[new_idx..new_idx + PAGE_SIZE as usize].copy_from_slice(&buf);
            }
        }

        // Unmap old region.
        self.munmap(old_addr, old_size)?;

        Ok(new_addr)
    }

    // ── Program break ─────────────────────────────────────────────────────

    /// Adjust the program break.  Returns the (possibly unchanged) break address.
    pub fn brk(&mut self, new_brk: u64) -> u64 {
        if new_brk == 0 || new_brk < self.program_brk {
            return self.program_brk;
        }
        let old_brk = self.program_brk;
        let new_brk = page_align_up(new_brk);
        if new_brk > old_brk {
            let start_page = old_brk >> 12;
            let end_page   = new_brk >> 12;
            for page in start_page..end_page {
                let frame = self.get_or_alloc_frame(page);
                let idx = frame as usize * PAGE_SIZE as usize;
                self.data[idx..idx + PAGE_SIZE as usize].fill(0);
            }
            self.program_brk = new_brk;
        }
        self.program_brk
    }

    // ── Byte-level reads and writes ───────────────────────────────────────

    /// Return a slice of guest bytes at `guest_addr..guest_addr+len`.
    ///
    /// Fast path: if the entire range lies within one page, returns a direct
    /// slice into the frame.  Cross-page reads return `Err(NotMapped)` — use
    /// `read_bytes_copy` for those (or let the caller fall back).
    pub fn read_bytes(&self, guest_addr: u64, len: usize) -> MemResult<&[u8]> {
        if len == 0 {
            // Return an empty slice — any valid guest address works.
            return Ok(&[]);
        }
        let page_off = (guest_addr & PAGE_MASK) as usize;
        if page_off + len <= PAGE_SIZE as usize {
            // Fast path: entire range within one page.
            let idx = self.translate_inner(guest_addr, Prot::READ)?;
            self.data.get(idx..idx + len).ok_or(MemError::WasmBounds)
        } else {
            // Cross-page: cannot return a contiguous slice.
            // Callers that need cross-page data should use read_bytes_copy().
            Err(MemError::NotMapped(guest_addr))
        }
    }

    /// Read `len` bytes starting at `guest_addr` into an owned `Vec<u8>`.
    /// Handles cross-page reads correctly by copying page-by-page.
    pub fn read_bytes_copy(&self, guest_addr: u64, len: usize) -> MemResult<Vec<u8>> {
        if len == 0 { return Ok(Vec::new()); }
        let page_off = (guest_addr & PAGE_MASK) as usize;
        if page_off + len <= PAGE_SIZE as usize {
            // Single page — just copy the slice.
            Ok(self.read_bytes(guest_addr, len)?.to_vec())
        } else {
            // Split at the page boundary.
            let first_chunk = PAGE_SIZE as usize - page_off;
            let mut result = Vec::with_capacity(len);
            result.extend_from_slice(self.read_bytes(guest_addr, first_chunk)?);
            result.extend(self.read_bytes_copy(
                guest_addr + first_chunk as u64,
                len - first_chunk,
            )?);
            Ok(result)
        }
    }

    /// Write `src` bytes into guest memory at `guest_addr`, checking WRITE prot.
    /// Handles cross-page writes by splitting at page boundaries.
    pub fn write_bytes_at(&mut self, guest_addr: u64, src: &[u8]) -> MemResult<()> {
        if src.is_empty() { return Ok(()); }
        let page_off = (guest_addr & PAGE_MASK) as usize;
        if page_off + src.len() <= PAGE_SIZE as usize {
            // Fast path: single page.
            let idx = self.translate_inner(guest_addr, Prot::WRITE)?;
            let dst = self.data.get_mut(idx..idx + src.len())
                .ok_or(MemError::WasmBounds)?;
            dst.copy_from_slice(src);
            Ok(())
        } else {
            // Split at the page boundary.
            let first_chunk = PAGE_SIZE as usize - page_off;
            self.write_bytes_at(guest_addr, &src[..first_chunk])?;
            self.write_bytes_at(guest_addr + first_chunk as u64, &src[first_chunk..])
        }
    }

    // ── Typed reads ───────────────────────────────────────────────────────

    pub fn read_u8(&self, addr: u64) -> MemResult<u8> {
        Ok(self.read_bytes(addr, 1)?[0])
    }

    pub fn read_u16(&self, addr: u64) -> MemResult<u16> {
        // Fast path: aligned within a page.
        if (addr & PAGE_MASK) <= PAGE_SIZE - 2 {
            Ok(u16::from_le_bytes(
                self.read_bytes(addr, 2)?.try_into().unwrap(),
            ))
        } else {
            let b = self.read_bytes_copy(addr, 2)?;
            Ok(u16::from_le_bytes(b.try_into().unwrap()))
        }
    }

    pub fn read_u32(&self, addr: u64) -> MemResult<u32> {
        if (addr & PAGE_MASK) <= PAGE_SIZE - 4 {
            Ok(u32::from_le_bytes(
                self.read_bytes(addr, 4)?.try_into().unwrap(),
            ))
        } else {
            let b = self.read_bytes_copy(addr, 4)?;
            Ok(u32::from_le_bytes(b.try_into().unwrap()))
        }
    }

    pub fn read_u64(&self, addr: u64) -> MemResult<u64> {
        if (addr & PAGE_MASK) <= PAGE_SIZE - 8 {
            Ok(u64::from_le_bytes(
                self.read_bytes(addr, 8)?.try_into().unwrap(),
            ))
        } else {
            let b = self.read_bytes_copy(addr, 8)?;
            Ok(u64::from_le_bytes(b.try_into().unwrap()))
        }
    }

    pub fn read_i8(&self,  addr: u64) -> MemResult<i8>  { Ok(self.read_u8(addr)?  as i8)  }
    pub fn read_i16(&self, addr: u64) -> MemResult<i16> { Ok(self.read_u16(addr)? as i16) }
    pub fn read_i32(&self, addr: u64) -> MemResult<i32> { Ok(self.read_u32(addr)? as i32) }
    pub fn read_i64(&self, addr: u64) -> MemResult<i64> { Ok(self.read_u64(addr)? as i64) }

    // ── Typed writes ──────────────────────────────────────────────────────

    pub fn write_u8(&mut self,  addr: u64, v: u8)  -> MemResult<()> {
        self.write_bytes_at(addr, &[v])
    }
    pub fn write_u16(&mut self, addr: u64, v: u16) -> MemResult<()> {
        self.write_bytes_at(addr, &v.to_le_bytes())
    }
    pub fn write_u32(&mut self, addr: u64, v: u32) -> MemResult<()> {
        self.write_bytes_at(addr, &v.to_le_bytes())
    }
    pub fn write_u64(&mut self, addr: u64, v: u64) -> MemResult<()> {
        self.write_bytes_at(addr, &v.to_le_bytes())
    }

    // ── C string ──────────────────────────────────────────────────────────

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

    // ── ELF loader helpers ────────────────────────────────────────────────

    /// Write bytes directly (bypasses protection checks).
    /// Allocates frames on demand — used by the ELF loader and mmap file-back.
    pub fn loader_write(&mut self, guest_addr: u64, src: &[u8]) {
        if src.is_empty() { return; }
        let page_off = (guest_addr & PAGE_MASK) as usize;
        if page_off + src.len() <= PAGE_SIZE as usize {
            let page_num = guest_addr >> 12;
            let frame = self.get_or_alloc_frame(page_num);
            let idx = frame as usize * PAGE_SIZE as usize + page_off;
            self.data[idx..idx + src.len()].copy_from_slice(src);
        } else {
            // Cross-page: split at the page boundary.
            let first_chunk = PAGE_SIZE as usize - page_off;
            self.loader_write(guest_addr, &src[..first_chunk]);
            self.loader_write(guest_addr + first_chunk as u64, &src[first_chunk..]);
        }
    }

    /// Zero `len` bytes at `guest_addr` (bypasses protection checks).
    pub fn loader_zero(&mut self, guest_addr: u64, len: usize) {
        if len == 0 { return; }
        let zeros = vec![0u8; len];
        self.loader_write(guest_addr, &zeros);
    }

    // ── Memory snapshot / restore (for thread spawning) ───────────────────

    /// Serialize the entire guest address space into a compact binary blob.
    ///
    /// Format:
    /// ```text
    /// [u32 magic=0x434E5259] [u32 n_pages]
    /// ( [u64 page_num] [4096 bytes] ) × n_pages
    /// [u32 n_mappings]
    /// ( [u64 guest_start] [u64 length] [u8 prot_bits] ) × n_mappings
    /// [u64 mmap_brk] [u64 program_brk]
    /// ```
    ///
    /// The blob can be transferred to a Worker which calls `restore_pages()`
    /// to recreate an identical `GuestMemory` for the child thread.
    pub fn snapshot_pages(&self) -> Vec<u8> {
        let n_pages = self.page_table.len();
        let n_maps  = self.mappings.len();
        let capacity = 4 + 4 + n_pages * (8 + PAGE_SIZE as usize)
                     + 4 + n_maps * (8 + 8 + 1)
                     + 8 + 8;
        let mut out = Vec::with_capacity(capacity);

        // Header
        out.extend_from_slice(&0x434E_5259u32.to_le_bytes());
        out.extend_from_slice(&(n_pages as u32).to_le_bytes());

        // Pages: iterate sorted for determinism
        let mut pages: Vec<(u64, u32)> = self.page_table.iter().map(|(&k, &v)| (k, v)).collect();
        pages.sort_unstable_by_key(|&(k, _)| k);
        for (page_num, frame_idx) in pages {
            out.extend_from_slice(&page_num.to_le_bytes());
            let start = frame_idx as usize * PAGE_SIZE as usize;
            out.extend_from_slice(&self.data[start..start + PAGE_SIZE as usize]);
        }

        // Mappings
        out.extend_from_slice(&(n_maps as u32).to_le_bytes());
        for m in self.mappings.values() {
            out.extend_from_slice(&m.guest_start.to_le_bytes());
            out.extend_from_slice(&m.length.to_le_bytes());
            out.push(m.prot.bits());
        }

        // Metadata
        out.extend_from_slice(&self.mmap_brk.to_le_bytes());
        out.extend_from_slice(&self.program_brk.to_le_bytes());

        out
    }

    /// Restore a guest address space from a blob produced by `snapshot_pages()`.
    /// Completely replaces the current memory state.  Returns `false` on parse error.
    #[allow(unused_assignments)]
    pub fn restore_pages(&mut self, blob: &[u8]) -> bool {
        let mut pos = 0usize;

        macro_rules! read_u8 {
            () => {{
                if pos >= blob.len() { return false; }
                let v = blob[pos]; pos += 1; v
            }}
        }
        macro_rules! read_u32 {
            () => {{
                if pos + 4 > blob.len() { return false; }
                let v = u32::from_le_bytes(blob[pos..pos+4].try_into().unwrap());
                pos += 4; v
            }}
        }
        macro_rules! read_u64 {
            () => {{
                if pos + 8 > blob.len() { return false; }
                let v = u64::from_le_bytes(blob[pos..pos+8].try_into().unwrap());
                pos += 8; v
            }}
        }

        let magic = read_u32!();
        if magic != 0x434E_5259 { return false; }

        let n_pages = read_u32!() as usize;

        // Reset state
        self.data.clear();
        self.frame_count = 0;
        self.page_table.clear();
        self.mappings.clear();

        // Restore pages in the order they were serialised.
        for _ in 0..n_pages {
            let page_num = read_u64!();
            if pos + PAGE_SIZE as usize > blob.len() { return false; }
            let frame = self.alloc_frame();
            self.page_table.insert(page_num, frame);
            let start = frame as usize * PAGE_SIZE as usize;
            self.data[start..start + PAGE_SIZE as usize]
                .copy_from_slice(&blob[pos..pos + PAGE_SIZE as usize]);
            pos += PAGE_SIZE as usize;
        }

        // Restore mappings
        let n_maps = read_u32!() as usize;
        for _ in 0..n_maps {
            let guest_start = read_u64!();
            let length      = read_u64!();
            let prot_bits   = read_u8!();
            let prot        = Prot::from_bits_truncate(prot_bits);
            self.mappings.insert(guest_start, Mapping {
                guest_start,
                length,
                prot,
                wasm_offset: 0,
            });
        }

        // Metadata
        self.mmap_brk    = read_u64!();
        self.program_brk = read_u64!();

        true
    }
}

// ── ElfLoader trait ───────────────────────────────────────────────────────────
//
// Defined here so that canary-elf can depend on canary-memory and implement the
// trait without creating a circular dependency.

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
