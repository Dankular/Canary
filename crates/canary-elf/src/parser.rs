//! ELF64 binary parser.

use crate::types::*;

/// Fully parsed ELF64 binary.
#[derive(Debug, Clone)]
pub struct Elf64 {
    pub header:       Elf64Ehdr,
    pub phdrs:        Vec<Elf64Phdr>,
    pub shdrs:        Vec<Elf64Shdr>,
    pub load_segs:    Vec<LoadSegment>,
    /// Path to the dynamic linker (PT_INTERP), if present.
    pub interp:       Option<String>,
    /// Entry-point virtual address (after applying load bias for PIE).
    pub entry:        u64,
    /// Load bias — 0 for ET_EXEC, chosen base for ET_DYN.
    pub load_bias:    u64,
    /// Lowest virtual address across all PT_LOAD segments.
    pub load_base:    u64,
    /// One-past-highest virtual address across all PT_LOAD segments.
    pub load_end:     u64,
}

// ── Helper: read primitive types from a byte slice ────────────────────────────

fn read_u16(data: &[u8], off: usize) -> ElfResult<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or(ElfError::TooSmall)
}

fn read_u32(data: &[u8], off: usize) -> ElfResult<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or(ElfError::TooSmall)
}

fn read_u64(data: &[u8], off: usize) -> ElfResult<u64> {
    data.get(off..off + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .ok_or(ElfError::TooSmall)
}

fn read_i64(data: &[u8], off: usize) -> ElfResult<i64> {
    read_u64(data, off).map(|v| v as i64)
}

fn read_u8(data: &[u8], off: usize) -> ElfResult<u8> {
    data.get(off).copied().ok_or(ElfError::TooSmall)
}

// ── ELF header ────────────────────────────────────────────────────────────────

fn parse_ehdr(data: &[u8]) -> ElfResult<Elf64Ehdr> {
    if data.len() < 64 {
        return Err(ElfError::TooSmall);
    }

    let mut e_ident = [0u8; 16];
    e_ident.copy_from_slice(&data[..16]);

    if &e_ident[0..4] != &ELFMAG {
        return Err(ElfError::BadMagic);
    }
    if e_ident[4] != ELFCLASS64 {
        return Err(ElfError::Not64Bit(e_ident[4]));
    }
    if e_ident[5] != ELFDATA2LSB {
        return Err(ElfError::NotLittleEndian(e_ident[5]));
    }

    Ok(Elf64Ehdr {
        e_ident,
        e_type:      read_u16(data, 16)?,
        e_machine:   read_u16(data, 18)?,
        e_version:   read_u32(data, 20)?,
        e_entry:     read_u64(data, 24)?,
        e_phoff:     read_u64(data, 32)?,
        e_shoff:     read_u64(data, 40)?,
        e_flags:     read_u32(data, 48)?,
        e_ehsize:    read_u16(data, 52)?,
        e_phentsize: read_u16(data, 54)?,
        e_phnum:     read_u16(data, 56)?,
        e_shentsize: read_u16(data, 58)?,
        e_shnum:     read_u16(data, 60)?,
        e_shstrndx:  read_u16(data, 62)?,
    })
}

// ── Program headers ───────────────────────────────────────────────────────────

fn parse_phdr(data: &[u8], off: usize) -> ElfResult<Elf64Phdr> {
    Ok(Elf64Phdr {
        p_type:   read_u32(data, off)?,
        p_flags:  read_u32(data, off + 4)?,
        p_offset: read_u64(data, off + 8)?,
        p_vaddr:  read_u64(data, off + 16)?,
        p_paddr:  read_u64(data, off + 24)?,
        p_filesz: read_u64(data, off + 32)?,
        p_memsz:  read_u64(data, off + 40)?,
        p_align:  read_u64(data, off + 48)?,
    })
}

fn parse_phdrs(data: &[u8], hdr: &Elf64Ehdr) -> ElfResult<Vec<Elf64Phdr>> {
    let base  = hdr.e_phoff as usize;
    let esz   = hdr.e_phentsize as usize;
    let count = hdr.e_phnum as usize;

    let end = base.checked_add(esz.checked_mul(count).ok_or(ElfError::PhdrOutOfBounds)?)
                  .ok_or(ElfError::PhdrOutOfBounds)?;
    if end > data.len() {
        return Err(ElfError::PhdrOutOfBounds);
    }

    (0..count).map(|i| parse_phdr(data, base + i * esz)).collect()
}

// ── Section headers ───────────────────────────────────────────────────────────

fn parse_shdr(data: &[u8], off: usize) -> ElfResult<Elf64Shdr> {
    Ok(Elf64Shdr {
        sh_name:      read_u32(data, off)?,
        sh_type:      read_u32(data, off + 4)?,
        sh_flags:     read_u64(data, off + 8)?,
        sh_addr:      read_u64(data, off + 16)?,
        sh_offset:    read_u64(data, off + 24)?,
        sh_size:      read_u64(data, off + 32)?,
        sh_link:      read_u32(data, off + 40)?,
        sh_info:      read_u32(data, off + 44)?,
        sh_addralign: read_u64(data, off + 48)?,
        sh_entsize:   read_u64(data, off + 56)?,
    })
}

fn parse_shdrs(data: &[u8], hdr: &Elf64Ehdr) -> ElfResult<Vec<Elf64Shdr>> {
    if hdr.e_shoff == 0 || hdr.e_shnum == 0 {
        return Ok(vec![]);
    }
    let base  = hdr.e_shoff as usize;
    let esz   = hdr.e_shentsize as usize;
    let count = hdr.e_shnum as usize;

    let end = base.checked_add(esz.checked_mul(count).ok_or(ElfError::ShdrOutOfBounds)?)
                  .ok_or(ElfError::ShdrOutOfBounds)?;
    if end > data.len() {
        return Err(ElfError::ShdrOutOfBounds);
    }

    (0..count).map(|i| parse_shdr(data, base + i * esz)).collect()
}

// ── PT_INTERP ─────────────────────────────────────────────────────────────────

fn parse_interp(data: &[u8], phdr: &Elf64Phdr) -> ElfResult<String> {
    let start = phdr.p_offset as usize;
    let end   = start.checked_add(phdr.p_filesz as usize)
                     .ok_or(ElfError::InterpOutOfBounds)?;
    let bytes = data.get(start..end).ok_or(ElfError::InterpOutOfBounds)?;
    // Strip NUL terminator.
    let s = bytes.split(|&b| b == 0).next().unwrap_or(bytes);
    Ok(String::from_utf8_lossy(s).into_owned())
}

// ── Dynamic section ───────────────────────────────────────────────────────────

pub fn parse_dynamic(data: &[u8], phdr: &Elf64Phdr) -> ElfResult<Vec<Elf64Dyn>> {
    let start = phdr.p_offset as usize;
    let sz    = phdr.p_filesz as usize;
    let mut entries = Vec::new();
    let mut off = start;
    while off + 16 <= start + sz {
        let tag = read_i64(data, off)?;
        let val = read_u64(data, off + 8)?;
        entries.push(Elf64Dyn { d_tag: tag, d_val: val });
        if tag == DT_NULL { break; }
        off += 16;
    }
    Ok(entries)
}

// ── Symbol table ──────────────────────────────────────────────────────────────

pub fn parse_sym(data: &[u8], off: usize) -> ElfResult<Elf64Sym> {
    Ok(Elf64Sym {
        st_name:  read_u32(data, off)?,
        st_info:  read_u8(data, off + 4)?,
        st_other: read_u8(data, off + 5)?,
        st_shndx: read_u16(data, off + 6)?,
        st_value: read_u64(data, off + 8)?,
        st_size:  read_u64(data, off + 16)?,
    })
}

// ── RELA entries ──────────────────────────────────────────────────────────────

pub fn parse_rela(data: &[u8], off: usize) -> ElfResult<Elf64Rela> {
    Ok(Elf64Rela {
        r_offset: read_u64(data, off)?,
        r_info:   read_u64(data, off + 8)?,
        r_addend: read_i64(data, off + 16)?,
    })
}

// ── Main parse entry point ────────────────────────────────────────────────────

impl Elf64 {
    /// Parse an ELF64 x86-64 binary from raw bytes.
    ///
    /// For ET_DYN (PIE) binaries, supply `preferred_base` as the desired load
    /// address (e.g. 0x0040_0000). For ET_EXEC, the load addresses come from
    /// the binary itself and `preferred_base` is ignored.
    pub fn parse(data: &[u8], preferred_base: u64) -> ElfResult<Self> {
        let header = parse_ehdr(data)?;

        if header.e_machine != EM_X86_64 {
            return Err(ElfError::WrongArch(header.e_machine));
        }
        if header.e_type != ET_EXEC && header.e_type != ET_DYN {
            return Err(ElfError::UnsupportedType(header.e_type));
        }

        let phdrs = parse_phdrs(data, &header)?;
        let shdrs = parse_shdrs(data, &header)?;

        // ── Compute load bias for PIE ──────────────────────────────────────
        let is_pie = header.e_type == ET_DYN;
        let first_load = phdrs.iter()
            .find(|p| p.p_type == PT_LOAD)
            .ok_or(ElfError::NoLoadSegments)?;

        let load_bias = if is_pie {
            preferred_base.wrapping_sub(first_load.p_vaddr & !(first_load.p_align.saturating_sub(1)))
        } else {
            0
        };

        // ── Collect LOAD segments ──────────────────────────────────────────
        let load_segs: Vec<LoadSegment> = phdrs.iter()
            .filter(|p| p.p_type == PT_LOAD)
            .map(|p| LoadSegment {
                vaddr:  p.p_vaddr.wrapping_add(load_bias),
                memsz:  p.p_memsz,
                filesz: p.p_filesz,
                offset: p.p_offset,
                flags:  p.p_flags,
                align:  p.p_align,
            })
            .collect();

        let load_base = load_segs.iter().map(|s| s.vaddr).min().unwrap_or(0);
        let load_end  = load_segs.iter()
            .map(|s| s.vaddr.saturating_add(s.memsz))
            .max()
            .unwrap_or(0);

        // ── PT_INTERP ──────────────────────────────────────────────────────
        let interp = phdrs.iter()
            .find(|p| p.p_type == PT_INTERP)
            .map(|p| parse_interp(data, p))
            .transpose()?;

        let entry = header.e_entry.wrapping_add(load_bias);

        Ok(Elf64 { header, phdrs, shdrs, load_segs, interp, entry, load_bias, load_base, load_end })
    }

    /// Copy each PT_LOAD segment from `file_data` into `memory`.
    ///
    /// `memory` is indexed from 0 — callers must map virtual addresses to
    /// memory indices themselves (typically `vaddr - memory_base`).
    pub fn load_into<M: GuestMemory>(&self, file_data: &[u8], mem: &mut M) -> ElfResult<()> {
        for seg in &self.load_segs {
            let file_start = seg.offset as usize;
            let file_end   = file_start + seg.filesz as usize;
            let src = &file_data[file_start..file_end];
            mem.write_bytes(seg.vaddr, src);
            // Zero BSS (memsz > filesz).
            if seg.memsz > seg.filesz {
                let bss_start = seg.vaddr + seg.filesz;
                let bss_len   = (seg.memsz - seg.filesz) as usize;
                mem.zero_bytes(bss_start, bss_len);
            }
        }
        Ok(())
    }
}

/// Trait that abstracts over whatever backing memory store is used.
pub trait GuestMemory {
    fn write_bytes(&mut self, guest_addr: u64, data: &[u8]);
    fn zero_bytes(&mut self, guest_addr: u64, len: usize);
}
