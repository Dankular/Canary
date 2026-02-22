//! ELF64 type definitions — mirrors the C structs from <elf.h>.

use thiserror::Error;

// ── ELF magic ─────────────────────────────────────────────────────────────────
pub const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1; // little-endian

// ── e_type ────────────────────────────────────────────────────────────────────
pub const ET_EXEC: u16 = 2; // static executable
pub const ET_DYN:  u16 = 3; // shared / PIE

// ── e_machine ─────────────────────────────────────────────────────────────────
pub const EM_X86_64:  u16 = 62;
pub const EM_AARCH64: u16 = 183;

// ── p_type ────────────────────────────────────────────────────────────────────
pub const PT_NULL:         u32 = 0;
pub const PT_LOAD:         u32 = 1;
pub const PT_DYNAMIC:      u32 = 2;
pub const PT_INTERP:       u32 = 3;
pub const PT_NOTE:         u32 = 4;
pub const PT_PHDR:         u32 = 6;
pub const PT_TLS:          u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
pub const PT_GNU_STACK:    u32 = 0x6474_e551;
pub const PT_GNU_RELRO:    u32 = 0x6474_e552;

// ── p_flags ───────────────────────────────────────────────────────────────────
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

// ── d_tag (Dynamic section) ───────────────────────────────────────────────────
pub const DT_NULL:     i64 = 0;
pub const DT_NEEDED:   i64 = 1;
pub const DT_PLTRELSZ: i64 = 2;
pub const DT_PLTGOT:   i64 = 3;
pub const DT_STRTAB:   i64 = 5;
pub const DT_SYMTAB:   i64 = 6;
pub const DT_RELA:     i64 = 7;
pub const DT_RELASZ:   i64 = 8;
pub const DT_RELAENT:  i64 = 9;
pub const DT_STRSZ:    i64 = 10;
pub const DT_SYMENT:   i64 = 11;
pub const DT_INIT:     i64 = 12;
pub const DT_FINI:     i64 = 13;
pub const DT_SONAME:   i64 = 14;
pub const DT_JMPREL:   i64 = 23;
pub const DT_PLTREL:   i64 = 20;

// ── Relocation types (x86-64) ─────────────────────────────────────────────────
pub const R_X86_64_NONE:     u32 = 0;
pub const R_X86_64_64:       u32 = 1;
pub const R_X86_64_PC32:     u32 = 2;
pub const R_X86_64_GLOB_DAT: u32 = 6;
pub const R_X86_64_JUMP_SLOT:u32 = 7;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_X86_64_IRELATIVE:u32 = 37;

// ── ELF64 Header ──────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct Elf64Ehdr {
    pub e_ident:     [u8; 16],
    pub e_type:      u16,
    pub e_machine:   u16,
    pub e_version:   u32,
    pub e_entry:     u64,
    pub e_phoff:     u64,
    pub e_shoff:     u64,
    pub e_flags:     u32,
    pub e_ehsize:    u16,
    pub e_phentsize: u16,
    pub e_phnum:     u16,
    pub e_shentsize: u16,
    pub e_shnum:     u16,
    pub e_shstrndx:  u16,
}

// ── ELF64 Program Header ──────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct Elf64Phdr {
    pub p_type:   u32,
    pub p_flags:  u32,
    pub p_offset: u64,
    pub p_vaddr:  u64,
    pub p_paddr:  u64,
    pub p_filesz: u64,
    pub p_memsz:  u64,
    pub p_align:  u64,
}

// ── ELF64 Section Header ──────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct Elf64Shdr {
    pub sh_name:      u32,
    pub sh_type:      u32,
    pub sh_flags:     u64,
    pub sh_addr:      u64,
    pub sh_offset:    u64,
    pub sh_size:      u64,
    pub sh_link:      u32,
    pub sh_info:      u32,
    pub sh_addralign: u64,
    pub sh_entsize:   u64,
}

// ── Dynamic entry ─────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct Elf64Dyn {
    pub d_tag: i64,
    pub d_val: u64, // union d_val / d_ptr
}

// ── Symbol table entry ────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct Elf64Sym {
    pub st_name:  u32,
    pub st_info:  u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size:  u64,
}

// ── Relocation with addend ────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct Elf64Rela {
    pub r_offset: u64,
    pub r_info:   u64,
    pub r_addend: i64,
}

impl Elf64Rela {
    pub fn sym(&self) -> u32 { (self.r_info >> 32) as u32 }
    pub fn ty(&self)  -> u32 { (self.r_info & 0xffff_ffff) as u32 }
}

// ── Parsed load segment ───────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct LoadSegment {
    /// Virtual address at which this segment starts (page-aligned).
    pub vaddr:   u64,
    /// Total size in virtual memory (may exceed filesz, zero-padded).
    pub memsz:   u64,
    /// Bytes from file to copy.
    pub filesz:  u64,
    /// Offset into the file for file content.
    pub offset:  u64,
    /// Protection flags (PF_R | PF_W | PF_X).
    pub flags:   u32,
    /// Required alignment.
    pub align:   u64,
}

// ── Error type ────────────────────────────────────────────────────────────────
#[derive(Debug, Error)]
pub enum ElfError {
    #[error("file too small to contain ELF header")]
    TooSmall,
    #[error("bad ELF magic bytes")]
    BadMagic,
    #[error("not a 64-bit ELF (EI_CLASS = {0})")]
    Not64Bit(u8),
    #[error("not little-endian (EI_DATA = {0})")]
    NotLittleEndian(u8),
    #[error("not an x86-64 ELF (e_machine = {0})")]
    WrongArch(u16),
    #[error("unsupported ELF type {0} (need ET_EXEC or ET_DYN)")]
    UnsupportedType(u16),
    #[error("program header out of bounds")]
    PhdrOutOfBounds,
    #[error("section header out of bounds")]
    ShdrOutOfBounds,
    #[error("PT_INTERP segment out of bounds")]
    InterpOutOfBounds,
    #[error("no PT_LOAD segments found")]
    NoLoadSegments,
    #[error("string table index out of bounds")]
    StrTabOutOfBounds,
}

pub type ElfResult<T> = Result<T, ElfError>;
