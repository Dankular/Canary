//! ELF64 parser for x86-64 Linux binaries.
//!
//! Supports ET_EXEC (static) and ET_DYN (PIE/shared) ELF files.
//! Reference: https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html

pub mod types;
pub mod parser;
pub mod auxv;

pub use parser::Elf64;
pub use types::*;
