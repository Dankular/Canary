//! Linux auxiliary vector (auxv) construction for x86-64.
//!
//! The kernel passes an auxv array above the initial stack, which the C
//! runtime (ld-linux, glibc) uses during startup.

/// Auxiliary vector types (AT_* constants from <elf.h>).
pub mod at {
    pub const AT_NULL:         u64 = 0;
    pub const AT_IGNORE:       u64 = 1;
    pub const AT_EXECFD:       u64 = 2;
    pub const AT_PHDR:         u64 = 3;  // address of program headers
    pub const AT_PHENT:        u64 = 4;  // size of one program header
    pub const AT_PHNUM:        u64 = 5;  // number of program headers
    pub const AT_PAGESZ:       u64 = 6;  // page size
    pub const AT_BASE:         u64 = 7;  // base addr of interpreter
    pub const AT_FLAGS:        u64 = 8;
    pub const AT_ENTRY:        u64 = 9;  // entry point of executable
    pub const AT_UID:          u64 = 11;
    pub const AT_EUID:         u64 = 12;
    pub const AT_GID:          u64 = 13;
    pub const AT_EGID:         u64 = 14;
    pub const AT_PLATFORM:     u64 = 15; // string: "x86_64"
    pub const AT_HWCAP:        u64 = 16; // hardware capabilities
    pub const AT_CLKTCK:       u64 = 17; // clock ticks per second
    pub const AT_SECURE:       u64 = 23;
    pub const AT_RANDOM:       u64 = 25; // address of 16 random bytes
    pub const AT_HWCAP2:       u64 = 26;
    pub const AT_EXECFN:       u64 = 31; // filename of executable
    pub const AT_SYSINFO_EHDR: u64 = 33; // vDSO ELF header (optional)
}

/// A single auxv entry.
#[derive(Debug, Clone, Copy)]
pub struct AuxEntry {
    pub key: u64,
    pub val: u64,
}

/// Build a typical auxv for an x86-64 Linux process.
///
/// Arguments mirror what the real kernel provides.
pub fn build_auxv(
    phdr_addr:    u64,   // virtual address where phdrs are mapped
    phent_size:   u64,   // sizeof(Elf64_Phdr) = 56
    phnum:        u64,   // number of program headers
    interp_base:  u64,   // load address of ld-linux.so (0 if static)
    entry:        u64,   // entry point of the executable
    random_addr:  u64,   // address of 16 random bytes on the stack
    execfn_addr:  u64,   // address of executable filename string
) -> Vec<AuxEntry> {
    use at::*;

    // x86-64 hwcap bits: fpu, sse, sse2 (the baseline for x86-64)
    const HWCAP: u64 = (1 << 0)  // FPU
                     | (1 << 3)  // DE
                     | (1 << 4)  // TSC
                     | (1 << 6)  // PAE
                     | (1 << 8)  // CX8
                     | (1 << 9)  // APIC
                     | (1 << 11) // SEP
                     | (1 << 12) // MTRR
                     | (1 << 15) // CMOV
                     | (1 << 23) // MMX
                     | (1 << 24) // FXSR
                     | (1 << 25) // SSE
                     | (1 << 26) // SSE2
                     ;

    vec![
        AuxEntry { key: AT_PHDR,    val: phdr_addr   },
        AuxEntry { key: AT_PHENT,   val: phent_size   },
        AuxEntry { key: AT_PHNUM,   val: phnum        },
        AuxEntry { key: AT_PAGESZ,  val: 4096         },
        AuxEntry { key: AT_BASE,    val: interp_base  },
        AuxEntry { key: AT_FLAGS,   val: 0            },
        AuxEntry { key: AT_ENTRY,   val: entry        },
        AuxEntry { key: AT_UID,     val: 1000         },
        AuxEntry { key: AT_EUID,    val: 1000         },
        AuxEntry { key: AT_GID,     val: 1000         },
        AuxEntry { key: AT_EGID,    val: 1000         },
        AuxEntry { key: AT_SECURE,  val: 0            },
        AuxEntry { key: AT_RANDOM,  val: random_addr  },
        AuxEntry { key: AT_HWCAP,   val: HWCAP        },
        AuxEntry { key: AT_HWCAP2,  val: 0            },
        AuxEntry { key: AT_CLKTCK,  val: 100          },
        AuxEntry { key: AT_PLATFORM,val: 0            }, // filled in by loader
        AuxEntry { key: AT_EXECFN,  val: execfn_addr  },
        AuxEntry { key: AT_NULL,    val: 0            },
    ]
}

/// Serialise the auxv + argv + envp into an initial stack layout.
///
/// Stack layout (top → bottom, addresses grow downwards):
/// ```text
///   [strings: argv[0..], envp[0..], "x86_64\0", 16 random bytes, execfn]
///   [AT_NULL pair]
///   [auxv pairs   …]
///   [NULL]
///   [envp pointers…]
///   [NULL]
///   [argv pointers…]
///   [argc]          ← rsp
/// ```
pub struct InitialStack {
    /// Raw bytes to write at `stack_top - data.len()`.
    pub data:      Vec<u8>,
    /// Value to set rsp to (lowest address of this block).
    pub rsp:       u64,
    /// Absolute address of the 16 random bytes within the stack.
    pub rand_addr: u64,
}

/// Build the initial stack image.
///
/// `stack_top` is the first byte *above* the usable stack region.
/// `argv` and `envp` are null-terminated C strings (without the trailing NUL
/// — that is added automatically).
pub fn build_initial_stack(
    stack_top:   u64,
    argv:        &[&str],
    envp:        &[&str],
    auxv:        &[AuxEntry],
    random_seed: [u8; 16],
) -> InitialStack {
    // ── Phase 1: collect all strings ──────────────────────────────────────
    // We build the data from the top downward in a Vec, then reverse.
    let mut strings: Vec<u8> = Vec::new();

    fn push_str(buf: &mut Vec<u8>, s: &str) -> usize {
        let start = buf.len();
        buf.extend_from_slice(s.as_bytes());
        buf.push(0); // NUL
        start
    }

    // execfn string (argv[0])
    let execfn_off = push_str(&mut strings, argv.first().copied().unwrap_or(""));
    // platform string
    let platform_off = push_str(&mut strings, "x86_64");
    // 16 random bytes
    let rand_off = strings.len();
    strings.extend_from_slice(&random_seed);
    // all argv strings
    let argv_offs: Vec<usize> = argv.iter().map(|s| push_str(&mut strings, s)).collect();
    // all envp strings
    let envp_offs: Vec<usize> = envp.iter().map(|s| push_str(&mut strings, s)).collect();

    // Align strings section to 16 bytes.
    while strings.len() % 16 != 0 {
        strings.push(0);
    }
    let strings_len = strings.len();

    // ── Phase 2: build the pointer/auxv section ───────────────────────────
    let mut ptrs: Vec<u64> = Vec::new();

    // argc
    ptrs.push(argv.len() as u64);
    // argv pointers (each string is at stack_top - strings_len + off)
    let str_base = stack_top - strings_len as u64;
    for off in &argv_offs {
        ptrs.push(str_base + *off as u64);
    }
    ptrs.push(0); // argv NULL
    // envp pointers
    for off in &envp_offs {
        ptrs.push(str_base + *off as u64);
    }
    ptrs.push(0); // envp NULL
    // auxv — patch AT_PLATFORM and AT_RANDOM
    for entry in auxv {
        let val = match entry.key {
            at::AT_PLATFORM => str_base + platform_off as u64,
            at::AT_RANDOM   => str_base + rand_off as u64,
            at::AT_EXECFN   => str_base + execfn_off as u64,
            _               => entry.val,
        };
        ptrs.push(entry.key);
        ptrs.push(val);
    }

    let ptrs_bytes: Vec<u8> = ptrs.iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();

    // ── Phase 3: combine ──────────────────────────────────────────────────
    // Memory layout: [ptrs_section][strings_section] with ptrs at lower addr.
    let mut data = ptrs_bytes;
    data.extend_from_slice(&strings);

    let rsp = stack_top - data.len() as u64;
    let rand_addr = str_base + rand_off as u64;

    InitialStack { data, rsp, rand_addr }
}
