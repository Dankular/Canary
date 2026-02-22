# Canary

A from-scratch x86-64 Linux ELF emulator written in Rust, compiled to WebAssembly. Runs unmodified 64-bit Linux binaries directly in the browser — no plugins, no CDN, no native code.

### Key differences from CheerpX

| Feature | CheerpX | Canary |
|---|---|---|
| Architecture | x86 (32-bit only) | **x86-64 (64-bit)** |
| ELF support | ET_EXEC 32-bit | **ET_EXEC + ET_DYN (PIE) 64-bit** |
| Syscall ABI | `INT 0x80` (i386) | **`SYSCALL` instruction (x86-64)** |
| Registers | 8 GPRs (EAX–EDI) | **16 GPRs (RAX–R15) + XMM0–XMM15** |
| Runtime | Closed-source CDN binary | **Open-source Rust → WASM** |
| CDN dependency | Required | **None — fully self-hosted** |
| TLS support | Limited | **FS.base via `arch_prctl`** |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│               JavaScript / Browser                   │
│  canary-host.mjs: fetch image, run_elf(), I/O        │
└────────────────────────┬────────────────────────────┘
                         │ wasm-bindgen
┌────────────────────────▼────────────────────────────┐
│              canary-wasm  (WASM entry point)          │
│  CanaryRuntime { cpu, mem, ctx }                     │
│  Interpreter loop → syscall trap → dispatch          │
└───┬──────────────┬──────────────┬────────────────────┘
    │              │              │
┌───▼────┐  ┌─────▼──────┐  ┌───▼──────────┐
│canary- │  │ canary-cpu │  │canary-syscall│
│  elf   │  │            │  │              │
│        │  │ registers  │  │ ~60 syscalls │
│ELF64   │  │ decoder    │  │ mmap/brk/    │
│parser  │  │ interpreter│  │ read/write/  │
│auxv    │  │ flags      │  │ arch_prctl…  │
└────────┘  └────────────┘  └──────┬───────┘
                                    │
                          ┌─────────▼───────┐   ┌─────────────────┐
                          │ canary-memory    │   │   canary-fs      │
                          │ GuestMemory     │   │ VFS / MemFs     │
                          │ page table      │   │ /proc /dev      │
                          │ mmap/munmap/brk │   │ ext2 parser     │
                          └─────────────────┘   └─────────────────┘
```

### Crates

| Crate | Purpose |
|---|---|
| `canary-elf` | Parse ELF64 headers, program headers, dynamic section, RELA relocations, auxv/stack construction |
| `canary-cpu` | x86-64 register file (16 GPRs, XMM0–15, x87, RFLAGS), instruction decoder, interpreter |
| `canary-memory` | 64-bit guest VM backed by WASM linear memory; identity-mapped, lazy growth |
| `canary-fs` | In-memory VFS (MemFs), /proc and /dev pseudo-files, read-only ext2 image parser |
| `canary-syscall` | Linux x86-64 syscall dispatcher, file descriptor table, stdout/stderr capture |
| `canary-wasm` | WASM entry point, wasm-bindgen glue, interpreter loop orchestration |

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) (stable)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/)
- Node.js ≥ 18

```bash
cargo install wasm-pack
```

### Build & Run

```bash
# Build the WASM core
wasm-pack build crates/canary-wasm --target web --out-dir crates/canary-wasm/pkg

# Start the dev server
node harness/server.mjs
# → http://localhost:3000
```

The harness will try to load an ext2 filesystem image from `/steam/rootfs-x64.ext2`. Place a disk image there or override via query string.

### Harness query parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `image` | `/steam/rootfs-x64.ext2` | Path to ext2 disk image |
| `bin` | `/bin/true` | Binary to execute |
| `args` | _(empty)_ | Comma-separated arguments |

Examples:
```
http://localhost:3000/?bin=/bin/bash&args=-c,echo+hello+world
http://localhost:3000/?image=/steam/rootfs-x64.ext2&bin=/usr/bin/python3
```

### JavaScript API (canary-wasm)

The WASM module exposes a `CanaryRuntime` class:

```js
import init, { CanaryRuntime } from './crates/canary-wasm/pkg/canary_wasm.js';
await init();

const rt = new CanaryRuntime();

// Load a filesystem image (raw ext2 bytes)
rt.load_fs_image(ext2Bytes);

// Or add individual files
rt.add_file('/myapp', elfBytes);

// Execute an ELF binary
const argv = JSON.stringify(['/myapp', 'arg1']);
const envp = JSON.stringify(['HOME=/root', 'TERM=xterm-256color']);
const exitCode = rt.run_elf(elfBytes, argv, envp);

// Read captured output
const stdout = rt.drain_stdout();  // Uint8Array
const stderr = rt.drain_stderr();  // Uint8Array

rt.free();
```

## Implemented Syscalls

`read` `write` `open` `openat` `close` `lseek` `pread64` `readv` `writev`
`stat` `fstat` `lstat` `fstatat`
`mmap` `mprotect` `munmap` `mremap` `brk` `madvise`
`arch_prctl` (FS/GS base — required for glibc TLS)
`getpid` `getppid` `gettid` `getuid` `geteuid` `getgid` `getegid` `setuid` `setgid`
`rt_sigaction` `rt_sigprocmask` `futex` `sched_yield` `sched_getaffinity`
`uname` `getcwd` `chdir` `mkdir` `mkdirat` `access` `faccessat`
`readlink` `readlinkat` `ioctl` (TIOCGWINSZ, TCGETS, TCSETS)
`gettimeofday` `clock_gettime` `nanosleep` `getrlimit` `setrlimit` `sysinfo`
`dup` `dup2` `dup3` `pipe` `pipe2` `fcntl` `getdents64` `ftruncate` `truncate`
`getrandom` `memfd_create` `memfd_create` `symlink` `chmod` `chown`
`set_robust_list` `rseq` `prctl` `sigaltstack` `prlimit64`
`kill` `wait4` `clone` `fork` `execve` _(stubs — return ENOSYS)_
`exit` `exit_group`

## Supported x86-64 Instructions

| Family | Instructions |
|--------|-------------|
| Data movement | MOV, MOVSX/ZX, LEA, PUSH/POP, XCHG, XADD, MOVS |
| Arithmetic | ADD, ADC, SUB, SBB, IMUL, MUL, IDIV, DIV, INC, DEC, NEG |
| Logical | AND, OR, XOR, TEST, CMP |
| Shifts/rotates | SHL, SHR, SAR, ROL, ROR, RCL, RCR, SHLD, SHRD |
| Bit ops | BSF, BSR, BT/S/R/C, POPCNT, LZCNT, TZCNT |
| Control flow | JMP, Jcc (all 16), CALL, RET, SYSCALL, INT, INT3, UD2 |
| Conditionals | SETcc, CMOVcc |
| Atomics | CMPXCHG (with LOCK prefix) |
| Sign extension | CBW, CWDE, CDQE, CWD, CDQ, CQO |
| SSE2 scalar | ADDSD/SS, SUBSD/SS, MULSD/SS, DIVSD/SS, SQRTSD/SS, UCOMIxx, CVTxx |
| SSE2 packed | PXOR, PAND, POR, PCMPEQ, MOVDQU/A, MOVQ |
| x87 FPU | FLD, FSTP, FADDP, FSUBP, FMULP, FDIVP, FCOMPP |
| String ops | SCAS, CMPS, STOS, LODS (with REP) |
| Misc | NOP, HLT, CPUID, RDTSC, XGETBV, PUSHF/POPF, LAHF/SAHF |

## Memory Layout

Guest virtual addresses are **identity-mapped** to WASM linear memory offsets (guest VA = WASM byte index), so no translation table lookup is needed at runtime. The backing store grows lazily as pages are mapped.

| Region | Guest VA |
|--------|----------|
| ELF text/data | `0x0040_0000` |
| Dynamic linker | `0x1000_0000` |
| mmap / heap | `0x2000_0000` → up |
| Stack top | `0xBFFF_F000` (8 MiB, grows down) |

## Filesystem

Canary includes a **read-only ext2 parser** (`canary-fs/src/ext2.rs`) that populates the in-memory VFS from a raw disk image. Supported features:

- Superblock parsing (block size, inode size, group descriptors)
- Direct blocks (i_block[0–11]), single-indirect, and double-indirect
- Inline symlinks (≤ 60 bytes) and block-based symlinks
- Files > 128 MiB are stubbed empty to bound RAM usage

## Roadmap

- [ ] Dynamic linker (`ld-linux-x86-64.so.2`) for fully dynamically-linked ELFs
- [ ] JIT compiler (x86-64 → WASM basic-block translation)
- [ ] Threads (`clone`, `futex` WAIT/WAKE via SharedArrayBuffer)
- [ ] Signal delivery
- [ ] `execve` (process replacement)
- [ ] Networking (TCP/IP via lwIP)
- [ ] Graphical output (Xorg / KMS)
- [ ] WASM64 (remove 4 GiB guest VA constraint)
- [ ] ARM64 ELF support

## License

MIT OR Apache-2.0
