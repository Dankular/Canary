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
| Threads | ❌ | **pthreads via SharedArrayBuffer + Web Workers** |
| Networking | ❌ | **BSD sockets → WebSocket bridge** |
| Graphical output | ❌ | **/dev/fb0 framebuffer → Canvas** |
| JIT | Interpreter only | **Basic-block JIT (decode-once cache)** |
| Signal delivery | ❌ | **rt_sigaction, ucontext frames, rt_sigreturn** |
| execve | ENOSYS | **Full process replacement** |
| Address space | 4 GiB limit | **Full 64-bit VA (page-table memory)** |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      JavaScript / Browser                            │
│  canary-host.mjs: fetch image, run_elf(), framebuffer, net bridge    │
└────────────────────────────┬────────────────────────────────────────┘
                             │ wasm-bindgen
┌────────────────────────────▼────────────────────────────────────────┐
│                   canary-wasm  (WASM entry point)                    │
│  CanaryRuntime { cpu, mem, ctx, jit }                                │
│  JIT dispatch → interpreter fallback → syscall trap → dispatch       │
└───┬──────────────┬──────────────┬──────────────────────────────────-┘
    │              │              │
┌───▼────┐  ┌─────▼──────┐  ┌───▼──────────┐  ┌────────────────┐
│canary- │  │ canary-cpu │  │canary-syscall│  │  canary-jit    │
│  elf   │  │            │  │              │  │                │
│        │  │ registers  │  │ ~80 syscalls │  │ JitCache       │
│ELF64   │  │ decoder    │  │ mmap/brk/    │  │ basic-block    │
│parser  │  │ interpreter│  │ signals/net/ │  │ decode-once/   │
│auxv    │  │ flags      │  │ threads/fb…  │  │ replay         │
└────────┘  └────────────┘  └──────┬───────┘  └────────────────┘
                                    │
              ┌─────────────────────┼──────────────────────────┐
              │                     │                          │
  ┌───────────▼──────┐  ┌──────────▼──────┐  ┌───────────────▼──────┐
  │  canary-memory   │  │   canary-fs      │  │   canary-net         │
  │  GuestMemory     │  │ VFS / MemFs      │  │ SocketTable          │
  │  page-table      │  │ /proc /dev       │  │ 18 BSD socket calls  │
  │  mmap/munmap/brk │  │ ext2 parser      │  │ WebSocket bridge     │
  └──────────────────┘  └─────────────────┘  └──────────────────────┘
              │
  ┌───────────▼──────────────────────────────┐
  │  canary-fb              canary-thread     │
  │  /dev/fb0 framebuffer   ThreadTable       │
  │  FBIO ioctls            clone/futex       │
  │  BGRA → Canvas blit     Worker spawn      │
  └──────────────────────────────────────────┘
```

### Crates

| Crate | Purpose |
|---|---|
| `canary-elf` | Parse ELF64 headers, program headers, dynamic section, RELA relocations, auxv/stack construction |
| `canary-cpu` | x86-64 register file (16 GPRs, XMM0–15, x87, RFLAGS), instruction decoder, interpreter |
| `canary-memory` | 64-bit guest VM backed by a page-table (`HashMap<page_number, frame_index>`); only touched pages consume physical RAM |
| `canary-fs` | In-memory VFS (MemFs), /proc and /dev pseudo-files, read-only ext2 image parser |
| `canary-syscall` | Linux x86-64 syscall dispatcher, file descriptor table, signal state, stdout/stderr capture |
| `canary-jit` | Soft basic-block JIT: decode-once `Vec<Instruction>` cache keyed by entry RIP; interpreter replay on cache hit |
| `canary-net` | Virtual socket table, 18 BSD socket syscalls, `PendingConnect`/`PendingSend` queues for JS WebSocket bridge |
| `canary-fb` | `/dev/fb0` framebuffer emulation (1024×768 BGRA), FBIO ioctls, pixel readback for Canvas blit |
| `canary-thread` | `ThreadTable`, per-thread `CpuState` + signal mask, `clone`/`futex` support, Web Worker spawn requests |
| `canary-wasm` | WASM entry point, wasm-bindgen glue, interpreter/JIT loop orchestration |

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) (stable, or nightly for threading builds)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/)
- Node.js >= 18

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

### Threading build (SharedArrayBuffer)

Requires nightly Rust and the `atomics`, `bulk-memory`, and `mutable-globals` target features:

```bash
rustup override set nightly

RUSTFLAGS="-C target-feature=+atomics,+bulk-memory,+mutable-globals" \
    wasm-pack build crates/canary-wasm \
        --target web \
        --out-dir crates/canary-wasm/pkg \
        -- -Z build-std=panic_abort,std
```

The dev server (`harness/server.mjs`) already sets the `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp` headers required for `SharedArrayBuffer`.

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

// Framebuffer
const pixels = rt.get_framebuffer();   // Uint8Array (BGRA, width×height×4)
const dims   = rt.get_fb_dimensions(); // "1024x768"
const hasFb  = rt.has_framebuffer();   // bool

// Networking (called by JS harness automatically)
const connects = JSON.parse(rt.drain_connect_requests()); // [{fd,ip,port}]
const sends    = JSON.parse(rt.drain_socket_sends());      // [{fd,data}] (base64)
rt.socket_connected(BigInt(fd));
rt.socket_recv_data(BigInt(fd), bytes);

// Threads (called by JS harness automatically)
const clones = JSON.parse(rt.drain_clone_requests()); // [{tid,child_stack,tls,...}]
rt.set_current_tid(tid);
const tid = rt.current_tid();

// Signals
// (signals are delivered automatically at instruction boundaries — no JS API needed)

rt.free();
```

## Implemented Syscalls

`read` `write` `open` `openat` `close` `lseek` `pread64` `readv` `writev`
`stat` `fstat` `lstat` `fstatat`
`mmap` `mprotect` `munmap` `mremap` `brk` `madvise`
`arch_prctl` (FS/GS base — required for glibc TLS)
`getpid` `getppid` `gettid` `getuid` `geteuid` `getgid` `getegid` `setuid` `setgid`
`rt_sigaction` `rt_sigprocmask` `rt_sigreturn` `sigaltstack` — real signal delivery
`kill` `tkill` `tgkill` — signal sending
`execve` — full process replacement
`clone` — thread creation (spawns Web Worker)
`futex` — WAIT/WAKE (cooperative yield + JS Atomics)
`socket` `connect` `bind` `listen` `accept` `sendto` `recvfrom` `sendmsg` `recvmsg` `shutdown` `setsockopt` `getsockopt` `getsockname` `getpeername` `socketpair` — networking
`ioctl` FBIOGET_VSCREENINFO, FBIOPUT_VSCREENINFO, FBIOGET_FSCREENINFO, FBIOPAN_DISPLAY — framebuffer
`ioctl` TIOCGWINSZ, TCGETS, TCSETS — terminal
`sched_yield` `sched_getaffinity`
`uname` `getcwd` `chdir` `mkdir` `mkdirat` `access` `faccessat`
`readlink` `readlinkat`
`gettimeofday` `clock_gettime` `nanosleep` `getrlimit` `setrlimit` `sysinfo`
`dup` `dup2` `dup3` `pipe` `pipe2` `fcntl` `getdents64` `ftruncate` `truncate`
`getrandom` `memfd_create` `symlink` `chmod` `chown`
`set_robust_list` `rseq` `prctl` `prlimit64`
`wait4` `fork`
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

Memory is backed by a page-table (`HashMap<page_number, frame_index>`) so only touched pages consume physical RAM — no up-front 3 GiB allocation.

| Region | Guest VA |
|--------|----------|
| ELF text/data | `0x0040_0000` |
| Dynamic linker | `0x1000_0000` |
| mmap / heap | `0x2000_0000` → up |
| Framebuffer mmap | `0x5000_0000` |
| Stack top | `0x0000_7FFF_FFFF_F000` (8 MiB, grows down) |

## JIT Compiler

Canary implements a **Tier-0 soft JIT** (decode-once basic-block cache) in `canary-jit`:

1. On the first visit to a code address, the decoder reads up to 64 instructions starting at the current RIP and stores them as a `Vec<Instruction>` in a `HashMap<u64, JitBlock>` keyed by entry RIP.
2. On subsequent visits (cache hit) the pre-decoded instruction list is replayed through the interpreter, eliminating the per-instruction byte-level decode that dominates hot-loop cost.
3. The cache holds up to 8,192 blocks; on overflow an arbitrary entry is evicted in O(1).
4. `invalidate_range(guest_start, length)` removes all cached blocks whose entry RIP falls in the invalidated range. This is called from `mprotect(PROT_NONE)` and from any self-modifying-code write path to prevent stale decoded blocks from being re-used.

A **Tier-1 JIT** (genuine WASM bytecode emission per basic block) can replace `execute_block` without changing the public API — the `JitCache` interface is designed for this upgrade path.

## Threads

Canary supports POSIX threads via the `clone(CLONE_VM | CLONE_THREAD)` syscall, backed by Web Workers:

- `clone` records a `CloneRequest` (new TID, child stack pointer, TLS base, etc.) in a queue and returns the new TID to the guest immediately.
- The JS harness polls `drain_clone_requests()` each animation frame, spawns a new `Worker` for each entry, and sends it a `run` message containing the initial register state.
- Each Worker runs its own interpreter/JIT loop and shares the same WASM linear memory as the main thread (requires `SharedArrayBuffer`-backed memory, enabled by the COOP/COEP headers set in `server.mjs`).
- `futex(FUTEX_WAIT)` on the main thread returns `EAGAIN` immediately (cooperative yield); Worker threads block using `Atomics.wait` on the shared memory word.
- Per-thread state (register file, signal mask, `clear_child_tid` / `set_child_tid` addresses) is tracked in `ThreadTable` inside `canary-thread`.

Requires a nightly Rust build with `+atomics,+bulk-memory,+mutable-globals` (see "Threading build" above).

## Networking

Canary bridges Linux BSD sockets to browser WebSockets via an asynchronous queue mechanism:

- `socket()` allocates a virtual `Socket` in the `SocketTable` (fd numbers start at 100 to avoid collisions with file fds).
- `connect()` does not block; it queues a `PendingConnect { fd, ip, port }` entry and returns immediately.
- The JS harness polls `drain_connect_requests()` each animation frame, opens a `WebSocket` to `ws://<ip>:<port>`, and calls `socket_connected(fd)` on open or leaves the socket in `Connecting` state on failure.
- Inbound data received by the WebSocket is pushed into the guest receive buffer via `socket_recv_data(fd, bytes)`.
- Outbound data written by the guest via `sendto`/`sendmsg` is queued as `PendingSend { fd, data }` entries; the harness drains these via `drain_socket_sends()` and forwards the base64-decoded bytes over the WebSocket.
- For real TCP connections (not native WebSocket servers), a TCP-over-WebSocket proxy such as `websockify` is required on the target host.
- `/etc/hosts`, `/etc/resolv.conf`, and `/etc/nsswitch.conf` are pre-populated in the VFS so that standard glibc name-resolution code finds valid configuration files.

Implemented syscalls: `socket` `connect` `bind` `listen` `accept` `sendto` `recvfrom` `sendmsg` `recvmsg` `shutdown` `setsockopt` `getsockopt` `getsockname` `getpeername` `socketpair` (18 total).

## Graphical Output (/dev/fb0)

Canary emulates a Linux framebuffer device at `/dev/fb0` (1024×768, 32-bit BGRA):

- Applications open `/dev/fb0` and call `mmap()` to receive a guest virtual address (`0x5000_0000` by default) pointing to a 3 MiB BGRA pixel buffer in guest memory.
- Pixels are written directly to that address range using ordinary store instructions — no special API is needed.
- FBIO ioctls are handled by `canary-fb`: `FBIOGET_VSCREENINFO` returns the `fb_var_screeninfo` struct (including channel offsets for BGRA), `FBIOGET_FSCREENINFO` returns `fb_fix_screeninfo` with the correct `smem_start` and `line_length`, `FBIOPAN_DISPLAY` and `FBIO_WAITFORVSYNC` are no-ops.
- The JS harness calls `rt.has_framebuffer()` every animation frame. Once the framebuffer is first mapped the hidden `<canvas>` element is made visible.
- `rt.get_framebuffer()` returns a `Uint8Array` view of the raw BGRA pixel data. The harness swaps channels (B↔R) and writes the result into a `ImageData` object via `putImageData`, blitting the frame to the canvas at ~60 fps.

## Filesystem

Canary includes a **read-only ext2 parser** (`canary-fs/src/ext2.rs`) that populates the in-memory VFS from a raw disk image. Supported features:

- Superblock parsing (block size, inode size, group descriptors)
- Direct blocks (i_block[0–11]), single-indirect, and double-indirect
- Inline symlinks (≤ 60 bytes) and block-based symlinks
- Files > 128 MiB are stubbed empty to bound RAM usage

## Roadmap

- [x] Dynamic linker (`ld-linux-x86-64.so.2`) loaded and executed
- [x] JIT compiler (basic-block decode-once cache)
- [x] Threads (`clone` → Web Worker, futex cooperative yield)
- [x] Signal delivery (`rt_sigaction`, ucontext frames, `rt_sigreturn`)
- [x] `execve` (process replacement)
- [x] Networking (BSD sockets → WebSocket bridge)
- [x] Graphical output (`/dev/fb0` → Canvas)
- [x] WASM64 (page-table memory, full 64-bit VA)
- [ ] JIT Tier-1: emit WASM bytecode per basic block
- [ ] Threads Tier-2: true SharedArrayBuffer memory sharing between Workers
- [ ] Networking: TCP-over-WebSocket proxy for real TCP connections
- [ ] X11/Wayland protocol emulation
- [ ] ARM64 ELF support
- [ ] `/dev/input/event0` evdev for keyboard/mouse

## License

MIT OR Apache-2.0
