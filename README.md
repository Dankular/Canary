# Canary

A from-scratch x86-64 Linux ELF emulator running in WebAssembly — the 64-bit successor to [CheerpX](https://github.com/leaningtech/cheerpx-meta).

## What is Canary?

Canary runs unmodified **64-bit x86-64 Linux ELF binaries** directly in the browser via a WebAssembly sandbox. It exposes the same JavaScript API as CheerpX so existing projects can migrate without rewriting their integration code.

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
| Addressing | 32-bit VA space | **64-bit VA (mapped into WASM linear memory)** |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  JavaScript / TypeScript              │
│  Linux.create() → Linux.run(elf, argv, env)          │
│  Devices: HttpBytesDevice, IDBDevice, DataDevice …   │
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
└───────-┘  └────────────┘  └──────┬───────┘
                                    │
                          ┌─────────▼───────┐
                          │ canary-memory    │
                          │                 │
                          │ GuestMemory     │
                          │ page table      │
                          │ mmap/munmap/brk │
                          └─────────────────┘
                          ┌─────────────────┐
                          │   canary-fs      │
                          │                 │
                          │ VFS / MemFs     │
                          │ /proc /dev      │
                          │ open/read/write │
                          └─────────────────┘
```

### Crates

| Crate | Purpose |
|---|---|
| `canary-elf` | Parse ELF64 headers, program headers, dynamic section, RELA, auxv construction |
| `canary-cpu` | x86-64 register file (16 GPRs, XMM0–15, RFLAGS), instruction decoder, interpreter |
| `canary-memory` | 64-bit guest virtual memory manager backed by WASM linear memory |
| `canary-fs` | Virtual filesystem (MemFs), /proc, /dev pseudo-files |
| `canary-syscall` | Linux x86-64 syscall dispatcher (~60 syscalls implemented) |
| `canary-wasm` | WASM entry point, wasm-bindgen glue, interpreter loop |

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) + `wasm32-unknown-unknown` target
- [wasm-pack](https://rustwasm.github.io/wasm-pack/)
- Node.js ≥ 18

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

### Build

```bash
# Build the WASM core
wasm-pack build crates/canary-wasm --target web --out-dir pkg

# Install JS dependencies
npm install

# Type-check the JS layer
npm run typecheck
```

### Usage (JavaScript)

```js
import { Linux, HttpBytesDevice, IDBDevice, OverlayDevice } from "canary";

// Mount a disk image over HTTP with an IndexedDB overlay for writes
const baseDevice = await HttpBytesDevice.create("/images/debian-x64.ext2");
const idbDevice  = await IDBDevice.create("rootfs");
const overlay    = await OverlayDevice.create(baseDevice, idbDevice);

const cx = await Linux.create({
  mounts: [
    { type: "ext2", path: "/", dev: overlay },
  ],
});

cx.setCustomConsole(
  (buffer, vt) => term.write(buffer),  // xterm.js or similar
  80, 24
);

const result = await cx.run("/bin/bash", [], {
  env: ["HOME=/root", "TERM=xterm-256color"],
});
console.log("exit code:", result.status);
```

### Run an ELF binary directly

```js
import { Linux } from "canary";

const cx = await Linux.create();

// Load ELF bytes from anywhere (fetch, File API, etc.)
const elfBytes = new Uint8Array(await fetch("/myapp").then(r => r.arrayBuffer()));

cx.add_file("/myapp", elfBytes);

const result = await cx.run("/myapp", ["arg1", "arg2"], {
  env: ["HOME=/tmp"],
});
```

## Implemented Syscalls

`read` `write` `open` `openat` `close` `lseek` `stat` `fstat` `lstat` `fstatat`
`mmap` `mprotect` `munmap` `mremap` `brk` `madvise`
`arch_prctl` (FS/GS base — required for glibc TLS)
`getpid` `getppid` `gettid` `getuid` `geteuid` `getgid` `getegid`
`rt_sigaction` `rt_sigprocmask` `futex` `sched_yield` `sched_getaffinity`
`uname` `getcwd` `chdir` `mkdir` `mkdirat` `access` `faccessat`
`readlink` `readlinkat` `ioctl` (TIOCGWINSZ, TCGETS, TCSETS)
`gettimeofday` `clock_gettime` `getrlimit` `setrlimit` `sysinfo`
`dup` `dup2` `pipe` `pipe2` `fcntl` `writev` `nanosleep`
`getrandom` `memfd_create` `set_robust_list` `rseq`
`exit` `exit_group`

## Roadmap

- [ ] Dynamic linker (`ld-linux-x86-64.so.2`) support for dynamically linked ELFs
- [ ] JIT compiler (x86-64 → WASM basic block translation) for near-native performance
- [ ] Threads (`clone`, `futex` WAIT/WAKE across threads via SharedArrayBuffer)
- [ ] Signal delivery
- [ ] `execve` (process replacement)
- [ ] Networking (TCP/IP via lwIP compiled to WASM)
- [ ] Xorg / KMS graphical output
- [ ] WASM64 memory model (remove the 4 GiB guest VA constraint)
- [ ] ARM64 ELF support

## Licence

MIT OR Apache-2.0

## Legacy Reference

The `legacy/` directory (git-ignored) contains a clone of
[cheerpx-meta](https://github.com/leaningtech/cheerpx-meta) for API reference.
It is not part of Canary and is not committed to this repository.
