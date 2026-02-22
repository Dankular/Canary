//! Canary WASM entry point — exposed to JavaScript via wasm-bindgen.

use wasm_bindgen::prelude::*;
use canary_elf::{Elf64, ElfError};
use canary_memory::{GuestMemory, layout, Prot, MapFlags};
use canary_cpu::{CpuState, decoder::decode, interpreter::{execute, ExecError}};
use canary_syscall::dispatch::{SyscallCtx, handle_syscall};
use canary_elf::auxv::{build_auxv, build_initial_stack};

// ── JS-side console logging ───────────────────────────────────────────────────

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    #[wasm_bindgen(js_namespace = console)]
    fn warn(s: &str);
    #[wasm_bindgen(js_namespace = console)]
    fn error(s: &str);
}

// ── Canary runtime ────────────────────────────────────────────────────────────

#[wasm_bindgen]
pub struct CanaryRuntime {
    cpu:  CpuState,
    mem:  GuestMemory,
    ctx:  SyscallCtx,
}

#[wasm_bindgen]
impl CanaryRuntime {
    /// Create a new Canary runtime instance.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        console_error_panic_hook_init();
        CanaryRuntime {
            cpu: CpuState::default(),
            mem: GuestMemory::new(layout::TOTAL_WASM_BYTES),
            ctx: SyscallCtx::new(),
        }
    }

    /// Load a filesystem image (raw ext2 image bytes).
    /// Populates the virtual filesystem from the image.
    #[wasm_bindgen]
    pub fn load_fs_image(&mut self, data: &[u8]) {
        log(&format!("Canary: loading ext2 image ({} bytes)...", data.len()));
        if canary_fs::ext2::populate_memfs(data, &mut self.ctx.vfs.mem) {
            log("Canary: ext2 filesystem loaded successfully");
        } else {
            warn("Canary: load_fs_image — not a valid ext2 image, ignoring");
        }
    }

    /// Add a single file to the virtual filesystem.
    #[wasm_bindgen]
    pub fn add_file(&mut self, path: &str, data: &[u8]) {
        self.ctx.vfs.mem.write_file(path, data.to_vec()).ok();
    }

    /// Read a file from the virtual filesystem.
    /// Returns the file content as a Uint8Array, or null if not found.
    #[wasm_bindgen]
    pub fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        let ino = self.ctx.vfs.mem.lookup(path).ok()?;
        let node = self.ctx.vfs.mem.node(ino);
        // Don't return directory content.
        if node.kind == canary_fs::FileKind::Directory {
            return None;
        }
        Some(node.content.clone())
    }

    /// Check if a path exists in the VFS.
    #[wasm_bindgen]
    pub fn path_exists(&self, path: &str) -> bool {
        self.ctx.vfs.mem.lookup(path).is_ok()
    }

    /// List directory entries as a JSON array of {name, kind} objects.
    #[wasm_bindgen]
    pub fn list_dir(&self, path: &str) -> String {
        match self.ctx.vfs.mem.lookup(path) {
            Ok(ino) => {
                let node = self.ctx.vfs.mem.node(ino);
                if node.kind != canary_fs::FileKind::Directory {
                    return "[]".into();
                }
                let entries: Vec<String> = node.children.iter()
                    .map(|(name, &child_ino)| {
                        let kind = match self.ctx.vfs.mem.node(child_ino).kind {
                            canary_fs::FileKind::Directory => "dir",
                            canary_fs::FileKind::Symlink   => "link",
                            _                              => "file",
                        };
                        format!(r#"{{"name":{},"kind":"{}"}}"#,
                            serde_json::to_string(name).unwrap_or_default(), kind)
                    })
                    .collect();
                format!("[{}]", entries.join(","))
            }
            Err(_) => "[]".into(),
        }
    }

    /// Load and execute a 64-bit ELF binary.
    ///
    /// `argv` is a JSON array of strings: `["./prog", "arg1", "arg2"]`
    /// `envp` is a JSON array of strings: `["HOME=/root", "PATH=/usr/bin"]`
    ///
    /// Returns the exit code.
    #[wasm_bindgen]
    pub fn run_elf(&mut self, elf_bytes: &[u8], argv_json: &str, envp_json: &str) -> i32 {
        let argv: Vec<String> = serde_json::from_str(argv_json).unwrap_or_default();
        let envp: Vec<String> = serde_json::from_str(envp_json).unwrap_or_default();

        match self.run_elf_inner(elf_bytes, &argv, &envp) {
            Ok(code)                       => code,
            Err(CanaryError::Exit(code))   => code,
            Err(e) => {
                error(&format!("Canary: run_elf error: {e}"));
                1
            }
        }
    }

    /// Execute a single instruction step.  Returns false when the program ends.
    #[wasm_bindgen]
    pub fn step(&mut self) -> bool {
        self.step_inner()
    }

    /// Read bytes from the stdout capture buffer and clear it.
    #[wasm_bindgen]
    pub fn drain_stdout(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.ctx.stdout_buf)
    }

    /// Read bytes from the stderr capture buffer and clear it.
    #[wasm_bindgen]
    pub fn drain_stderr(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.ctx.stderr_buf)
    }

    /// Write bytes into the stdin buffer.
    #[wasm_bindgen]
    pub fn write_stdin(&mut self, data: &[u8]) {
        // TODO: pipe into stdin fd.
        let _ = data;
    }

    /// Set/update the working directory.
    #[wasm_bindgen]
    pub fn set_cwd(&mut self, path: &str) {
        self.ctx.cwd = path.to_string();
    }

    /// Return current RIP value (for debugging).
    #[wasm_bindgen]
    pub fn rip(&self) -> u64 { self.cpu.rip }

    /// Return a JSON object with all GPR values (for debugging).
    #[wasm_bindgen]
    pub fn dump_regs_json(&self) -> String {
        use canary_cpu::registers::reg;
        format!(
            r#"{{"rax":{rax},"rcx":{rcx},"rdx":{rdx},"rbx":{rbx},"rsp":{rsp},"rbp":{rbp},"rsi":{rsi},"rdi":{rdi},"r8":{r8},"r9":{r9},"r10":{r10},"r11":{r11},"r12":{r12},"r13":{r13},"r14":{r14},"r15":{r15},"rip":{rip},"rflags":{rflags}}}"#,
            rax=self.cpu.gpr[reg::RAX], rcx=self.cpu.gpr[reg::RCX],
            rdx=self.cpu.gpr[reg::RDX], rbx=self.cpu.gpr[reg::RBX],
            rsp=self.cpu.gpr[reg::RSP], rbp=self.cpu.gpr[reg::RBP],
            rsi=self.cpu.gpr[reg::RSI], rdi=self.cpu.gpr[reg::RDI],
            r8 =self.cpu.gpr[reg::R8 ], r9 =self.cpu.gpr[reg::R9 ],
            r10=self.cpu.gpr[reg::R10], r11=self.cpu.gpr[reg::R11],
            r12=self.cpu.gpr[reg::R12], r13=self.cpu.gpr[reg::R13],
            r14=self.cpu.gpr[reg::R14], r15=self.cpu.gpr[reg::R15],
            rip=self.cpu.rip, rflags=self.cpu.rflags,
        )
    }
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum CanaryError {
    Elf(ElfError),
    Exec(String),
    Exit(i32),
}

impl From<ElfError> for CanaryError {
    fn from(e: ElfError) -> Self { CanaryError::Elf(e) }
}
impl std::fmt::Display for CanaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CanaryError::Elf(e)  => write!(f, "ELF error: {e}"),
            CanaryError::Exec(e) => write!(f, "exec error: {e}"),
            CanaryError::Exit(c) => write!(f, "exited with {c}"),
        }
    }
}

// ── Internal implementation ───────────────────────────────────────────────────

impl CanaryRuntime {
    fn run_elf_inner(&mut self, data: &[u8], argv: &[String], envp: &[String]) -> Result<i32, CanaryError> {
        // ── 1. Parse main ELF ─────────────────────────────────────────────
        let elf = Elf64::parse(data, layout::ELF_BASE)?;
        log(&format!(
            "Canary: loading ELF @ base={:#x} entry={:#x} ({} PT_LOAD segs) interp={:?}",
            elf.load_base, elf.entry, elf.load_segs.len(), elf.interp
        ));

        // ── 2. Reset memory state for a fresh execution ───────────────────
        self.mem  = GuestMemory::new(layout::TOTAL_WASM_BYTES);
        self.cpu  = CpuState::default();
        // Keep ctx.vfs (filesystem) but reset fds.
        self.ctx.fds = canary_syscall::dispatch::FdTable::new();
        self.ctx.cwd = "/".to_string();
        self.ctx.stdout_buf.clear();
        self.ctx.stderr_buf.clear();

        // ── 3. Map + load PT_LOAD segments for main ELF ───────────────────
        self.load_elf_segments(data, &elf)?;

        // ── 4. Optionally load the dynamic interpreter ─────────────────────
        let (interp_base, interp_entry) = if let Some(ref interp_path) = elf.interp {
            match self.load_interpreter(interp_path) {
                Ok((base, entry)) => {
                    log(&format!("Canary: interpreter loaded @ base={:#x} entry={:#x}", base, entry));
                    (base, entry)
                }
                Err(e) => {
                    warn(&format!("Canary: failed to load interpreter '{}': {e}", interp_path));
                    warn("Canary: attempting to run as static binary (likely to fail for glibc)");
                    (0, elf.entry)
                }
            }
        } else {
            (0, elf.entry)
        };

        // The CPU will start at the interpreter's entry (or the ELF entry for static).
        let start_rip = if interp_base != 0 { interp_entry } else { elf.entry };

        // ── 5. Map stack ──────────────────────────────────────────────────
        let stack_base = layout::STACK_TOP - layout::STACK_SIZE;
        self.mem.mmap(stack_base, layout::STACK_SIZE,
                      Prot::READ | Prot::WRITE,
                      MapFlags::FIXED | MapFlags::PRIVATE | MapFlags::ANONYMOUS)
            .map_err(|e| CanaryError::Exec(e.to_string()))?;

        // ── 6. Build auxv + initial stack ─────────────────────────────────
        let phdr_addr  = elf.load_base + elf.header.e_phoff;
        let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        let envp_refs: Vec<&str> = envp.iter().map(|s| s.as_str()).collect();

        let auxv = build_auxv(
            phdr_addr,
            56,                             // sizeof Elf64Phdr
            elf.header.e_phnum as u64,
            interp_base,                    // AT_BASE = interp load addr (0 = static)
            elf.entry,                      // AT_ENTRY = main ELF entry
            0, 0,                           // patched by build_initial_stack
        );
        let stack = build_initial_stack(layout::STACK_TOP, &argv_refs, &envp_refs, &auxv, [0u8; 16]);
        self.mem.loader_write(stack.rsp, &stack.data);

        // ── 7. Set up CPU state ───────────────────────────────────────────
        self.cpu.rip = start_rip;
        self.cpu.gpr[canary_cpu::registers::reg::RSP] = stack.rsp;

        // ── 8. Run interpreter loop ───────────────────────────────────────
        log(&format!("Canary: executing from {:#x}", self.cpu.rip));
        loop {
            match self.step_once() {
                Ok(()) => {}
                Err(CanaryError::Exit(code)) => return Ok(code),
                Err(e) => return Err(e),
            }
        }
    }

    /// Load all PT_LOAD segments of `elf` from `data` into guest memory.
    fn load_elf_segments(&mut self, data: &[u8], elf: &Elf64) -> Result<(), CanaryError> {
        for seg in &elf.load_segs {
            let prot = {
                let mut p = Prot::NONE;
                if seg.flags & canary_elf::PF_R != 0 { p |= Prot::READ; }
                if seg.flags & canary_elf::PF_W != 0 { p |= Prot::WRITE; }
                if seg.flags & canary_elf::PF_X != 0 { p |= Prot::EXEC; }
                p
            };
            self.mem.mmap(seg.vaddr, seg.memsz, prot | Prot::WRITE,
                          MapFlags::FIXED | MapFlags::PRIVATE | MapFlags::ANONYMOUS)
                .map_err(|e| CanaryError::Exec(e.to_string()))?;
        }
        elf.load_into(data, &mut self.mem)
            .map_err(|e| CanaryError::Exec(e.to_string()))?;
        Ok(())
    }

    /// Load the dynamic interpreter (ld-linux-x86-64.so.2) from VFS.
    /// Returns `(load_base, entry_point)`.
    fn load_interpreter(&mut self, interp_path: &str) -> Result<(u64, u64), CanaryError> {
        // Look up the interpreter in the VFS (two-step to avoid borrow conflicts).
        let ino = self.ctx.vfs.mem.lookup(interp_path)
            .map_err(|_| CanaryError::Exec(format!("interpreter not found: {interp_path}")))?;

        let interp_data = {
            let node = self.ctx.vfs.mem.node(ino);
            if node.content.is_empty() {
                return Err(CanaryError::Exec(format!("interpreter file empty: {interp_path}")));
            }
            node.content.clone()
        };

        // Parse the interpreter ELF (always a PIE/ET_DYN); load at INTERP_BASE.
        let interp_elf = Elf64::parse(&interp_data, layout::INTERP_BASE)
            .map_err(|e| CanaryError::Exec(format!("interpreter parse error: {e}")))?;

        log(&format!(
            "Canary: interpreter ELF: base={:#x} entry={:#x} segs={}",
            interp_elf.load_base, interp_elf.entry, interp_elf.load_segs.len()
        ));

        self.load_elf_segments(&interp_data, &interp_elf)?;

        Ok((interp_elf.load_base, interp_elf.entry))
    }

    fn step_once(&mut self) -> Result<(), CanaryError> {
        let rip = self.cpu.rip;
        let bytes = self.mem.read_bytes(rip, 15)
            .or_else(|_| self.mem.read_bytes(rip, 1))
            .map_err(|e| CanaryError::Exec(format!("fetch @{rip:#x}: {e}")))?
            .to_vec();

        let instr = decode(&bytes, rip)
            .map_err(|e| CanaryError::Exec(format!("decode @{rip:#x}: {e}")))?;

        match execute(&instr, &mut self.cpu, &mut self.mem) {
            Ok(()) => Ok(()),
            Err(ExecError::Syscall) => self.dispatch_syscall(),
            Err(ExecError::Halt)    => Err(CanaryError::Exit(0)),
            Err(ExecError::DivideByZero)     => Err(CanaryError::Exec("divide by zero".into())),
            Err(ExecError::IllegalInstruction) => {
                Err(CanaryError::Exec(format!("illegal instruction @{rip:#x}")))
            }
            Err(ExecError::Int(n)) => Err(CanaryError::Exec(format!("INT {n} @{rip:#x}"))),
            Err(e) => Err(CanaryError::Exec(e.to_string())),
        }
    }

    fn dispatch_syscall(&mut self) -> Result<(), CanaryError> {
        use canary_cpu::registers::reg;
        let nr  = self.cpu.gpr[reg::RAX];
        let a0  = self.cpu.gpr[reg::RDI];
        let a1  = self.cpu.gpr[reg::RSI];
        let a2  = self.cpu.gpr[reg::RDX];
        let a3  = self.cpu.gpr[reg::R10];
        let a4  = self.cpu.gpr[reg::R8];
        let a5  = self.cpu.gpr[reg::R9];

        let mut fs_base = self.cpu.fs_base;
        let mut gs_base = self.cpu.gs_base;

        match handle_syscall(nr, a0, a1, a2, a3, a4, a5,
                             &mut self.mem, &mut self.ctx,
                             &mut fs_base, &mut gs_base) {
            Ok(ret) => {
                self.cpu.fs_base = fs_base;
                self.cpu.gs_base = gs_base;
                self.cpu.gpr[reg::RAX] = ret as u64;
                Ok(())
            }
            Err(canary_syscall::SyscallError::Exit(code)) => {
                Err(CanaryError::Exit(code))
            }
            Err(e) => {
                warn(&format!("syscall {nr} error: {e}"));
                self.cpu.gpr[reg::RAX] = (-38i64) as u64; // ENOSYS
                Ok(())
            }
        }
    }

    fn step_inner(&mut self) -> bool {
        match self.step_once() {
            Ok(())                    => true,
            Err(CanaryError::Exit(_)) => false,
            Err(e) => {
                error(&format!("Canary step error: {e}"));
                false
            }
        }
    }
}

// ── panic hook ────────────────────────────────────────────────────────────────

fn console_error_panic_hook_init() {}
