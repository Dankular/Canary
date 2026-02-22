//! Canary WASM entry point — exposed to JavaScript via wasm-bindgen.

use wasm_bindgen::prelude::*;
use canary_elf::{Elf64, ElfError, EM_AARCH64};
use canary_memory::{GuestMemory, layout, Prot, MapFlags};
use canary_cpu::{CpuState, decoder::decode, interpreter::{execute, ExecError}};
use canary_cpu_arm64::{ArmCpuState,
    decoder::decode as arm_decode,
    interpreter::{execute as arm_execute, ArmExecError}};
use canary_syscall::dispatch::{SyscallCtx, handle_syscall};
use canary_elf::auxv::{build_auxv, build_initial_stack};
use canary_jit::{JitCache, JitResult};
#[allow(unused_imports)]
use canary_thread;

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
    cpu:     CpuState,
    arm_cpu: Option<ArmCpuState>,
    mem:     GuestMemory,
    ctx:     SyscallCtx,
    jit:     JitCache,
}

#[wasm_bindgen]
impl CanaryRuntime {
    /// Create a new Canary runtime instance.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        console_error_panic_hook_init();
        CanaryRuntime {
            cpu:     CpuState::default(),
            arm_cpu: None,
            mem:     GuestMemory::new(layout::TOTAL_WASM_BYTES),
            ctx:     SyscallCtx::new(),
            jit:     JitCache::new(),
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

    /// Prepare an ELF binary for incremental execution via step().
    ///
    /// Unlike run_elf(), this does NOT enter the interpreter loop.
    /// It parses the ELF, resets CPU/memory, loads segments, sets up the
    /// stack and auxv, and positions RIP at the entry point — then returns.
    /// Call step() in a requestAnimationFrame loop to drive execution.
    ///
    /// Returns true on success, false if setup fails (check console for error).
    #[wasm_bindgen]
    pub fn prepare_elf(&mut self, elf_bytes: &[u8], argv_json: &str, envp_json: &str) -> bool {
        let argv: Vec<String> = serde_json::from_str(argv_json).unwrap_or_default();
        let envp: Vec<String> = serde_json::from_str(envp_json).unwrap_or_default();
        match self.prepare_elf_inner(elf_bytes, &argv, &envp) {
            Ok(())  => true,
            Err(e)  => { error(&format!("Canary: prepare_elf error: {e}")); false }
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

    /// Return current program counter (RIP on x86-64, PC on AArch64).
    #[wasm_bindgen]
    pub fn rip(&self) -> u64 {
        if let Some(ref a) = self.arm_cpu { a.pc } else { self.cpu.rip }
    }

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

    // ── Framebuffer API ───────────────────────────────────────────────────

    /// Returns the current framebuffer pixel data as a flat BGRA Uint8Array.
    /// Returns an empty Vec if the framebuffer has not been mmap'd by the guest yet.
    #[wasm_bindgen]
    pub fn get_framebuffer(&self) -> Vec<u8> {
        self.ctx.fb.read_pixels(&self.mem)
            .map(|s| s.to_vec())
            .unwrap_or_default()
    }

    /// Returns framebuffer dimensions as the string "{width},{height}".
    #[wasm_bindgen]
    pub fn get_fb_dimensions(&self) -> String {
        format!("{},{}", canary_fb::FB_WIDTH, canary_fb::FB_HEIGHT)
    }

    /// Returns true if the guest has mmap'd /dev/fb0.
    #[wasm_bindgen]
    pub fn has_framebuffer(&self) -> bool {
        self.ctx.fb.mmap_addr.is_some()
    }

    // ── Threading API ─────────────────────────────────────────────────────

    /// Initialize a thread Worker's register state.
    /// Called from a Web Worker after init, before run.
    /// Sets RSP to child_stack, FS base to tls, writes tid to child_tidptr.
    #[wasm_bindgen]
    pub fn init_thread(&mut self, child_stack: u64, tls: u64, child_tidptr: u64) {
        use canary_cpu::registers::reg;
        // Child thread starts with RAX=0 (clone returns 0 in child)
        self.cpu.gpr[reg::RAX] = 0;
        // RSP = child_stack (passed in clone() call)
        if child_stack != 0 {
            self.cpu.gpr[reg::RSP] = child_stack;
        }
        // TLS base (arch_prctl ARCH_SET_FS equivalent)
        if tls != 0 {
            self.cpu.fs_base = tls;
        }
        // Write TID to child_tidptr (CLONE_CHILD_SETTID)
        if child_tidptr != 0 {
            let tid = self.ctx.current_tid;
            self.mem.write_u32(child_tidptr, tid).ok();
        }
    }

    /// Drain any pending `clone` requests and return them as a JSON array.
    ///
    /// Each element has the shape:
    /// `{"tid":2,"child_stack":12345678,"tls":87654321,"child_tidptr":99,"flags":1234}`
    ///
    /// The JS harness should call this after every `step()` (or batch of steps)
    /// and spawn a Web Worker for each entry, passing in the data so the Worker
    /// can set up RSP = child_stack, fs_base = tls, and RAX = 0 (child return).
    #[wasm_bindgen]
    pub fn drain_clone_requests(&mut self) -> String {
        let reqs = std::mem::take(&mut self.ctx.pending_clone);
        if reqs.is_empty() {
            return "[]".to_string();
        }
        let items: Vec<String> = reqs
            .iter()
            .map(|r| {
                format!(
                    r#"{{"tid":{},"child_stack":{},"tls":{},"child_tidptr":{},"flags":{}}}"#,
                    r.new_tid, r.child_stack, r.tls, r.child_tidptr, r.flags
                )
            })
            .collect();
        format!("[{}]", items.join(","))
    }

    /// Return the current thread ID (used by the Worker harness to verify state).
    #[wasm_bindgen]
    pub fn current_tid(&self) -> u32 {
        self.ctx.current_tid
    }

    /// Set the current thread ID.  Called by the Worker harness when initialising
    /// a spawned thread so that `gettid()` returns the correct value.
    #[wasm_bindgen]
    pub fn set_current_tid(&mut self, tid: u32) {
        self.ctx.current_tid = tid;
    }

    // ── JIT Tier-1 API ────────────────────────────────────────────────────

    /// Emit WASM bytecode for the basic block at `entry_rip`.
    ///
    /// Returns the raw WASM module binary, or an empty Vec if the block could
    /// not be compiled or contains instructions not yet supported by the
    /// Tier-1 emitter.
    ///
    /// JS calls `WebAssembly.compile()` on the returned bytes and then calls
    /// `mark_jit_compiled(entry_rip)` to record that Tier-1 is ready.
    #[wasm_bindgen]
    pub fn emit_jit_block(&mut self, entry_rip: u64) -> Vec<u8> {
        if self.jit.get_mut(entry_rip).is_none() {
            self.jit.compile(entry_rip, &self.mem);
        }
        if let Some(block) = self.jit.get_mut(entry_rip) {
            canary_jit::emitter::emit_block(block).unwrap_or_default()
        } else {
            vec![]
        }
    }

    /// Mark the basic block at `entry_rip` as having a Tier-1 compiled WASM
    /// module ready for execution.
    ///
    /// JS calls this after `WebAssembly.compile()` succeeds on the bytes
    /// returned by `emit_jit_block()`.  Returns `true` if the block was found
    /// in the JIT cache and promoted, `false` otherwise.
    #[wasm_bindgen]
    pub fn mark_jit_compiled(&mut self, entry_rip: u64) -> bool {
        if let Some(block) = self.jit.get_mut(entry_rip) {
            block.tier = canary_jit::JitTier::Compiled;
            true
        } else {
            false
        }
    }

    // ── Networking API ────────────────────────────────────────────────────

    /// Drain any pending connect() requests.
    ///
    /// Returns a JSON array of `{"fd":N,"ip":"a.b.c.d","port":P}` objects.
    /// JS should open a WebSocket to `ws://ip:port` for each entry, then call
    /// `socket_connected(fd)` when the WebSocket opens and
    /// `socket_recv_data(fd, bytes)` when data arrives.
    #[wasm_bindgen]
    pub fn drain_connect_requests(&mut self) -> String {
        let reqs = std::mem::take(&mut self.ctx.net.pending_connect);
        if reqs.is_empty() {
            return "[]".to_string();
        }
        let items: Vec<String> = reqs
            .iter()
            .map(|c| {
                format!(
                    r#"{{"fd":{},"ip":"{}.{}.{}.{}","port":{}}}"#,
                    c.fd, c.ip[0], c.ip[1], c.ip[2], c.ip[3], c.port
                )
            })
            .collect();
        format!("[{}]", items.join(","))
    }

    /// Drain any pending outbound socket data.
    ///
    /// Returns a JSON array of `{"fd":N,"data":"<base64>"}` objects.
    /// JS should forward each chunk over the corresponding WebSocket.
    #[wasm_bindgen]
    pub fn drain_socket_sends(&mut self) -> String {
        let sends = std::mem::take(&mut self.ctx.net.pending_sends);
        if sends.is_empty() {
            return "[]".to_string();
        }
        let items: Vec<String> = sends
            .iter()
            .map(|s| {
                // Encode as base64 using the alphabet A-Za-z0-9+/
                let b64 = base64_encode(&s.data);
                format!(r#"{{"fd":{},"data":"{}"}}"#, s.fd, b64)
            })
            .collect();
        format!("[{}]", items.join(","))
    }

    /// Called from JS when a connect() WebSocket successfully opens.
    /// Transitions the socket from `Connecting` to `Connected`.
    #[wasm_bindgen]
    pub fn socket_connected(&mut self, fd: u64) {
        if let Some(sock) = self.ctx.net.socks.get_mut(fd) {
            sock.state = canary_net::SocketState::Connected;
        }
    }

    /// Called from JS when data arrives on a socket's WebSocket.
    /// Appends data to the socket's receive buffer so that `recvfrom` can read it.
    #[wasm_bindgen]
    pub fn socket_recv_data(&mut self, fd: u64, data: &[u8]) {
        if let Some(sock) = self.ctx.net.socks.get_mut(fd) {
            sock.recv_buf.extend(data.iter().copied());
            // If we were waiting for the connection, mark it as established.
            if sock.state == canary_net::SocketState::Connecting {
                sock.state = canary_net::SocketState::Connected;
            }
        }
    }

    // ── I/O port API ──────────────────────────────────────────────────────

    /// Drain all I/O port writes from the guest as JSON.
    /// Format: [{"port":0x7860,"size":4,"val":305419896}, ...]
    #[wasm_bindgen]
    pub fn drain_io_writes(&mut self) -> String {
        let writes = self.ctx.io.drain_writes();
        if writes.is_empty() { return "[]".into(); }
        let entries: Vec<String> = writes.iter().map(|w| {
            format!(r#"{{"port":{},"size":{},"val":{}}}"#, w.port, w.size, w.val)
        }).collect();
        format!("[{}]", entries.join(","))
    }

    /// Push an I/O port read response (JS to guest).
    /// Call this before the guest's next IN instruction.
    #[wasm_bindgen]
    pub fn push_io_read(&mut self, port: u16, size: u8, val: u32) {
        self.ctx.io.push_read_response(port, size, val);
    }

    // ── Input device API ──────────────────────────────────────────────────

    /// Push a keyboard event from JS.
    /// `code` is the browser KeyboardEvent.code string (e.g., "KeyA", "Space").
    /// `pressed` is true for keydown, false for keyup.
    #[wasm_bindgen]
    pub fn push_key_event(&mut self, code: &str, pressed: bool) {
        use canary_input::keycodes::browser_code_to_linux;
        if let Some(keycode) = browser_code_to_linux(code) {
            self.ctx.input.key_event(keycode, pressed);
        }
    }

    /// Push a mouse button event.
    /// `button`: 0=left, 1=middle, 2=right (browser convention).
    /// `pressed`: true=down, false=up.
    #[wasm_bindgen]
    pub fn push_mouse_button(&mut self, button: u8, pressed: bool) {
        use canary_input::{BTN_LEFT, BTN_RIGHT, BTN_MIDDLE};
        let code = match button { 0 => BTN_LEFT, 1 => BTN_MIDDLE, _ => BTN_RIGHT };
        self.ctx.input.mouse_button(code, pressed);
    }

    /// Push a mouse motion event.
    /// `x`, `y` are canvas-relative pixel coordinates (will be converted to relative deltas).
    #[wasm_bindgen]
    pub fn push_mouse_move(&mut self, x: i32, y: i32) {
        self.ctx.input.mouse_move(x, y);
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
    /// Set up memory, CPU, and stack for an ELF binary without executing it.
    /// Shared setup between prepare_elf() and run_elf().
    fn prepare_elf_inner(&mut self, data: &[u8], argv: &[String], envp: &[String]) -> Result<(), CanaryError> {
        // ── 1. Peek at e_machine ──────────────────────────────────────────
        let e_machine = if data.len() >= 20 {
            u16::from_le_bytes([data[18], data[19]])
        } else {
            62 // default x86-64
        };
        let is_aarch64 = e_machine == EM_AARCH64;

        // ── 2. Parse main ELF ─────────────────────────────────────────────
        let elf = if is_aarch64 {
            Elf64::parse_aarch64(data, layout::ELF_BASE)?
        } else {
            Elf64::parse(data, layout::ELF_BASE)?
        };
        log(&format!(
            "Canary: loading ELF ({}) @ base={:#x} entry={:#x} ({} PT_LOAD segs) interp={:?}",
            if is_aarch64 { "aarch64" } else { "x86-64" },
            elf.load_base, elf.entry, elf.load_segs.len(), elf.interp
        ));

        // ── 3. Reset memory / CPU state for a fresh execution ─────────────
        self.mem     = GuestMemory::new(layout::TOTAL_WASM_BYTES);
        self.cpu     = CpuState::default();
        self.arm_cpu = None;
        self.jit     = JitCache::new();
        self.ctx.fds     = canary_syscall::dispatch::FdTable::new();
        self.ctx.cwd     = "/".to_string();
        self.ctx.stdout_buf.clear();
        self.ctx.stderr_buf.clear();
        self.ctx.signals = canary_syscall::dispatch::SignalState::default();
        self.ctx.threads       = canary_thread::ThreadTable::new(1);
        self.ctx.current_tid   = 1;
        self.ctx.pending_clone = Vec::new();

        // ── 4. Map + load PT_LOAD segments for main ELF ───────────────────
        self.load_elf_segments(data, &elf)?;

        // ── 5. Optionally load the dynamic interpreter ─────────────────────
        let (interp_base, interp_entry) = if let Some(ref interp_path) = elf.interp {
            match self.load_interpreter(interp_path, is_aarch64) {
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

        let start_pc = if interp_base != 0 { interp_entry } else { elf.entry };

        // ── 6. Map stack ──────────────────────────────────────────────────
        let stack_base = layout::STACK_TOP - layout::STACK_SIZE;
        self.mem.mmap(stack_base, layout::STACK_SIZE,
                      Prot::READ | Prot::WRITE,
                      MapFlags::FIXED | MapFlags::PRIVATE | MapFlags::ANONYMOUS)
            .map_err(|e| CanaryError::Exec(e.to_string()))?;

        // ── 7. Build auxv + initial stack ─────────────────────────────────
        let phdr_addr  = elf.load_base + elf.header.e_phoff;
        let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        let envp_refs: Vec<&str> = envp.iter().map(|s| s.as_str()).collect();

        let auxv = build_auxv(
            phdr_addr,
            56,
            elf.header.e_phnum as u64,
            interp_base,
            elf.entry,
            0, 0,
        );
        let stack = build_initial_stack(layout::STACK_TOP, &argv_refs, &envp_refs, &auxv, [0u8; 16]);
        self.mem.loader_write(stack.rsp, &stack.data);

        // ── 8. Position CPU at entry point (ready for step()) ─────────────
        if is_aarch64 {
            let mut acpu = ArmCpuState::default();
            acpu.pc = start_pc;
            acpu.sp = stack.rsp;
            self.arm_cpu = Some(acpu);
        } else {
            self.cpu.rip = start_pc;
            self.cpu.gpr[canary_cpu::registers::reg::RSP] = stack.rsp;
        }

        log(&format!("Canary: ELF prepared, entry={:#x} — call step() to execute", start_pc));
        Ok(())
    }

    fn run_elf_inner(&mut self, data: &[u8], argv: &[String], envp: &[String]) -> Result<i32, CanaryError> {
        // Set up ELF (parse, load, stack, CPU) then immediately run to completion.
        self.prepare_elf_inner(data, argv, envp)?;

        let start_pc = self.arm_cpu.as_ref().map(|a| a.pc).unwrap_or(self.cpu.rip);
        log(&format!("Canary: executing from {:#x}", start_pc));
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

    /// Load the dynamic interpreter from VFS.
    /// Returns `(load_base, entry_point)`.
    fn load_interpreter(&mut self, interp_path: &str, is_aarch64: bool) -> Result<(u64, u64), CanaryError> {
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
        let interp_elf = if is_aarch64 {
            Elf64::parse_aarch64(&interp_data, layout::INTERP_BASE)
        } else {
            Elf64::parse(&interp_data, layout::INTERP_BASE)
        }.map_err(|e| CanaryError::Exec(format!("interpreter parse error: {e}")))?;

        log(&format!(
            "Canary: interpreter ELF: base={:#x} entry={:#x} segs={}",
            interp_elf.load_base, interp_elf.entry, interp_elf.load_segs.len()
        ));

        self.load_elf_segments(&interp_data, &interp_elf)?;

        Ok((interp_elf.load_base, interp_elf.entry))
    }

    fn step_once(&mut self) -> Result<(), CanaryError> {
        // Dispatch to the ARM64 interpreter when running an AArch64 binary.
        if self.arm_cpu.is_some() {
            return self.interpret_one_arm64();
        }

        // Check for deliverable signals before executing the next instruction.
        self.deliver_pending_signals()?;

        let rip = self.cpu.rip;

        // ── JIT cache lookup ──────────────────────────────────────────────
        let block_hit = self.jit.get_mut(rip).is_some();
        if block_hit {
            let block = self.jit.get_mut(rip).unwrap();
            block.hit_count += 1;
            let result = JitCache::execute_block(block, &mut self.cpu, &mut self.mem);
            return match result {
                JitResult::Continue(_)  => Ok(()),
                JitResult::Branch(_)    => Ok(()),
                JitResult::Syscall(_)   => self.dispatch_syscall(),
                JitResult::Halt         => Err(CanaryError::Exit(0)),
                JitResult::Fault(e)     => Err(CanaryError::Exec(e)),
            };
        }

        // ── JIT cache miss: try to compile this block ─────────────────────
        if self.jit.compile(rip, &self.mem).is_some() {
            let block = self.jit.get_mut(rip).unwrap();
            block.hit_count += 1;
            let result = JitCache::execute_block(block, &mut self.cpu, &mut self.mem);
            match result {
                JitResult::Continue(_)  => return Ok(()),
                JitResult::Branch(_)    => return Ok(()),
                JitResult::Syscall(_)   => return self.dispatch_syscall(),
                JitResult::Halt         => return Err(CanaryError::Exit(0)),
                JitResult::Fault(_)     => {
                    // Fall through to the single-instruction interpreter for
                    // faulting instructions (e.g. memory access on a tricky
                    // address) so we get a precise per-instruction error.
                }
            }
        }

        // ── Interpreter fallback (single instruction) ─────────────────────
        self.interpret_one()
    }

    /// Execute exactly one instruction via the pure interpreter.
    /// This is the original `step_once` body, used as a fallback when the JIT
    /// cannot compile or when a compiled block faults.
    fn interpret_one(&mut self) -> Result<(), CanaryError> {
        let rip = self.cpu.rip;
        // Instruction fetch: try 15 bytes (max x86-64 instruction length).
        // read_bytes() returns Err on cross-page reads; fall back to
        // read_bytes_copy() which handles page boundaries, then try 1 byte.
        let bytes = self.mem.read_bytes(rip, 15)
            .map(|s| s.to_vec())
            .or_else(|_| self.mem.read_bytes_copy(rip, 15))
            .or_else(|_| self.mem.read_bytes_copy(rip, 1))
            .map_err(|e| CanaryError::Exec(format!("fetch @{rip:#x}: {e}")))?;

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
            Err(ExecError::IoPort { dir: 1, port, size, val }) => {
                // OUT instruction — guest is writing to I/O port
                self.ctx.io.guest_out(port, size, val);
                Ok(())
            }
            Err(ExecError::IoPort { dir: 0, port, size, .. }) => {
                // IN instruction — guest wants to read from I/O port
                let val = self.ctx.io.guest_in(port, size);
                use canary_cpu::registers::reg;
                match size {
                    1  => self.cpu.gpr[reg::RAX] = (self.cpu.gpr[reg::RAX] & !0xFF) | (val as u64),
                    2  => self.cpu.gpr[reg::RAX] = (self.cpu.gpr[reg::RAX] & !0xFFFF) | (val as u64),
                    _  => self.cpu.gpr[reg::RAX] = val as u64,
                }
                Ok(())
            }
            Err(ExecError::IoPort { .. }) => Ok(()), // unexpected dir value — ignore
            Err(e) => Err(CanaryError::Exec(e.to_string())),
        }
    }

    /// Execute one AArch64 instruction (pure interpreter, no JIT).
    fn interpret_one_arm64(&mut self) -> Result<(), CanaryError> {
        let acpu = self.arm_cpu.as_mut().unwrap();
        let pc   = acpu.pc;

        // Fetch 4 bytes (ARM64 instructions are always 4 bytes, fixed-width).
        let bytes = self.mem.read_bytes(pc, 4)
            .map(|s| s.to_vec())
            .or_else(|_| self.mem.read_bytes_copy(pc, 4))
            .map_err(|e| CanaryError::Exec(format!("arm64 fetch @{pc:#x}: {e}")))?;

        let instr = arm_decode(&bytes, pc)
            .map_err(|e| CanaryError::Exec(format!("arm64 decode @{pc:#x}: {e}")))?;

        match arm_execute(&instr, acpu, &mut self.mem) {
            Ok(())                            => Ok(()),
            Err(ArmExecError::Syscall)        => self.dispatch_syscall_arm64(),
            Err(ArmExecError::Halt)           => Err(CanaryError::Exit(0)),
            Err(ArmExecError::MemFault(addr)) =>
                Err(CanaryError::Exec(format!("arm64 mem fault @{addr:#x} (pc={pc:#x})"))),
            Err(ArmExecError::IllegalInstruction) => {
                let raw = u32::from_le_bytes(bytes[..4].try_into().unwrap_or_default());
                Err(CanaryError::Exec(format!("arm64 illegal instruction {raw:#010x} @{pc:#x}")))
            }
        }
    }

    /// Handle an AArch64 `SVC #0` syscall.
    /// Translates AArch64 Linux syscall numbers to x86-64 and dispatches.
    fn dispatch_syscall_arm64(&mut self) -> Result<(), CanaryError> {
        let acpu = self.arm_cpu.as_mut().unwrap();
        // AArch64 Linux ABI: syscall nr in X8, args in X0..X5, result in X0.
        let arm_nr = acpu.x[8];
        let a0 = acpu.x[0];
        let a1 = acpu.x[1];
        let a2 = acpu.x[2];
        let a3 = acpu.x[3];
        let a4 = acpu.x[4];
        let a5 = acpu.x[5];

        // Translate AArch64 syscall number to the x86-64 number used by
        // canary-syscall's dispatch table.
        let nr = arm64_to_x86_syscall(arm_nr);

        if nr == u64::MAX {
            // Untranslated — return ENOSYS.
            acpu.x[0] = (-38i64) as u64;
            return Ok(());
        }

        // rt_sigreturn is not supported on ARM64 yet — return ENOSYS.
        if nr == canary_syscall::numbers::SYS_RT_SIGRETURN {
            acpu.x[0] = (-38i64) as u64;
            return Ok(());
        }

        let mut fs_base = acpu.tpidr_el0;
        let mut gs_base = 0u64;

        match handle_syscall(nr, a0, a1, a2, a3, a4, a5,
                             &mut self.mem, &mut self.ctx,
                             &mut fs_base, &mut gs_base) {
            Ok(ret) => {
                self.arm_cpu.as_mut().unwrap().tpidr_el0 = fs_base;
                self.arm_cpu.as_mut().unwrap().x[0] = ret as u64;
                Ok(())
            }
            Err(canary_syscall::SyscallError::Exit(code)) => {
                Err(CanaryError::Exit(code))
            }
            Err(canary_syscall::SyscallError::ExecveRequest { path, argv, envp }) => {
                self.do_execve(&path, &argv, &envp)
            }
            Err(canary_syscall::SyscallError::CloneRequest { new_tid, .. }) => {
                self.arm_cpu.as_mut().unwrap().x[0] = new_tid as u64;
                Ok(())
            }
            Err(canary_syscall::SyscallError::Fault(addr)) => {
                warn(&format!("arm64 syscall {arm_nr}: fault at {addr:#x}"));
                self.arm_cpu.as_mut().unwrap().x[0] = (-14i64) as u64; // EFAULT
                Ok(())
            }
            Err(e) => {
                warn(&format!("arm64 syscall {arm_nr} (x86={nr}): {e}"));
                self.arm_cpu.as_mut().unwrap().x[0] = (-38i64) as u64; // ENOSYS
                Ok(())
            }
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

        // rt_sigreturn is handled entirely in the runtime, not in dispatch.rs,
        // because it needs access to both cpu and mem simultaneously.
        if nr == canary_syscall::numbers::SYS_RT_SIGRETURN {
            return self.do_rt_sigreturn();
        }

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
            Err(canary_syscall::SyscallError::ExecveRequest { path, argv, envp }) => {
                self.do_execve(&path, &argv, &envp)
            }
            Err(canary_syscall::SyscallError::CloneRequest {
                new_tid, child_stack: _, parent_tidptr: _, child_tidptr: _,
                tls: _, flags: _,
            }) => {
                // The CloneInfo was already pushed into ctx.pending_clone by the
                // syscall handler.  In the parent we return the new TID in RAX
                // (same as real Linux).  The JS harness calls drain_clone_requests()
                // after each step and spawns a Worker for each entry.
                self.cpu.fs_base = fs_base;
                self.cpu.gs_base = gs_base;
                self.cpu.gpr[reg::RAX] = new_tid as u64;
                Ok(())
            }
            Err(canary_syscall::SyscallError::Fault(addr)) => {
                warn(&format!("syscall {nr}: fault at {addr:#x}"));
                self.cpu.gpr[reg::RAX] = (-14i64) as u64; // EFAULT
                Ok(())
            }
            Err(e) => {
                warn(&format!("syscall {nr} error: {e}"));
                self.cpu.gpr[reg::RAX] = (-38i64) as u64; // ENOSYS
                Ok(())
            }
        }
    }

    /// Handle execve by loading the new binary from the VFS and restarting
    /// the interpreter loop within the same CanaryRuntime.
    fn do_execve(&mut self, path: &str, argv: &[String], envp: &[String]) -> Result<(), CanaryError> {
        // Resolve absolute path.
        let abs_path = if path.starts_with('/') {
            path.to_string()
        } else {
            let cwd = self.ctx.cwd.clone();
            if cwd.ends_with('/') {
                format!("{}{}", cwd, path)
            } else {
                format!("{}/{}", cwd, path)
            }
        };

        // Look up the binary in the VFS.
        let ino = self.ctx.vfs.mem.lookup(&abs_path)
            .map_err(|_| CanaryError::Exec(format!("execve: not found: {abs_path}")))?;
        let binary = {
            let node = self.ctx.vfs.mem.node(ino);
            if node.content.is_empty() {
                return Err(CanaryError::Exec(format!("execve: empty binary: {abs_path}")));
            }
            node.content.clone()
        };

        log(&format!("Canary: execve '{}' ({} bytes, {} args)", abs_path, binary.len(), argv.len()));

        // run_elf_inner resets cpu, mem, and fds — then runs the new binary
        // until it exits.  Its exit code becomes our Exit error.
        match self.run_elf_inner(&binary, argv, envp) {
            Ok(code)                     => Err(CanaryError::Exit(code)),
            Err(CanaryError::Exit(code)) => Err(CanaryError::Exit(code)),
            Err(e)                       => Err(e),
        }
    }

    /// Push a signal frame onto the guest stack and redirect execution to
    /// the signal handler.
    ///
    /// Signal frame layout on x86-64 Linux (simplified ucontext_t):
    ///   RSP →  [return address = restorer]           +0   (8 bytes)
    ///          [siginfo_t  — 128 bytes, zeroed]       +8
    ///          [uc_flags   (u64)]                     +136
    ///          [uc_link    (u64)]                     +144
    ///          [stack_t    (24 bytes)]                +152
    ///          [mcontext gregs — 23 × u64 = 184 bytes]+176
    ///
    /// Total = 176 + 184 = 360 bytes, rounded up to 16-byte alignment.
    fn push_signal_frame(
        &mut self,
        signum:     u32,
        handler_va: u64,
        restorer:   u64,
    ) -> Result<(), CanaryError> {
        use canary_cpu::registers::reg;

        // Snapshot all GPRs + RIP + RFLAGS before we touch anything.
        let saved_r8    = self.cpu.gpr[reg::R8];
        let saved_r9    = self.cpu.gpr[reg::R9];
        let saved_r10   = self.cpu.gpr[reg::R10];
        let saved_r11   = self.cpu.gpr[reg::R11];
        let saved_r12   = self.cpu.gpr[reg::R12];
        let saved_r13   = self.cpu.gpr[reg::R13];
        let saved_r14   = self.cpu.gpr[reg::R14];
        let saved_r15   = self.cpu.gpr[reg::R15];
        let saved_rdi   = self.cpu.gpr[reg::RDI];
        let saved_rsi   = self.cpu.gpr[reg::RSI];
        let saved_rbp   = self.cpu.gpr[reg::RBP];
        let saved_rbx   = self.cpu.gpr[reg::RBX];
        let saved_rdx   = self.cpu.gpr[reg::RDX];
        let saved_rax   = self.cpu.gpr[reg::RAX];
        let saved_rcx   = self.cpu.gpr[reg::RCX];
        let saved_rsp   = self.cpu.gpr[reg::RSP];
        let saved_rip   = self.cpu.rip;
        let saved_rflags= self.cpu.rflags;

        // Frame size: 8 (retaddr) + 128 (siginfo) + 8 (uc_flags) + 8 (uc_link)
        //             + 24 (stack_t) + 23*8 (gregs) = 360 bytes.
        const FRAME_SIZE: u64 = 360;

        // Align RSP down to 16, then subtract the frame.
        let new_rsp = (saved_rsp & !0xF_u64).wrapping_sub(FRAME_SIZE);

        // Write frame — everything starts zeroed in mapped memory.
        // +0: return address (restorer)
        self.mem.write_u64(new_rsp, restorer)
            .map_err(|e| CanaryError::Exec(format!("signal frame write: {e}")))?;

        // +8..+136: siginfo_t (128 bytes) — leave zeroed; just write signo.
        self.mem.write_u32(new_rsp + 8, signum)
            .map_err(|e| CanaryError::Exec(format!("signal frame write: {e}")))?;

        // +136: uc_flags
        self.mem.write_u64(new_rsp + 136, 0)
            .map_err(|e| CanaryError::Exec(format!("signal frame write: {e}")))?;
        // +144: uc_link
        self.mem.write_u64(new_rsp + 144, 0)
            .map_err(|e| CanaryError::Exec(format!("signal frame write: {e}")))?;
        // +152: stack_t (24 bytes) — leave zeroed (no altstack active).

        // +176: mcontext gregs[0..23]
        //   [0]=R8, [1]=R9, [2]=R10, [3]=R11,
        //   [4]=R12, [5]=R13, [6]=R14, [7]=R15,
        //   [8]=RDI, [9]=RSI, [10]=RBP, [11]=RBX,
        //   [12]=RDX, [13]=RAX, [14]=RCX, [15]=RSP,
        //   [16]=RIP, [17]=EFL, [18..22]=misc zeros
        let gregs_base = new_rsp + 176;
        let gregs: [u64; 23] = [
            saved_r8, saved_r9, saved_r10, saved_r11,
            saved_r12, saved_r13, saved_r14, saved_r15,
            saved_rdi, saved_rsi, saved_rbp, saved_rbx,
            saved_rdx, saved_rax, saved_rcx, saved_rsp,
            saved_rip, saved_rflags, 0, 0, 0, 0, 0,
        ];
        for (i, &v) in gregs.iter().enumerate() {
            self.mem.write_u64(gregs_base + i as u64 * 8, v)
                .map_err(|e| CanaryError::Exec(format!("signal frame write: {e}")))?;
        }

        // Redirect execution.
        self.cpu.gpr[reg::RSP] = new_rsp;
        self.cpu.gpr[reg::RDI] = signum as u64; // first arg: signal number
        self.cpu.rip = handler_va;

        Ok(())
    }

    /// Restore registers from the ucontext on the stack (rt_sigreturn).
    fn do_rt_sigreturn(&mut self) -> Result<(), CanaryError> {
        use canary_cpu::registers::reg;

        let frame_base = self.cpu.gpr[reg::RSP];

        // gregs are at frame_base + 176.
        let gregs_base = frame_base + 176;
        let mut gregs = [0u64; 23];
        for (i, v) in gregs.iter_mut().enumerate() {
            *v = self.mem.read_u64(gregs_base + i as u64 * 8)
                .map_err(|e| CanaryError::Exec(format!("sigreturn read: {e}")))?;
        }

        // Restore GPRs.
        self.cpu.gpr[reg::R8]  = gregs[0];
        self.cpu.gpr[reg::R9]  = gregs[1];
        self.cpu.gpr[reg::R10] = gregs[2];
        self.cpu.gpr[reg::R11] = gregs[3];
        self.cpu.gpr[reg::R12] = gregs[4];
        self.cpu.gpr[reg::R13] = gregs[5];
        self.cpu.gpr[reg::R14] = gregs[6];
        self.cpu.gpr[reg::R15] = gregs[7];
        self.cpu.gpr[reg::RDI] = gregs[8];
        self.cpu.gpr[reg::RSI] = gregs[9];
        self.cpu.gpr[reg::RBP] = gregs[10];
        self.cpu.gpr[reg::RBX] = gregs[11];
        self.cpu.gpr[reg::RDX] = gregs[12];
        self.cpu.gpr[reg::RAX] = gregs[13];
        self.cpu.gpr[reg::RCX] = gregs[14];
        self.cpu.gpr[reg::RSP] = gregs[15];
        self.cpu.rip            = gregs[16];
        self.cpu.rflags         = gregs[17];

        Ok(())
    }

    /// Deliver any pending, unblocked signals before the next instruction.
    fn deliver_pending_signals(&mut self) -> Result<(), CanaryError> {
        let deliverable = self.ctx.signals.pending & !self.ctx.signals.mask;
        if deliverable == 0 { return Ok(()); }

        // Find the lowest-numbered pending signal.
        let bit    = deliverable.trailing_zeros();  // 0-based bit index
        let signum = bit + 1;                       // 1-based signal number

        // Clear the pending bit.
        self.ctx.signals.pending &= !(1u64 << bit);

        let handler = self.ctx.signals.handlers[bit as usize];

        match handler.handler_va {
            0 => {
                // SIG_DFL — default action.
                match signum {
                    // SIGCHLD=17, SIGCONT=18, SIGSTOP=19, SIGTSTP=20,
                    // SIGURG=23, SIGWINCH=28: default is ignore.
                    17 | 18 | 19 | 20 | 23 | 28 => {}
                    _ => return Err(CanaryError::Exit(-(signum as i32))),
                }
            }
            1 => {
                // SIG_IGN — explicitly ignored.
            }
            va => {
                // User-space handler: build a signal frame and redirect RIP.
                self.push_signal_frame(signum, va, handler.restorer)?;
            }
        }

        Ok(())
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

// ── AArch64 → x86-64 syscall number translation ───────────────────────────────
//
// AArch64 Linux uses a "unified" syscall table (different from x86-64).
// We map the common ones to their x86-64 equivalents so we can reuse the
// existing canary-syscall dispatch implementation.
// Returns u64::MAX for unmapped syscalls (caller returns ENOSYS).

fn arm64_to_x86_syscall(arm_nr: u64) -> u64 {
    match arm_nr {
        // ── File I/O ─────────────────────────────────────────────────────
        63  => 0,    // read
        64  => 1,    // write
        57  => 3,    // close
        62  => 8,    // lseek
        65  => 19,   // readv
        66  => 20,   // writev
        67  => 17,   // pread64
        68  => 18,   // pwrite64
        23  => 72,   // fcntl  (arm64 fcntl=25? actually arm64 fcntl=25)
        25  => 72,   // fcntl
        29  => 16,   // ioctl
        // ── File system ───────────────────────────────────────────────────
        56  => 257,  // openat
        17  => 79,   // getcwd
        49  => 80,   // chdir
        61  => 217,  // getdents64
        79  => 262,  // newfstatat
        80  => 5,    // fstat
        // ── Memory management ─────────────────────────────────────────────
        222 => 9,    // mmap
        226 => 10,   // mprotect
        215 => 11,   // munmap
        214 => 12,   // brk
        216 => 25,   // mremap
        // ── Process / thread ──────────────────────────────────────────────
        93  => 60,   // exit
        94  => 231,  // exit_group
        172 => 39,   // getpid
        178 => 186,  // gettid
        174 => 102,  // getuid
        175 => 107,  // geteuid
        176 => 104,  // getgid
        177 => 108,  // getegid
        96  => 218,  // set_tid_address
        98  => 202,  // futex
        220 => 56,   // clone
        221 => 59,   // execve
        260 => 61,   // wait4
        // ── Signals ───────────────────────────────────────────────────────
        134 => 13,   // rt_sigaction
        135 => 14,   // rt_sigprocmask
        139 => 15,   // rt_sigreturn
        // ── System info ───────────────────────────────────────────────────
        160 => 63,   // uname
        169 => 99,   // sysinfo (arm64 sysinfo=179? no, 179 is sched_getaffinity; sysinfo=179 on arm64)
        // ── Networking ────────────────────────────────────────────────────
        198 => 41,   // socket
        200 => 49,   // bind
        203 => 42,   // connect
        201 => 50,   // listen
        202 => 43,   // accept
        206 => 44,   // sendto
        207 => 45,   // recvfrom
        208 => 54,   // setsockopt
        209 => 55,   // getsockopt
        204 => 51,   // getsockname
        205 => 52,   // getpeername
        210 => 46,   // sendmsg
        211 => 47,   // recvmsg
        // ── Time ──────────────────────────────────────────────────────────
        113 => 228,  // clock_gettime
        116 => 35,   // nanosleep
        // ── Misc ──────────────────────────────────────────────────────────
        167 => 101,  // setsid
        130 => 110,  // setgid (arm64 setgid=144)
        144 => 106,  // setgid on arm64
        _   => u64::MAX, // unmapped
    }
}

// ── Base64 helper (no external dependency) ────────────────────────────────────

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity((data.len() + 2) / 3 * 4);
    let mut chunks = data.chunks_exact(3);
    for chunk in chunks.by_ref() {
        let n = (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8 | chunk[2] as u32;
        out.push(CHARS[((n >> 18) & 0x3F) as usize]);
        out.push(CHARS[((n >> 12) & 0x3F) as usize]);
        out.push(CHARS[((n >>  6) & 0x3F) as usize]);
        out.push(CHARS[( n        & 0x3F) as usize]);
    }
    let rem = chunks.remainder();
    match rem.len() {
        1 => {
            let n = (rem[0] as u32) << 16;
            out.push(CHARS[((n >> 18) & 0x3F) as usize]);
            out.push(CHARS[((n >> 12) & 0x3F) as usize]);
            out.push(b'=');
            out.push(b'=');
        }
        2 => {
            let n = (rem[0] as u32) << 16 | (rem[1] as u32) << 8;
            out.push(CHARS[((n >> 18) & 0x3F) as usize]);
            out.push(CHARS[((n >> 12) & 0x3F) as usize]);
            out.push(CHARS[((n >>  6) & 0x3F) as usize]);
            out.push(b'=');
        }
        _ => {}
    }
    String::from_utf8(out).unwrap_or_default()
}
