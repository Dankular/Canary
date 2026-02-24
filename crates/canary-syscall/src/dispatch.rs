//! Syscall dispatcher — called by the interpreter when SYSCALL is executed.

use canary_memory::{GuestMemory, Prot, MapFlags};
use canary_fs::Vfs;
use crate::{numbers::*, errno::*, SyscallError, CloneInfo};

use std::collections::{HashMap, HashSet};

// ── Signal infrastructure ─────────────────────────────────────────────────────

/// Per-signal handler registration (mirrors Linux kernel_sigaction).
#[derive(Clone, Copy, Default)]
pub struct SignalHandler {
    /// Virtual address of the handler.
    /// 0 = SIG_DFL, 1 = SIG_IGN, anything else = real handler VA.
    pub handler_va: u64,
    pub flags:      u64,
    pub sa_mask:    u64,
    /// Address of the signal restorer (__restore_rt in glibc).
    pub restorer:   u64,
}

/// All signal-related state for the emulated process.
pub struct SignalState {
    /// Registered signal handlers: index = signum - 1.
    pub handlers: [SignalHandler; 64],
    /// Pending signal bitmap: bit N set means signal N+1 is pending.
    pub pending:  u64,
    /// Blocked signal mask: bit N set means signal N+1 is blocked.
    pub mask:     u64,
    /// Alternate signal stack (ss_sp, ss_size), if set by sigaltstack.
    pub altstack: Option<(u64, usize)>,
}

impl Default for SignalState {
    fn default() -> Self {
        SignalState {
            handlers: [SignalHandler::default(); 64],
            pending:  0,
            mask:     0,
            altstack: None,
        }
    }
}

// ── File descriptor table ─────────────────────────────────────────────────────

pub struct FdTable {
    /// fd → (inode, offset, flags)
    fds: HashMap<u64, OpenFd>,
    next_fd: u64,
    /// Set of fds that map to the /dev/fb0 framebuffer device.
    fb_fds: HashSet<u64>,
    /// Set of fds that map to /dev/input/event* devices.
    input_fds: HashSet<u64>,
}

struct OpenFd {
    ino:    usize,
    offset: u64,
    flags:  u64,
}

impl FdTable {
    pub fn new() -> Self {
        let mut t = FdTable {
            fds: HashMap::new(),
            next_fd: 3,
            fb_fds: HashSet::new(),
            input_fds: HashSet::new(),
        };
        // stdin=0, stdout=1, stderr=2 are pre-opened.
        for fd in 0..3u64 {
            t.fds.insert(fd, OpenFd { ino: 0, offset: 0, flags: 0 });
        }
        t
    }
    fn alloc(&mut self, ino: usize, flags: u64) -> u64 {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.fds.insert(fd, OpenFd { ino, offset: 0, flags });
        fd
    }
    /// Allocate a framebuffer fd (backed by a sentinel inode 0).
    pub fn alloc_fb(&mut self) -> u64 {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.fds.insert(fd, OpenFd { ino: 0, offset: 0, flags: 0 });
        self.fb_fds.insert(fd);
        fd
    }
    /// Allocate an input device fd (backed by a sentinel inode 0).
    pub fn alloc_input(&mut self) -> u64 {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.fds.insert(fd, OpenFd { ino: 0, offset: 0, flags: 0 });
        self.input_fds.insert(fd);
        fd
    }
    /// Returns true if `fd` refers to the /dev/fb0 framebuffer.
    pub fn is_framebuffer(&self, fd: u64) -> bool {
        self.fb_fds.contains(&fd)
    }
    /// Returns true if `fd` refers to a /dev/input/event* device.
    pub fn is_input(&self, fd: u64) -> bool {
        self.input_fds.contains(&fd)
    }
    fn get(&self, fd: u64) -> Option<&OpenFd> { self.fds.get(&fd) }
    fn get_mut(&mut self, fd: u64) -> Option<&mut OpenFd> { self.fds.get_mut(&fd) }
    fn close(&mut self, fd: u64) -> bool {
        self.fb_fds.remove(&fd);
        self.input_fds.remove(&fd);
        self.fds.remove(&fd).is_some()
    }
}

// ── Syscall context ────────────────────────────────────────────────────────────

pub struct SyscallCtx {
    pub fds:     FdTable,
    pub vfs:     Vfs,
    pub cwd:     String,
    /// stdout/stderr capture buffer (for the JS layer to read).
    pub stdout_buf: Vec<u8>,
    pub stderr_buf: Vec<u8>,
    pub pid:     u32,
    pub uid:     u32,
    pub gid:     u32,
    /// Signal delivery state.
    pub signals: SignalState,
    /// Linux /dev/fb0 framebuffer device state.
    pub fb: canary_fb::Framebuffer,
    // ── Threading ─────────────────────────────────────────────────────────
    /// All spawned threads (the main thread itself is not stored here; its
    /// registers live in `CanaryRuntime::cpu`).
    pub threads: canary_thread::ThreadTable,
    /// TID of the currently-executing thread.  Main thread = 1.
    pub current_tid: canary_thread::ThreadId,
    /// Queue of clone requests that the JS harness must act on by spawning
    /// Web Workers.  Drained by `CanaryRuntime::drain_clone_requests()`.
    pub pending_clone: Vec<CloneInfo>,
    // ── Networking ────────────────────────────────────────────────────────
    /// Virtual socket table and JS bridge queues.
    pub net: canary_net::NetCtx,
    // ── I/O ports ─────────────────────────────────────────────────────────
    /// I/O port emulation (IN/OUT instructions, WebX GPU bridge).
    pub io: canary_io::IoCtx,
    // ── Input devices ─────────────────────────────────────────────────────
    /// Linux evdev input emulation for /dev/input/event0.
    pub input: canary_input::InputCtx,
    /// Path of the main executable (returned by readlink("/proc/self/exe")).
    pub proc_exe: String,
}

impl SyscallCtx {
    pub fn new() -> Self {
        let mut vfs = Vfs::new();
        // Pre-populate device stubs so that open() succeeds for these paths.
        vfs.mem.write_file("/dev/fb0",            vec![]).ok();
        vfs.mem.write_file("/dev/input/event0",   vec![]).ok();
        vfs.mem.write_file("/dev/input/mice",     vec![]).ok();
        vfs.mem.write_file("/dev/dri/card0",      vec![]).ok();
        vfs.mem.write_file("/dev/dri/renderD128", vec![]).ok();
        // Pre-populate DNS/hosts stubs for libc name resolution.
        vfs.mem.write_file("/etc/hosts",
            b"127.0.0.1 localhost\n::1 localhost\n".to_vec()).ok();
        vfs.mem.write_file("/etc/resolv.conf",
            b"nameserver 127.0.0.1\n".to_vec()).ok();
        vfs.mem.write_file("/etc/nsswitch.conf",
            b"hosts: files dns\n".to_vec()).ok();

        SyscallCtx {
            fds:           FdTable::new(),
            vfs,
            cwd:           "/".to_string(),
            stdout_buf:    Vec::new(),
            stderr_buf:    Vec::new(),
            pid:           1,
            uid:           1000,
            gid:           1000,
            signals:       SignalState::default(),
            fb:            canary_fb::Framebuffer::new(),
            threads:       canary_thread::ThreadTable::new(1),
            current_tid:   1,
            pending_clone: Vec::new(),
            net:           canary_net::NetCtx::new(),
            io:            canary_io::IoCtx::new(),
            input:         canary_input::InputCtx::new(),
            proc_exe:      String::new(),
        }
    }
}

// ── Main dispatch ──────────────────────────────────────────────────────────────

/// Dispatch a syscall.
///
/// Arguments match the x86-64 Linux syscall ABI:
///   nr  = RAX
///   a0  = RDI, a1 = RSI, a2 = RDX, a3 = R10, a4 = R8, a5 = R9
///
/// Returns the value to store in RAX (negative errno on failure).
pub fn handle_syscall(
    nr:  u64,
    a0:  u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64,
    mem: &mut GuestMemory,
    ctx: &mut SyscallCtx,
    fs_base_out: &mut u64,
    gs_base_out: &mut u64,
) -> Result<i64, SyscallError> {

    log::debug!("syscall {} ({:#x}), args: {:#x} {:#x} {:#x} {:#x}", nr, nr, a0, a1, a2, a3);

    // ── Network socket syscalls ────────────────────────────────────────────────
    // These are handled entirely in canary-net, before the main match.
    if canary_net::syscalls::is_socket_syscall(nr) {
        return Ok(canary_net::syscalls::handle_socket_syscall(
            nr, a0, a1, a2, a3, a4, a5, mem, &mut ctx.net,
        ));
    }

    let ret: i64 = match nr {

        // ── read(fd, buf, count) ──────────────────────────────────────────
        SYS_READ => {
            let fd    = a0;
            let buf   = a1;
            let count = a2 as usize;
            // Intercept reads from /dev/input/event* fds.
            if ctx.fds.is_input(fd) {
                let data = ctx.input.read_events(count);
                if data.is_empty() {
                    return Ok(-EAGAIN);  // non-blocking: no events pending
                }
                mem.write_bytes_at(buf, &data)?;
                return Ok(data.len() as i64);
            }
            match fd {
                0 => {
                    // stdin: return EOF for now.
                    0
                }
                _ => {
                    let ofd = match ctx.fds.get_mut(fd) { Some(f) => f, None => return Ok(-EBADF) };
                    let ino    = ofd.ino;
                    let offset = ofd.offset;
                    let node = ctx.vfs.mem.node(ino);
                    let start = offset as usize;
                    let avail = node.content.len().saturating_sub(start);
                    let n     = count.min(avail);
                    if n > 0 {
                        let slice = &node.content[start..start + n];
                        mem.write_bytes_at(buf, slice)?;
                        ctx.fds.get_mut(fd).unwrap().offset += n as u64;
                    }
                    n as i64
                }
            }
        }

        // ── write(fd, buf, count) ─────────────────────────────────────────
        SYS_WRITE => {
            let fd    = a0;
            let buf   = a1;
            let count = a2 as usize;
            let data  = mem.read_bytes(buf, count)?.to_vec();
            match fd {
                1 => { ctx.stdout_buf.extend_from_slice(&data); count as i64 }
                2 => { ctx.stderr_buf.extend_from_slice(&data); count as i64 }
                _ => {
                    let ofd = match ctx.fds.get_mut(fd) { Some(f) => f, None => return Ok(-EBADF) };
                    let ino = ofd.ino;
                    let off = ofd.offset as usize;
                    let node = ctx.vfs.mem.node_mut(ino);
                    if off + data.len() > node.content.len() {
                        node.content.resize(off + data.len(), 0);
                    }
                    node.content[off..off + data.len()].copy_from_slice(&data);
                    ctx.fds.get_mut(fd).unwrap().offset += data.len() as u64;
                    data.len() as i64
                }
            }
        }

        // ── open(path, flags, mode) ───────────────────────────────────────
        SYS_OPEN | SYS_CREAT => {
            let path_ptr = a0;
            let flags    = if nr == SYS_CREAT { O_CREAT | O_WRONLY | O_TRUNC } else { a1 };
            let path     = mem.read_cstr(path_ptr)?;
            let abs      = resolve_path(&ctx.cwd, &path);
            // Intercept /dev/fb0 — return a framebuffer fd.
            if abs == "/dev/fb0" {
                return Ok(ctx.fds.alloc_fb() as i64);
            }
            // Intercept /dev/input/event* — return an input fd.
            if abs.starts_with("/dev/input/event") || abs == "/dev/input/mice" {
                return Ok(ctx.fds.alloc_input() as i64);
            }
            match ctx.vfs.mem.lookup(&abs) {
                Ok(ino) => {
                    let fd = ctx.fds.alloc(ino, flags);
                    fd as i64
                }
                Err(_) if flags & O_CREAT != 0 => {
                    ctx.vfs.mem.write_file(&abs, vec![]).ok();
                    let ino = ctx.vfs.mem.lookup(&abs).unwrap_or(0);
                    let fd = ctx.fds.alloc(ino, flags);
                    fd as i64
                }
                Err(_) => -ENOENT,
            }
        }

        // ── openat(dirfd, path, flags, mode) ─────────────────────────────
        SYS_OPENAT => {
            let dirfd    = a0 as i64;
            let path_ptr = a1;
            let flags    = a2;
            let path     = mem.read_cstr(path_ptr)?;
            let abs = if path.starts_with('/') {
                path.clone()
            } else if dirfd == AT_FDCWD {
                resolve_path(&ctx.cwd, &path)
            } else {
                // Resolve relative to dirfd — simplified.
                resolve_path(&ctx.cwd, &path)
            };
            // Intercept /dev/fb0 — return a framebuffer fd.
            if abs == "/dev/fb0" {
                return Ok(ctx.fds.alloc_fb() as i64);
            }
            // Intercept /dev/input/event* — return an input fd.
            if abs.starts_with("/dev/input/event") || abs == "/dev/input/mice" {
                return Ok(ctx.fds.alloc_input() as i64);
            }
            match ctx.vfs.mem.lookup(&abs) {
                Ok(ino) => {
                    let fd = ctx.fds.alloc(ino, flags);
                    fd as i64
                }
                Err(_) if flags & O_CREAT != 0 => {
                    ctx.vfs.mem.write_file(&abs, vec![]).ok();
                    let ino = ctx.vfs.mem.lookup(&abs).unwrap_or(0);
                    let fd = ctx.fds.alloc(ino, flags);
                    fd as i64
                }
                Err(_) => -ENOENT,
            }
        }

        // ── close(fd) ─────────────────────────────────────────────────────
        SYS_CLOSE => {
            if ctx.fds.close(a0) { 0 } else { -EBADF }
        }

        // ── lseek(fd, offset, whence) ─────────────────────────────────────
        SYS_LSEEK => {
            let fd     = a0;
            let offset = a1 as i64;
            let whence = a2;
            let ofd = match ctx.fds.get_mut(fd) { Some(f) => f, None => return Ok(-EBADF) };
            let node = ctx.vfs.mem.node(ofd.ino);
            let file_size = node.content.len() as i64;
            let new_off = match whence {
                SEEK_SET => offset,
                SEEK_CUR => ofd.offset as i64 + offset,
                SEEK_END => file_size + offset,
                _        => return Ok(-EINVAL),
            };
            if new_off < 0 { return Ok(-EINVAL); }
            ofd.offset = new_off as u64;
            new_off
        }

        // ── stat/fstat/lstat ──────────────────────────────────────────────
        SYS_STAT => {
            let path = mem.read_cstr(a0)?;
            let abs  = resolve_path(&ctx.cwd, &path);
            match ctx.vfs.mem.lookup(&abs) {
                Ok(ino) => {
                    write_stat(mem, a1, ctx.vfs.mem.node(ino).stat.clone())?;
                    0
                }
                Err(_) => -ENOENT,
            }
        }
        SYS_LSTAT => {
            // lstat must NOT follow the final symlink component.
            let path = mem.read_cstr(a0)?;
            let abs  = resolve_path(&ctx.cwd, &path);
            let ino_result = {
                let (par, nam) = match abs.rfind('/') {
                    None      => ("/", abs.as_str()),
                    Some(0)   => ("/", &abs[1..]),
                    Some(pos) => (&abs[..pos], &abs[pos+1..]),
                };
                ctx.vfs.mem.lookup(par)
                    .ok()
                    .and_then(|parent_ino| {
                        ctx.vfs.mem.node(parent_ino).children.get(nam).copied()
                    })
            };
            match ino_result {
                Some(ino) => {
                    write_stat(mem, a1, ctx.vfs.mem.node(ino).stat.clone())?;
                    0
                }
                None => -ENOENT,
            }
        }
        SYS_FSTAT => {
            let ofd = match ctx.fds.get(a0) { Some(f) => f, None => return Ok(-EBADF) };
            let ino = ofd.ino;
            let stat = ctx.vfs.mem.node(ino).stat.clone();
            write_stat(mem, a1, stat)?;
            0
        }
        SYS_FSTATAT => {
            let path = mem.read_cstr(a1)?;
            let abs  = resolve_path(&ctx.cwd, &path);
            match ctx.vfs.mem.lookup(&abs) {
                Ok(ino) => {
                    write_stat(mem, a2, ctx.vfs.mem.node(ino).stat.clone())?;
                    0
                }
                Err(_) => -ENOENT,
            }
        }

        // ── mmap(addr, length, prot, flags, fd, offset) ───────────────────
        SYS_MMAP => {
            let addr   = a0;
            let length = a1;
            let prot   = linux_prot_to_canary(a2);
            let flags  = linux_map_flags_to_canary(a3);
            let fd     = a4 as i64;
            let off    = a5 as usize;

            // Check if this mmap is for /dev/fb0.
            if fd >= 0 && ctx.fds.is_framebuffer(fd as u64) {
                // Map the framebuffer pixel buffer at the requested (or default) address.
                let fb_addr = if addr != 0 { addr } else { canary_fb::FB_MMAP_ADDR };
                let fb_size = canary_fb::FB_SIZE as u64;
                return Ok(match mem.mmap(
                    fb_addr,
                    fb_size,
                    Prot::READ | Prot::WRITE,
                    MapFlags::FIXED | MapFlags::PRIVATE | MapFlags::ANONYMOUS,
                ) {
                    Ok(mapped) => {
                        ctx.fb.mmap_addr = Some(mapped);
                        mapped as i64
                    }
                    Err(_) => -ENOMEM,
                });
            }

            match mem.mmap(addr, length, prot, flags) {
                Ok(mapped) => {
                    // If fd >= 0, load file content from offset into mapped address.
                    if fd >= 0 {
                        if let Some(ofd) = ctx.fds.get(fd as u64) {
                            let ino = ofd.ino;
                            let content = ctx.vfs.mem.node(ino).content.clone();
                            let available = content.len().saturating_sub(off);
                            let n = (length as usize).min(available);
                            if n > 0 {
                                mem.loader_write(mapped, &content[off..off + n]);
                            }
                        }
                    }
                    mapped as i64
                }
                Err(_) => -(ENOMEM),
            }
        }

        // ── mprotect(addr, len, prot) ─────────────────────────────────────
        SYS_MPROTECT => {
            let prot = linux_prot_to_canary(a2);
            mem.mprotect(a0, a1, prot).map_or(-EINVAL, |_| 0)
        }

        // ── munmap(addr, len) ─────────────────────────────────────────────
        SYS_MUNMAP => {
            mem.munmap(a0, a1).map_or(-EINVAL, |_| 0)
        }

        // ── brk(new_brk) ─────────────────────────────────────────────────
        SYS_BRK => {
            mem.brk(a0) as i64
        }

        // ── arch_prctl(code, addr) ────────────────────────────────────────
        SYS_ARCH_PRCTL => {
            match a0 {
                ARCH_SET_FS => { *fs_base_out = a1; 0 }
                ARCH_GET_FS => { mem.write_u64(a1, *fs_base_out)?; 0 }
                ARCH_SET_GS => { *gs_base_out = a1; 0 }
                ARCH_GET_GS => { mem.write_u64(a1, *gs_base_out)?; 0 }
                _           => -EINVAL,
            }
        }

        // ── getpid / gettid ───────────────────────────────────────────────
        SYS_GETPID  => ctx.pid as i64,
        SYS_GETPPID => 0,
        // gettid returns the current thread's TID, not the process PID.
        SYS_GETTID  => ctx.current_tid as i64,

        // ── getuid / geteuid / getgid / getegid ───────────────────────────
        SYS_GETUID  | SYS_GETEUID => ctx.uid as i64,
        SYS_GETGID  | SYS_GETEGID => ctx.gid as i64,

        // ── rt_sigaction(signum, new_sa, old_sa, sigsetsize) ─────────────
        SYS_RT_SIGACTION => {
            let signum  = a0 as usize;
            if signum < 1 || signum > 64 { return Ok(-EINVAL); }
            let idx     = signum - 1;
            let new_ptr = a1;
            let old_ptr = a2;
            // Write out old handler if requested.
            if old_ptr != 0 {
                let h = &ctx.signals.handlers[idx];
                mem.write_u64(old_ptr,      h.handler_va)?;
                mem.write_u64(old_ptr +  8, h.flags)?;
                mem.write_u64(old_ptr + 16, h.restorer)?;
                mem.write_u64(old_ptr + 24, h.sa_mask)?;
            }
            // Install new handler if requested.
            if new_ptr != 0 {
                let handler_va = mem.read_u64(new_ptr)?;
                let flags      = mem.read_u64(new_ptr +  8)?;
                let restorer   = mem.read_u64(new_ptr + 16)?;
                let sa_mask    = mem.read_u64(new_ptr + 24)?;
                ctx.signals.handlers[idx] = SignalHandler { handler_va, flags, sa_mask, restorer };
            }
            0
        }

        // ── rt_sigprocmask(how, set_ptr, oldset_ptr, sigsetsize) ─────────
        SYS_RT_SIGPROCMASK => {
            let how     = a0;
            let set_ptr = a1;
            let old_ptr = a2;
            // SIG_BLOCK=0, SIG_UNBLOCK=1, SIG_SETMASK=2
            if old_ptr != 0 {
                mem.write_u64(old_ptr, ctx.signals.mask)?;
            }
            if set_ptr != 0 {
                let new_set = mem.read_u64(set_ptr)?;
                match how {
                    0 => ctx.signals.mask |= new_set,   // SIG_BLOCK
                    1 => ctx.signals.mask &= !new_set,  // SIG_UNBLOCK
                    2 => ctx.signals.mask  = new_set,   // SIG_SETMASK
                    _ => return Ok(-EINVAL),
                }
            }
            0
        }

        // ── rt_sigreturn — restore registers from ucontext on stack ───────
        // (Handled specially in canary-wasm; if we somehow reach here, no-op.)
        SYS_RT_SIGRETURN => 0,

        // ── robust-list stubs ─────────────────────────────────────────────
        SYS_SET_ROBUST_LIST | SYS_GET_ROBUST_LIST => 0,

        // ── uname ─────────────────────────────────────────────────────────
        SYS_UNAME => {
            // struct utsname: 6 × 65 bytes
            let base = a0;
            write_utsname(mem, base)?;
            0
        }

        // ── getcwd(buf, size) ─────────────────────────────────────────────
        SYS_GETCWD => {
            let cwd = ctx.cwd.as_bytes();
            if cwd.len() + 1 > a1 as usize { return Ok(-ENOMEM); }
            mem.write_bytes_at(a0, cwd)?;
            mem.write_u8(a0 + cwd.len() as u64, 0)?;
            a0 as i64
        }

        // ── chdir ─────────────────────────────────────────────────────────
        SYS_CHDIR => {
            let path = mem.read_cstr(a0)?;
            ctx.cwd = resolve_path(&ctx.cwd, &path);
            0
        }

        // ── mkdir / mkdirat ───────────────────────────────────────────────
        SYS_MKDIR | SYS_MKDIRAT => {
            let path_ptr = if nr == SYS_MKDIR { a0 } else { a1 };
            let path = mem.read_cstr(path_ptr)?;
            let abs  = resolve_path(&ctx.cwd, &path);
            ctx.vfs.mem.mkdir_p(&abs).map_or(-EIO, |_| 0)
        }

        // ── access / faccessat ────────────────────────────────────────────
        SYS_ACCESS | SYS_FACCESSAT => {
            let path_ptr = if nr == SYS_ACCESS { a0 } else { a1 };
            let path = mem.read_cstr(path_ptr)?;
            let abs  = resolve_path(&ctx.cwd, &path);
            match ctx.vfs.mem.lookup(&abs) {
                Ok(_) => 0,
                Err(_) => -ENOENT,
            }
        }

        // ── readlink / readlinkat ─────────────────────────────────────────
        SYS_READLINK | SYS_READLINKAT => {
            let path_ptr = if nr == SYS_READLINK { a0 } else { a1 };
            let buf_ptr  = if nr == SYS_READLINK { a1 } else { a2 };
            let buf_sz   = if nr == SYS_READLINK { a2 } else { a3 } as usize;
            let path = mem.read_cstr(path_ptr)?;
            let abs  = resolve_path(&ctx.cwd, &path);
            // Special: /proc/self/exe → main binary path.
            if abs == "/proc/self/exe" || abs == "/proc/1/exe" {
                let exe = ctx.proc_exe.as_bytes();
                let n = exe.len().min(buf_sz);
                if n > 0 { mem.write_bytes_at(buf_ptr, &exe[..n])?; }
                return Ok(n as i64);
            }
            // Look up the PARENT dir (symlinks in the middle are followed),
            // then inspect the final component WITHOUT following it.
            let link_target: Option<String> = {
                let (par, nam) = match abs.rfind('/') {
                    None      => ("/", abs.as_str()),
                    Some(0)   => ("/", &abs[1..]),
                    Some(pos) => (&abs[..pos], &abs[pos+1..]),
                };
                ctx.vfs.mem.lookup(par)
                    .ok()
                    .and_then(|parent_ino| {
                        ctx.vfs.mem.node(parent_ino).children.get(nam).copied()
                    })
                    .and_then(|child_ino| {
                        ctx.vfs.mem.node(child_ino).link_target.clone()
                    })
            };
            match link_target {
                Some(target) => {
                    let bytes = target.as_bytes();
                    let n = bytes.len().min(buf_sz);
                    if n > 0 { mem.write_bytes_at(buf_ptr, &bytes[..n])?; }
                    n as i64
                }
                None => {
                    // Path exists but is not a symlink → EINVAL; not found → ENOENT.
                    let exists = ctx.vfs.mem.lookup(&abs).is_ok();
                    if exists { -EINVAL } else { -ENOENT }
                }
            }
        }

        // ── gettimeofday ─────────────────────────────────────────────────
        SYS_GETTIMEOFDAY => {
            // Return fake time (unix epoch + 1 day).
            mem.write_u64(a0, 86400)?;      // tv_sec
            mem.write_u64(a0 + 8, 0)?;     // tv_usec
            0
        }

        // ── clock_gettime ─────────────────────────────────────────────────
        SYS_CLOCK_GETTIME => {
            mem.write_u64(a1, 86400)?;
            mem.write_u64(a1 + 8, 0)?;
            0
        }

        // ── ioctl (terminal size, tty, framebuffer, evdev) ───────────────
        SYS_IOCTL => {
            let ioctl_fd  = a0;
            let ioctl_cmd = a1;
            let ioctl_arg = a2;
            // Route framebuffer ioctls to the FB handler.
            if ctx.fds.is_framebuffer(ioctl_fd) {
                return Ok(ctx.fb.ioctl(ioctl_cmd, ioctl_arg, mem));
            }
            // Handle evdev ioctls for /dev/input/event* fds.
            if ctx.fds.is_input(ioctl_fd) {
                // EVIOCGVERSION _IOC(_IOC_READ,'E',0x01,sizeof(int)) = 0x80044501
                const EVIOCGVERSION: u64 = 0x80044501;
                // EVIOCGID       _IOC(_IOC_READ,'E',0x02,sizeof(struct input_id)) = 0x80084502
                const EVIOCGID:      u64 = 0x80084502;
                // EVIOCGNAME(len) _IOC(_IOC_READ,'E',0x06,len)
                const EVIOCGNAME_BASE: u64 = 0x80004506;
                // EVIOCGBIT(EV_KEY, len) _IOC(_IOC_READ,'E',0x20+type,len)
                const EVIOCGBIT_KEY_BASE: u64 = 0x80004520;
                // EVIOCGBIT(EV_REL, len)
                const EVIOCGBIT_REL_BASE: u64 = 0x80004522;

                match ioctl_cmd {
                    EVIOCGVERSION => {
                        // Write driver version 1.0.1 as u32 LE.
                        mem.write_u32(ioctl_arg, 0x00010001).ok();
                        0
                    }
                    EVIOCGID => {
                        // struct input_id: bustype(u16), vendor(u16), product(u16), version(u16)
                        mem.write_u16(ioctl_arg,     0).ok(); // BUS_VIRTUAL
                        mem.write_u16(ioctl_arg + 2, 0).ok();
                        mem.write_u16(ioctl_arg + 4, 0).ok();
                        mem.write_u16(ioctl_arg + 6, 0).ok();
                        0
                    }
                    cmd if (cmd & 0xFFFF_FF00) == (EVIOCGNAME_BASE & 0xFFFF_FF00) => {
                        // EVIOCGNAME: write device name string.
                        let name = b"Canary Virtual Input\0";
                        // The upper 14 bits encode max length.
                        let max_len = ((cmd >> 16) & 0x3FFF) as usize;
                        let n = name.len().min(max_len);
                        if ioctl_arg != 0 {
                            mem.write_bytes_at(ioctl_arg, &name[..n]).ok();
                        }
                        n as i64
                    }
                    cmd if (cmd & 0xFFFF_00FF) == (EVIOCGBIT_KEY_BASE & 0xFFFF_00FF)
                        && ((cmd >> 8) & 0xFF) == 0x20 =>
                    {
                        // EVIOCGBIT(EV_KEY): write key bitmap — all zeros (no caps report).
                        let max_len = ((cmd >> 16) & 0x3FFF) as usize;
                        for i in 0..max_len.min(96) {
                            mem.write_u8(ioctl_arg + i as u64, 0).ok();
                        }
                        0
                    }
                    cmd if (cmd & 0xFFFF_00FF) == (EVIOCGBIT_REL_BASE & 0xFFFF_00FF)
                        && ((cmd >> 8) & 0xFF) == 0x22 =>
                    {
                        // EVIOCGBIT(EV_REL): report REL_X (bit0) and REL_Y (bit1) supported.
                        if ioctl_arg != 0 {
                            mem.write_u8(ioctl_arg, 0x03).ok(); // bits 0 and 1 set
                        }
                        0
                    }
                    _ => 0, // ignore unknown evdev ioctls
                }
            } else {
                match ioctl_cmd {
                    TIOCGWINSZ => {
                        // struct winsize: ws_row, ws_col, ws_xpixel, ws_ypixel (u16 each)
                        mem.write_u16(ioctl_arg,      24)?;  // rows
                        mem.write_u16(ioctl_arg + 2,  80)?;  // cols
                        mem.write_u16(ioctl_arg + 4,   0)?;
                        mem.write_u16(ioctl_arg + 6,   0)?;
                        0
                    }
                    TCGETS | TCSETS => 0,
                    _ => -EINVAL,
                }
            }
        }

        // ── futex (WAIT/WAKE) ─────────────────────────────────────────────
        // a0 = uaddr, a1 = futex_op, a2 = val, a3 = timeout_ptr (WAIT) or
        //   val2 (WAKE), a4 = uaddr2, a5 = val3.
        SYS_FUTEX => {
            let uaddr = a0;
            let op    = (a1 & 0x7f) as u32;
            let val   = a2 as i32;

            // Note: `op` already has FUTEX_PRIVATE_FLAG (0x80) and
            // FUTEX_CLOCK_REALTIME (0x100) stripped by the `& 0x7f` mask above,
            // so we only match against the base opcode values.
            const FUTEX_WAIT:        u32 = 0;
            const FUTEX_WAKE:        u32 = 1;
            const FUTEX_REQUEUE:     u32 = 3;
            const FUTEX_CMP_REQUEUE: u32 = 4;
            const FUTEX_WAIT_BITSET: u32 = 9;
            const FUTEX_WAKE_BITSET: u32 = 10;

            match op {
                // ── WAIT / WAIT_BITSET ────────────────────────────────────
                // In cooperative single-threaded mode we cannot truly block.
                // Return EAGAIN so glibc's spin loop backs off and retries on
                // the next scheduler slice; the JS step loop interleaves.
                FUTEX_WAIT | FUTEX_WAIT_BITSET => {
                    let current = mem.read_i32(uaddr)
                        .map_err(|_| SyscallError::Fault(uaddr))?;
                    if current != val { return Ok(-EAGAIN); }
                    -EAGAIN
                }

                // ── WAKE / WAKE_BITSET ────────────────────────────────────
                // We don't track waiters in Rust; Atomics.notify() on the JS
                // side handles Worker thread wakeups.
                FUTEX_WAKE | FUTEX_WAKE_BITSET => 0,

                // ── REQUEUE (condition variable broadcast) ────────────────
                FUTEX_REQUEUE => 0, // stub: no waiters to requeue

                // ── CMP_REQUEUE (pthread_cond_signal) ─────────────────────
                FUTEX_CMP_REQUEUE => {
                    // a5 = val3 (expected value of *uaddr)
                    let expected = a5 as i32;
                    let current  = mem.read_i32(uaddr)
                        .map_err(|_| SyscallError::Fault(uaddr))?;
                    if current != expected { return Ok(-EAGAIN); }
                    0
                }

                _ => -EINVAL,
            }
        }

        // ── sched_yield ──────────────────────────────────────────────────
        SYS_SCHED_YIELD => 0,

        // ── madvise ───────────────────────────────────────────────────────
        SYS_MADVISE => 0,

        // ── mremap ───────────────────────────────────────────────────────
        SYS_MREMAP => {
            let old_addr = a0;
            let old_size = a1;
            let new_size = a2;
            let flags    = a3 as u32;
            match mem.mremap(old_addr, old_size, new_size, flags) {
                Ok(new_addr) => new_addr as i64,
                Err(_)       => -ENOMEM,
            }
        }

        // ── getrandom ─────────────────────────────────────────────────────
        SYS_GETRANDOM => {
            // Fill with a deterministic pseudo-random pattern for reproducibility.
            let buf = a0;
            let len = a1 as usize;
            for i in 0..len {
                mem.write_u8(buf + i as u64, ((i as u64).wrapping_mul(6364136223846793005u64).wrapping_add(1442695040888963407u64) & 0xFF) as u8)?;
            }
            len as i64
        }

        // ── dup / dup2 ────────────────────────────────────────────────────
        SYS_DUP => {
            let old = a0;
            if let Some(ofd) = ctx.fds.get(old) {
                let ino   = ofd.ino;
                let flags = ofd.flags;
                let new_fd = ctx.fds.alloc(ino, flags);
                new_fd as i64
            } else { -EBADF }
        }
        SYS_DUP2 => {
            let old = a0;
            let new = a1;
            if let Some(ofd) = ctx.fds.get(old) {
                let ino   = ofd.ino;
                let flags = ofd.flags;
                ctx.fds.fds.insert(new, OpenFd { ino, flags, offset: 0 });
                new as i64
            } else { -EBADF }
        }

        // ── fcntl (basic) ─────────────────────────────────────────────────
        SYS_FCNTL => {
            match a1 {
                1 /* F_GETFD */ => 0,
                2 /* F_SETFD */ => 0,
                3 /* F_GETFL */ => {
                    ctx.fds.get(a0).map(|f| f.flags as i64).unwrap_or(-EBADF)
                }
                4 /* F_SETFL */ => 0,
                _ => -EINVAL,
            }
        }

        // ── writev ────────────────────────────────────────────────────────
        SYS_WRITEV => {
            let fd     = a0;
            let iov    = a1;
            let iovcnt = a2 as usize;
            let mut total = 0i64;
            for i in 0..iovcnt {
                let iov_base = mem.read_u64(iov + i as u64 * 16)?;
                let iov_len  = mem.read_u64(iov + i as u64 * 16 + 8)? as usize;
                if iov_len == 0 { continue; }
                let data = mem.read_bytes(iov_base, iov_len)
                    .map(|s| s.to_vec())
                    .or_else(|_| mem.read_bytes_copy(iov_base, iov_len))
                    .unwrap_or_default();
                match fd {
                    1 => ctx.stdout_buf.extend_from_slice(&data),
                    2 => ctx.stderr_buf.extend_from_slice(&data),
                    _ => {
                        let ino = match ctx.fds.get(fd) { Some(f) => f.ino, None => return Ok(-EBADF) };
                        let off = match ctx.fds.get(fd) { Some(f) => f.offset as usize, None => return Ok(-EBADF) };
                        let node = ctx.vfs.mem.node_mut(ino);
                        if off + data.len() > node.content.len() {
                            node.content.resize(off + data.len(), 0);
                        }
                        node.content[off..off + data.len()].copy_from_slice(&data);
                        ctx.fds.get_mut(fd).unwrap().offset += data.len() as u64;
                    }
                }
                total += data.len() as i64;
            }
            total
        }

        // ── nanosleep ─────────────────────────────────────────────────────
        SYS_NANOSLEEP => 0,

        // ── getrlimit / setrlimit ─────────────────────────────────────────
        SYS_GETRLIMIT => {
            // Return generous limits.
            mem.write_u64(a1,       u64::MAX)?; // rlim_cur
            mem.write_u64(a1 + 8,   u64::MAX)?; // rlim_max
            0
        }
        SYS_SETRLIMIT => 0,

        // ── sched_getaffinity ─────────────────────────────────────────────
        SYS_SCHED_GETAFFINITY => {
            // Single CPU, CPU 0.
            mem.write_u64(a2, 1)?;
            0
        }

        // ── sysinfo ───────────────────────────────────────────────────────
        SYS_SYSINFO => {
            // struct sysinfo (simplified)
            mem.write_u64(a0,       86400)?;        // uptime
            mem.write_u64(a0 + 8,  0xC000_0000)?;  // totalram
            mem.write_u64(a0 + 16, 0x8000_0000)?;  // freeram
            mem.write_u64(a0 + 24, 0)?;             // sharedram
            mem.write_u64(a0 + 32, 0)?;             // bufferram
            mem.write_u64(a0 + 40, 0xC000_0000)?;  // totalswap
            mem.write_u64(a0 + 48, 0xC000_0000)?;  // freeswap
            mem.write_u16(a0 + 56, 1)?;             // procs
            0
        }

        // ── rseq (return ENOSYS to signal no kernel support) ──────────────
        SYS_RSEQ => -ENOSYS,

        // ── memfd_create ─────────────────────────────────────────────────
        SYS_MEMFD_CREATE => {
            let name = mem.read_cstr(a0).unwrap_or_default();
            let path = format!("/memfd:{}", name);
            ctx.vfs.mem.write_file(&path, vec![]).ok();
            let ino = ctx.vfs.mem.lookup(&path).unwrap_or(0);
            ctx.fds.alloc(ino, O_RDWR) as i64
        }

        // ── exit / exit_group ─────────────────────────────────────────────
        SYS_EXIT | SYS_EXIT_GROUP => {
            return Err(SyscallError::Exit(a0 as i32));
        }

        // ── pipe / pipe2 ──────────────────────────────────────────────────
        SYS_PIPE | SYS_PIPE2 => {
            // Create two connected "files" for the read/write ends.
            let read_ino  = { ctx.vfs.mem.write_file("/pipe/r", vec![]).ok(); ctx.vfs.mem.lookup("/pipe/r").unwrap_or(0) };
            let write_ino = read_ino;
            let rfd = ctx.fds.alloc(read_ino, O_RDONLY);
            let wfd = ctx.fds.alloc(write_ino, O_WRONLY);
            mem.write_u32(a0, rfd as u32)?;
            mem.write_u32(a0 + 4, wfd as u32)?;
            0
        }

        // ── readv(fd, iov, iovcnt) ────────────────────────────────────────
        SYS_READV => {
            let fd     = a0;
            let iov    = a1;
            let iovcnt = a2 as usize;
            if fd == 0 { return Ok(0); } // stdin: EOF
            let mut total = 0i64;
            for i in 0..iovcnt {
                let iov_base = mem.read_u64(iov + i as u64 * 16)?;
                let iov_len  = mem.read_u64(iov + i as u64 * 16 + 8)? as usize;
                if iov_len == 0 { continue; }
                let ino    = match ctx.fds.get(fd)  { Some(f) => f.ino,    None => return Ok(-EBADF) };
                let offset = match ctx.fds.get(fd)  { Some(f) => f.offset, None => return Ok(-EBADF) };
                let avail  = ctx.vfs.mem.node(ino).content.len().saturating_sub(offset as usize);
                let n      = iov_len.min(avail);
                if n > 0 {
                    let slice = ctx.vfs.mem.node(ino).content[offset as usize..offset as usize + n].to_vec();
                    mem.write_bytes_at(iov_base, &slice)?;
                    ctx.fds.get_mut(fd).unwrap().offset += n as u64;
                    total += n as i64;
                }
                if n < iov_len { break; } // EOF reached
            }
            total
        }

        // ── pread64(fd, buf, count, offset) ──────────────────────────────
        SYS_PREAD64 => {
            let fd     = a0;
            let buf    = a1;
            let count  = a2 as usize;
            let offset = a3 as usize;
            let ofd = match ctx.fds.get(fd) { Some(f) => f, None => return Ok(-EBADF) };
            let ino    = ofd.ino;
            let node   = ctx.vfs.mem.node(ino);
            let start  = offset;
            let avail  = node.content.len().saturating_sub(start);
            let n      = count.min(avail);
            if n > 0 {
                let slice = &node.content[start..start + n];
                mem.write_bytes_at(buf, slice)?;
            }
            n as i64
        }

        // ── pwrite64(fd, buf, count, offset) ─────────────────────────────
        SYS_PWRITE64 => {
            let fd     = a0;
            let buf    = a1;
            let count  = a2 as usize;
            let offset = a3 as usize;
            let data = mem.read_bytes(buf, count)
                .map(|s| s.to_vec())
                .or_else(|_| mem.read_bytes_copy(buf, count))?;
            match fd {
                1 => { ctx.stdout_buf.extend_from_slice(&data); data.len() as i64 }
                2 => { ctx.stderr_buf.extend_from_slice(&data); data.len() as i64 }
                _ => {
                    let ino = match ctx.fds.get(fd) { Some(f) => f.ino, None => return Ok(-EBADF) };
                    let node = ctx.vfs.mem.node_mut(ino);
                    if offset + data.len() > node.content.len() {
                        node.content.resize(offset + data.len(), 0);
                    }
                    node.content[offset..offset + data.len()].copy_from_slice(&data);
                    node.stat.size = node.content.len() as i64;
                    data.len() as i64
                }
            }
        }

        // ── getdents64(fd, buf, count) ───────────────────────────────────
        SYS_GETDENTS64 | SYS_GETDENTS => {
            let fd       = a0;
            let buf_ptr  = a1;
            let buf_size = a2 as usize;

            let (ino, pos) = match ctx.fds.get(fd) {
                Some(f) => (f.ino, f.offset as usize),
                None    => return Ok(-EBADF),
            };

            let node = ctx.vfs.mem.node(ino);
            if node.kind != canary_fs::FileKind::Directory {
                return Ok(-ENOTDIR);
            }

            // Collect entries: "." and ".." first, then children sorted by name.
            let mut all: Vec<(String, u64, u8)> = vec![
                (".".into(),  ino as u64, 4u8),
                ("..".into(), 0u64,       4u8),
            ];
            for (name, &child_ino) in &node.children {
                let d_type: u8 = match ctx.vfs.mem.node(child_ino).kind {
                    canary_fs::FileKind::Regular    => 8,
                    canary_fs::FileKind::Directory  => 4,
                    canary_fs::FileKind::Symlink    => 10,
                    canary_fs::FileKind::CharDevice => 2,
                    canary_fs::FileKind::BlockDevice=> 6,
                    _                               => 0,
                };
                all.push((name.clone(), child_ino as u64, d_type));
            }
            all[2..].sort_by(|a, b| a.0.cmp(&b.0));

            let mut written  = 0usize;
            let mut new_pos  = pos;

            for (name, d_ino, d_type) in all.iter().skip(pos) {
                let name_bytes = name.as_bytes();
                // dirent64: u64 ino + i64 off + u16 reclen + u8 type + name + NUL, aligned to 8
                let reclen = ((19 + name_bytes.len() + 1) + 7) & !7usize;
                if written + reclen > buf_size { break; }

                let base = buf_ptr + written as u64;
                mem.write_u64(base,      *d_ino)?;
                mem.write_u64(base + 8,  new_pos as u64 + 1)?;
                mem.write_u16(base + 16, reclen as u16)?;
                mem.write_u8 (base + 18, *d_type)?;
                mem.write_bytes_at(base + 19, name_bytes)?;
                mem.write_u8(base + 19 + name_bytes.len() as u64, 0)?;

                written  += reclen;
                new_pos  += 1;
            }

            ctx.fds.get_mut(fd).unwrap().offset = new_pos as u64;
            written as i64
        }

        // ── dup3(old, new, flags) ─────────────────────────────────────────
        SYS_DUP3 => {
            let old = a0;
            let new = a1;
            if let Some(ofd) = ctx.fds.get(old) {
                let ino   = ofd.ino;
                let flags = ofd.flags;
                ctx.fds.fds.insert(new, OpenFd { ino, flags, offset: 0 });
                new as i64
            } else { -EBADF }
        }

        // ── ftruncate(fd, length) ─────────────────────────────────────────
        SYS_FTRUNCATE => {
            let fd  = a0;
            let len = a1 as usize;
            let ofd = match ctx.fds.get(fd) { Some(f) => f, None => return Ok(-EBADF) };
            let ino = ofd.ino;
            let node = ctx.vfs.mem.node_mut(ino);
            node.content.resize(len, 0);
            node.stat.size = len as i64;
            0
        }

        // ── unlink / unlinkat ─────────────────────────────────────────────
        SYS_UNLINK | SYS_UNLINKAT => {
            // Stub: pretend success for now.
            0
        }

        // ── rename / renameat ─────────────────────────────────────────────
        SYS_RENAME | SYS_RENAMEAT => {
            // Stub: pretend success.
            0
        }

        // ── rmdir ─────────────────────────────────────────────────────────
        SYS_RMDIR => 0,

        // ── symlink ───────────────────────────────────────────────────────
        SYS_SYMLINK => {
            let target = mem.read_cstr(a0)?;
            let path   = mem.read_cstr(a1)?;
            let abs    = resolve_path(&ctx.cwd, &path);
            ctx.vfs.mem.symlink(&abs, &target).map_or(0, |_| 0)
        }

        // ── chmod / fchmod / chown / fchown (stubs) ───────────────────────
        SYS_CHMOD | SYS_FCHMOD | SYS_CHOWN | SYS_FCHOWN | SYS_LCHOWN
        | SYS_FCHMODAT => 0,

        // ── setuid / setgid / setsid / setpgid ───────────────────────────
        SYS_SETUID => { ctx.uid = a0 as u32; 0 }
        SYS_SETGID => { ctx.gid = a0 as u32; 0 }
        SYS_SETSID | SYS_SETPGID | SYS_SETGROUPS => 0,
        SYS_GETGROUPS => {
            // Return 0 supplementary groups.
            if a0 > 0 { mem.write_u32(a1, 0).ok(); }
            0
        }

        // ── kill(pid, signum) ─────────────────────────────────────────────
        SYS_KILL => {
            let signum = a1 as i32;
            if signum == 0 { return Ok(0); }          // existence check only
            if signum < 1 || signum > 64 { return Ok(-EINVAL); }
            ctx.signals.pending |= 1u64 << (signum - 1);
            0
        }

        // ── tkill(tid, signum) ────────────────────────────────────────────
        SYS_TKILL => {
            let signum = a1 as i32;
            if signum == 0 { return Ok(0); }
            if signum < 1 || signum > 64 { return Ok(-EINVAL); }
            ctx.signals.pending |= 1u64 << (signum - 1);
            0
        }

        // ── tgkill(tgid, tid, signum) ─────────────────────────────────────
        SYS_TGKILL => {
            let signum = a2 as i32;
            if signum == 0 { return Ok(0); }
            if signum < 1 || signum > 64 { return Ok(-EINVAL); }
            ctx.signals.pending |= 1u64 << (signum - 1);
            0
        }

        // ── wait4 (stub — no child processes) ────────────────────────────
        SYS_WAIT4 => -ECHILD,

        // ── clone(flags, child_stack, ptidptr, ctidptr, tls) ─────────────
        // x86-64 ABI:
        //   a0 = flags, a1 = child_stack, a2 = parent_tidptr,
        //   a3 = child_tidptr, a4 = tls
        SYS_CLONE => {
            let flags         = a0;
            let child_stack   = a1;
            let parent_tidptr = a2;
            let child_tidptr  = a3;
            let tls           = a4;

            // Clone flag bits (prefixed with _ to suppress dead_code warnings
            // for flags that are recorded in CloneInfo but not acted on here).
            const CLONE_VM:              u64 = 0x0000_0100;
            const _CLONE_THREAD:         u64 = 0x0001_0000;
            const _CLONE_SETTLS:         u64 = 0x0008_0000;
            const CLONE_PARENT_SETTID:   u64 = 0x0010_0000;
            const _CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
            const _CLONE_CHILD_SETTID:   u64 = 0x0100_0000;

            if flags & CLONE_VM == 0 {
                // fork() or vfork() — we don't support process-level forking.
                return Ok(-ENOSYS);
            }

            // Allocate a new TID for the child thread.
            let new_tid = ctx.threads.alloc_tid();

            // CLONE_PARENT_SETTID: write new_tid into parent's memory at
            // parent_tidptr.
            if flags & CLONE_PARENT_SETTID != 0 && parent_tidptr != 0 {
                mem.write_u32(parent_tidptr, new_tid)
                    .map_err(|_| SyscallError::Fault(parent_tidptr))?;
            }

            // Build a CloneInfo for the JS harness to act on, so it can spawn
            // a Web Worker for this thread.
            let info = CloneInfo {
                flags,
                child_stack,
                parent_tidptr,
                child_tidptr,
                tls,
                new_tid,
                rip: 0, // patched by canary-wasm's dispatch_syscall
            };
            ctx.pending_clone.push(info);

            // Return the new TID in the *parent* (the child will get 0 when
            // its Worker is initialised by the JS harness).
            new_tid as i64
        }

        // ── fork (not supported — use clone instead) ──────────────────────
        SYS_FORK => -ENOSYS,

        // ── execve(pathname, argv, envp) ──────────────────────────────────
        SYS_EXECVE => {
            let path = mem.read_cstr(a0)?;
            // Read argv: array of u64 pointers, null-terminated.
            let mut argv: Vec<String> = Vec::new();
            let mut ptr = a1;
            loop {
                let p = mem.read_u64(ptr)?;
                if p == 0 { break; }
                argv.push(mem.read_cstr(p)?);
                ptr += 8;
            }
            // Read envp similarly.
            let mut envp: Vec<String> = Vec::new();
            let mut ptr = a2;
            loop {
                let p = mem.read_u64(ptr)?;
                if p == 0 { break; }
                envp.push(mem.read_cstr(p)?);
                ptr += 8;
            }
            return Err(SyscallError::ExecveRequest { path, argv, envp });
        }

        // ── prctl (stub) ──────────────────────────────────────────────────
        SYS_PRCTL => 0,

        // ── sigaltstack(ss, old_ss) ───────────────────────────────────────
        // struct stack_t: ss_sp (u64), ss_flags (i32 padded to u64), ss_size (u64)
        SYS_SIGALTSTACK => {
            let new_ss = a0;
            let old_ss = a1;
            // Write old stack to *old_ss if requested.
            if old_ss != 0 {
                match ctx.signals.altstack {
                    Some((sp, sz)) => {
                        mem.write_u64(old_ss,      sp)?;
                        mem.write_u64(old_ss + 8,  0)?;  // SS_ONSTACK/SS_DISABLE flags
                        mem.write_u64(old_ss + 16, sz as u64)?;
                    }
                    None => {
                        mem.write_u64(old_ss,      0)?;
                        mem.write_u64(old_ss + 8,  2)?;  // SS_DISABLE = 2
                        mem.write_u64(old_ss + 16, 0)?;
                    }
                }
            }
            // Install new stack if requested.
            if new_ss != 0 {
                let ss_sp    = mem.read_u64(new_ss)?;
                let ss_flags = mem.read_u64(new_ss + 8)?;
                let ss_size  = mem.read_u64(new_ss + 16)? as usize;
                if ss_flags & 2 != 0 {
                    // SS_DISABLE
                    ctx.signals.altstack = None;
                } else {
                    ctx.signals.altstack = Some((ss_sp, ss_size));
                }
            }
            0
        }

        // ── prlimit64(pid, resource, new, old) ───────────────────────────
        SYS_PRLIMIT64 => {
            if a3 != 0 {
                // Write generous limits into *old.
                mem.write_u64(a3,     u64::MAX)?;
                mem.write_u64(a3 + 8, u64::MAX)?;
            }
            0
        }

        // ── poll / select / pselect / ppoll (stubs) ──────────────────────
        SYS_POLL | SYS_SELECT | SYS_PSELECT6 | SYS_PPOLL => 0,

        // ── socket syscalls — handled above via canary_net early-return ──
        // These arms are unreachable because is_socket_syscall() returns true
        // for all of them and we return early above.  They are kept here only
        // to prevent "unreachable pattern" warnings from the wildcard arm.
        SYS_SOCKET | SYS_CONNECT | SYS_BIND | SYS_LISTEN
        | SYS_ACCEPT | SYS_ACCEPT4
        | SYS_SENDTO | SYS_RECVFROM | SYS_SENDMSG | SYS_RECVMSG
        | SYS_SETSOCKOPT | SYS_GETSOCKOPT | SYS_GETSOCKNAME | SYS_GETPEERNAME
        | SYS_SOCKETPAIR | SYS_SENDMMSG | SYS_RECVMMSG => -ENOSYS,

        // ── epoll stubs ───────────────────────────────────────────────────
        SYS_EPOLL_CREATE | SYS_EPOLL_CREATE1 => {
            // Return a fake epoll fd.
            ctx.vfs.mem.write_file("/epoll", vec![]).ok();
            let ino = ctx.vfs.mem.lookup("/epoll").unwrap_or(0);
            ctx.fds.alloc(ino, 0) as i64
        }
        SYS_EPOLL_CTL | SYS_EPOLL_WAIT => 0,

        // ── eventfd2 / timerfd / inotify stubs ───────────────────────────
        SYS_EVENTFD2 | SYS_TIMERFD_CREATE | SYS_TIMERFD_SETTIME
        | SYS_TIMERFD_GETTIME | SYS_INOTIFY_INIT1 => {
            ctx.vfs.mem.write_file("/fd_stub", vec![]).ok();
            let ino = ctx.vfs.mem.lookup("/fd_stub").unwrap_or(0);
            ctx.fds.alloc(ino, 0) as i64
        }

        // ── utimensat / utime (stub) ──────────────────────────────────────
        SYS_UTIMENSAT => 0,

        // ── statx(dirfd, path, flags, mask, statxbuf) ────────────────────
        SYS_STATX => {
            // Layout of struct statx (x86-64, kernel 4.11+):
            //  +0   stx_mask       u32    +4  stx_blksize  u32
            //  +8   stx_attributes u64
            //  +16  stx_nlink      u32    +20 stx_uid      u32
            //  +24  stx_gid        u32    +28 stx_mode     u16  +30 __spare0 u16
            //  +32  stx_ino        u64    +40 stx_size     u64
            //  +48  stx_blocks     u64    +56 stx_attributes_mask u64
            //  +64  stx_atime (statx_timestamp: i64 sec + u32 nsec + i32 pad = 16 B)
            //  +80  stx_btime      +96  stx_ctime     +112 stx_mtime
            //  +128 stx_rdev_major u32  +132 stx_rdev_minor u32
            //  +136 stx_dev_major  u32  +140 stx_dev_minor  u32
            const AT_EMPTY_PATH: u64 = 0x1000;
            let statxbuf = a4;
            let ino_res: Result<usize, _> = if a2 & AT_EMPTY_PATH != 0 && a0 as i64 != AT_FDCWD {
                // fstat by dirfd
                match ctx.fds.get(a0) {
                    Some(f) => Ok(f.ino),
                    None    => Err(()),
                }
            } else {
                let path = mem.read_cstr(a1)?;
                let abs  = resolve_path(&ctx.cwd, &path);
                ctx.vfs.mem.lookup(&abs).map_err(|_| ())
            };
            match ino_res {
                Ok(ino) => {
                    let s = ctx.vfs.mem.node(ino).stat.clone();
                    mem.write_u32(statxbuf,       0x07ff)?; // stx_mask: all basic fields
                    mem.write_u32(statxbuf +   4, 4096)?;   // stx_blksize
                    mem.write_u64(statxbuf +   8, 0)?;      // stx_attributes
                    mem.write_u32(statxbuf +  16, s.nlink as u32)?;
                    mem.write_u32(statxbuf +  20, s.uid)?;
                    mem.write_u32(statxbuf +  24, s.gid)?;
                    mem.write_u16(statxbuf +  28, s.mode as u16)?;
                    mem.write_u64(statxbuf +  32, s.ino)?;
                    mem.write_u64(statxbuf +  40, s.size as u64)?;
                    mem.write_u64(statxbuf +  48, s.blocks as u64)?;
                    mem.write_u64(statxbuf +  56, 0)?;      // stx_attributes_mask
                    // timestamps: atime=+64, btime=+80, ctime=+96, mtime=+112
                    for off in [64u64, 80, 96, 112] {
                        mem.write_u64(statxbuf + off,      s.mtime as u64)?;
                        mem.write_u32(statxbuf + off +  8, 0)?;
                        mem.write_u32(statxbuf + off + 12, 0)?;
                    }
                    mem.write_u32(statxbuf + 128, (s.rdev >> 8) as u32)?;
                    mem.write_u32(statxbuf + 132, (s.rdev & 0xff) as u32)?;
                    mem.write_u32(statxbuf + 136, (s.dev >> 8) as u32)?;
                    mem.write_u32(statxbuf + 140, (s.dev & 0xff) as u32)?;
                    0
                }
                Err(_) => -ENOENT,
            }
        }

        // ── truncate ──────────────────────────────────────────────────────
        SYS_TRUNCATE => {
            let path = mem.read_cstr(a0)?;
            let abs  = resolve_path(&ctx.cwd, &path);
            let len  = a1 as usize;
            if let Ok(ino) = ctx.vfs.mem.lookup(&abs) {
                let node = ctx.vfs.mem.node_mut(ino);
                node.content.resize(len, 0);
                node.stat.size = len as i64;
                0
            } else { -ENOENT }
        }

        // ── set_tid_address(tidptr) ───────────────────────────────────────
        SYS_SET_TID_ADDRESS => ctx.current_tid as i64,

        // ── mlock / munlock / mlockall / munlockall (no-ops) ─────────────
        SYS_MLOCK | SYS_MUNLOCK | SYS_MLOCKALL | SYS_MUNLOCKALL => 0,

        // ── personality (return PER_LINUX = 0) ───────────────────────────
        SYS_PERSONALITY => 0,

        // ── scheduler stubs ───────────────────────────────────────────────
        SYS_SCHED_SETSCHEDULER | SYS_SCHED_GETSCHEDULER
        | SYS_SCHED_SETPARAM   | SYS_SCHED_GETPARAM
        | SYS_SCHED_SETAFFINITY => 0,

        // ── getrusage(who, buf) ───────────────────────────────────────────
        SYS_GETRUSAGE => {
            // struct rusage is 18 × u64 on x86-64; zero-fill.
            for i in 0..18u64 {
                mem.write_u64(a1 + i * 8, 0).ok();
            }
            0
        }

        // ── renameat2 (flags-extended rename; stub as success) ────────────
        SYS_RENAMEAT2 => 0,

        // ── unimplemented ─────────────────────────────────────────────────
        _ => {
            log::warn!("unimplemented syscall {nr}");
            -ENOSYS
        }
    };

    Ok(ret)
}

// ── Path helpers ──────────────────────────────────────────────────────────────

fn resolve_path(cwd: &str, path: &str) -> String {
    if path.starts_with('/') {
        normalize_path(path)
    } else {
        normalize_path(&format!("{cwd}/{path}"))
    }
}

fn normalize_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => { parts.pop(); }
            s    => { parts.push(s); }
        }
    }
    if parts.is_empty() { "/".to_string() } else { format!("/{}", parts.join("/")) }
}

// ── stat serialisation ────────────────────────────────────────────────────────

fn write_stat(mem: &mut GuestMemory, ptr: u64, s: canary_fs::FileStat) -> canary_memory::MemResult<()> {
    // struct stat on x86-64 Linux (144 bytes):
    mem.write_u64(ptr,       s.dev)?;     // st_dev
    mem.write_u64(ptr + 8,   s.ino)?;     // st_ino
    mem.write_u32(ptr + 16,  s.mode)?;    // st_mode
    mem.write_u32(ptr + 20,  s.nlink as u32)?;
    mem.write_u32(ptr + 24,  s.uid)?;
    mem.write_u32(ptr + 28,  s.gid)?;
    mem.write_u64(ptr + 32,  s.rdev)?;
    mem.write_u64(ptr + 40,  s.size as u64)?;
    mem.write_u64(ptr + 48,  s.blksize as u64)?;
    mem.write_u64(ptr + 56,  s.blocks as u64)?;
    mem.write_u64(ptr + 64,  s.atime as u64)?;  // atime sec
    mem.write_u64(ptr + 72,  0)?;                // atime nsec
    mem.write_u64(ptr + 80,  s.mtime as u64)?;
    mem.write_u64(ptr + 88,  0)?;
    mem.write_u64(ptr + 96,  s.ctime as u64)?;
    mem.write_u64(ptr + 104, 0)?;
    Ok(())
}

// ── utsname ───────────────────────────────────────────────────────────────────

fn write_utsname(mem: &mut GuestMemory, ptr: u64) -> canary_memory::MemResult<()> {
    fn copy_str(mem: &mut GuestMemory, base: u64, s: &str) -> canary_memory::MemResult<()> {
        let b = s.as_bytes();
        let n = b.len().min(64);
        mem.write_bytes_at(base, &b[..n])?;
        mem.write_u8(base + n as u64, 0)
    }
    copy_str(mem, ptr,          "Linux")?;
    copy_str(mem, ptr + 65,     "canary")?;
    copy_str(mem, ptr + 130,    "5.15.0-canary")?;
    copy_str(mem, ptr + 195,    "#1 SMP")?;
    copy_str(mem, ptr + 260,    "x86_64")?;
    Ok(())
}

// ── Flag conversion ───────────────────────────────────────────────────────────

fn linux_prot_to_canary(p: u64) -> Prot {
    let mut out = Prot::NONE;
    if p & PROT_READ  != 0 { out |= Prot::READ;  }
    if p & PROT_WRITE != 0 { out |= Prot::WRITE; }
    if p & PROT_EXEC  != 0 { out |= Prot::EXEC;  }
    out
}

fn linux_map_flags_to_canary(f: u64) -> MapFlags {
    let mut out = MapFlags::PRIVATE;
    if f & MAP_SHARED    != 0 { out |= MapFlags::SHARED;    }
    if f & MAP_FIXED     != 0 { out |= MapFlags::FIXED;     }
    if f & MAP_ANON      != 0 { out |= MapFlags::ANONYMOUS; }
    if f & MAP_GROWSDOWN != 0 { out |= MapFlags::GROWSDOWN; }
    out
}
