//! Syscall dispatcher — called by the interpreter when SYSCALL is executed.

use canary_memory::{GuestMemory, Prot, MapFlags};
use canary_fs::Vfs;
use crate::{numbers::*, errno::*, SyscallError};

use std::collections::HashMap;

// ── File descriptor table ─────────────────────────────────────────────────────

pub struct FdTable {
    /// fd → (inode, offset, flags)
    fds: HashMap<u64, OpenFd>,
    next_fd: u64,
}

struct OpenFd {
    ino:    usize,
    offset: u64,
    flags:  u64,
}

impl FdTable {
    pub fn new() -> Self {
        let mut t = FdTable { fds: HashMap::new(), next_fd: 3 };
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
    fn get(&self, fd: u64) -> Option<&OpenFd> { self.fds.get(&fd) }
    fn get_mut(&mut self, fd: u64) -> Option<&mut OpenFd> { self.fds.get_mut(&fd) }
    fn close(&mut self, fd: u64) -> bool { self.fds.remove(&fd).is_some() }
}

// ── Syscall context ────────────────────────────────────────────────────────────

pub struct SyscallCtx {
    pub fds:  FdTable,
    pub vfs:  Vfs,
    pub cwd:  String,
    /// stdout/stderr capture buffer (for the JS layer to read).
    pub stdout_buf: Vec<u8>,
    pub stderr_buf: Vec<u8>,
    /// stdin provider — a closure that provides bytes.
    pub pid:  u32,
    pub uid:  u32,
    pub gid:  u32,
}

impl SyscallCtx {
    pub fn new() -> Self {
        SyscallCtx {
            fds:  FdTable::new(),
            vfs:  Vfs::new(),
            cwd:  "/".to_string(),
            stdout_buf: Vec::new(),
            stderr_buf: Vec::new(),
            pid:  1,
            uid:  1000,
            gid:  1000,
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

    let ret: i64 = match nr {

        // ── read(fd, buf, count) ──────────────────────────────────────────
        SYS_READ => {
            let fd    = a0;
            let buf   = a1;
            let count = a2 as usize;
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
        SYS_STAT | SYS_LSTAT => {
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
        SYS_GETTID  => ctx.pid as i64,

        // ── getuid / geteuid / getgid / getegid ───────────────────────────
        SYS_GETUID  | SYS_GETEUID => ctx.uid as i64,
        SYS_GETGID  | SYS_GETEGID => ctx.gid as i64,

        // ── rt_sigaction (stub — we don't deliver signals) ────────────────
        SYS_RT_SIGACTION | SYS_RT_SIGPROCMASK | SYS_SET_ROBUST_LIST
        | SYS_GET_ROBUST_LIST => 0,

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
            match ctx.vfs.mem.lookup(&abs) {
                Ok(ino) => {
                    if let Some(target) = &ctx.vfs.mem.node(ino).link_target {
                        let bytes = target.as_bytes();
                        let n = bytes.len().min(buf_sz);
                        mem.write_bytes_at(buf_ptr, &bytes[..n])?;
                        n as i64
                    } else { -EINVAL }
                }
                Err(_) => -ENOENT,
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

        // ── ioctl (terminal size, tty) ─────────────────────────────────────
        SYS_IOCTL => {
            match a1 {
                TIOCGWINSZ => {
                    // struct winsize: ws_row, ws_col, ws_xpixel, ws_ypixel (u16 each)
                    mem.write_u16(a2,      24)?;  // rows
                    mem.write_u16(a2 + 2,  80)?;  // cols
                    mem.write_u16(a2 + 4,   0)?;
                    mem.write_u16(a2 + 6,   0)?;
                    0
                }
                TCGETS | TCSETS => 0,
                _ => -EINVAL,
            }
        }

        // ── futex (WAIT/WAKE) ─────────────────────────────────────────────
        SYS_FUTEX => {
            let op = a1 & 0x7F;
            match op {
                FUTEX_WAIT | FUTEX_WAIT_PRIVATE => {
                    // Check if value matches; if so "wait" (just return).
                    let val = mem.read_u32(a0)? as u64;
                    if val == a2 { 0 } else { -EAGAIN }
                }
                FUTEX_WAKE | FUTEX_WAKE_PRIVATE => {
                    0 // 0 waiters woken (single-threaded)
                }
                _ => -ENOSYS,
            }
        }

        // ── sched_yield ──────────────────────────────────────────────────
        SYS_SCHED_YIELD => 0,

        // ── madvise ───────────────────────────────────────────────────────
        SYS_MADVISE => 0,

        // ── mremap ───────────────────────────────────────────────────────
        SYS_MREMAP => {
            // Simplified: allocate new region, copy, unmap old.
            let old_addr = a0;
            let old_size = a1;
            let new_size = a2;
            let _flags   = a3;
            match mem.mmap(0, new_size, Prot::READ | Prot::WRITE, MapFlags::PRIVATE | MapFlags::ANONYMOUS) {
                Ok(new_addr) => {
                    let copy_size = old_size.min(new_size) as usize;
                    if let Ok(src) = mem.read_bytes(old_addr, copy_size) {
                        let src = src.to_vec();
                        mem.write_bytes_at(new_addr, &src).ok();
                    }
                    mem.munmap(old_addr, old_size).ok();
                    new_addr as i64
                }
                Err(_) => -ENOMEM,
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
            let fd    = a0;
            let iov   = a1;
            let iovcnt = a2 as usize;
            let mut total = 0i64;
            for i in 0..iovcnt {
                let iov_base = mem.read_u64(iov + i as u64 * 16)?;
                let iov_len  = mem.read_u64(iov + i as u64 * 16 + 8)? as usize;
                let data = mem.read_bytes(iov_base, iov_len)?.to_vec();
                match fd {
                    1 => ctx.stdout_buf.extend_from_slice(&data),
                    2 => ctx.stderr_buf.extend_from_slice(&data),
                    _ => {}
                }
                total += iov_len as i64;
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

        // ── kill (stub) ───────────────────────────────────────────────────
        SYS_KILL => 0,

        // ── wait4 (stub — no child processes) ────────────────────────────
        SYS_WAIT4 => -ECHILD,

        // ── clone / fork (stubs) ─────────────────────────────────────────
        SYS_CLONE | SYS_FORK => {
            // Return ENOSYS; a single-threaded emulator can't fork.
            -ENOSYS
        }

        // ── execve (stub) ─────────────────────────────────────────────────
        SYS_EXECVE => -ENOSYS,

        // ── prctl (stub) ──────────────────────────────────────────────────
        SYS_PRCTL => 0,

        // ── sigaltstack (stub) ────────────────────────────────────────────
        SYS_SIGALTSTACK => 0,

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

        // ── socket / connect / send / recv stubs ─────────────────────────
        SYS_SOCKET => -ENOSYS,
        SYS_CONNECT | SYS_BIND | SYS_LISTEN | SYS_ACCEPT | SYS_ACCEPT4
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

        // ── statx (forward to stat) ───────────────────────────────────────
        SYS_STATX => {
            // a1 = path, a4 = buf (statx_buf), simplified: return ENOSYS
            -ENOSYS
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
