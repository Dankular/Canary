//! Linux x86-64 syscall emulation layer.
//!
//! On a real x86-64 Linux system, the SYSCALL instruction transfers to the
//! kernel with:
//!   RAX = syscall number
//!   RDI, RSI, RDX, R10, R8, R9 = up to 6 arguments
//!   Return value in RAX (negative errno on error)
//!
//! We intercept the SYSCALL exit from the interpreter and dispatch here.

pub mod numbers;
pub mod dispatch;

pub use dispatch::handle_syscall;

use thiserror::Error;

/// Information about a pending `clone` syscall that the JS runtime must act on
/// by spawning a new Web Worker.
#[derive(Debug, Clone)]
pub struct CloneInfo {
    /// The flags passed to clone(2).
    pub flags: u64,
    /// The child stack pointer (RSP for the new thread).
    pub child_stack: u64,
    /// Pointer in parent's address space for CLONE_PARENT_SETTID.
    pub parent_tidptr: u64,
    /// Pointer in child's address space for CLONE_CHILD_SETTID /
    /// CLONE_CHILD_CLEARTID.
    pub child_tidptr: u64,
    /// TLS pointer passed via CLONE_SETTLS (new fs_base for the child).
    pub tls: u64,
    /// The TID that was allocated for the new thread.
    pub new_tid: u32,
}

#[derive(Debug, Error)]
pub enum SyscallError {
    #[error("memory error: {0}")]
    Mem(#[from] canary_memory::MemError),
    #[error("fs error: {0}")]
    Fs(#[from] canary_fs::FsError),
    #[error("process exited with code {0}")]
    Exit(i32),
    #[error("unimplemented syscall {0}")]
    Unimplemented(u64),
    #[error("execve: {path}")]
    ExecveRequest {
        path: String,
        argv: Vec<String>,
        envp: Vec<String>,
    },
    /// Emitted by the clone handler so `canary-wasm` can spawn a Worker.
    #[error("clone request: new tid {new_tid}")]
    CloneRequest {
        flags:         u64,
        child_stack:   u64,
        parent_tidptr: u64,
        child_tidptr:  u64,
        tls:           u64,
        new_tid:       u32,
    },
    /// Bad guest address in a syscall argument.
    #[error("fault at address {0:#x}")]
    Fault(u64),
}

/// Linux errno values (negated into RAX on error).
pub mod errno {
    pub const EPERM:  i64 = 1;
    pub const ENOENT: i64 = 2;
    pub const ESRCH:  i64 = 3;
    pub const EINTR:  i64 = 4;
    pub const EIO:    i64 = 5;
    pub const ENXIO:  i64 = 6;
    pub const E2BIG:  i64 = 7;
    pub const EBADF:  i64 = 9;
    pub const ECHILD: i64 = 10;
    pub const EAGAIN: i64 = 11;
    pub const ENOMEM: i64 = 12;
    pub const EACCES: i64 = 13;
    pub const EFAULT: i64 = 14;
    pub const EBUSY:  i64 = 16;
    pub const EEXIST: i64 = 17;
    pub const ENODEV: i64 = 19;
    pub const ENOTDIR:i64 = 20;
    pub const EISDIR: i64 = 21;
    pub const EINVAL: i64 = 22;
    pub const ENFILE: i64 = 23;
    pub const EMFILE: i64 = 24;
    pub const ENOSYS: i64 = 38;
    pub const ENOTEMPTY: i64 = 39;
    pub const ELOOP:  i64 = 40;
    pub const EOVERFLOW: i64 = 75;
    pub const ENOSPC: i64 = 28;
    pub const ETIMEDOUT: i64 = 110;
}
