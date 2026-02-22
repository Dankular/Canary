//! x86-64 Linux syscall numbers (from arch/x86/entry/syscalls/syscall_64.tbl).

pub const SYS_READ:            u64 = 0;
pub const SYS_WRITE:           u64 = 1;
pub const SYS_OPEN:            u64 = 2;
pub const SYS_CLOSE:           u64 = 3;
pub const SYS_STAT:            u64 = 4;
pub const SYS_FSTAT:           u64 = 5;
pub const SYS_LSTAT:           u64 = 6;
pub const SYS_POLL:            u64 = 7;
pub const SYS_LSEEK:           u64 = 8;
pub const SYS_MMAP:            u64 = 9;
pub const SYS_MPROTECT:        u64 = 10;
pub const SYS_MUNMAP:          u64 = 11;
pub const SYS_BRK:             u64 = 12;
pub const SYS_RT_SIGACTION:    u64 = 13;
pub const SYS_RT_SIGPROCMASK:  u64 = 14;
pub const SYS_IOCTL:           u64 = 16;
pub const SYS_PREAD64:         u64 = 17;
pub const SYS_PWRITE64:        u64 = 18;
pub const SYS_READV:           u64 = 19;
pub const SYS_WRITEV:          u64 = 20;
pub const SYS_ACCESS:          u64 = 21;
pub const SYS_PIPE:            u64 = 22;
pub const SYS_SELECT:          u64 = 23;
pub const SYS_SCHED_YIELD:     u64 = 24;
pub const SYS_MREMAP:          u64 = 25;
pub const SYS_MADVISE:         u64 = 28;
pub const SYS_DUP:             u64 = 32;
pub const SYS_DUP2:            u64 = 33;
pub const SYS_NANOSLEEP:       u64 = 35;
pub const SYS_GETPID:          u64 = 39;
pub const SYS_SOCKET:          u64 = 41;
pub const SYS_CONNECT:         u64 = 42;
pub const SYS_SENDTO:          u64 = 44;
pub const SYS_RECVFROM:        u64 = 45;
pub const SYS_CLONE:           u64 = 56;
pub const SYS_FORK:            u64 = 57;
pub const SYS_EXECVE:          u64 = 59;
pub const SYS_EXIT:            u64 = 60;
pub const SYS_WAIT4:           u64 = 61;
pub const SYS_KILL:            u64 = 62;
pub const SYS_UNAME:           u64 = 63;
pub const SYS_FCNTL:           u64 = 72;
pub const SYS_FTRUNCATE:       u64 = 77;
pub const SYS_GETDENTS:        u64 = 78;
pub const SYS_GETCWD:          u64 = 79;
pub const SYS_CHDIR:           u64 = 80;
pub const SYS_RENAME:          u64 = 82;
pub const SYS_MKDIR:           u64 = 83;
pub const SYS_RMDIR:           u64 = 84;
pub const SYS_CREAT:           u64 = 85;
pub const SYS_UNLINK:          u64 = 87;
pub const SYS_READLINK:        u64 = 89;
pub const SYS_GETTIMEOFDAY:    u64 = 96;
pub const SYS_GETRLIMIT:       u64 = 97;
pub const SYS_SYSINFO:         u64 = 99;
pub const SYS_GETUID:          u64 = 102;
pub const SYS_GETGID:          u64 = 104;
pub const SYS_SETUID:          u64 = 105;
pub const SYS_SETGID:          u64 = 106;
pub const SYS_GETEUID:         u64 = 107;
pub const SYS_GETEGID:         u64 = 108;
pub const SYS_SETGROUPS:       u64 = 116;
pub const SYS_GETGROUPS:       u64 = 115;
pub const SYS_SETPGID:         u64 = 109;
pub const SYS_GETPPID:         u64 = 110;
pub const SYS_SETSID:          u64 = 112;
pub const SYS_SETRLIMIT:       u64 = 160;
pub const SYS_ARCH_PRCTL:      u64 = 158;
pub const SYS_GETTID:          u64 = 186;
pub const SYS_FUTEX:           u64 = 202;
pub const SYS_SCHED_GETAFFINITY: u64 = 204;
pub const SYS_CLOCK_GETTIME:   u64 = 228;
pub const SYS_EXIT_GROUP:      u64 = 231;
pub const SYS_OPENAT:          u64 = 257;
pub const SYS_MKDIRAT:         u64 = 258;
pub const SYS_FSTATAT:         u64 = 262;
pub const SYS_UNLINKAT:        u64 = 263;
pub const SYS_RENAMEAT:        u64 = 264;
pub const SYS_FACCESSAT:       u64 = 269;
pub const SYS_PSELECT6:        u64 = 270;
pub const SYS_PPOLL:           u64 = 271;
pub const SYS_READLINKAT:      u64 = 267;
pub const SYS_FCHMODAT:        u64 = 268;
pub const SYS_SET_ROBUST_LIST: u64 = 273;
pub const SYS_GET_ROBUST_LIST: u64 = 274;
pub const SYS_UTIMENSAT:       u64 = 280;
pub const SYS_EPOLL_CREATE1:   u64 = 291;
pub const SYS_PIPE2:           u64 = 293;
pub const SYS_GETRANDOM:       u64 = 318;
pub const SYS_MEMFD_CREATE:    u64 = 319;
pub const SYS_STATX:           u64 = 332;
pub const SYS_RSEQ:            u64 = 334;

// Additional syscalls not in the original list
pub const SYS_ACCEPT:          u64 = 43;
pub const SYS_SENDMSG:         u64 = 46;
pub const SYS_RECVMSG:         u64 = 47;
pub const SYS_BIND:            u64 = 49;
pub const SYS_LISTEN:          u64 = 50;
pub const SYS_GETSOCKNAME:     u64 = 51;
pub const SYS_GETPEERNAME:     u64 = 52;
pub const SYS_SOCKETPAIR:      u64 = 53;
pub const SYS_SETSOCKOPT:      u64 = 54;
pub const SYS_GETSOCKOPT:      u64 = 55;
pub const SYS_TRUNCATE:        u64 = 76;
pub const SYS_SYMLINK:         u64 = 88;
pub const SYS_CHMOD:           u64 = 90;
pub const SYS_FCHMOD:          u64 = 91;
pub const SYS_CHOWN:           u64 = 92;
pub const SYS_FCHOWN:          u64 = 93;
pub const SYS_LCHOWN:          u64 = 94;
pub const SYS_SIGALTSTACK:     u64 = 131;
pub const SYS_PRCTL:           u64 = 157;
pub const SYS_EPOLL_CREATE:    u64 = 213;
pub const SYS_GETDENTS64:      u64 = 217;
pub const SYS_EPOLL_WAIT:      u64 = 232;
pub const SYS_EPOLL_CTL:       u64 = 233;
pub const SYS_ACCEPT4:         u64 = 288;
pub const SYS_EVENTFD2:        u64 = 290;
pub const SYS_DUP3:            u64 = 292;
pub const SYS_INOTIFY_INIT1:   u64 = 294;
pub const SYS_RECVMMSG:        u64 = 299;
pub const SYS_PRLIMIT64:       u64 = 302;
pub const SYS_SENDMMSG:        u64 = 307;
pub const SYS_RENAMEAT2:       u64 = 316;
pub const SYS_TIMERFD_CREATE:  u64 = 283;
pub const SYS_TIMERFD_SETTIME: u64 = 286;
pub const SYS_TIMERFD_GETTIME: u64 = 287;

// Signal-related syscalls
pub const SYS_RT_SIGRETURN:    u64 = 15;
pub const SYS_TKILL:           u64 = 200;
pub const SYS_TGKILL:          u64 = 234;

// arch_prctl codes
pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;
pub const ARCH_SET_GS: u64 = 0x1001;
pub const ARCH_GET_GS: u64 = 0x1004;

// mmap prot flags
pub const PROT_NONE:  u64 = 0;
pub const PROT_READ:  u64 = 1;
pub const PROT_WRITE: u64 = 2;
pub const PROT_EXEC:  u64 = 4;

// mmap flags
pub const MAP_SHARED:    u64 = 0x01;
pub const MAP_PRIVATE:   u64 = 0x02;
pub const MAP_FIXED:     u64 = 0x10;
pub const MAP_ANON:      u64 = 0x20;
pub const MAP_ANONYMOUS: u64 = 0x20;
pub const MAP_GROWSDOWN: u64 = 0x100;
pub const MAP_STACK:     u64 = 0x20000;
pub const MAP_FAILED:    u64 = u64::MAX; // (void*)-1

// O_* flags (x86-64 Linux)
pub const O_RDONLY:   u64 = 0;
pub const O_WRONLY:   u64 = 1;
pub const O_RDWR:     u64 = 2;
pub const O_CREAT:    u64 = 0o100;
pub const O_EXCL:     u64 = 0o200;
pub const O_TRUNC:    u64 = 0o1000;
pub const O_APPEND:   u64 = 0o2000;
pub const O_NONBLOCK: u64 = 0o4000;
pub const O_CLOEXEC:  u64 = 0o2000000;
pub const O_DIRECTORY:u64 = 0o200000;
pub const O_PATH:     u64 = 0o10000000;
pub const AT_FDCWD:   i64 = -100;

// IOCTL codes
pub const TIOCGWINSZ: u64 = 0x5413;
pub const TCGETS:     u64 = 0x5401;
pub const TCSETS:     u64 = 0x5402;

// FUTEX operations
pub const FUTEX_WAIT:          u64 = 0;
pub const FUTEX_WAKE:          u64 = 1;
pub const FUTEX_PRIVATE_FLAG:  u64 = 128;
pub const FUTEX_WAIT_PRIVATE:  u64 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
pub const FUTEX_WAKE_PRIVATE:  u64 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;

// SEEK
pub const SEEK_SET: u64 = 0;
pub const SEEK_CUR: u64 = 1;
pub const SEEK_END: u64 = 2;
