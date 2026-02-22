//! Virtual networking layer for Canary — socket table and related data structures.
//!
//! Sockets are backed by JS-side WebSocket connections.  The Rust code manages
//! a virtual socket table and queues connect/send events; the JS harness drains
//! those queues and drives the actual network I/O.

pub mod syscalls;

use std::collections::{HashMap, VecDeque};

// ── Domain ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Domain {
    Inet,
    Inet6,
    Unix,
    Netlink,
    Other(u64),
}

impl Domain {
    pub fn from_linux(v: u64) -> Self {
        match v {
            1  => Domain::Unix,
            2  => Domain::Inet,
            10 => Domain::Inet6,
            16 => Domain::Netlink,
            n  => Domain::Other(n),
        }
    }
}

// ── SockType ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SockType {
    Stream,
    Dgram,
    Raw,
    Other(u64),
}

impl SockType {
    /// Linux type field low bits (masking out SOCK_NONBLOCK / SOCK_CLOEXEC).
    pub fn from_linux(v: u64) -> Self {
        // SOCK_NONBLOCK = 0o4000 = 2048; SOCK_CLOEXEC = 0o2000000 = 524288
        match v & !0o2004000u64 {
            1 => SockType::Stream,
            2 => SockType::Dgram,
            3 => SockType::Raw,
            n => SockType::Other(n),
        }
    }
}

// ── SocketState ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SocketState {
    Created,
    Bound { addr: [u8; 16], port: u16 },
    Connecting,
    Connected,
    Listening,
    Closed,
}

// ── Socket ────────────────────────────────────────────────────────────────────

pub struct Socket {
    pub domain:   Domain,
    pub socktype: SockType,
    pub state:    SocketState,
    pub recv_buf: VecDeque<u8>,
    pub send_buf: VecDeque<u8>,
    pub nonblock: bool,
    /// Remote address for connected sockets: (ipv4_bytes[4], port).
    pub peer:     Option<([u8; 4], u16)>,
}

impl Socket {
    pub fn new(domain: Domain, socktype: SockType, nonblock: bool) -> Self {
        Socket {
            domain,
            socktype,
            state:    SocketState::Created,
            recv_buf: VecDeque::new(),
            send_buf: VecDeque::new(),
            nonblock,
            peer:     None,
        }
    }
}

// ── SocketTable ───────────────────────────────────────────────────────────────

pub struct SocketTable {
    sockets: HashMap<u64, Socket>,
}

impl SocketTable {
    pub fn new() -> Self {
        SocketTable { sockets: HashMap::new() }
    }

    pub fn insert(&mut self, fd: u64, sock: Socket) {
        self.sockets.insert(fd, sock);
    }

    pub fn get(&self, fd: u64) -> Option<&Socket> {
        self.sockets.get(&fd)
    }

    pub fn get_mut(&mut self, fd: u64) -> Option<&mut Socket> {
        self.sockets.get_mut(&fd)
    }

    pub fn remove(&mut self, fd: u64) -> Option<Socket> {
        self.sockets.remove(&fd)
    }

    pub fn is_socket(&self, fd: u64) -> bool {
        self.sockets.contains_key(&fd)
    }
}

impl Default for SocketTable {
    fn default() -> Self { Self::new() }
}

// ── PendingConnect ────────────────────────────────────────────────────────────

/// A connect() request queued for JS to fulfil via WebSocket.
#[derive(Debug, Clone)]
pub struct PendingConnect {
    pub fd:   u64,
    pub ip:   [u8; 4],
    pub port: u16,
}

// ── PendingSend ───────────────────────────────────────────────────────────────

/// Data queued for JS to forward over the socket's WebSocket.
#[derive(Debug, Clone)]
pub struct PendingSend {
    pub fd:   u64,
    pub data: Vec<u8>,
}

// ── NetCtx ────────────────────────────────────────────────────────────────────

/// Top-level networking context held by `SyscallCtx`.
pub struct NetCtx {
    pub socks:           SocketTable,
    /// Next fd number to allocate for sockets.
    /// Starts at 100 to stay far above stdio/file fds.
    pub next_sock_fd:    u64,
    /// connect() calls waiting for JS to open a WebSocket.
    pub pending_connect: Vec<PendingConnect>,
    /// send_buf data waiting for JS to forward.
    pub pending_sends:   Vec<PendingSend>,
}

impl NetCtx {
    pub fn new() -> Self {
        NetCtx {
            socks:           SocketTable::new(),
            next_sock_fd:    100,
            pending_connect: Vec::new(),
            pending_sends:   Vec::new(),
        }
    }
}

impl Default for NetCtx {
    fn default() -> Self { Self::new() }
}
