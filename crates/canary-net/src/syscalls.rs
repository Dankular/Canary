//! Socket syscall handler — called from `canary-syscall/src/dispatch.rs`.

use canary_memory::GuestMemory;
use crate::{Domain, NetCtx, PendingConnect, PendingSend, Socket, SocketState, SockType};

// ── errno constants (negated) ─────────────────────────────────────────────────

pub const EBADF:       i64 = -9;
pub const EAGAIN:      i64 = -11;
pub const EINVAL:      i64 = -22;
pub const ENOSYS:      i64 = -38;
pub const ENOTSOCK:    i64 = -88;
pub const EAFNOSUPPORT: i64 = -97;
pub const ECONNREFUSED: i64 = -111;
pub const EPIPE:       i64 = -32;
pub const EWOULDBLOCK: i64 = EAGAIN;

// ── Syscall numbers (x86-64 Linux) ────────────────────────────────────────────

pub const SYS_SOCKET:     u64 = 41;
pub const SYS_CONNECT:    u64 = 42;
pub const SYS_ACCEPT:     u64 = 43;
pub const SYS_SENDTO:     u64 = 44;
pub const SYS_RECVFROM:   u64 = 45;
pub const SYS_SENDMSG:    u64 = 46;
pub const SYS_RECVMSG:    u64 = 47;
pub const SYS_SHUTDOWN:   u64 = 48;
pub const SYS_BIND:       u64 = 49;
pub const SYS_LISTEN:     u64 = 50;
pub const SYS_GETSOCKNAME: u64 = 51;
pub const SYS_GETPEERNAME: u64 = 52;
pub const SYS_SOCKETPAIR: u64 = 53;
pub const SYS_SETSOCKOPT: u64 = 54;
pub const SYS_GETSOCKOPT: u64 = 55;
pub const SYS_ACCEPT4:    u64 = 288;
pub const SYS_SENDMMSG:   u64 = 307;
pub const SYS_RECVMMSG:   u64 = 299;

/// Returns true if `nr` is one of the socket-related syscalls we handle.
pub fn is_socket_syscall(nr: u64) -> bool {
    matches!(
        nr,
        SYS_SOCKET | SYS_CONNECT | SYS_ACCEPT | SYS_ACCEPT4
        | SYS_SENDTO | SYS_RECVFROM | SYS_SENDMSG | SYS_RECVMSG
        | SYS_SHUTDOWN | SYS_BIND | SYS_LISTEN
        | SYS_GETSOCKNAME | SYS_GETPEERNAME | SYS_SOCKETPAIR
        | SYS_SETSOCKOPT | SYS_GETSOCKOPT
        | SYS_SENDMMSG | SYS_RECVMMSG
    )
}

/// Dispatch a socket-related syscall.
///
/// `net` is the mutable network context (socket table + queues).
///
/// Returns the value to store in RAX (negative errno on error).
pub fn handle_socket_syscall(
    nr:  u64,
    a0:  u64, a1: u64, a2: u64, _a3: u64, _a4: u64, _a5: u64,
    mem: &mut GuestMemory,
    net: &mut NetCtx,
) -> i64 {
    match nr {

        // ── socket(domain, type, protocol) ────────────────────────────────
        SYS_SOCKET => {
            let domain_raw = a0;
            let type_raw   = a1;
            // type & SOCK_NONBLOCK (0o4000 = 2048)
            let nonblock = type_raw & 0o4000 != 0;

            let domain   = Domain::from_linux(domain_raw);
            let socktype = SockType::from_linux(type_raw);

            let fd = net.next_sock_fd;
            net.next_sock_fd += 1;

            let sock = Socket::new(domain, socktype, nonblock);
            net.socks.insert(fd, sock);

            fd as i64
        }

        // ── bind(fd, sockaddr_ptr, addrlen) ───────────────────────────────
        SYS_BIND => {
            let fd         = a0;
            let addr_ptr   = a1;
            let _addrlen   = a2;

            if !net.socks.is_socket(fd) { return EBADF; }

            // Read sockaddr_in: family(u16) + port(u16 BE) + addr(u32) = 8 bytes
            let family = match mem.read_u16(addr_ptr) { Ok(v) => v, Err(_) => return EINVAL };
            let port_be = match mem.read_u16(addr_ptr + 2) { Ok(v) => v, Err(_) => return EINVAL };
            let port = u16::from_be(port_be);

            let mut addr16 = [0u8; 16];
            if family == 2 {
                // AF_INET
                let addr4 = match mem.read_u32(addr_ptr + 4) { Ok(v) => v, Err(_) => return EINVAL };
                addr16[..4].copy_from_slice(&addr4.to_be_bytes());
            } else if family == 10 {
                // AF_INET6 — read 16 bytes
                match mem.read_bytes(addr_ptr + 8, 16) {
                    Ok(bytes) => addr16.copy_from_slice(bytes),
                    Err(_)    => return EINVAL,
                }
            }

            if let Some(sock) = net.socks.get_mut(fd) {
                sock.state = SocketState::Bound { addr: addr16, port };
            }
            0
        }

        // ── listen(fd, backlog) ───────────────────────────────────────────
        SYS_LISTEN => {
            let fd = a0;
            if let Some(sock) = net.socks.get_mut(fd) {
                sock.state = SocketState::Listening;
                0
            } else {
                EBADF
            }
        }

        // ── connect(fd, sockaddr_ptr, addrlen) ────────────────────────────
        SYS_CONNECT => {
            let fd       = a0;
            let addr_ptr = a1;
            let _addrlen = a2;

            if !net.socks.is_socket(fd) { return EBADF; }

            let family = match mem.read_u16(addr_ptr) { Ok(v) => v, Err(_) => return EINVAL };
            let port_be = match mem.read_u16(addr_ptr + 2) { Ok(v) => v, Err(_) => return EINVAL };
            let port = u16::from_be(port_be);

            let ip: [u8; 4] = if family == 2 {
                // AF_INET: 4-byte address at offset +4
                match mem.read_bytes(addr_ptr + 4, 4) {
                    Ok(b) => [b[0], b[1], b[2], b[3]],
                    Err(_) => return EINVAL,
                }
            } else {
                // For non-IPv4 (AF_UNIX, AF_INET6, etc.) — use zeroed placeholder.
                [0, 0, 0, 0]
            };

            // Set state to Connecting and queue a connect request for JS.
            if let Some(sock) = net.socks.get_mut(fd) {
                sock.state = SocketState::Connecting;
                sock.peer  = Some((ip, port));
            }

            net.pending_connect.push(PendingConnect { fd, ip, port });
            // Return 0 (success) — for blocking sockets we pretend the connect
            // completed immediately; JS will call socket_connected() later.
            0
        }

        // ── accept(fd, addr_ptr, addrlen_ptr) ─────────────────────────────
        SYS_ACCEPT | SYS_ACCEPT4 => {
            let fd = a0;
            if !net.socks.is_socket(fd) { return EBADF; }
            // No incoming connections in this implementation yet.
            EAGAIN
        }

        // ── sendto(fd, buf_ptr, len, flags, dest_addr, addrlen) ───────────
        SYS_SENDTO => {
            let fd      = a0;
            let buf_ptr = a1;
            let len     = a2 as usize;
            // flags = a3, dest_addr = a4, addrlen = a5 — ignored for now.

            if !net.socks.is_socket(fd) { return EBADF; }

            if len == 0 { return 0; }

            let data = match mem.read_bytes(buf_ptr, len) {
                Ok(b)  => b.to_vec(),
                Err(_) => return EINVAL,
            };

            if let Some(sock) = net.socks.get_mut(fd) {
                if sock.state == SocketState::Closed { return EPIPE; }
                sock.send_buf.extend(data.iter().copied());
            }

            // Queue a send event so JS can forward the data.
            net.pending_sends.push(PendingSend { fd, data });
            len as i64
        }

        // ── sendmsg(fd, msghdr_ptr, flags) ────────────────────────────────
        SYS_SENDMSG => {
            let fd       = a0;
            let msg_ptr  = a1;
            // struct msghdr layout (x86-64):
            //   msg_name (u64), msg_namelen (u32), pad (u32)
            //   msg_iov  (u64), msg_iovlen  (u64)
            //   ...
            if !net.socks.is_socket(fd) { return EBADF; }

            let iov_ptr = match mem.read_u64(msg_ptr + 8) { Ok(v) => v, Err(_) => return EINVAL };
            let iovlen  = match mem.read_u64(msg_ptr + 16) { Ok(v) => v, Err(_) => return EINVAL };

            let mut total_sent: i64 = 0;
            for i in 0..iovlen {
                let iov_base = match mem.read_u64(iov_ptr + i * 16)     { Ok(v) => v, Err(_) => return EINVAL };
                let iov_len  = match mem.read_u64(iov_ptr + i * 16 + 8) { Ok(v) => v, Err(_) => return EINVAL };
                let chunk = match mem.read_bytes(iov_base, iov_len as usize) {
                    Ok(b)  => b.to_vec(),
                    Err(_) => return EINVAL,
                };
                if let Some(sock) = net.socks.get_mut(fd) {
                    sock.send_buf.extend(chunk.iter().copied());
                }
                net.pending_sends.push(PendingSend { fd, data: chunk });
                total_sent += iov_len as i64;
            }
            total_sent
        }

        // ── recvfrom(fd, buf_ptr, len, flags, src_addr, addrlen_ptr) ──────
        SYS_RECVFROM => {
            let fd      = a0;
            let buf_ptr = a1;
            let len     = a2 as usize;
            // flags = a3, src_addr = a4, addrlen_ptr = a5

            if !net.socks.is_socket(fd) { return EBADF; }

            if let Some(sock) = net.socks.get_mut(fd) {
                if sock.recv_buf.is_empty() {
                    return EAGAIN; // Would block
                }
                let n = len.min(sock.recv_buf.len());
                let drained: Vec<u8> = sock.recv_buf.drain(..n).collect();
                match mem.write_bytes_at(buf_ptr, &drained) {
                    Ok(_)  => n as i64,
                    Err(_) => EINVAL,
                }
            } else {
                EBADF
            }
        }

        // ── recvmsg(fd, msghdr_ptr, flags) ────────────────────────────────
        SYS_RECVMSG => {
            let fd      = a0;
            let msg_ptr = a1;

            if !net.socks.is_socket(fd) { return EBADF; }

            let iov_ptr = match mem.read_u64(msg_ptr + 8) { Ok(v) => v, Err(_) => return EINVAL };
            let iovlen  = match mem.read_u64(msg_ptr + 16) { Ok(v) => v, Err(_) => return EINVAL };

            if let Some(sock) = net.socks.get_mut(fd) {
                if sock.recv_buf.is_empty() {
                    return EAGAIN;
                }
                let mut total_recv: i64 = 0;
                for i in 0..iovlen {
                    if sock.recv_buf.is_empty() { break; }
                    let iov_base = match mem.read_u64(iov_ptr + i * 16)     { Ok(v) => v, Err(_) => return EINVAL };
                    let iov_len  = match mem.read_u64(iov_ptr + i * 16 + 8) { Ok(v) => v, Err(_) => return EINVAL };
                    let n = (iov_len as usize).min(sock.recv_buf.len());
                    let drained: Vec<u8> = sock.recv_buf.drain(..n).collect();
                    match mem.write_bytes_at(iov_base, &drained) {
                        Ok(_)  => total_recv += n as i64,
                        Err(_) => return EINVAL,
                    }
                }
                total_recv
            } else {
                EBADF
            }
        }

        // ── shutdown(fd, how) ─────────────────────────────────────────────
        SYS_SHUTDOWN => {
            let fd = a0;
            if let Some(sock) = net.socks.get_mut(fd) {
                sock.state = SocketState::Closed;
                0
            } else {
                EBADF
            }
        }

        // ── setsockopt(fd, level, optname, optval_ptr, optlen) ────────────
        SYS_SETSOCKOPT => {
            let fd = a0;
            if !net.socks.is_socket(fd) { return EBADF; }
            // Accept and ignore all options for now.
            // Common ones: SO_REUSEADDR=2, SO_REUSEPORT=15, TCP_NODELAY=1, SO_KEEPALIVE=9
            0
        }

        // ── getsockopt(fd, level, optname, optval_ptr, optlen_ptr) ────────
        SYS_GETSOCKOPT => {
            let fd      = a0;
            let optval  = _a3;  // a3 in the original call position
            let optlen  = _a4;  // a4 in the original call position

            if !net.socks.is_socket(fd) { return EBADF; }

            // Write zero value for most options.
            if optval != 0 {
                mem.write_u32(optval, 0).ok();
            }
            if optlen != 0 {
                mem.write_u32(optlen, 4).ok();
            }
            0
        }

        // ── getsockname(fd, addr_ptr, addrlen_ptr) ────────────────────────
        SYS_GETSOCKNAME => {
            let fd       = a0;
            let addr_ptr = a1;
            let alen_ptr = a2;

            if let Some(sock) = net.socks.get(fd) {
                match sock.state {
                    SocketState::Bound { addr, port } => {
                        // Write sockaddr_in: family(u16) + port(u16 BE) + addr(u32) + padding(8)
                        mem.write_u16(addr_ptr, 2).ok();                                    // AF_INET
                        mem.write_u16(addr_ptr + 2, port.to_be()).ok();
                        mem.write_bytes_at(addr_ptr + 4, &addr[..4]).ok();
                        mem.write_bytes_at(addr_ptr + 8, &[0u8; 8]).ok();
                        if alen_ptr != 0 { mem.write_u32(alen_ptr, 16).ok(); }
                    }
                    _ => {
                        // Not bound — return zeroed AF_INET addr.
                        mem.write_u16(addr_ptr, 2).ok();
                        mem.write_bytes_at(addr_ptr + 2, &[0u8; 14]).ok();
                        if alen_ptr != 0 { mem.write_u32(alen_ptr, 16).ok(); }
                    }
                }
                0
            } else {
                EBADF
            }
        }

        // ── getpeername(fd, addr_ptr, addrlen_ptr) ────────────────────────
        SYS_GETPEERNAME => {
            let fd       = a0;
            let addr_ptr = a1;
            let alen_ptr = a2;

            if let Some(sock) = net.socks.get(fd) {
                if let Some((ip, port)) = sock.peer {
                    mem.write_u16(addr_ptr, 2).ok();
                    mem.write_u16(addr_ptr + 2, port.to_be()).ok();
                    mem.write_bytes_at(addr_ptr + 4, &ip).ok();
                    mem.write_bytes_at(addr_ptr + 8, &[0u8; 8]).ok();
                    if alen_ptr != 0 { mem.write_u32(alen_ptr, 16).ok(); }
                    0
                } else {
                    // Not connected.
                    ENOTCONNECTED
                }
            } else {
                EBADF
            }
        }

        // ── socketpair(domain, type, protocol, sv[2]) ─────────────────────
        SYS_SOCKETPAIR => {
            // Create two connected sockets; write their fds to sv[].
            let type_raw = a1;
            let nonblock = type_raw & 0o4000 != 0;
            let sv_ptr   = _a3;

            let domain   = Domain::from_linux(a0);
            let socktype = SockType::from_linux(type_raw);

            let fd0 = net.next_sock_fd;      net.next_sock_fd += 1;
            let fd1 = net.next_sock_fd;      net.next_sock_fd += 1;

            let mut s0 = Socket::new(domain, socktype, nonblock);
            let mut s1 = Socket::new(domain, socktype, nonblock);
            s0.state = SocketState::Connected;
            s1.state = SocketState::Connected;

            net.socks.insert(fd0, s0);
            net.socks.insert(fd1, s1);

            mem.write_u32(sv_ptr,     fd0 as u32).ok();
            mem.write_u32(sv_ptr + 4, fd1 as u32).ok();
            0
        }

        // ── sendmmsg / recvmmsg (stubs) ───────────────────────────────────
        SYS_SENDMMSG | SYS_RECVMMSG => {
            let fd = a0;
            if !net.socks.is_socket(fd) { return EBADF; }
            EAGAIN
        }

        _ => ENOSYS,
    }
}

// ENOTCONN = -107
const ENOTCONNECTED: i64 = -107;
