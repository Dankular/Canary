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

            let family = match mem.read_u16(addr_ptr) { Ok(v) => v, Err(_) => return EINVAL };

            if family == 1 {
                // AF_UNIX: sockaddr_un = family(u16) + path(up to 108 bytes, null-terminated)
                let path_bytes = match mem.read_bytes(addr_ptr + 2, 108) {
                    Ok(b) => b.to_vec(),
                    Err(_) => return EINVAL,
                };
                let path_end = path_bytes.iter().position(|&b| b == 0).unwrap_or(108);
                let path = match std::str::from_utf8(&path_bytes[..path_end]) {
                    Ok(s) => s.to_string(),
                    Err(_) => return EINVAL,
                };
                if let Some(sock) = net.socks.get_mut(fd) {
                    sock.state = SocketState::Bound { addr: [0u8; 16], port: 0 };
                }
                net.unix_paths.insert(path, fd);
                net.unix_accept_queue.entry(fd).or_default();
                return 0;
            }

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

            if family == 1 {
                // AF_UNIX: read the path from sockaddr_un
                let path_bytes = match mem.read_bytes(addr_ptr + 2, 108) {
                    Ok(b) => b.to_vec(),
                    Err(_) => return EINVAL,
                };
                let path_end = path_bytes.iter().position(|&b| b == 0).unwrap_or(108);
                let path = match std::str::from_utf8(&path_bytes[..path_end]) {
                    Ok(s) => s.to_string(),
                    Err(_) => return EINVAL,
                };

                // Find the listening server socket.
                let server_fd = match net.unix_paths.get(&path).copied() {
                    Some(sfd) => sfd,
                    None      => return ECONNREFUSED,
                };

                // Determine client socket's domain/type for the peer.
                let (domain, socktype, nonblock) = match net.socks.get(fd) {
                    Some(s) => (s.domain, s.socktype, s.nonblock),
                    None    => return EBADF,
                };

                // Allocate a peer socket for the server side of this connection.
                let peer_fd = net.next_sock_fd;
                net.next_sock_fd += 1;

                let mut peer = Socket::new(domain, socktype, nonblock);
                peer.state     = SocketState::Connected;
                peer.unix_peer = Some(fd);
                net.socks.insert(peer_fd, peer);

                // Link client to its peer.
                if let Some(sock) = net.socks.get_mut(fd) {
                    sock.state     = SocketState::Connected;
                    sock.unix_peer = Some(peer_fd);
                }

                // Enqueue the peer fd for the server's accept() call.
                net.unix_accept_queue
                    .entry(server_fd)
                    .or_default()
                    .push_back(peer_fd);

                return 0;
            }

            let port_be = match mem.read_u16(addr_ptr + 2) { Ok(v) => v, Err(_) => return EINVAL };
            let port = u16::from_be(port_be);

            let ip: [u8; 4] = if family == 2 {
                // AF_INET: 4-byte address at offset +4
                match mem.read_bytes(addr_ptr + 4, 4) {
                    Ok(b) => [b[0], b[1], b[2], b[3]],
                    Err(_) => return EINVAL,
                }
            } else {
                [0, 0, 0, 0]
            };

            // Set state to Connecting and queue a connect request for JS.
            if let Some(sock) = net.socks.get_mut(fd) {
                sock.state = SocketState::Connecting;
                sock.peer  = Some((ip, port));
            }

            net.pending_connect.push(PendingConnect { fd, ip, port });
            0
        }

        // ── accept(fd, addr_ptr, addrlen_ptr) ─────────────────────────────
        SYS_ACCEPT | SYS_ACCEPT4 => {
            let fd          = a0;
            let addr_ptr    = a1;
            let addrlen_ptr = a2;

            if !net.socks.is_socket(fd) { return EBADF; }

            // AF_UNIX: dequeue from in-memory accept queue.
            if let Some(peer_fd) = net.unix_accept_queue
                .get_mut(&fd)
                .and_then(|q| q.pop_front())
            {
                // Optionally write peer address (abstract/unnamed — all zeros).
                if addr_ptr != 0 {
                    mem.write_u16(addr_ptr, 1).ok(); // AF_UNIX
                    if addrlen_ptr != 0 { mem.write_u32(addrlen_ptr, 2).ok(); }
                }
                return peer_fd as i64;
            }

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

            // AF_UNIX: route directly to peer socket's recv_buf (no JS round-trip).
            let peer_fd = net.socks.get(fd).and_then(|s| s.unix_peer);
            if let Some(pfd) = peer_fd {
                if let Some(sock) = net.socks.get(fd) {
                    if sock.state == SocketState::Closed { return EPIPE; }
                }
                if let Some(peer) = net.socks.get_mut(pfd) {
                    peer.recv_buf.extend(data.iter().copied());
                }
                return len as i64;
            }

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
            if !net.socks.is_socket(fd) { return EBADF; }

            let iov_ptr = match mem.read_u64(msg_ptr + 8)  { Ok(v) => v, Err(_) => return EINVAL };
            let iovlen  = match mem.read_u64(msg_ptr + 16) { Ok(v) => v, Err(_) => return EINVAL };

            // Determine if this is a AF_UNIX socket with a peer (in-memory routing).
            let peer_fd = net.socks.get(fd).and_then(|s| s.unix_peer);

            let mut total_sent: i64 = 0;
            for i in 0..iovlen {
                let iov_base = match mem.read_u64(iov_ptr + i * 16)     { Ok(v) => v, Err(_) => return EINVAL };
                let iov_len  = match mem.read_u64(iov_ptr + i * 16 + 8) { Ok(v) => v, Err(_) => return EINVAL };
                let chunk = match mem.read_bytes(iov_base, iov_len as usize) {
                    Ok(b)  => b.to_vec(),
                    Err(_) => return EINVAL,
                };
                if let Some(pfd) = peer_fd {
                    // AF_UNIX: push directly into peer recv_buf.
                    if let Some(peer) = net.socks.get_mut(pfd) {
                        peer.recv_buf.extend(chunk.iter().copied());
                    }
                } else {
                    if let Some(sock) = net.socks.get_mut(fd) {
                        sock.send_buf.extend(chunk.iter().copied());
                    }
                    net.pending_sends.push(PendingSend { fd, data: chunk });
                }
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
