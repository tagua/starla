//! Raw socket abstraction for sending/receiving packets
//!
//! This module provides a safe wrapper around raw sockets, handling:
//! - IPv4 and IPv6 support
//! - Socket creation and configuration
//! - Sending and receiving raw packets
//! - Integration with Tokio for async I/O
//!
//! Supports both privileged (RAW) and unprivileged (DGRAM) ICMP sockets.
//! On Linux with ping_group_range configured, DGRAM sockets allow unprivileged
//! users to send ICMP echo requests without CAP_NET_RAW.

use crate::RecvMeta;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use tokio::io::unix::AsyncFd;
use tracing::trace;

/// A raw socket capable of sending and receiving packets
pub struct RawSocket {
    /// The underlying async file descriptor
    inner: AsyncFd<Socket>,
    /// Protocol (e.g., ICMPv4, ICMPv6)
    protocol: Protocol,
    /// Whether this is a DGRAM socket (unprivileged ICMP)
    is_dgram: bool,
}

impl RawSocket {
    /// Create a new raw socket for the specified protocol and address family
    ///
    /// Tries DGRAM first (unprivileged), falls back to RAW if needed.
    pub fn new(protocol: Protocol, domain: Domain) -> io::Result<Self> {
        // Try unprivileged DGRAM socket first for ICMP
        if protocol == Protocol::ICMPV4 || protocol == Protocol::ICMPV6 {
            if let Ok(socket) = Socket::new(domain, Type::DGRAM, Some(protocol)) {
                socket.set_nonblocking(true)?;
                trace!("Created unprivileged DGRAM ICMP socket");
                return Ok(Self {
                    inner: AsyncFd::new(socket)?,
                    protocol,
                    is_dgram: true,
                });
            }
        }

        // Fall back to RAW socket (requires CAP_NET_RAW or root)
        let socket = Socket::new(domain, Type::RAW, Some(protocol))?;
        socket.set_nonblocking(true)?;
        trace!("Created privileged RAW socket");

        Ok(Self {
            inner: AsyncFd::new(socket)?,
            protocol,
            is_dgram: false,
        })
    }

    /// Create a raw socket with explicit type (RAW or DGRAM)
    pub fn new_with_type(
        protocol: Protocol,
        domain: Domain,
        socket_type: Type,
    ) -> io::Result<Self> {
        let socket = Socket::new(domain, socket_type, Some(protocol))?;
        socket.set_nonblocking(true)?;

        Ok(Self {
            inner: AsyncFd::new(socket)?,
            protocol,
            is_dgram: socket_type == Type::DGRAM,
        })
    }

    /// Create a raw socket bound to a specific interface or address (optional)
    pub fn bind(protocol: Protocol, domain: Domain, addr: &SocketAddr) -> io::Result<Self> {
        // Try unprivileged DGRAM socket first for ICMP
        if protocol == Protocol::ICMPV4 || protocol == Protocol::ICMPV6 {
            if let Ok(socket) = Socket::new(domain, Type::DGRAM, Some(protocol)) {
                socket.set_nonblocking(true)?;
                socket.bind(&(*addr).into())?;
                trace!("Created bound unprivileged DGRAM ICMP socket");
                return Ok(Self {
                    inner: AsyncFd::new(socket)?,
                    protocol,
                    is_dgram: true,
                });
            }
        }

        let socket = Socket::new(domain, Type::RAW, Some(protocol))?;
        socket.set_nonblocking(true)?;
        socket.bind(&(*addr).into())?;

        Ok(Self {
            inner: AsyncFd::new(socket)?,
            protocol,
            is_dgram: false,
        })
    }

    /// Send a packet to a destination
    pub async fn send_to(&self, buf: &[u8], target: &SocketAddr) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;

            match guard.try_io(|inner| inner.get_ref().send_to(buf, &(*target).into())) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Receive a packet
    ///
    /// Returns the number of bytes read and the source address.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            let mut guard = self.inner.readable().await?;

            match guard.try_io(|inner| {
                // socket2's recv_from requires MaybeUninit buffer.
                // SAFETY: &mut [u8] is a valid &mut [MaybeUninit<u8>]: initialized
                // memory is trivially valid as MaybeUninit. The layout is guaranteed
                // identical (MaybeUninit<u8> is repr(transparent) over u8).
                let maybe_uninit_buf: &mut [std::mem::MaybeUninit<u8>] = unsafe {
                    std::slice::from_raw_parts_mut(
                        buf.as_mut_ptr().cast::<std::mem::MaybeUninit<u8>>(),
                        buf.len(),
                    )
                };
                inner.get_ref().recv_from(maybe_uninit_buf)
            }) {
                Ok(Ok((n, addr))) => {
                    let addr = addr
                        .as_socket()
                        .ok_or_else(|| io::Error::other("Invalid socket address"))?;
                    return Ok((n, addr));
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }

    /// Ask the kernel to hand each packet's TTL (IPv4, IP_RECVTTL) or hop
    /// limit (IPv6, IPV6_RECVHOPLIMIT) over with it, for
    /// [`RawSocket::recv_meta`]: what ping.c reads its "ttl" from on
    /// IPv6 (ping.c:1536, 1155-1162).
    pub fn set_recv_ttl(&self) -> io::Result<()> {
        if self.protocol == Protocol::ICMPV6 {
            self.set_int_option(libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT)
        } else {
            self.set_int_option(libc::IPPROTO_IP, libc::IP_RECVTTL)
        }
    }

    /// Ask the kernel to hand each packet's destination address over with
    /// it (IPV6_RECVPKTINFO; IP_PKTINFO on Linux, whose ICMP datagram
    /// sockets give no IPv4 header), for [`RawSocket::recv_meta`]: the
    /// local address a reply came to, which ping.c compares with its own
    /// for a reply's "src_addr" (ping.c:1531-1533, 1150-1156, 417-428).
    /// IPv4 sockets that hand the header over need nothing.
    pub fn set_recv_pktinfo(&self) -> io::Result<()> {
        if self.protocol == Protocol::ICMPV6 {
            return self.set_int_option(libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO);
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if self.is_dgram {
            return self.set_int_option(libc::IPPROTO_IP, libc::IP_PKTINFO);
        }
        Ok(())
    }

    /// Ask the kernel to stamp each packet's arrival and hand the stamp
    /// over with it (SO_TIMESTAMPNS), for [`RawSocket::recv_meta`]'s
    /// `stamp`: the `kernel_rx_timestamps` option ([`crate::rxstamp`]).
    /// Linux only; Unsupported elsewhere.
    pub fn set_rx_timestamps(&self) -> io::Result<()> {
        crate::rxstamp::enable(self.inner.get_ref().as_raw_fd())
    }

    fn set_int_option(&self, level: libc::c_int, name: libc::c_int) -> io::Result<()> {
        let on: libc::c_int = 1;
        // SAFETY: `on` is a c_int that outlives the call, and its size is
        // the length given.
        let r = unsafe {
            libc::setsockopt(
                self.inner.get_ref().as_raw_fd(),
                level,
                name,
                (&on as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if r == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Receive a packet, with the TTL or hop limit, the destination
    /// address it arrived with and the kernel's stamp of its arrival when
    /// the kernel gives them as ancillary data (see
    /// [`RawSocket::set_recv_ttl`], [`RawSocket::set_recv_pktinfo`],
    /// [`RawSocket::set_rx_timestamps`]).
    pub async fn recv_meta(&self, buf: &mut [u8]) -> io::Result<(usize, RecvMeta)> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| recvmsg_meta(inner.get_ref().as_raw_fd(), buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// connect(2) the socket to `target`, as ping.c does before it sends
    /// (ping.c:1569-1580): the kernel then picks the source address, which
    /// [`RawSocket::local_addr`] gives, and passes only that peer's packets
    /// up. Send with [`RawSocket::send`] afterwards.
    pub fn connect(&self, target: &SocketAddr) -> io::Result<()> {
        self.inner.get_ref().connect(&(*target).into())
    }

    /// The socket's own address: getsockname(2).
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner
            .get_ref()
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("not an IP socket address"))
    }

    /// Send a packet on a connected socket.
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Send on a connected socket the packet `packet` makes, made once the
    /// socket is known to be writable, immediately before the send(2): a
    /// send time it stamps into the packet is then the time the packet
    /// left, as ping.c stamps its evdata just before its sendto
    /// (fmticmp4/6, ping.c:559, 635; sendto 732, 757). A socket's
    /// readiness starts empty, so on a new socket the first writable()
    /// waits for a turn of the reactor; a packet made before it carried
    /// that wait in its stamp. Should the send block after all, the packet
    /// is made again.
    pub async fn send_with(
        &self,
        mut packet: impl FnMut() -> io::Result<Vec<u8>>,
    ) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            let buf = packet()?;
            match guard.try_io(|inner| inner.get_ref().send(&buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Get the protocol this socket is configured for
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Check if this is a DGRAM (unprivileged) socket
    pub fn is_dgram(&self) -> bool {
        self.is_dgram
    }

    /// Set the time-to-live (TTL) for outgoing packets
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        if self.protocol == Protocol::ICMPV6 {
            self.inner.get_ref().set_unicast_hops_v6(ttl)
        } else {
            // socket2 0.6 renamed IPv4 setters with a _v4 suffix.
            self.inner.get_ref().set_ttl_v4(ttl)
        }
    }
}

/// recvmsg(2) into `buf`, and among the ancillary data the TTL or hop
/// limit, IPV6_HOPLIMIT (an int), IP_TTL (an int, Linux) or IP_RECVTTL (a
/// byte, the BSDs and macOS), the destination address, IPV6_PKTINFO
/// (in6_pktinfo: the address first) or IP_PKTINFO (in_pktinfo: ifindex,
/// spec_dst, then the header's destination), and the kernel's receive
/// stamp, SCM_TIMESTAMPNS ([`crate::rxstamp::from_cmsg`]). Any socket's
/// descriptor will do: a UDP socket's too.
pub fn recvmsg_meta(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, RecvMeta)> {
    // u64s, so the control buffer is aligned for cmsghdr
    let mut control = [0u64; 32];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: all zero is a valid msghdr.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&control) as _;
    // SAFETY: msg points at `iov` (over `buf`) and `control`, both live and
    // as long as their lengths say.
    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut meta = RecvMeta::default();
    // SAFETY: the CMSG_* walk stays within msg_controllen bytes of
    // `control`, which recvmsg filled; each item's data is as long as its
    // cmsg_len says, and is read unaligned.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let (level, kind) = ((*cmsg).cmsg_level, (*cmsg).cmsg_type);
            let data = libc::CMSG_DATA(cmsg);
            let len = ((*cmsg).cmsg_len as usize).saturating_sub(data as usize - cmsg as usize);
            let int = || std::ptr::read_unaligned(data.cast::<libc::c_int>());
            let bytes = |at: usize, n: usize| std::slice::from_raw_parts(data.add(at), n);
            let hop_limit = level == libc::IPPROTO_IPV6 && kind == libc::IPV6_HOPLIMIT;
            if hop_limit || (level == libc::IPPROTO_IP && kind == libc::IP_TTL) {
                meta.ttl = u8::try_from(int()).ok();
            } else if level == libc::IPPROTO_IP && kind == libc::IP_RECVTTL {
                meta.ttl = Some(*data);
            } else if level == libc::IPPROTO_IPV6 && kind == libc::IPV6_PKTINFO && len >= 16 {
                let addr: [u8; 16] = bytes(0, 16).try_into().unwrap_or_default();
                meta.dst = Some(std::net::Ipv6Addr::from(addr).into());
            } else if level == libc::IPPROTO_IP && is_ip_pktinfo(kind) && len >= 12 {
                let addr: [u8; 4] = bytes(8, 4).try_into().unwrap_or_default();
                meta.dst = Some(std::net::Ipv4Addr::from(addr).into());
            } else if level == libc::SOL_SOCKET {
                meta.stamp = crate::rxstamp::from_cmsg(level, kind, bytes(0, len)).or(meta.stamp);
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    Ok((n as usize, meta))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn is_ip_pktinfo(kind: libc::c_int) -> bool {
    kind == libc::IP_PKTINFO
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn is_ip_pktinfo(_kind: libc::c_int) -> bool {
    false
}

// Re-export Type for consumers that need explicit socket type control
pub use socket2::Type as SocketType;

/// Helper to create an ICMPv4 socket
pub fn new_icmpv4_socket() -> io::Result<RawSocket> {
    RawSocket::new(Protocol::ICMPV4, Domain::IPV4)
}

/// Helper to create an ICMPv6 socket
pub fn new_icmpv6_socket() -> io::Result<RawSocket> {
    RawSocket::new(Protocol::ICMPV6, Domain::IPV6)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::task::{Context, Waker};

    /// The packet is made after the socket is known to be writable, not
    /// before: a new socket's readiness is empty, so the first poll waits
    /// for the reactor without making it; once made it goes out as made.
    #[tokio::test]
    async fn a_packet_is_made_when_the_socket_is_writable() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = RawSocket::new_with_type(Protocol::UDP, Domain::IPV4, Type::DGRAM).unwrap();
        socket.connect(&peer.local_addr().unwrap()).unwrap();
        let made = std::cell::Cell::new(0u8);
        let send = socket.send_with(|| {
            made.set(made.get() + 1);
            Ok(vec![made.get(); 4])
        });
        let mut send = std::pin::pin!(send);
        let first = send.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        assert!(first.is_pending(), "a new socket is not known writable");
        assert_eq!(made.get(), 0, "made before the socket was writable");
        assert_eq!(send.await.unwrap(), 4);
        assert_eq!(made.get(), 1);
        let mut buf = [0u8; 8];
        assert_eq!(peer.recv(&mut buf).await.unwrap(), 4);
        assert_eq!(buf[..4], [1; 4]);
    }

    /// A datagram over loopback from a peer at `to`, to a socket that asks
    /// for receive stamps when `stamps` says so, and reads it 30 ms after
    /// it came (a blocking sleep in between): what it came with, when it
    /// went, and when it was read. None where `to` cannot be had.
    async fn read_late(
        to: &str,
        stamps: bool,
    ) -> Option<(RecvMeta, std::time::Instant, std::time::Instant)> {
        let domain = if to.starts_with('[') {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let Ok(peer) = std::net::UdpSocket::bind(to) else {
            eprintln!("skipping {to}: no such address here");
            return None;
        };
        let socket = RawSocket::new_with_type(Protocol::UDP, domain, Type::DGRAM).unwrap();
        socket.connect(&peer.local_addr().unwrap()).unwrap();
        if stamps {
            socket.set_rx_timestamps().unwrap();
        }
        socket.send(b"bind").await.unwrap();
        let (_, from) = peer.recv_from(&mut [0u8; 8]).unwrap();
        let sent = std::time::Instant::now();
        peer.send_to(b"reply", from).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        let mut buf = [0u8; 16];
        let (n, meta) = socket.recv_meta(&mut buf).await.unwrap();
        let read = std::time::Instant::now();
        assert_eq!(&buf[..n], b"reply");
        Some((meta, sent, read))
    }

    /// With receive stamps asked for, a datagram that waited 30 ms to be
    /// read carries the kernel's stamp of when it came: on the monotonic
    /// clock, after it was sent and well before it was read — the rtt it
    /// gives leaves the wait out, the userspace one has it in. Not asked
    /// for, there is none: the packet is read as before.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn a_kernel_stamp_leaves_the_wait_to_read_out() {
        use crate::rxstamp::{hold, monotonic, stamping_at_arrival, Arrival};
        use std::time::{Duration, Instant};
        // as set_enabled holds it
        hold().unwrap();
        assert!(stamping_at_arrival(Duration::from_secs(2)));
        for to in ["127.0.0.1:0", "[::1]:0"] {
            let Some((meta, sent, read)) = read_late(to, true).await else {
                continue;
            };
            let user = Instant::now();
            let stamp = meta.stamp.expect("SCM_TIMESTAMPNS");
            let kernel = monotonic(stamp, Instant::now).unwrap();
            let arrival = Arrival {
                user,
                kernel: Some(kernel),
            };
            let at = arrival.after(sent);
            assert_eq!(at, kernel, "{to}");
            let (rtt, user_rtt) = (at - sent, user - sent);
            eprintln!("{to}: kernel rtt {rtt:?}, userspace {user_rtt:?}");
            assert!(rtt <= user_rtt, "{to}");
            assert!(rtt < Duration::from_millis(10), "{to}: {rtt:?}");
            assert!(read - at >= Duration::from_millis(25), "{to}");

            let (meta, ..) = read_late(to, false).await.unwrap();
            assert_eq!(meta.stamp, None, "{to}: not asked for");
        }
    }

    /// Elsewhere no socket can ask, and none come.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[tokio::test]
    async fn no_kernel_stamps_elsewhere() {
        let socket = RawSocket::new_with_type(Protocol::UDP, Domain::IPV4, Type::DGRAM).unwrap();
        let e = socket.set_rx_timestamps().unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        let (meta, ..) = read_late("127.0.0.1:0", false).await.unwrap();
        assert_eq!(meta.stamp, None);
    }
}
