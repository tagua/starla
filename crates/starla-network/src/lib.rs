//! Network primitives for Starla measurements

pub mod capabilities;

pub mod icmp;
#[cfg(unix)]
pub mod raw_socket;
#[cfg(windows)]
pub mod windows_icmp;
pub mod wsacmsg;

pub use capabilities::*;
pub use icmp::*;
#[cfg(unix)]
pub use raw_socket::{new_icmpv4_socket, new_icmpv6_socket, RawSocket};

/// What came with a packet: its TTL or hop limit, and the address it was
/// sent to. On unix from recvmsg's ancillary data
/// ([`RawSocket::recv_meta`]), on Windows from WSARecvMsg's
/// ([`wsacmsg::recv_meta`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecvMeta {
    pub ttl: Option<u8>,
    pub dst: Option<std::net::IpAddr>,
}

/// The index of the network interface called `name`, as if_nametoindex(3)
/// gives it: what an IPv6 address's `%zone` names (a link-local resolver
/// in resolv.conf, `nameserver fe80::1%eth0`). None when there is no such
/// interface.
#[cfg(unix)]
pub fn interface_index(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    // SAFETY: `name` is a NUL-terminated string that outlives the call.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

/// Send on a connected UDP socket the datagram `stamped` makes, with what
/// it stamps (a send time), made once the socket is known to be writable,
/// immediately before the send(2), as the reference stamps a query or a
/// request just before its send (evtdig.c:1459-1465, ntp.c:544-564). A
/// socket's readiness starts empty, so on a new socket the first
/// writable() waits for a turn of the reactor; a stamp taken before it
/// counted that wait. Should the send block after all, the datagram is
/// made again.
pub async fn send_stamped<S, B: AsRef<[u8]>>(
    socket: &tokio::net::UdpSocket,
    mut stamped: impl FnMut() -> (S, B),
) -> (S, std::io::Result<usize>) {
    loop {
        if let Err(e) = socket.writable().await {
            return (stamped().0, Err(e));
        }
        let (stamp, datagram) = stamped();
        match socket.try_send(datagram.as_ref()) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            sent => return (stamp, sent),
        }
    }
}

/// Get the source IP address that would be used to reach a destination.
///
/// Creates a UDP socket and connects it to the destination (without sending
/// data). The kernel assigns the appropriate local address based on routing
/// tables.
pub fn get_source_addr_for_dest(dest: std::net::IpAddr) -> std::io::Result<std::net::IpAddr> {
    use std::net::{SocketAddr, UdpSocket};

    let dest_addr = SocketAddr::new(dest, 9);

    let socket = if dest.is_ipv4() {
        UdpSocket::bind("0.0.0.0:0")?
    } else {
        UdpSocket::bind("[::]:0")?
    };

    socket.connect(dest_addr)?;
    let local_addr = socket.local_addr()?;
    Ok(local_addr.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::task::{Context, Waker};

    /// The stamp is taken after the socket is known to be writable: a new
    /// socket's readiness is empty, so the first poll waits for the
    /// reactor without stamping; the datagram goes out with its stamp.
    #[tokio::test]
    async fn a_datagram_is_stamped_when_the_socket_is_writable() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(peer.local_addr().unwrap()).await.unwrap();
        let stamps = std::cell::Cell::new(0u8);
        let send = send_stamped(&socket, || {
            stamps.set(stamps.get() + 1);
            (std::time::Instant::now(), [stamps.get(); 3])
        });
        let mut send = std::pin::pin!(send);
        let first = send.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        assert!(first.is_pending(), "a new socket is not known writable");
        assert_eq!(stamps.get(), 0, "stamped before the socket was writable");
        let polled = std::time::Instant::now();
        let (stamp, sent) = send.await;
        assert_eq!(sent.unwrap(), 3);
        assert!(stamp > polled);
        assert_eq!(stamps.get(), 1);
        let mut buf = [0u8; 8];
        assert_eq!(peer.recv(&mut buf).await.unwrap(), 3);
        assert_eq!(buf[..3], [1; 3]);
    }

    #[cfg(unix)]
    #[test]
    fn interface_indexes() {
        let lo = if cfg!(target_os = "linux") {
            "lo"
        } else {
            "lo0"
        };
        assert!(interface_index(lo).is_some_and(|i| i > 0));
        assert_eq!(interface_index("nosuchif0"), None);
        assert_eq!(interface_index("bad\0name"), None);
    }

    #[tokio::test]
    async fn test_socket_creation() {
        #[cfg(unix)]
        {
            use std::io;
            match new_icmpv4_socket() {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    println!("Skipping test: Permission denied (CAP_NET_RAW required)");
                }
                Err(e) => panic!("Failed to create socket: {}", e),
            }
        }
    }
}
