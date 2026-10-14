//! Kernel receive timestamps: the `[measurements] kernel_rx_timestamps`
//! option, off by default, and a deliberate departure from the reference.
//!
//! Off, a reply's receive time is the reference's: a userspace clock read
//! once the event loop has the reply in hand (ping.c, traceroute.c and
//! evtdig.c read the clock in their read callbacks, ntp.c just before its
//! read). Whatever kept the probe from reading it at once — another task
//! on the runtime, the scheduler, a stall — is in the rtt. On, the
//! measurement sockets ask for SO_TIMESTAMPNS (socket(7)), and a reply's
//! receive time is the kernel's software stamp, taken as the packet came in
//! and before any socket saw it (net_timestamp_check(), net/core/dev.c),
//! which recvmsg(2) hands over as an SCM_TIMESTAMPNS control message. Send
//! times stay userspace, taken right before the send.
//!
//! The stamp is CLOCK_REALTIME. [`monotonic`] moves it onto the monotonic
//! clock the rtts are taken on, as `mono_now - (real_now - stamp)`, the two
//! clocks read back to back. On Linux CLOCK_REALTIME and CLOCK_MONOTONIC
//! tick at the same, NTP-disciplined rate and differ only by steps
//! (clock_settime(2), a leap second), so that is the stamp to within the
//! time between the two reads — tens of nanoseconds through the vDSO —
//! unless the wall clock steps between the packet's arrival and its read:
//! then it is off by the step. A stamp after the wall clock's reading (a
//! step back) is not used, nor one before its request went out (a step
//! forward, [`Arrival::after`]): the userspace stamp stands. NTP's T4 is
//! wall-clock time anyway, and takes the stamp as it is.
//!
//! TCP measurements (DNS over TCP, TLS, HTTP) keep userspace stamps: what
//! they time — a connect's completion, a response's first bytes through
//! TLS and HTTP buffers — is not one datagram that recvmsg hands over with
//! its stamp.
//!
//! The cost: a socket that asks turns on net_enable_timestamp(), a static
//! key that has the kernel stamp every packet it receives — the whole
//! host's, not only the probe's — with one clock read each. The key is
//! counted: the last socket that asked closing switches it off, through a
//! jump-label rewrite of kernel text, and the next one asking switches it
//! on again — from a work queue, a moment later, and until then a packet
//! is stamped when it is read, not when it came. Measurement sockets come
//! and go several times a second, and each run's first reply comes right
//! after its socket asked, so [`set_enabled`] keeps a socket of its own
//! asking for the life of the process ([`hold`]): the key stays on.
//!
//! Linux only: elsewhere the option is accepted and ignored.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Where the kernel has SO_TIMESTAMPNS.
const SUPPORTED: bool = cfg!(any(target_os = "linux", target_os = "android"));

static ENABLED: AtomicBool = AtomicBool::new(false);

/// Whether measurements take the kernel's receive stamps: the option as
/// [`set_enabled`] set it, where the kernel has them; false until then, and
/// always elsewhere.
pub fn enabled() -> bool {
    SUPPORTED && ENABLED.load(Ordering::Relaxed)
}

/// Set the option from the config, once at start-up, before any
/// measurement runs. On, it also holds the kernel's timestamping on for
/// the life of the process (see the module's docs); should that fail, the
/// measurement sockets still get their stamps, each turning it on and off.
pub fn set_enabled(on: bool) {
    if !on {
        ENABLED.store(false, Ordering::Relaxed);
        return;
    }
    if !SUPPORTED {
        tracing::warn!(
            "kernel_rx_timestamps is Linux only: ignored, replies are stamped in userspace"
        );
        return;
    }
    if let Err(e) = hold() {
        tracing::warn!(
            "kernel receive timestamps: no socket to hold the kernel's timestamping on ({}); \
             each measurement's socket turns it on and off",
            e
        );
    }
    ENABLED.store(true, Ordering::Relaxed);
    tracing::info!(
        "kernel receive timestamps on: replies are timed by the kernel's receive stamps, \
         not in userspace as the reference times them"
    );
}

/// Hold the kernel's timestamping on for the life of the process: a
/// socket that asks for receive stamps and is never closed keeps
/// net_enable_timestamp()'s count above zero. Unbound, it receives
/// nothing. [`set_enabled`] holds it; so does a test that wants a socket's
/// first packet stamped as it came ([`stamping_at_arrival`]). Unsupported
/// where the kernel has no receive stamps.
pub fn hold() -> std::io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use socket2::{Domain, Socket, Type};
        use std::os::fd::AsRawFd;
        use std::sync::OnceLock;

        static HELD: OnceLock<Socket> = OnceLock::new();
        if HELD.get().is_some() {
            return Ok(());
        }
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)
            .or_else(|_| Socket::new(Domain::IPV6, Type::DGRAM, None))?;
        enable(socket.as_raw_fd())?;
        let _ = HELD.set(socket);
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    Err(std::io::ErrorKind::Unsupported.into())
}

/// Whether the kernel stamps packets as they come, not as they are read,
/// waiting up to `limit` for it to: it switches its timestamping on from a
/// work queue, a moment after a first socket asks or [`hold`]. A datagram
/// sent to itself over loopback and read 2 ms later says so, by a stamp
/// from before the wait. False where there are no receive stamps.
pub fn stamping_at_arrival(limit: Duration) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
        use std::os::fd::AsRawFd;

        let loopback = [
            IpAddr::from(Ipv4Addr::LOCALHOST),
            Ipv6Addr::LOCALHOST.into(),
        ];
        let Some(socket) = loopback
            .into_iter()
            .find_map(|ip| UdpSocket::bind((ip, 0)).ok())
        else {
            return false;
        };
        let Ok(to) = socket.local_addr() else {
            return false;
        };
        let ready = enable(socket.as_raw_fd())
            .and_then(|()| socket.set_read_timeout(Some(Duration::from_secs(1))));
        if ready.is_err() {
            return false;
        }
        let deadline = Instant::now() + limit;
        let mut buf = [0u8; 8];
        loop {
            let sent = realtime();
            if socket.send_to(b"stamp", to).is_err() {
                return false;
            }
            std::thread::sleep(Duration::from_millis(2));
            let Ok((_, meta)) = crate::raw_socket::recvmsg_meta(socket.as_raw_fd(), &mut buf)
            else {
                return false;
            };
            if meta
                .stamp
                .is_some_and(|at| at < sent + Duration::from_millis(1))
            {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = limit;
        false
    }
}

/// Ask the kernel to stamp what `fd` receives: SO_TIMESTAMPNS, whose
/// stamps come as [`from_cmsg`] reads them. Unsupported where the kernel
/// has no such option.
#[cfg(unix)]
pub fn enable(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let on: libc::c_int = 1;
        // SAFETY: `on` is a c_int that outlives the call, and its size is
        // the length given.
        let r = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMPNS,
                (&on as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if r == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = fd;
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

/// The kernel's receive stamp, when the control message of `level` and
/// `kind` with `data` is one: SCM_TIMESTAMPNS, a struct timespec of
/// CLOCK_REALTIME, as the time since the epoch. libc's SO_TIMESTAMPNS is
/// the one whose timespec is libc's (SO_TIMESTAMPNS_NEW where time_t is 64
/// bits on a 32-bit system), and the kernel answers in kind.
#[cfg(unix)]
pub fn from_cmsg(level: libc::c_int, kind: libc::c_int, data: &[u8]) -> Option<Duration> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if level == libc::SOL_SOCKET
        && kind == libc::SCM_TIMESTAMPNS
        && data.len() >= std::mem::size_of::<libc::timespec>()
    {
        // SAFETY: `data` holds a timespec's bytes, read unaligned.
        let ts = unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<libc::timespec>()) };
        let secs = u64::try_from(ts.tv_sec).ok()?;
        let nanos = u32::try_from(ts.tv_nsec)
            .ok()
            .filter(|n| *n < 1_000_000_000)?;
        if (secs, nanos) == (0, 0) {
            return None;
        }
        return Some(Duration::new(secs, nanos));
    }
    let _ = (level, kind, data);
    None
}

/// CLOCK_REALTIME, as the time since the epoch: the clock the kernel's
/// receive stamps are on.
pub fn realtime() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// A monotonic clock a receive stamp can be moved onto: an [`Instant`], or
/// a reading taken as the time since some start, a [`Duration`].
pub trait Monotonic: Copy + Ord {
    fn checked_sub(self, d: Duration) -> Option<Self>;
}

impl Monotonic for Instant {
    fn checked_sub(self, d: Duration) -> Option<Self> {
        Instant::checked_sub(&self, d)
    }
}

impl Monotonic for Duration {
    fn checked_sub(self, d: Duration) -> Option<Self> {
        Duration::checked_sub(self, d)
    }
}

/// `stamp`, a kernel receive stamp ([`from_cmsg`]), on the monotonic clock
/// `now` reads: `now() - (realtime() - stamp)`, the two clocks read back to
/// back (see the module's docs for the error). None for a stamp after the
/// wall clock's reading — it stepped back since the packet came — or before
/// the start of a `now` that counts from one.
pub fn monotonic<T: Monotonic>(stamp: Duration, now: impl FnOnce() -> T) -> Option<T> {
    let real = realtime();
    now().checked_sub(real.checked_sub(stamp)?)
}

/// When a reply came, on one monotonic clock: as read once recvmsg(2) had
/// returned it — what the reference reads — and, when its socket asked, as
/// the kernel stamped it on arrival ([`monotonic`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arrival<T> {
    pub user: T,
    pub kernel: Option<T>,
}

impl<T: Copy + Ord> Arrival<T> {
    /// When a reply to what was sent at `sent` came: the kernel's stamp,
    /// unless it says the reply came before `sent` — the wall clock stepped
    /// forward between its arrival and its read — and then the userspace
    /// one. Never later than the userspace one.
    pub fn after(&self, sent: T) -> T {
        match self.kernel {
            Some(kernel) if kernel >= sent => kernel.min(self.user),
            _ => self.user,
        }
    }
}

impl<T> From<T> for Arrival<T> {
    /// A userspace stamp alone, as without the option.
    fn from(user: T) -> Self {
        Self { user, kernel: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Off until set; nothing in this crate's tests sets it.
    #[test]
    fn off_by_default() {
        assert!(!enabled());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn timespec(sec: libc::time_t, nsec: libc::c_long) -> Vec<u8> {
        // SAFETY: all zero is a valid timespec (and its padding, if any).
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        ts.tv_sec = sec;
        ts.tv_nsec = nsec;
        // SAFETY: a timespec's bytes, as long as it is.
        unsafe {
            std::slice::from_raw_parts(
                (&ts as *const libc::timespec).cast::<u8>(),
                std::mem::size_of::<libc::timespec>(),
            )
        }
        .to_vec()
    }

    /// SCM_TIMESTAMPNS at SOL_SOCKET is the stamp; any other message, one
    /// too short, a nonsense one or none at all (zero) is not.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn an_scm_timestampns_is_the_stamp() {
        use libc::{IPPROTO_IP, IP_TTL, SCM_TIMESTAMPNS, SOL_SOCKET};
        let data = timespec(1_760_400_000, 123_456_789);
        assert_eq!(
            from_cmsg(SOL_SOCKET, SCM_TIMESTAMPNS, &data),
            Some(Duration::new(1_760_400_000, 123_456_789))
        );
        assert_eq!(from_cmsg(IPPROTO_IP, SCM_TIMESTAMPNS, &data), None);
        assert_eq!(from_cmsg(SOL_SOCKET, IP_TTL, &data), None);
        assert_eq!(from_cmsg(SOL_SOCKET, libc::SCM_TIMESTAMP, &data), None);
        assert_eq!(
            from_cmsg(SOL_SOCKET, SCM_TIMESTAMPNS, &data[..data.len() - 1]),
            None
        );
        let bad = timespec(1_760_400_000, 1_000_000_000);
        assert_eq!(from_cmsg(SOL_SOCKET, SCM_TIMESTAMPNS, &bad), None);
        let bad = timespec(-1, 0);
        assert_eq!(from_cmsg(SOL_SOCKET, SCM_TIMESTAMPNS, &bad), None);
        let zero = timespec(0, 0);
        assert_eq!(from_cmsg(SOL_SOCKET, SCM_TIMESTAMPNS, &zero), None);
    }

    /// Elsewhere there is none.
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    #[test]
    fn no_stamps_elsewhere() {
        assert_eq!(from_cmsg(libc::SOL_SOCKET, 35, &[1; 16]), None);
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let e = enable(std::os::fd::AsRawFd::as_raw_fd(&socket)).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::Unsupported);
    }

    /// A stamp 5 ms ago is 5 ms before now on either clock; one from the
    /// future, or before a clock's start, is none.
    ///
    /// The bounds allow a few µs: on macOS the wall clock reads in whole
    /// µs while Instant reads in ns, so the difference of two wall-clock
    /// reads can exceed the time between them by up to 1 µs (it failed ~1
    /// run in 5 there without the slack). On Linux both read in ns.
    #[test]
    fn a_stamp_moves_onto_the_monotonic_clock() {
        let slack = Duration::from_micros(5);
        let before = Instant::now();
        let at = monotonic(realtime() - Duration::from_millis(5), Instant::now).unwrap();
        let after = Instant::now();
        assert!(
            at + Duration::from_millis(5) + slack >= before,
            "{at:?} {before:?}"
        );
        assert!(
            at + Duration::from_millis(5) <= after + slack,
            "{at:?} {after:?}"
        );
        let since = |start: Instant| move || start.elapsed();
        let start = Instant::now() - Duration::from_millis(50);
        let at = monotonic(realtime() - Duration::from_millis(20), since(start)).unwrap();
        assert!(at + slack >= Duration::from_millis(30), "{at:?}");
        assert!(at < Duration::from_millis(40), "{at:?}");
        assert_eq!(
            monotonic(realtime() + Duration::from_secs(1), Instant::now),
            None
        );
        assert_eq!(
            monotonic(realtime() - Duration::from_secs(1), since(Instant::now())),
            None
        );
    }

    /// The kernel's stamp when it is after the send; the userspace one
    /// without it, or when it says the reply came first.
    #[test]
    fn an_arrival_after_its_send() {
        let ms = Duration::from_millis;
        let arrival = Arrival {
            user: ms(130),
            kernel: Some(ms(100)),
        };
        assert_eq!(arrival.after(ms(90)), ms(100));
        assert_eq!(arrival.after(ms(100)), ms(100));
        assert_eq!(arrival.after(ms(101)), ms(130));
        assert_eq!(Arrival::from(ms(130)).after(ms(90)), ms(130));
        let late = Arrival {
            user: ms(130),
            kernel: Some(ms(131)),
        };
        assert_eq!(late.after(ms(90)), ms(130));
    }

    /// Held, timestamping is on, and soon packets are stamped as they come:
    /// the socket that holds it is made once.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn held_packets_are_stamped_as_they_come() {
        hold().unwrap();
        hold().unwrap();
        assert!(stamping_at_arrival(Duration::from_secs(2)));
    }

    /// Elsewhere nothing is held, and nothing stamped.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[test]
    fn nothing_is_held_elsewhere() {
        assert_eq!(hold().unwrap_err().kind(), std::io::ErrorKind::Unsupported);
        assert!(!stamping_at_arrival(Duration::from_millis(10)));
    }
}
