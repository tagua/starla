//! SNTP client with multi-sample support, as the reference probe's evntp
//! (probe-busybox/eperd/ntp.c, firmware 5130)

use super::NtpConfig;
use bytes::{Buf, BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::Interest;
use tokio::net::UdpSocket;

// NTP Epoch is 1900-01-01, Unix Epoch is 1970-01-01
const NTP_OFFSET: u64 = 2_208_988_800;

const FOUR_G: f64 = 4_294_967_296.0;

/// The reference id a client request carries: "RIPE", in network byte order
/// (5130 sends it with htonl, so it is "RIPE" on the wire on every
/// architecture). Starla sent 0.
const REF_ID_RIPE: [u8; 4] = *b"RIPE";

/// 5130's minimum time between requests (`-g`, in ms): the default and the
/// bounds outside which evntp refuses the measurement.
pub const GAP_MIN_MS: u64 = 2000;
pub const GAP_DEFAULT_MS: u64 = 4000;
pub const GAP_MAX_MS: u64 = 60000;

/// evntp's defaults for `-c` and `-w` (ms).
pub const COUNT_DEFAULT: u32 = 3;
pub const TIMEOUT_DEFAULT_MS: u64 = 1000;

/// Convert NTP timestamp (64-bit: 32-bit seconds + 32-bit fraction) to
/// f64, as ntp.c does: seconds + fraction / 2^32, in a double
pub(super) fn ntp_ts_to_f64(ts: u64) -> f64 {
    let secs = (ts >> 32) as f64;
    let frac = (ts & 0xFFFFFFFF) as f64 / FOUR_G;
    secs + frac
}

/// Current time as a raw 64-bit NTP timestamp
fn now_ntp() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() + NTP_OFFSET;
    let frac = ((now.subsec_nanos() as u64) << 32) / 1_000_000_000;
    (secs << 32) | (frac & 0xFFFF_FFFF)
}

/// RFC 5905 §8 delay and offset from T1 (client send), T2 (server receive),
/// T3 (server send), T4 (client receive), in 64-bit fixed point as 5130
/// computes them, so a negative offset is exact too:
/// delay = (T4 - T1) - (T3 - T2), offset = ((T2 - T1) + (T3 - T4)) / 2.
pub fn delay_and_offset(t1: u64, t2: u64, t3: u64, t4: u64) -> (f64, f64) {
    let d = |a: u64, b: u64| a.wrapping_sub(b) as i64;
    let delay = d(t4, t1).wrapping_sub(d(t3, t2)) as f64 / FOUR_G;
    let offset = d(t2, t1).wrapping_add(d(t3, t4)) as f64 / 2.0 / FOUR_G;
    (delay, offset)
}

/// A client request: version 4, mode 3, reference id "RIPE", transmit T1.
fn request(t1: u64) -> BytesMut {
    let mut packet = BytesMut::with_capacity(48);
    packet.put_u8(0x23); // LI=0, VN=4, Mode=3 (Client)
    packet.put_u8(0); // Stratum
    packet.put_u8(0); // Poll
    packet.put_u8(0); // Precision
    packet.put_u32(0); // Root Delay
    packet.put_u32(0); // Root Dispersion
    packet.put_slice(&REF_ID_RIPE);
    packet.put_u64(0); // Ref Timestamp
    packet.put_u64(0); // Origin Timestamp
    packet.put_u64(0); // Receive Timestamp
    packet.put_u64(t1); // Transmit Timestamp
    packet
}

/// A single NTP exchange sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtpSample {
    /// The header fields of the reply: the first reply's are the result's
    /// (report(), ntp.c:443-479), and a later reply writes, in its own
    /// entry, each of its own that differs from them (ready_callback,
    /// :755-868)
    pub header: NtpHeader,
    /// T1: client transmit time (NTP timestamp)
    pub origin_ts: f64,
    /// T2: server receive time (NTP timestamp)
    pub receive_ts: f64,
    /// T3: server transmit time (NTP timestamp)
    pub transmit_ts: f64,
    /// T4: client receive time (NTP timestamp)
    pub final_ts: f64,
    /// RTT in seconds
    pub rtt: f64,
    /// Offset in seconds
    pub offset: f64,
}

/// A reply's header fields as they came (struct ntphdr, ntp.c:154-167),
/// as ready_callback keeps the first reply's (ntp_flags … ntp_reference_ts
/// in its state, :755-767) and compares a later reply's with them, field
/// by field (:768-868): a field differs when its bits do. report() and
/// ready_callback format them (format_li … format_ts, :238-361).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NtpHeader {
    /// Leap indicator, version and mode: ntp_flags
    pub flags: u8,
    pub stratum: u8,
    /// Poll exponent (log2), a signed byte as evntp keeps it (int8_t
    /// ntp_poll, ntp.c:134)
    pub poll: i8,
    /// Precision exponent (log2)
    pub precision: i8,
    /// Root delay, 16.16 seconds
    pub root_delay: u32,
    /// Root dispersion, 16.16 seconds
    pub root_dispersion: u32,
    /// Reference id, its four bytes as they came (big-endian)
    pub ref_id: u32,
    /// Reference timestamp, 32.32 NTP
    pub ref_ts: u64,
}

impl NtpHeader {
    /// NTP_LI_MASK (ntp.c:191)
    pub fn leap(&self) -> u8 {
        self.flags >> 6
    }

    /// NTP_VERSION_MASK (ntp.c:198)
    pub fn version(&self) -> u8 {
        (self.flags >> 3) & 0x7
    }

    /// NTP_MODE_MASK (ntp.c:201)
    pub fn mode(&self) -> u8 {
        self.flags & 0x7
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtpResult {
    /// One per reply and per timeout, in the order they came; None for a
    /// timeout (`{ "x":"*" }`). The first reply's header is the result's;
    /// none answered, evntp prints none.
    pub samples: Vec<Option<NtpSample>>,
    /// The socket's own address once connected: the result's src_addr
    pub src_addr: Option<IpAddr>,
    /// create_socket's failure, `socket failed: …` or `connect failed: …`
    /// (ntp.c:1225-1238, 1255-1274), which ends the run before any request
    pub error: Option<String>,
}

/// The sample a server's reply makes, received at `t4`: T1 is the reply's
/// origin timestamp, the transmit timestamp of the request it answers, as
/// ready_callback takes it (ntp.c:870-871, 899-911) — not the time Starla
/// sent its latest request — and the reply's own header fields. None for a
/// datagram shorter than a header, which ready_callback skips
/// (ntp.c:735-740).
fn sample(reply: &[u8], t4: u64) -> Option<NtpSample> {
    let header = parse_header(reply)?;
    let mut buf = reply.get(24..48)?;
    let t1 = buf.get_u64();
    let t2 = buf.get_u64();
    let t3 = buf.get_u64();
    let (rtt, offset) = delay_and_offset(t1, t2, t3, t4);
    Some(NtpSample {
        header,
        origin_ts: ntp_ts_to_f64(t1),
        receive_ts: ntp_ts_to_f64(t2),
        transmit_ts: ntp_ts_to_f64(t3),
        final_ts: ntp_ts_to_f64(t4),
        rtt,
        offset,
    })
}

/// evntp's run (ntp.c:503-972, 1174-1316): a socket connected to the
/// server, so the kernel passes up only the server's datagrams
/// (create_socket, 1255-1274), then `config.count` requests. Each request
/// sets two timers, `-w` for its reply and `-g` before the next request
/// (send_pkt, 640-655). Every datagram of a header or more is a reply,
/// read the moment it comes and stamped just before it is read
/// (ready_callback, 661-716): it is an entry of its own, its T1 the
/// origin timestamp it carries, and it cancels the request's timeout. A
/// timeout is a `{ "x":"*" }` entry (noreply_callback, 949-963). After a
/// reply or a timeout the next request goes when the gap has passed, else
/// when the gap timer fires (gap_callback, 965-972); after the last
/// request's reply or timeout the run is over. As in libevent's loop, a
/// turn runs the socket's callback for one datagram before the timers
/// that came due in it, so a reply that is there when its timeout comes
/// due still counts, and a stream of datagrams does not hold the timers
/// off.
///
/// Starla's socket was unconnected and took any datagram from anyone as
/// the answer, and its T1 was its own latest send time: a reply that came
/// after its timeout was read only at the next request, as that request's
/// answer, with T1 and T4 from that request (a delay near zero or
/// negative, the offset off by the request's age), and a datagram from
/// any other source was taken the same way. evntp checks neither the mode
/// nor the origin of a reply: a late one is reported, with its own origin
/// and so its real delay, in the place of the request then in flight, and
/// that request's own reply, if it comes, after it.
pub async fn execute_ntp_query(config: &NtpConfig) -> anyhow::Result<NtpResult> {
    use crate::ping::strerror;

    let mut result = NtpResult {
        samples: Vec::new(),
        src_addr: None,
        error: None,
    };
    let bind_addr: SocketAddr = if config.target.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let dest = SocketAddr::new(config.target, config.port);
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(socket) => socket,
        Err(e) => {
            result.error = Some(format!("socket failed: {}", strerror(&e)));
            return Ok(result);
        }
    };
    if let Err(e) = socket.connect(dest).await {
        result.error = Some(format!("connect failed: {}", strerror(&e)));
        return Ok(result);
    }
    // getsockname once connected (ntp.c:1286-1293)
    result.src_addr = socket.local_addr().ok().map(|a| a.ip());

    let timeout = Duration::from_millis(config.timeout_ms);
    let gap = Duration::from_millis(config.gap_ms);
    let mut sent = 0;
    // A reply came to the latest request (gotresp)
    let mut answered = false;
    // The pending timers: the latest request's timeout, and the gap
    let mut timeout_at: Option<tokio::time::Instant> = None;
    let mut gap_at: Option<tokio::time::Instant> = None;
    // Read errors in a row; past a few the socket waits for a timer
    let mut errors = 0;
    let mut buf = vec![0u8; 2048];

    // send_pkt (ntp.c:503-659): the next request, or the end of the run
    let mut send = true;
    loop {
        if send {
            send = false;
            answered = false;
            if sent >= config.count {
                break;
            }
            // T1 once the socket takes the request, just before the send
            // (ntp.c:544-564): the first request's socket is new to the
            // reactor, and T1 taken before `send().await` counted a reactor
            // turn into the request's delay.
            let (_t1, sending) = starla_network::send_stamped(&socket, || {
                let t1 = now_ntp();
                (t1, request(t1))
            })
            .await;
            if let Err(e) = sending {
                // Its timeout reports it as unanswered.
                tracing::debug!("NTP request {} to {} not sent: {}", sent + 1, dest, e);
            }
            sent += 1;
            let now = tokio::time::Instant::now();
            timeout_at = Some(now + timeout);
            gap_at = Some(now + gap);
        }

        let first_timer = timeout_at.into_iter().chain(gap_at).min();
        let timer = async {
            match first_timer {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        // The socket's event: a datagram, or an error pending on it, which
        // libevent's epoll hands ready_callback as EV_READ too (EPOLLERR).
        // tokio's readable() does not wake for EPOLLERR alone (its
        // Ready::ERROR), so it is asked for.
        tokio::select! {
            ready = socket.ready(Interest::READABLE | Interest::ERROR), if errors < 16 => {
                ready?;
            }
            () = timer => {}
        }

        // One turn of eperd's event loop: the socket's callback, one
        // datagram read, then the timers that came due, which a callback
        // before them may have deleted or set again. A timer that came due
        // is no longer pending.
        let now = tokio::time::Instant::now();
        let gap_pending = gap_at.is_some_and(|at| at > now);
        // ready_callback stamps the time, then reads (ntp.c:688, 714)
        let t4 = now_ntp();
        match read(&socket, &mut buf) {
            Ok(len) => {
                errors = 0;
                if let Some(sample) = sample(&buf[..len], t4) {
                    result.samples.push(Some(sample));
                    answered = true;
                    timeout_at = None;
                    send = !gap_pending || sent >= config.count;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            // a read error is skipped (ntp.c:718-724): an ICMP error on the
            // connected socket, say, which the read takes
            Err(_) => errors += 1,
        }
        if send {
            // send_pkt set both timers again: neither is due
            continue;
        }
        if timeout_at.is_some_and(|at| at <= now) {
            // noreply_callback (ntp.c:949-963)
            tracing::debug!("NTP request {} to {} unanswered", sent, dest);
            result.samples.push(None);
            timeout_at = None;
            errors = 0;
            send = !gap_pending || sent >= config.count;
        }
        if !send && gap_at.is_some_and(|at| at <= now) {
            // gap_callback (ntp.c:965-972)
            gap_at = None;
            errors = 0;
            send = answered || timeout_at.is_none();
        }
    }

    Ok(result)
}

/// ready_callback's read (ntp.c:714-724): a socket error pending — an ICMP
/// error on the connected socket, port unreachable, say — is what the read
/// returns, and takes, before any datagram: Linux's UDP recvmsg asks
/// sock_error first. On Linux only EPOLLERR says so, which tokio keeps as
/// Ready::ERROR, and its try_recv, seeing no READABLE, would not read: the
/// error stayed, and the next request's send took it instead and did not
/// go out. It is taken here with SO_ERROR, as the read takes it. (macOS
/// reports the error readable, and the read takes it.)
fn read(socket: &UdpSocket, buf: &mut [u8]) -> std::io::Result<usize> {
    let pending = socket.try_io(Interest::ERROR, || match socket.take_error() {
        Ok(Some(e)) => Ok(e),
        // none: the readiness goes, until the next error
        Ok(None) => Err(std::io::ErrorKind::WouldBlock.into()),
        Err(e) => Ok(e),
    });
    match pending {
        Ok(e) => Err(e),
        Err(_) => socket.try_recv(buf),
    }
}

/// The header fields of a reply of a header or more, as they came.
fn parse_header(raw: &[u8]) -> Option<NtpHeader> {
    let mut buf = raw.get(..48)?;
    Some(NtpHeader {
        flags: buf.get_u8(),
        stratum: buf.get_u8(),
        poll: buf.get_i8(),
        precision: buf.get_i8(),
        root_delay: buf.get_u32(),
        root_dispersion: buf.get_u32(),
        ref_id: buf.get_u32(),
        ref_ts: buf.get_u64(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn ts(secs: f64) -> u64 {
        (secs * FOUR_G).round() as u64
    }

    /// 5130's fix: 5120 reported half the round trip as the offset.
    #[test]
    fn delay_and_offset_are_rfc_5905s_either_way() {
        let t1 = 3_000_000_000.0;
        // Server 0.25 s ahead, 10 ms each way, 1 ms in the server.
        let (d, o) = delay_and_offset(
            ts(t1),
            ts(t1 + 0.260),
            ts(t1 + 0.261),
            ts(t1 + 0.261 - 0.25 + 0.010),
        );
        assert!((d - 0.020).abs() < 1e-6, "{d}");
        assert!((o - 0.250).abs() < 1e-6, "{o}");
        // Server 0.25 s behind.
        let (d, o) = delay_and_offset(
            ts(t1),
            ts(t1 - 0.240),
            ts(t1 - 0.239),
            ts(t1 - 0.239 + 0.25 + 0.010),
        );
        assert!((d - 0.020).abs() < 1e-6, "{d}");
        assert!((o + 0.250).abs() < 1e-6, "{o}");
    }

    #[test]
    fn a_request_carries_ripe_and_t1() {
        let p = request(0x0123_4567_89ab_cdef);
        assert_eq!(p.len(), 48);
        assert_eq!(p[0], 0x23);
        assert_eq!(&p[12..16], b"RIPE");
        assert_eq!(&p[40..48], &0x0123_4567_89ab_cdef_u64.to_be_bytes());
    }

    /// A server that answers the first two requests and ignores the third.
    #[tokio::test]
    async fn requests_keep_the_gap_and_a_timeout_is_recorded() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut buf = [0u8; 48];
            for n in 0..3 {
                let (_, from) = server.recv_from(&mut buf).await.unwrap();
                tx.send((Instant::now(), buf)).unwrap();
                if n < 2 {
                    let mut reply = buf;
                    reply[0] = 0x24; // LI 0, VN 4, mode 4 (server)
                    reply[1] = 1; // stratum 1
                    reply[12..16].copy_from_slice(b"GPS\0");
                    let now = now_ntp().to_be_bytes();
                    reply[24..32].copy_from_slice(&buf[40..48]); // origin = T1
                    reply[32..40].copy_from_slice(&now); // T2
                    reply[40..48].copy_from_slice(&now); // T3
                    server.send_to(&reply, from).await.unwrap();
                }
            }
        });

        let config = NtpConfig {
            target: "127.0.0.1".parse().unwrap(),
            timeout_ms: 300,
            port,
            count: 3,
            gap_ms: 200,
        };
        let res = execute_ntp_query(&config).await.unwrap();
        assert_eq!(res.samples.len(), 3);
        assert!(res.samples[0].is_some() && res.samples[1].is_some());
        assert!(res.samples[2].is_none(), "the third timed out");
        let header = res.samples[0].as_ref().unwrap().header;
        assert_eq!(header.ref_id.to_be_bytes(), *b"GPS\0");

        let mut at = Vec::new();
        while let Ok((t, req)) = rx.try_recv() {
            assert_eq!(&req[12..16], b"RIPE");
            at.push(t);
        }
        assert_eq!(at.len(), 3);
        for w in at.windows(2) {
            assert!(
                w[1] - w[0] >= Duration::from_millis(190),
                "gap {:?}",
                w[1] - w[0]
            );
        }
    }

    /// A server's reply to `request`, received at `t2` and sent at `t3`:
    /// mode 4, stratum 1, "GPS", the request's transmit timestamp as origin.
    fn reply(request: &[u8; 48], t2: u64, t3: u64) -> [u8; 48] {
        let mut reply = *request;
        reply[0] = 0x24; // LI 0, VN 4, mode 4 (server)
        reply[1] = 1; // stratum 1
        reply[12..16].copy_from_slice(b"GPS\0");
        reply[24..32].copy_from_slice(&request[40..48]); // origin = T1
        reply[32..40].copy_from_slice(&t2.to_be_bytes());
        reply[40..48].copy_from_slice(&t3.to_be_bytes());
        reply
    }

    fn config(port: u16, count: u32, timeout_ms: u64, gap_ms: u64) -> NtpConfig {
        NtpConfig {
            target: "127.0.0.1".parse().unwrap(),
            timeout_ms,
            port,
            count,
            gap_ms,
        }
    }

    /// A reply that comes after its timeout, while the next request is in
    /// flight, is an entry of its own with its own origin and so its real
    /// delay and offset, and the next request's reply is another
    /// (ready_callback, ntp.c:661-946). The server holds its reply to
    /// request 1 until request 2 comes (its T3 - T2 says so), then answers
    /// that one 30 ms later. Starla took the late reply as request 2's
    /// answer, with request 2's T1 (a delay of minus the gap, the offset off
    /// by half of it), and request 2's reply as request 3's.
    #[tokio::test]
    async fn a_late_reply_is_not_the_next_requests_answer() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        let sent = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = sent.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 48];
            let (_, from) = server.recv_from(&mut buf).await.unwrap();
            let (first, first_at) = (buf, now_ntp());
            seen.lock().unwrap().push(buf);
            let (_, _) = server.recv_from(&mut buf).await.unwrap();
            let second_at = now_ntp();
            seen.lock().unwrap().push(buf);
            server
                .send_to(&reply(&first, first_at, now_ntp()), from)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            server
                .send_to(&reply(&buf, second_at, now_ntp()), from)
                .await
                .unwrap();
            let (_, _) = server.recv_from(&mut buf).await.unwrap();
            let at = now_ntp();
            seen.lock().unwrap().push(buf);
            server.send_to(&reply(&buf, at, at), from).await.unwrap();
        });

        let res = execute_ntp_query(&config(port, 3, 150, 250)).await.unwrap();
        let t1: Vec<f64> = sent
            .lock()
            .unwrap()
            .iter()
            .map(|r| ntp_ts_to_f64(u64::from_be_bytes(r[40..48].try_into().unwrap())))
            .collect();
        assert_eq!(t1.len(), 3);
        assert_eq!(res.samples.len(), 4, "{:?}", res.samples);
        assert!(res.samples[0].is_none(), "request 1 timed out");
        let late = res.samples[1].as_ref().unwrap();
        assert_eq!(late.origin_ts, t1[0], "the late reply is request 1's");
        assert!(late.final_ts - late.origin_ts >= 0.25, "{late:?}");
        let second = res.samples[2].as_ref().unwrap();
        assert_eq!(second.origin_ts, t1[1]);
        assert!(second.final_ts - second.origin_ts >= 0.03, "{second:?}");
        let third = res.samples[3].as_ref().unwrap();
        assert_eq!(third.origin_ts, t1[2]);
        for s in res.samples.iter().flatten() {
            assert!((0.0..0.05).contains(&s.rtt), "{s:?}");
            assert!(s.offset.abs() < 0.05, "{s:?}");
        }
    }

    /// The socket is connected to the server (create_socket, ntp.c:
    /// 1255-1274), so a datagram from anywhere else never reaches it: here
    /// a reply from another port, the request's origin in it and the clock
    /// 1000 s ahead, comes before the server's own. Starla's socket was not
    /// connected and took it.
    #[tokio::test]
    async fn a_reply_from_elsewhere_is_not_read() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        let spoofer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 48];
            let (_, from) = server.recv_from(&mut buf).await.unwrap();
            let at = now_ntp();
            let ahead = at + (1000 << 32);
            spoofer
                .send_to(&reply(&buf, ahead, ahead), from)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            server
                .send_to(&reply(&buf, at, now_ntp()), from)
                .await
                .unwrap();
        });

        let res = execute_ntp_query(&config(port, 1, 500, 2000))
            .await
            .unwrap();
        assert_eq!(res.samples.len(), 1);
        let s = res.samples[0].as_ref().unwrap();
        assert!(s.offset.abs() < 1.0, "the spoofed reply was read: {s:?}");
        assert!(s.final_ts - s.origin_ts >= 0.05, "{s:?}");
        assert_eq!(res.src_addr, Some("127.0.0.1".parse().unwrap()));
    }

    /// T1 is taken once the socket takes the request, just before its send
    /// (ntp.c:544-564). The run's socket is new to the reactor, so its first
    /// send waits a reactor turn for writable: a run held there 50 ms — a
    /// busy runtime — still has the delay of the server's answer alone.
    /// Stamped before that wait, as c9cb056 stamped it, T1 put the 50 ms
    /// into the delay.
    #[tokio::test]
    async fn t1_is_taken_when_the_socket_takes_the_request() {
        use std::future::Future;
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        let (came, mut requests) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut buf = [0u8; 48];
            let (_, from) = server.recv_from(&mut buf).await.unwrap();
            let at = now_ntp();
            server.send_to(&reply(&buf, at, at), from).await.unwrap();
            let _ = came.send(());
        });

        let config = config(port, 1, 1000, 2000);
        let mut run = std::pin::pin!(execute_ntp_query(&config));
        let first = run
            .as_mut()
            .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()));
        assert!(first.is_pending(), "a new socket is not known writable");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(requests.try_recv().is_err(), "sent before it was writable");
        let res = run.await.unwrap();
        let s = res.samples[0].as_ref().unwrap();
        assert!(s.rtt < 0.04, "the wait for writable is in the delay: {s:?}");
    }

    /// Each reply's sample carries that reply's own header fields, as
    /// ready_callback reads each reply's (ntp.c:755-868): here a root
    /// dispersion that grows 4/65536 s a reply, as time.mediainvent.at's
    /// does in the lines RIPE stores from 5130 probes (msm 112928959).
    /// Starla kept the first reply's alone.
    #[tokio::test]
    async fn each_sample_has_its_replys_header() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 48];
            for n in 0..3u32 {
                let (_, from) = server.recv_from(&mut buf).await.unwrap();
                let at = now_ntp();
                let mut answer = reply(&buf, at, at);
                answer[8..12].copy_from_slice(&(2354 + 4 * n).to_be_bytes());
                server.send_to(&answer, from).await.unwrap();
            }
        });

        let res = execute_ntp_query(&config(port, 3, 500, 150)).await.unwrap();
        let headers: Vec<NtpHeader> = res.samples.iter().flatten().map(|s| s.header).collect();
        assert_eq!(headers.len(), 3, "{:?}", res.samples);
        let dispersions: Vec<u32> = headers.iter().map(|h| h.root_dispersion).collect();
        assert_eq!(dispersions, [2354, 2358, 2362]);
        for h in headers {
            assert_eq!((h.flags, h.stratum), (0x24, 1));
            assert_eq!((h.leap(), h.version(), h.mode()), (0, 4, 4));
            assert_eq!(h.ref_id.to_be_bytes(), *b"GPS\0");
        }
    }

    /// The poll exponent is a signed byte (int8_t ntp_poll, ntp.c:134),
    /// as precision: 0xfa is -6, which format_8bit prints as 0.015625.
    #[test]
    fn the_poll_is_a_signed_byte() {
        let mut r = [0u8; 48];
        r[2] = 0xfa;
        r[3] = 0xe9;
        let h = parse_header(&r).unwrap();
        assert_eq!((h.poll, h.precision), (-6, -23));
    }

    /// The first request goes to a closed port: the ICMP port unreachable
    /// leaves an error on the connected socket, which ready_callback's read
    /// takes and skips (ntp.c:714-724, libevent handing it EPOLLERR as
    /// EV_READ), and the request times out. The server is then up for the
    /// second and third, which both go out and are answered. On Linux,
    /// waiting on readable() alone, Starla never read the error; the
    /// second request's send took it (ECONNREFUSED) and did not go out.
    #[tokio::test]
    async fn an_icmp_error_is_read_and_the_next_request_goes_out() {
        let closed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let (came, mut requests) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            // up once the first request has met the closed port
            tokio::time::sleep(Duration::from_millis(100)).await;
            let server = UdpSocket::bind(("127.0.0.1", port)).await.unwrap();
            let mut buf = [0u8; 48];
            loop {
                let (_, from) = server.recv_from(&mut buf).await.unwrap();
                let at = now_ntp();
                server.send_to(&reply(&buf, at, at), from).await.unwrap();
                let _ = came.send(buf);
            }
        });

        let res = execute_ntp_query(&config(port, 3, 250, 300)).await.unwrap();
        server.abort();
        let mut answered = 0;
        while requests.try_recv().is_ok() {
            answered += 1;
        }
        assert_eq!(answered, 2, "{:?}", res.samples);
        assert_eq!(res.samples.len(), 3, "{:?}", res.samples);
        assert!(res.samples[0].is_none(), "{:?}", res.samples);
        assert!(
            res.samples[1].is_some() && res.samples[2].is_some(),
            "{:?}",
            res.samples
        );
    }

    /// Datagrams shorter than a header are skipped (ntp.c:735-740).
    #[test]
    fn a_short_datagram_is_no_reply() {
        assert!(sample(&[0u8; 47], 0).is_none());
        assert!(parse_header(&[0u8; 47]).is_none());
        let mut r = [0u8; 48];
        r[24..32].copy_from_slice(&ts(3_000_000_000.0).to_be_bytes());
        r[32..48].copy_from_slice(&[0u8; 16]);
        let s = sample(&r, ts(3_000_000_000.5)).unwrap();
        assert_eq!(s.origin_ts, 3_000_000_000.0, "T1 is the reply's origin");
    }
}
