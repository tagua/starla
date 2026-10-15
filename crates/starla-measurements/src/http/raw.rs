//! HTTP GET, HEAD and POST as the reference probe's evhttpget does them
//! (probe-busybox/eperd/httpget.c), for `http://` and `https://` URLs.
//!
//! RIPE learns a probe's public addresses from its hourly built-ins to
//! ip-echo.ripe.net (12027 over IPv4, 13027 over IPv6, both with
//! `--store-headers 1024`): the reference reports the response's raw header
//! lines, among them `X-Client-IP: <the address the server saw>`. Through
//! reqwest Starla could not report raw header lines (names lowercased, order
//! not kept), and it ignored `-4`/`-6` when resolving. So this client speaks
//! HTTP/1.x itself and reports exactly what httpget reports.
//!
//! An `https://` URL is the same fetch over TLS, as the reference's httpget
//! makes it (CONFIG_FEATURE_EVHTTPGET_HTTPS=y, tu_connect_to_name's
//! do_tls): the certificate is not verified, and the server name sent is
//! `--sni`'s, or the URL's host (httpget.c:773; tcputil.c:352-453). Starla
//! fetched those through reqwest: no ttr, no line for a failed lookup or
//! connect, the source address from a route query, and the headers
//! rebuilt.

use crate::target::{self, Resolver};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// httpget's default User-Agent.
pub const USER_AGENT: &str = "httpget for atlas.ripe.net";

/// httpget's timeout when the line has no `--timeout` (CONN_TO,
/// httpget.c:23, 711-719), in ms.
pub const DEFAULT_TIMEOUT_MS: u64 = 5000;

/// Stop reading a response after this many bytes (built-ins fetch a 14-byte
/// echo and a favicon; this only bounds a misbehaving server).
const MAX_RESPONSE_BYTES: usize = 1 << 20;

/// An `http://` or `https://` URL split as httpget's parse_url splits it.
#[derive(Debug, Clone, PartialEq)]
pub struct HttpUrl {
    /// The authority exactly as written, used for the Host header
    pub hostport: String,
    /// The host without brackets
    pub host: String,
    /// The URL's, else 80, or 443 for https (httpget.c:309-312)
    pub port: u16,
    /// "/" when the URL has none
    pub path: String,
    /// `https://`: over TLS
    pub tls: bool,
}

/// parse_url (httpget.c:192-322): either prefix, in any case. Anything
/// else is "bad prefix in url", and httpget_init refuses the line.
pub fn parse_http_url(url: &str) -> anyhow::Result<HttpUrl> {
    let prefixed = |prefix: &str| {
        url.get(..prefix.len())
            .filter(|p| p.eq_ignore_ascii_case(prefix))
            .map(|_| &url[prefix.len()..])
    };
    let (rest, tls) = match (prefixed("http://"), prefixed("https://")) {
        (Some(rest), _) => (rest, false),
        (None, Some(rest)) => (rest, true),
        (None, None) => anyhow::bail!("bad prefix in url '{url}'"),
    };
    let default_port = if tls { 443 } else { 80 };
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if hostport.is_empty() {
        anyhow::bail!("missing host part in url '{url}'");
    }
    let (host, port) = if let Some(inner) = hostport.strip_prefix('[') {
        let end = inner
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("unterminated [ in url '{url}'"))?;
        let port = match &inner[end + 1..] {
            "" => default_port,
            p => p
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .ok_or_else(|| anyhow::anyhow!("bad port in url '{url}'"))?,
        };
        (inner[..end].to_string(), port)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse()
                    .map_err(|_| anyhow::anyhow!("bad port in url '{url}'"))?,
            ),
            None => (hostport.to_string(), default_port),
        }
    };
    Ok(HttpUrl {
        hostport: hostport.to_string(),
        host,
        port,
        path: path.to_string(),
        tls,
    })
}

/// The method httpget sends: `--get` (the default), `--head` or `--post`,
/// whichever the line names last (httpget.c:514-546).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Method {
    #[default]
    Get,
    Head,
    Post,
}

impl Method {
    /// HttpConfig's method, in any case: anything but HEAD and POST is GET.
    pub fn from_name(name: &str) -> Self {
        if name.eq_ignore_ascii_case("HEAD") {
            Method::Head
        } else if name.eq_ignore_ascii_case("POST") {
            Method::Post
        } else {
            Method::Get
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
        }
    }
}

/// The request httpget writes (writecb, httpget.c:1826-1866). The Host
/// header is `--host`'s, which takes the URL's host and port's place there
/// and nowhere else: the name looked up and the server name sent are still
/// the URL's (httpget.c:730-735, 773). The User-Agent is `--user-agent`'s
/// (:565-566, 1838-1839). A POST says its body's type and length; its body
/// is the --post-header, --post-file and --post-footer files, which must
/// be under data/out. Starla keeps no files there, and httpget posts
/// nothing for a file it cannot stat or open (:1849-1863, 1767-1772), so
/// the length is 0.
pub fn request(url: &HttpUrl, opts: &FetchOptions) -> String {
    let mut request = format!(
        "{} {} HTTP/1.{}\r\nHost: {}\r\nConnection: close\r\nUser-Agent: {}\r\n",
        opts.method.as_str(),
        url.path,
        if opts.http10 { '0' } else { '1' },
        opts.host.as_deref().unwrap_or(&url.hostport),
        opts.user_agent.as_deref().unwrap_or(USER_AGENT)
    );
    if opts.method == Method::Post {
        request
            .push_str("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n");
    }
    request.push_str("\r\n");
    request
}

/// What evhttpget's line asks of a fetch beyond its URL.
#[derive(Debug, Clone)]
pub struct FetchOptions {
    /// `-4` / `-6`: 4, 6, or 0 for either
    pub af: u8,
    /// `-0`: HTTP/1.0
    pub http10: bool,
    /// `--store-headers`
    pub store_headers: usize,
    /// `--timeout`: the timer each connect arms
    pub timeout: Duration,
    /// `--sni`: the server name an https fetch sends in place of the host
    pub sni: Option<String>,
    /// `--get`, `--head`, `--post`
    pub method: Method,
    /// `--all`: fetch from every address the lookup gave, each fetch
    /// reported
    pub all: bool,
    /// `--user-agent`: the User-Agent sent, [`USER_AGENT`] when None
    pub user_agent: Option<String>,
    /// `--host`: the Host header's, the URL's host and port when None
    pub host: Option<String>,
    /// `--read-limit`: the bytes read after which the response is not read
    /// further, 0 for no limit (see [`Reader`])
    pub read_limit: usize,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            af: 0,
            http10: false,
            store_headers: 0,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            sni: None,
            method: Method::Get,
            all: false,
            user_agent: None,
            host: None,
            read_limit: 0,
        }
    }
}

/// What httpget reports for one fetch.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RawHttpOutcome {
    /// DNS time in ms, only when the host was a name (httpget's ttr)
    pub ttr: Option<f64>,
    pub af: u8,
    pub dst_addr: Option<IpAddr>,
    pub src_addr: Option<IpAddr>,
    /// Connect start to end of body, ms
    pub rt: f64,
    pub res: u16,
    /// The response's version, e.g. "1.0"
    pub ver: String,
    /// Header-line bytes including their line ends, status line and the
    /// closing blank line not counted
    pub hsize: usize,
    /// Body bytes (dechunked)
    pub bsize: usize,
    /// The stored header entries, `--store-headers` budget applied
    pub header: Option<Vec<String>>,
    /// httpget's "err" text, when the fetch failed after resolution
    pub err: Option<String>,
    /// The lookup's failure, evutil_gai_strerror()'s words: reporterr()'s
    /// TU_DNS_ERR, `{ "dnserr":"…" }` and nothing else in the result
    /// (httpget.c:2038-2043)
    pub dnserr: Option<String>,
    /// `dst_addr` is one atlas_check_addr refuses: reporterr()'s
    /// TU_BAD_ADDR, `{ "error": "address not allowed", "dst_addr":"…" }`
    /// and nothing else (tcputil.c:262-266, httpget.c:2073-2087)
    pub refused: bool,
    /// The response was read to the end (httpget's READ_DONE)
    pub done: bool,
    /// `--read-limit` stopped the reading: `"read-truncated": true` after
    /// "af" (httpget.c:909-910), the response done or `err` saying where
    /// it was cut
    pub read_truncated: bool,
    /// The method sent
    pub method: Method,
    /// The fetch's address among the lookup's, from 1, and their count:
    /// `--all`'s "subid" and "submax" (dnscount, report();
    /// httpget.c:1969-1978, 838, 891-896)
    pub subid: usize,
    pub submax: usize,
    /// gettime_mono's seconds when the connect started: `--all
    /// --combine`'s "time", which is CLOCK_MONOTONIC's, not the Unix time
    /// the result format describes (state->start, httpget.c:886-890,
    /// 2021)
    pub started: u64,
    /// ms from the fetch's start to its first connect: `--etim`'s "ttr" in
    /// the result, the lookup's time and a little more (beforeconnect,
    /// httpget.c:2014-2020, 2152)
    pub connect_ttr: f64,
    /// ms from the connect's start to connected, the TLS handshake
    /// included: "ttc" (writecb's WRITE_FIRST, httpget.c:1817-1822)
    pub ttc: f64,
    /// Each read that brought data: the bytes read before it and ms from
    /// the connect's start. `--eetim`'s "readtiming" (get_input,
    /// httpget.c:1063-1075); the first is "ttfb" (readcb's READ_FIRST,
    /// :1234-1243)
    pub reads: Vec<(usize, f64)>,
}

impl RawHttpOutcome {
    /// ms from the connect's start to the first byte read: "ttfb"
    pub fn ttfb(&self) -> f64 {
        self.reads.first().map_or(0.0, |&(_, t)| t)
    }
}

/// Fetch `url` as evhttpget does, with the line's options: one outcome, or
/// with `--all` one for each address.
pub async fn fetch(url: &HttpUrl, opts: &FetchOptions) -> anyhow::Result<Vec<RawHttpOutcome>> {
    fetch_via(None, target::address_allowed, url, opts).await
}

/// [`fetch`], a host name looked up with `dns`, the probe's resolver when
/// None.
///
/// An address literal of the family `af` asks for is fetched from as it is,
/// with no ttr; one of the other family is a name to evdns, as httpget's
/// hints make it (httpget.c:2166-2169), so -6 with an IPv4 literal is a
/// lookup failure, not an IPv4 connect. A name is
/// looked up as tu_connect_to_name() looks it up (tcputil.c:78): by
/// Starla's evdns, on the runtime, the family `af` asks for, with no bound
/// but evdns's own timeout and attempts (the fetch's timer is set once
/// there is an address). A failure is reported as reporterr() reports
/// TU_DNS_ERR, with the lookup's ttr. Starla asked the system resolver
/// with getaddrinfo() on the blocking pool, cut off at the fetch's
/// timeout, and reported nothing when it failed.
///
/// The addresses are tried in the lookup's order, as tu_connect_to_name
/// tries them (tcputil.c:81-147, 250-337): a connect that fails or times
/// out goes on to the next, and only the last one's is reported, as
/// beforeconnect clears the result for each (httpget.c:353-358,
/// 2008-2010, 2055-2066); a fetch that connected is reported whatever it
/// comes to. With `--all` each address is fetched from and each fetch
/// reported (report() connects again, httpget.c:999-1003). Starla tried
/// the first address alone.
///
/// An address atlas_check_addr refuses (`allowed`, the probe's
/// [`target::address_allowed`]) is reported, not connected to, and ends
/// the fetch (tcputil.c:95-100, 262-266). Starla fetched from 10/8, 127/8
/// and the like. (The reference's `--all` goes on past one, with its
/// dnserr flag left set, into lines that are not JSON.)
///
/// Each connect arms one timer, `timeout` long, that runs to the end of
/// the response, as tu_connect_to_name arms it before each connect and
/// nothing arms it again for the read (tcputil.c:93, 260); Starla gave the
/// read a timeout of its own on top. A failed connect is
/// `"err":"connect: <why>"` with strerror's words (tcputil.c:525-529), not
/// Rust's, which add " (os error N)".
///
/// Over TLS the handshake is part of the connect, as the openssl
/// bufferevent's CONNECTED event comes after it: its time is in rt, its
/// failure is `"err":"connect: <why>"` (eventcb, tcputil.c:514-531) —
/// rustls's words for why, where the reference has OpenSSL's — and a
/// handshake that outlasts the timeout is "connect: timeout"
/// (timeout_callback while connecting, httpget.c:347-362).
async fn fetch_via(
    dns: Option<&Resolver>,
    allowed: fn(IpAddr) -> bool,
    url: &HttpUrl,
    opts: &FetchOptions,
) -> anyhow::Result<Vec<RawHttpOutcome>> {
    // httpget_start's start, from which the first connect's "ttr" runs
    let began = Instant::now();
    let (addrs, ttr) = match target::literal(&url.host, url.port, opts.af) {
        Some(dst) => (vec![dst], None),
        None => {
            let start = Instant::now();
            let found = match dns {
                Some(dns) => dns.addresses(&url.host, opts.af).await,
                None => Resolver::system().addresses(&url.host, opts.af).await,
            };
            let ttr = Some(start.elapsed().as_secs_f64() * 1e3);
            match found {
                Ok(ips) => (
                    ips.into_iter()
                        .map(|ip| SocketAddr::new(ip, url.port))
                        .collect(),
                    ttr,
                ),
                Err(e) => {
                    return Ok(vec![RawHttpOutcome {
                        ttr,
                        af: if opts.af == 6 { 6 } else { 4 },
                        dnserr: Some(e.to_string()),
                        method: opts.method,
                        ..Default::default()
                    }])
                }
            }
        }
    };

    let submax = addrs.len();
    let mut connect_ttr = None;
    let mut outcomes = Vec::new();
    for (i, &dst) in addrs.iter().enumerate() {
        let mut out = RawHttpOutcome {
            ttr,
            af: if dst.is_ipv4() { 4 } else { 6 },
            dst_addr: Some(dst.ip()),
            method: opts.method,
            subid: i + 1,
            submax,
            ..Default::default()
        };
        if !allowed(dst.ip()) {
            out.refused = true;
            outcomes.push(out);
            break;
        }
        out.connect_ttr = *connect_ttr.get_or_insert_with(|| began.elapsed().as_secs_f64() * 1e3);
        let connected = attempt(&mut out, dst, url, opts).await;
        if opts.all || connected || i + 1 == addrs.len() {
            outcomes.push(out);
            if !opts.all {
                break;
            }
        }
    }
    Ok(outcomes)
}

/// One connect to `dst` and the exchange after it, into `out`: false when
/// the connect failed or timed out, and the next address may be tried.
async fn attempt(
    out: &mut RawHttpOutcome,
    dst: SocketAddr,
    url: &HttpUrl,
    opts: &FetchOptions,
) -> bool {
    out.started = mono_secs();
    let start = Instant::now();
    let deadline = tokio::time::Instant::now() + opts.timeout;
    let connect = async {
        let stream = TcpStream::connect(dst).await?;
        let src = stream.local_addr().ok().map(|a| a.ip());
        let stream = if url.tls {
            let name = opts.sni.as_deref().unwrap_or(&url.host);
            Conn::Tls(Box::new(tls_connect(name, stream).await?))
        } else {
            Conn::Plain(stream)
        };
        Ok::<_, std::io::Error>((stream, src))
    };
    let mut stream = match tokio::time::timeout_at(deadline, connect).await {
        Ok(Ok((stream, src))) => {
            out.ttc = start.elapsed().as_secs_f64() * 1000.0;
            out.src_addr = src;
            stream
        }
        Ok(Err(e)) => {
            out.err = Some(format!("connect: {}", crate::tls::strerror(&e)));
            return false;
        }
        Err(_) => {
            out.err = Some("connect: timeout".into());
            return false;
        }
    };

    let head = opts.method == Method::Head;
    let request = request(url, opts);
    let mut raw = Vec::with_capacity(4096);
    let reads = &mut out.reads;
    let mut reader = (opts.read_limit > 0).then(|| Reader::new(opts.read_limit, head));
    let read = async {
        let reader = reader.as_mut();
        match &mut stream {
            Conn::Plain(s) => {
                exchange(s, request.as_bytes(), head, reader, start, &mut raw, reads).await
            }
            Conn::Tls(s) => {
                let s = s.as_mut();
                exchange(s, request.as_bytes(), head, reader, start, &mut raw, reads).await
            }
        }
    };
    let stop = match tokio::time::timeout_at(deadline, read).await {
        Ok(Ok(stop)) => stop,
        Ok(Err(e)) => {
            out.err = Some(format!("error reading response: {e}"));
            return true;
        }
        Err(_) => {
            out.err = Some("timeout reading status".into());
            return true;
        }
    };
    out.rt = start.elapsed().as_secs_f64() * 1000.0;

    let parsed = match stop {
        None => parse_response(&raw, opts.store_headers),
        Some(Stop::End(n)) => parse_response(&raw[..n], opts.store_headers),
        Some(Stop::Cut(cut)) => {
            out.read_truncated = true;
            match cut {
                // err_status and err_header (httpget.c:1168-1188,
                // 1219-1225): the header lines so far, no closing ""
                Cut::Status => Err("bad status line: read truncated".to_string()),
                Cut::Header { parsed } => {
                    out.header = header_so_far(&raw[..parsed], opts.store_headers);
                    Err("bad header line: read truncated".to_string())
                }
                // READ_DONE with the body read so far (:1226-1228)
                Cut::Body { header_end, body } => {
                    parse_response(&raw[..header_end], opts.store_headers)
                        .map(|p| ParsedResponse { bsize: body, ..p })
                }
            }
        }
    };
    match parsed {
        Ok(p) => {
            out.res = p.res;
            out.ver = p.ver;
            out.hsize = p.hsize;
            // a HEAD's answer has no body, whatever its header says
            // (httpget.c:1505-1514)
            out.bsize = if head { 0 } else { p.bsize };
            out.header = p.header;
            out.done = true;
        }
        Err(e) => out.err = Some(e),
    }
    true
}

/// gettime_mono's whole seconds (libbb/atlas_gettime_mono.c): the
/// CLOCK_MONOTONIC reading httpget's state->start holds.
#[cfg(unix)]
fn mono_secs() -> u64 {
    crate::traceroute::net::mono().as_secs()
}

/// gettime_mono's whole seconds where there is no CLOCK_MONOTONIC: the
/// seconds since the process first asked.
#[cfg(not(unix))]
fn mono_secs() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_secs()
}

/// A fetch's connection: TCP, or TLS over it.
enum Conn {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

/// Write the request, then read the response into `buf` to its end, at
/// most [`MAX_RESPONSE_BYTES`] — a HEAD's to the end of its header, as
/// httpget reads no body for one (httpget.c:1505-1514). Each read that
/// brings data is logged in `reads`: the bytes read before it, and ms from
/// `start`.
///
/// With `--read-limit`, `reader` is shown each read as httpget's readcb
/// would be, and the reading stops where it stops: the limit reached, the
/// response ended, or found malformed. A read it did not get to take from
/// is not logged, as get_input logs none (httpget.c:1063-1075).
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &[u8],
    head: bool,
    mut reader: Option<&mut Reader>,
    start: Instant,
    buf: &mut Vec<u8>,
    reads: &mut Vec<(usize, f64)>,
) -> std::io::Result<Option<Stop>> {
    stream.write_all(request).await?;
    let mut chunk = [0u8; 8192];
    let size = if reader.is_some() {
        SOCKET_READ
    } else {
        chunk.len()
    };
    loop {
        let n = match stream.read(&mut chunk[..size]).await {
            Ok(n) => n,
            // A TLS server that closes the connection with no close_notify,
            // as many do after `Connection: close`: the end of the response,
            // as the openssl bufferevent takes it. rustls calls it an error.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(e),
        };
        if n == 0 || buf.len() >= MAX_RESPONSE_BYTES {
            break;
        }
        reads.push((buf.len(), start.elapsed().as_secs_f64() * 1000.0));
        buf.extend_from_slice(&chunk[..n]);
        if let Some(reader) = reader.as_deref_mut() {
            let taken = reader.taken;
            if let Some(stop) = reader.readcb(buf) {
                if reader.taken == taken {
                    reads.pop();
                }
                return Ok(Some(stop));
            }
        }
        // Stop once the body is complete by Content-Length or a chunked
        // terminator, so a server that ignores `Connection: close` does
        // not make the whole-read timeout discard a complete response; a
        // HEAD's once its header has ended.
        let ended = if head {
            header_ended(buf)
        } else {
            response_complete(buf)
        };
        if ended {
            break;
        }
    }
    Ok(None)
}

/// What get_input takes at most: the room in httpget's line buffer,
/// MAX_LINE_LEN less what it holds unparsed (httpget.c:30, 1034-1061).
const LINE_MAX: usize = 2048;

/// What libevent reads from a socket before it runs httpget's readcb, at
/// most (EVBUFFER_MAX_READ): Starla's reads under `--read-limit`.
const SOCKET_READ: usize = 4096;

/// Why [`exchange`] stopped reading before the response's end.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Stop {
    /// `--read-limit` reached
    Cut(Cut),
    /// The response's first `n` bytes are all of it, or all httpget would
    /// read of a response it finds malformed
    End(usize),
}

/// Where `--read-limit` cut the response: in the status line, in the
/// header after `parsed` bytes, or in the body (from where it was in
/// readcb, httpget.c:1212-1229).
#[derive(Debug, Clone, Copy, PartialEq)]
enum Cut {
    Status,
    Header {
        parsed: usize,
    },
    /// The header ends at `header_end`; `body` bytes of the body were read
    Body {
        header_end: usize,
        body: usize,
    },
}

/// httpget's readcb (httpget.c:1200-1760) as far as `--read-limit` needs
/// it: what it takes from the connection, when, and where the limit stops
/// it.
///
/// The limit is checked against the bytes taken (roffset) before each step
/// of the parse — a line of the status, header or chunk framing, the start
/// of the body, a piece of the body — and not as they are read
/// (:1212-1229). A step takes input (get_input) only when what it has is
/// not enough: as much as has come, at most the room in the 2048-byte line
/// buffer. So a read that crosses the limit is parsed one step further: a
/// limit of 2048 or less that the first read reaches stops the response
/// after its status line, however much of the header came. A read that
/// leaves a line unfinished is found over the limit only when the next
/// read comes.
///
/// Starla's reads stand for libevent's socket reads, one readcb each, at
/// most [`SOCKET_READ`] bytes. Where data comes faster or slower than
/// libevent would have read it, the pieces get_input takes, and so the
/// bytes read when the limit is found, can differ by up to a read; so can
/// they over TLS, where the openssl bufferevent reads whole records, up to
/// 16 KB, before readcb runs.
///
/// The body read when the limit is found right after the header is
/// content_offset before anything set it for this response: 0, where the
/// reference's `--all` reports the previous address's.
#[derive(Debug)]
struct Reader {
    limit: usize,
    head: bool,
    state: ReadState,
    /// roffset: bytes taken from what came
    taken: usize,
    /// lineoffset from the response's start: bytes parsed
    parsed: usize,
    status: u16,
    content_length: Option<usize>,
    chunked: bool,
    header_end: usize,
    /// content_offset: body bytes read
    body: usize,
    /// tot_chunked: the body bytes at the end of the chunk being read
    chunk_end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ReadState {
    Status,
    Header,
    Body,
    Simple,
    Chunked,
    ChunkBody,
    ChunkEnd,
    Trailer,
    /// READ_DONE, which the limit check still sees: a response whose last
    /// line came in the read that crossed the limit is done and truncated
    Done,
}

impl Reader {
    fn new(limit: usize, head: bool) -> Self {
        Self {
            limit,
            head,
            state: ReadState::Status,
            taken: 0,
            parsed: 0,
            status: 0,
            content_length: None,
            chunked: false,
            header_end: 0,
            body: 0,
            chunk_end: 0,
        }
    }

    /// get_input: take what has come, as much as the line buffer has room
    /// for.
    fn get_input(&mut self, buf: &[u8]) {
        let room = LINE_MAX - (self.taken - self.parsed);
        self.taken += room.min(buf.len() - self.taken);
    }

    /// The next line taken, from where the parse is, without its line end:
    /// None when it has not all come (and the parse waits for more).
    fn line<'a>(&mut self, buf: &'a [u8]) -> Option<&'a [u8]> {
        let nl = |r: &Self| buf[r.parsed..r.taken].iter().position(|&b| b == b'\n');
        let nl = match nl(self) {
            Some(nl) => nl,
            None => {
                self.get_input(buf);
                nl(self)?
            }
        };
        let line = &buf[self.parsed..self.parsed + nl];
        self.parsed += nl + 1;
        Some(line.strip_suffix(b"\r").unwrap_or(line))
    }

    /// readcb, `buf` all that came so far: None when it waits for more,
    /// else where the reading stops.
    fn readcb(&mut self, buf: &[u8]) -> Option<Stop> {
        use ReadState::*;
        let malformed = Some(Stop::End(buf.len()));
        loop {
            if self.taken >= self.limit {
                return Some(Stop::Cut(match self.state {
                    Status => Cut::Status,
                    Header => Cut::Header {
                        parsed: self.parsed,
                    },
                    _ => Cut::Body {
                        header_end: self.header_end,
                        body: self.body,
                    },
                }));
            }
            let line = match self.state {
                Status | Header | Chunked | ChunkEnd | Trailer => match self.line(buf) {
                    Some(line) => Some(String::from_utf8_lossy(line).into_owned()),
                    // "line too long" (:1290-1298)
                    None if self.taken - self.parsed >= LINE_MAX => return malformed,
                    None => return None,
                },
                Body | Simple | ChunkBody | Done => None,
            };
            let line = line.as_deref().unwrap_or("");
            match self.state {
                Status => match status_line(line) {
                    Ok((status, _)) => {
                        self.status = status;
                        self.state = Header;
                    }
                    Err(_) => return malformed,
                },
                Header if line.is_empty() => {
                    self.header_end = self.parsed;
                    self.state = Body;
                }
                Header => framing(line, &mut self.content_length, &mut self.chunked),
                Body => {
                    // no body whatever the header says (:1505-1514)
                    self.state = if self.head
                        || matches!(self.status, 204 | 304)
                        || self.status / 100 == 1
                    {
                        Done
                    } else {
                        self.body = 0;
                        if self.chunked {
                            Chunked
                        } else {
                            Simple
                        }
                    };
                }
                Simple | ChunkBody => {
                    let end = match self.state {
                        Simple => self.content_length,
                        _ => Some(self.chunk_end),
                    };
                    if end.is_some_and(|end| self.body >= end) {
                        self.state = if self.state == Simple { Done } else { ChunkEnd };
                        continue;
                    }
                    if self.parsed >= self.taken {
                        self.get_input(buf);
                        if self.parsed >= self.taken {
                            return None;
                        }
                    }
                    let mut len = self.taken - self.parsed;
                    if self.state == ChunkBody {
                        len = len.min(self.chunk_end - self.body);
                    }
                    self.body += len;
                    self.parsed += len;
                }
                Chunked => {
                    let size = line.split(|c: char| c.is_ascii_whitespace()).next();
                    match size.and_then(|s| usize::from_str_radix(s, 16).ok()) {
                        Some(0) => self.state = Trailer,
                        Some(size) => {
                            self.chunk_end += size;
                            self.state = ChunkBody;
                        }
                        None => return malformed,
                    }
                }
                ChunkEnd if line.is_empty() => self.state = Chunked,
                ChunkEnd => return malformed,
                Trailer if line.is_empty() => self.state = Done,
                Trailer => {}
                Done => return Some(Stop::End(self.parsed)),
            }
        }
    }
}

/// The header lines in `raw` after its status line, stored as
/// `--store-headers` stores them, with no closing "": the header was cut
/// before its end (err_header, httpget.c:1180-1184).
fn header_so_far(raw: &[u8], max: usize) -> Option<Vec<String>> {
    let lines: Vec<String> = raw
        .split_inclusive(|&b| b == b'\n')
        .skip(1)
        .map(|line| {
            let line = line.strip_suffix(b"\n").unwrap_or(line);
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            String::from_utf8_lossy(line).into_owned()
        })
        .collect();
    let mut stored = stored_headers(&lines, max)?;
    if stored.last().is_some_and(String::is_empty) {
        stored.pop();
    }
    Some(stored)
}

/// Whether `buf` holds a whole header: the status line and header lines,
/// then an empty line.
fn header_ended(buf: &[u8]) -> bool {
    buf.windows(2).any(|w| w == b"\n\n") || buf.windows(3).any(|w| w == b"\n\r\n")
}

/// TLS over `stream`, sending `name` as the server name: a host name as
/// one, an address literal as none (rustls sends no IP in SNI; OpenSSL
/// sends the literal's text).
async fn tls_connect(
    name: &str,
    stream: TcpStream,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let server = rustls::pki_types::ServerName::try_from(name.to_string())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    tokio_rustls::TlsConnector::from(tls_config())
        .connect(server, stream)
        .await
}

/// The client httpget's create_bev makes for https (tcputil.c:352-453):
/// the library's defaults, no ALPN, and no verification of the server's
/// certificate — SSL_CTX_set_verify is called only for --http2 with a
/// certificate name. The handshake's own signatures are still checked, as
/// OpenSSL checks them with verification off.
///
/// No session is resumed: create_bev makes a new SSL_CTX for every
/// connection (tcputil.c:350, 368), so each handshake is a full one.
/// rustls's default keeps 256 sessions and resumes them, which would take a
/// round trip off a TLS 1.2 fetch's rt. Its store here keeps none, but the
/// ClientHello still asks for a TLS 1.2 ticket (an empty SessionTicket
/// extension), as OpenSSL's with a fresh SSL_CTX does: rustls's
/// `Resumption::disabled()` alone would leave the extension out.
///
/// Where rustls stays stricter than OpenSSL with verification off, the
/// fetch fails as `connect: …` where httpget's goes on: TLS 1.0 and 1.1,
/// which rustls does not speak; and an end-entity certificate webpki
/// cannot parse to check the handshake's signature with (not v3, an
/// unknown critical extension) or an RSA key under 2048 bits.
fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let mut config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .expect("aws-lc-rs supports the default versions")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
                .with_no_client_auth();
            config.resumption = rustls::client::Resumption::disabled()
                .tls12_resumption(rustls::client::Tls12Resumption::SessionIdOrTickets);
            Arc::new(config)
        })
        .clone()
}

/// Takes any certificate, as httpget does without `--http2`.
#[derive(Debug)]
struct AnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedResponse {
    pub res: u16,
    pub ver: String,
    pub hsize: usize,
    pub bsize: usize,
    pub header: Option<Vec<String>>,
}

/// Whether `buf` holds a response the read loop can stop at: headers done and
/// the body complete by Content-Length or a chunked terminator. A response
/// with neither is read until the server closes the connection.
fn response_complete(buf: &[u8]) -> bool {
    let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
    let body = &buf[header_end + 4..];
    if let Some(len) = headers
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
    {
        return body.len() >= len;
    }
    if headers
        .lines()
        .any(|l| l.trim_start().starts_with("transfer-encoding:") && l.contains("chunked"))
    {
        return body.ends_with(b"0\r\n\r\n");
    }
    false
}

/// Parse a complete response the way httpget's read loop does: the status
/// line, header lines counted into hsize (with their line ends), then the
/// body by Content-Length, chunked encoding, or to the end.
pub fn parse_response(raw: &[u8], store_headers: usize) -> Result<ParsedResponse, String> {
    let mut pos = 0;
    let next_line = |pos: &mut usize| -> Option<(String, usize)> {
        let rest = raw.get(*pos..)?;
        let nl = rest.iter().position(|&b| b == b'\n')?;
        let len = nl + 1;
        let mut line = &rest[..nl];
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        *pos += len;
        Some((String::from_utf8_lossy(line).into_owned(), len))
    };

    let (status, _) = next_line(&mut pos).ok_or("bad status line: no line")?;
    let (res, ver) = status_line(&status)?;

    let mut lines = Vec::new();
    let mut hsize = 0;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    loop {
        let (line, len) = next_line(&mut pos).ok_or("bad header line: truncated")?;
        if line.is_empty() {
            break;
        }
        hsize += len;
        framing(&line, &mut content_length, &mut chunked);
        lines.push(line);
    }

    let body = &raw[pos..];
    let bsize = if chunked {
        dechunked_len(body)
    } else {
        content_length.map_or(body.len(), |n| n.min(body.len()))
    };

    Ok(ParsedResponse {
        res,
        ver,
        hsize,
        bsize,
        header: stored_headers(&lines, store_headers),
    })
}

/// A status line's code and version ("1.1").
fn status_line(status: &str) -> Result<(u16, String), String> {
    let bad = || format!("bad status line: {status}");
    let rest = status
        .get(..5)
        .filter(|p| p.eq_ignore_ascii_case("HTTP/"))
        .map(|_| &status[5..])
        .ok_or_else(bad)?;
    let (ver, code) = rest.split_once(' ').ok_or_else(bad)?;
    let (major, minor) = ver
        .split_once('.')
        .and_then(|(a, b)| Some((a.parse::<u8>().ok()?, b.parse::<u8>().ok()?)))
        .ok_or_else(bad)?;
    let res: u16 = code
        .trim_start()
        .get(..3)
        .and_then(|c| c.parse().ok())
        .ok_or_else(bad)?;
    Ok((res, format!("{major}.{minor}")))
}

/// What a header line says of how the body is framed: its length, or
/// chunked.
fn framing(line: &str, content_length: &mut Option<usize>, chunked: &mut bool) {
    if let Some((name, value)) = line.split_once(':') {
        let name = name.trim();
        if name.eq_ignore_ascii_case("Content-Length") {
            *content_length = value.trim().parse().ok();
        } else if name.eq_ignore_ascii_case("Transfer-Encoding")
            && value.trim().to_ascii_lowercase().starts_with("chunked")
        {
            *chunked = true;
        }
    }
}

fn dechunked_len(mut body: &[u8]) -> usize {
    let mut total = 0;
    while let Some(nl) = body.iter().position(|&b| b == b'\n') {
        let size_line = String::from_utf8_lossy(&body[..nl]);
        let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or(""), 16);
        let Ok(size) = size else { break };
        if size == 0 {
            break;
        }
        let data = nl + 1;
        let take = size.min(body.len().saturating_sub(data));
        total += take;
        body = body.get(data + take..).unwrap_or(&[]);
        // the chunk's own CRLF
        body = body
            .strip_prefix(b"\r\n")
            .or(body.strip_prefix(b"\n"))
            .unwrap_or(body);
    }
    total
}

/// httpget's `--store-headers` budget: a line goes in whole while the lines so
/// far plus it and one byte fit; the first that does not is cut to the space
/// left and marked "[...]"; after that nothing. A closing "" follows when the
/// budget was not overrun. None when headers are not stored.
pub fn stored_headers(lines: &[String], max: usize) -> Option<Vec<String>> {
    if max == 0 {
        return None;
    }
    let mut out = Vec::new();
    let mut tot = 0usize;
    for line in lines {
        let len = line.len();
        // httpget: tot_headers+len+1 <= max_headers
        if tot + len < max {
            out.push(line.clone());
            tot += len;
        } else if tot <= max {
            let mut keep = max - tot;
            while !line.is_char_boundary(keep) {
                keep -= 1;
            }
            out.push(format!("{}[...]", &line[..keep]));
            tot += len + 1;
        }
    }
    if tot <= max {
        out.push(String::new());
    }
    Some(out)
}

/// httpget's add_str_quoted: `"` and `\` escaped, printable ASCII as is,
/// every other byte as \u00XX.
pub fn quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for &b in s.as_bytes() {
        match b {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(b as char);
            }
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\u{b:04x}")),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a test fetches with: `af`, `--store-headers`, the timeout and
    /// `--sni`.
    fn opts(af: u8, store_headers: usize, timeout: Duration, sni: Option<&str>) -> FetchOptions {
        FetchOptions {
            af,
            store_headers,
            timeout,
            sni: sni.map(str::to_string),
            ..Default::default()
        }
    }

    /// The one outcome of a fetch without --all.
    fn one(mut outs: Vec<RawHttpOutcome>) -> RawHttpOutcome {
        assert_eq!(outs.len(), 1, "{outs:?}");
        outs.remove(0)
    }

    /// ip-echo.ripe.net's answer to reference probe 1000004 (13027, from
    /// RIPE's archive): the header list and sizes it stored.
    const ECHO: &[u8] = b"HTTP/1.0 200 OK\r\nX-Client-IP: 2001:418:1::33\r\nContent-Type: text/plain\r\nAccess-Control-Allow-Origin: *\r\nServer: BigIP\r\nConnection: close\r\nContent-Length: 14\r\n\r\n2001:418:1::33";

    #[test]
    fn an_echo_answer_is_reported_as_the_reference_stored_it() {
        let p = parse_response(ECHO, 1024).unwrap();
        assert_eq!(
            (p.res, p.ver.as_str(), p.hsize, p.bsize),
            (200, "1.0", 141, 14)
        );
        assert_eq!(
            p.header.unwrap(),
            [
                "X-Client-IP: 2001:418:1::33",
                "Content-Type: text/plain",
                "Access-Control-Allow-Origin: *",
                "Server: BigIP",
                "Connection: close",
                "Content-Length: 14",
                "",
            ]
        );
        assert_eq!(parse_response(ECHO, 0).unwrap().header, None);
    }

    #[test]
    fn the_header_budget_cuts_like_httpget() {
        let lines: Vec<String> = ["Aaaa: 1", "Bbbb: 22", "Cccc: 333"]
            .map(String::from)
            .into();
        // 7+1 fits in 10; 7+8+1 = 16 does not: cut to 3 bytes, then nothing.
        assert_eq!(stored_headers(&lines, 10).unwrap(), ["Aaaa: 1", "Bbb[...]"]);
        // Two lines fit (7+8+1 <= 16), the third is cut to the 1 byte left.
        assert_eq!(
            stored_headers(&lines, 16).unwrap(),
            ["Aaaa: 1", "Bbbb: 22", "C[...]"]
        );
        // Without a third line the budget holds, so the closing "" follows.
        assert_eq!(
            stored_headers(&lines[..2], 16).unwrap(),
            ["Aaaa: 1", "Bbbb: 22", ""]
        );
        assert_eq!(
            stored_headers(&lines, 1024).unwrap(),
            ["Aaaa: 1", "Bbbb: 22", "Cccc: 333", ""]
        );
    }

    #[test]
    fn urls_split_as_parse_url_splits_them() {
        let u = parse_http_url("http://[2001:67c:2e8:16::c100:68d]").unwrap();
        assert_eq!(
            (
                u.hostport.as_str(),
                u.host.as_str(),
                u.port,
                u.path.as_str()
            ),
            (
                "[2001:67c:2e8:16::c100:68d]",
                "2001:67c:2e8:16::c100:68d",
                80,
                "/"
            )
        );
        let u = parse_http_url("http://www.ripe.net/favicon.ico").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("www.ripe.net", 80, "/favicon.ico")
        );
        let u = parse_http_url("http://193.0.6.141:8080/x?y=1").unwrap();
        assert_eq!(
            (u.hostport.as_str(), u.port, u.path.as_str()),
            ("193.0.6.141:8080", 8080, "/x?y=1")
        );
        let u = parse_http_url("HTTPS://secure.example/x").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str(), u.tls),
            ("secure.example", 443, "/x", true)
        );
        let u = parse_http_url("https://[2001:db8::1]:8443").unwrap();
        assert_eq!((u.port, u.tls), (8443, true));
        assert!(!parse_http_url("http://x/").unwrap().tls);
        assert!(parse_http_url("ftp://x/").is_err());
    }

    #[test]
    fn the_request_is_httpgets() {
        let u = parse_http_url("http://[2001:67c:2e8:16::c100:68d]").unwrap();
        let with = |method, http10| FetchOptions {
            method,
            http10,
            ..Default::default()
        };
        assert_eq!(
            request(&u, &with(Method::Get, false)),
            "GET / HTTP/1.1\r\nHost: [2001:67c:2e8:16::c100:68d]\r\nConnection: close\r\nUser-Agent: httpget for atlas.ripe.net\r\n\r\n"
        );
        assert!(request(&u, &with(Method::Get, true)).starts_with("GET / HTTP/1.0\r\n"));
        // --head and --post send theirs; a POST says its body's type and
        // length (writecb, httpget.c:1826-1866)
        assert_eq!(
            request(&u, &with(Method::Head, false)),
            "HEAD / HTTP/1.1\r\nHost: [2001:67c:2e8:16::c100:68d]\r\nConnection: close\r\nUser-Agent: httpget for atlas.ripe.net\r\n\r\n"
        );
        assert_eq!(
            request(&u, &with(Method::Post, false)),
            "POST / HTTP/1.1\r\nHost: [2001:67c:2e8:16::c100:68d]\r\nConnection: close\r\nUser-Agent: httpget for atlas.ripe.net\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n\r\n"
        );
        // --user-agent is sent as given; --host is the Host header's, port
        // and all, in place of the URL's (httpget.c:730-735, 1834-1839).
        // Starla sent its own User-Agent and the URL's host whatever the
        // line said.
        let u = parse_http_url("http://193.0.6.139:8080/4096?x=1").unwrap();
        let opts = FetchOptions {
            user_agent: Some("RIPE Atlas test agent/1.0".into()),
            host: Some("anchor.example".into()),
            ..Default::default()
        };
        assert_eq!(
            request(&u, &opts),
            "GET /4096?x=1 HTTP/1.1\r\nHost: anchor.example\r\nConnection: close\r\nUser-Agent: RIPE Atlas test agent/1.0\r\n\r\n"
        );
        // an empty --user-agent is still the header's value
        let opts = FetchOptions {
            user_agent: Some(String::new()),
            ..Default::default()
        };
        assert!(request(&u, &opts).contains("\r\nHost: 193.0.6.139:8080\r\n"));
        assert!(request(&u, &opts).contains("\r\nUser-Agent: \r\n"));
        assert_eq!(Method::from_name("head"), Method::Head);
        assert_eq!(Method::from_name("POST"), Method::Post);
        assert_eq!(Method::from_name("GET"), Method::Get);
    }

    /// A HEAD is read to the end of its answer's header: the body its
    /// Content-Length announces does not come, and the server need not
    /// close (httpget.c:1505-1514). The reads are logged from offset 0,
    /// and the times run connect, first byte, end.
    #[tokio::test]
    async fn a_head_is_read_to_the_end_of_its_header() {
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = server.accept().await.unwrap();
            let mut req = vec![0u8; 512];
            let n = s.read(&mut req).await.unwrap();
            assert!(req[..n].starts_with(b"HEAD /x HTTP/1.1\r\n"));
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(s);
        });
        let url = parse_http_url(&format!("http://127.0.0.1:{port}/x")).unwrap();
        let head = FetchOptions {
            method: Method::Head,
            ..opts(4, 0, Duration::from_secs(2), None)
        };
        let started = Instant::now();
        let out = one(fetch_via(None, anywhere, &url, &head).await.unwrap());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(out.done && out.err.is_none(), "{out:?}");
        assert_eq!(
            (out.method, out.res, out.hsize, out.bsize),
            (Method::Head, 200, 22, 0)
        );
        assert_eq!(out.reads.first().map(|&(o, _)| o), Some(0));
        assert!(
            0.0 < out.ttc && out.ttc <= out.ttfb() && out.ttfb() <= out.rt,
            "{out:?}"
        );
    }

    /// What a [`Reader`] limited to `limit` makes of a response that comes
    /// in `reads`: where it stops, if it does, and how many of the reads it
    /// took from.
    fn limited(limit: usize, head: bool, reads: &[&[u8]]) -> (Option<Stop>, usize) {
        let mut reader = Reader::new(limit, head);
        let mut buf = Vec::new();
        for (i, read) in reads.iter().enumerate() {
            buf.extend_from_slice(read);
            let taken = reader.taken;
            if let Some(stop) = reader.readcb(&buf) {
                return (Some(stop), i + usize::from(reader.taken > taken));
            }
        }
        (None, reads.len())
    }

    /// 49 bytes of header announcing 6000 of body.
    const HEADER: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 6000\r\nX-A: 1\r\n\r\n";

    /// readcb checks the bytes it has taken against --read-limit before
    /// each step of the parse, taking at most 2048 at a time
    /// (httpget.c:1034-1101, 1212-1229). In the body the response is done
    /// with what was read; a read that brings more than the limit before
    /// the header is parsed stops it in the header, its status line
    /// parsed.
    #[test]
    fn the_read_limit_stops_where_readcb_finds_it() {
        let body = [b'x'; 3000];
        // The header alone, then 3000 bytes: 2048 of them taken, and the
        // limit found in the body
        assert_eq!(
            limited(2000, false, &[HEADER, &body, &body]),
            (
                Some(Stop::Cut(Cut::Body {
                    header_end: 49,
                    body: 2048
                })),
                2
            )
        );
        // All at once: the first 2048 bytes parsed to the end (1999 of the
        // body), the next 2048 taken, and the limit found
        let all: Vec<u8> = [HEADER, &body, &body].concat();
        assert_eq!(
            limited(2049, false, &[&all]),
            (
                Some(Stop::Cut(Cut::Body {
                    header_end: 49,
                    body: 4047
                })),
                1
            )
        );
        // ... and with a limit under the first 2048, it is found after the
        // status line, the whole header read or not
        for limit in [10, 100, 2048] {
            assert_eq!(
                limited(limit, false, &[&all]),
                (Some(Stop::Cut(Cut::Header { parsed: 17 })), 1),
                "{limit}"
            );
        }
        // A read that leaves a line unfinished: the limit is found when the
        // next read comes, before readcb takes from it
        assert_eq!(
            limited(10, false, &[b"HTTP/1.1 2", b"00 OK\r\n\r\n"]),
            (Some(Stop::Cut(Cut::Status)), 1)
        );
        assert_eq!(
            limited(
                30,
                false,
                &[b"HTTP/1.1 200 OK\r\nContent-Le", b"ngth: 0\r\n\r\n"]
            ),
            (Some(Stop::Cut(Cut::Header { parsed: 36 })), 2)
        );
        // Within the limit the response ends as it says: at its length, at
        // a HEAD's header, at the chunked body's trailer
        assert_eq!(
            limited(
                4096,
                false,
                &[b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello"]
            ),
            (Some(Stop::End(43)), 1)
        );
        assert_eq!(limited(4096, true, &[HEADER]), (Some(Stop::End(49)), 1));
        let chunked: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n3\r\nefg\r\n0\r\n\r\n";
        assert_eq!(limited(4096, false, &[chunked]), (Some(Stop::End(69)), 1));
        // ... and one whose last line came with the read that crossed the
        // limit is done and truncated, as readcb checks READ_DONE too
        assert_eq!(
            limited(68, false, &[&chunked[..67], &chunked[67..]]),
            (
                Some(Stop::Cut(Cut::Body {
                    header_end: 47,
                    body: 7
                })),
                2
            )
        );
        // A malformed response is read no further, and is not truncated
        assert_eq!(
            limited(4096, false, &[b"garbage\r\n"]),
            (Some(Stop::End(9)), 1)
        );
        // Not there yet: more is read
        assert_eq!(limited(8000, false, &[HEADER, &body]), (None, 2));
    }

    /// A server on 127.0.0.1 for one connection that checks the request
    /// with `check`, then writes each of `writes` 100 ms apart and holds
    /// the connection.
    async fn paced_server(check: fn(&str), writes: Vec<Vec<u8>>) -> u16 {
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = server.accept().await.unwrap();
            let mut req = vec![0u8; 512];
            let n = s.read(&mut req).await.unwrap();
            check(&String::from_utf8_lossy(&req[..n]));
            for write in writes {
                s.write_all(&write).await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        port
    }

    /// --user-agent and --host go out in the request; --read-limit stops
    /// the reading in the body, the response done and "read-truncated"
    /// (httpget.c:909-910, 1212-1229), without waiting for the rest or the
    /// timeout. Starla sent its own User-Agent and the URL's host, and read
    /// to the end.
    #[tokio::test]
    async fn a_read_limit_ends_the_fetch_in_the_body() {
        let header = b"HTTP/1.1 200 OK\r\nContent-Length: 10000\r\n\r\n".to_vec();
        let header_len = header.len();
        let port = paced_server(
            |req| {
                assert!(req.starts_with("GET /10000 HTTP/1.1\r\nHost: anchor.example\r\nConnection: close\r\nUser-Agent: test agent\r\n\r\n"), "{req}");
            },
            vec![header, vec![b'x'; 3000], vec![b'x'; 3000], vec![b'x'; 4000]],
        )
        .await;
        let url = parse_http_url(&format!("http://127.0.0.1:{port}/10000")).unwrap();
        let limited = FetchOptions {
            user_agent: Some("test agent".into()),
            host: Some("anchor.example".into()),
            read_limit: 2000,
            ..opts(4, 0, Duration::from_secs(5), None)
        };
        let started = Instant::now();
        let out = one(fetch_via(None, anywhere, &url, &limited).await.unwrap());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(
            out.done && out.read_truncated && out.err.is_none(),
            "{out:?}"
        );
        assert_eq!((out.res, out.hsize), (200, 23));
        // 2048 of the 3000 when they come in one read
        assert!(
            2000 - header_len <= out.bsize && out.bsize <= 3000,
            "{out:?}"
        );
        let body = crate::http::result_body(1001, 1, &out);
        assert!(
            body.contains("{ \"method\":\"GET\", \"af\": 4, \"read-truncated\": true, \"dst_addr\":\"127.0.0.1\""),
            "{body}"
        );
    }

    /// A status line the limit cuts short: "bad status line: read
    /// truncated", found when the next read comes, which is not logged as
    /// one readcb took from (httpget.c:1063-1075, 1218-1222).
    #[tokio::test]
    async fn a_read_limit_in_the_status_line_is_an_error() {
        let port = paced_server(
            |_| {},
            vec![b"HTTP/1.1 2".to_vec(), b"00 OK\r\n\r\n".to_vec()],
        )
        .await;
        let url = parse_http_url(&format!("http://127.0.0.1:{port}/")).unwrap();
        let limited = FetchOptions {
            read_limit: 10,
            ..opts(4, 1024, Duration::from_secs(5), None)
        };
        let out = one(fetch_via(None, anywhere, &url, &limited).await.unwrap());
        assert!(!out.done && out.read_truncated, "{out:?}");
        assert_eq!(out.err.as_deref(), Some("bad status line: read truncated"));
        assert_eq!(out.header, None, "no header list before the status line");
        assert_eq!(out.reads.len(), 1, "{:?}", out.reads);
    }

    /// The lookup's addresses are tried in turn: a refused connect goes on
    /// to the next, and the fetch that connected is the one reported
    /// (tu_restart_connect, tcputil.c:81-147; httpget.c:2055-2066). With
    /// --all each address is fetched from and reported, with its subid and
    /// submax, and the first connect's ttr. Starla tried the first address
    /// alone.
    #[tokio::test]
    async fn the_addresses_are_tried_in_turn() {
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = server.accept().await.unwrap();
                let mut req = vec![0u8; 512];
                let _ = s.read(&mut req).await.unwrap();
                s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await
                    .unwrap();
            }
        });
        // the hosts file's, in its order; nothing listens on [::1]
        let v6 = IpAddr::from(std::net::Ipv6Addr::LOCALHOST);
        let v4 = IpAddr::from([127, 0, 0, 1]);
        let dns = Resolver::new(
            target::ResolvConf::default(),
            vec![("two.example".into(), v6), ("two.example".into(), v4)],
        );
        let url = parse_http_url(&format!("http://two.example:{port}/")).unwrap();
        let mut either = opts(0, 0, Duration::from_secs(2), None);
        let out = one(fetch_via(Some(&dns), anywhere, &url, &either)
            .await
            .unwrap());
        assert!(out.done && out.err.is_none(), "{out:?}");
        assert_eq!((out.dst_addr, out.subid, out.submax), (Some(v4), 2, 2));
        assert!(out.ttr.is_some());

        either.all = true;
        let outs = fetch_via(Some(&dns), anywhere, &url, &either)
            .await
            .unwrap();
        assert_eq!(outs.len(), 2, "{outs:?}");
        let (failed, fetched) = (&outs[0], &outs[1]);
        assert_eq!(
            (failed.dst_addr, failed.subid, failed.submax),
            (Some(v6), 1, 2)
        );
        assert!(
            failed.err.as_deref().unwrap().starts_with("connect: "),
            "{failed:?}"
        );
        assert!(!failed.done && failed.src_addr.is_none() && failed.reads.is_empty());
        assert_eq!((fetched.dst_addr, fetched.subid), (Some(v4), 2));
        assert!(fetched.done && fetched.bsize == 2, "{fetched:?}");
        assert_eq!(
            failed.connect_ttr, fetched.connect_ttr,
            "the first connect's"
        );
    }

    #[test]
    fn chunked_and_unframed_bodies_are_sized() {
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n3\r\nefg\r\n0\r\n\r\n";
        assert_eq!(parse_response(chunked, 0).unwrap().bsize, 7);
        let unframed = b"HTTP/1.1 404 Not Found\r\nServer: x\r\n\r\nhello";
        let p = parse_response(unframed, 0).unwrap();
        assert_eq!((p.res, p.bsize, p.hsize), (404, 5, 11));
        assert!(parse_response(b"garbage\r\n\r\n", 0).is_err());
    }

    /// The tests' servers are on 127.0.0.1, which atlas_check_addr refuses.
    fn anywhere(_: IpAddr) -> bool {
        true
    }

    /// An address atlas_check_addr refuses, a literal's or a name's, is
    /// reported and not connected to (tcputil.c:262-266). Starla fetched
    /// from any.
    #[tokio::test]
    async fn a_refused_address_is_not_fetched_from() {
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        let (dns, _) = target::local_resolver(
            Some(|name| (name == "lan.example").then(|| IpAddr::from([127, 0, 0, 1]))),
            Duration::from_secs(2),
            1,
        )
        .await;
        for (url, ttr) in [
            (format!("http://127.0.0.1:{port}/"), false),
            (format!("https://lan.example:{port}/"), true),
        ] {
            let url = parse_http_url(&url).unwrap();
            let out = one(fetch_via(
                Some(&dns),
                target::address_allowed,
                &url,
                &opts(4, 0, Duration::from_secs(5), None),
            )
            .await
            .unwrap());
            assert!(out.refused, "{out:?}");
            assert_eq!(out.dst_addr, Some(IpAddr::from([127, 0, 0, 1])));
            assert_eq!(out.ttr.is_some(), ttr);
        }
        let nothing = tokio::time::timeout(Duration::from_millis(100), server.accept()).await;
        assert!(nothing.is_err(), "connected to a refused address");
    }

    /// One timer covers the connect and the read, as httpget's: a server
    /// that takes the connection at once and answers nothing ends the
    /// fetch at the timeout, not twice it. A refused connect is strerror's
    /// words.
    #[tokio::test]
    async fn one_timer_covers_connect_and_read() {
        let mute = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = mute.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (s, _) = mute.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(s);
        });
        let url = parse_http_url(&format!("http://127.0.0.1:{port}/")).unwrap();
        let started = Instant::now();
        let out = one(fetch_via(
            None,
            anywhere,
            &url,
            &opts(4, 0, Duration::from_millis(400), None),
        )
        .await
        .unwrap());
        let took = started.elapsed();
        assert_eq!(out.err.as_deref(), Some("timeout reading status"));
        assert!(took < Duration::from_millis(700), "{took:?}");

        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let url = parse_http_url(&format!("http://127.0.0.1:{port}/")).unwrap();
        let out = one(fetch_via(
            None,
            anywhere,
            &url,
            &opts(4, 0, Duration::from_secs(2), None),
        )
        .await
        .unwrap());
        assert_eq!(out.err.as_deref(), Some("connect: Connection refused"));
    }

    #[test]
    fn quoting_is_add_str_quoteds() {
        assert_eq!(quoted("a\"b\\c"), r#""a\"b\\c""#);
        assert_eq!(quoted("t\tx\u{e9}"), r#""t\u0009x\u00c3\u00a9""#);
    }

    /// Against a local server that answers like ip-echo: the fetch reports
    /// the address the server saw, sizes, version and our real source.
    #[tokio::test]
    async fn a_fetch_reports_what_the_server_said() {
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, peer) = server.accept().await.unwrap();
            let mut req = vec![0u8; 512];
            let n = s.read(&mut req).await.unwrap();
            let req = String::from_utf8_lossy(&req[..n]).into_owned();
            assert!(req.starts_with("GET /x HTTP/1.1\r\n"), "{req}");
            assert!(
                req.contains("\r\nUser-Agent: httpget for atlas.ripe.net\r\n"),
                "{req}"
            );
            let ip = peer.ip().to_string();
            let reply = format!(
                "HTTP/1.0 200 OK\r\nX-Client-IP: {ip}\r\nContent-Length: {}\r\n\r\n{ip}",
                ip.len()
            );
            s.write_all(reply.as_bytes()).await.unwrap();
        });
        let url = parse_http_url(&format!("http://127.0.0.1:{port}/x")).unwrap();
        let out = one(fetch_via(
            None,
            anywhere,
            &url,
            &opts(4, 1024, Duration::from_secs(5), None),
        )
        .await
        .unwrap());
        assert!(out.done && out.err.is_none(), "{out:?}");
        assert_eq!(
            (out.res, out.ver.as_str(), out.bsize, out.af),
            (200, "1.0", 9, 4)
        );
        assert_eq!(out.header.unwrap()[0], "X-Client-IP: 127.0.0.1");
        assert_eq!(out.src_addr, Some("127.0.0.1".parse().unwrap()));
        assert_eq!(out.ttr, None, "a literal host is not resolved");
    }

    /// A host name is looked up as tu_connect_to_name() looks it up, by
    /// Starla's evdns with the family -4/-6 asks for (tcputil.c:78), and a
    /// failure is reporterr()'s TU_DNS_ERR: `"dnserr"` alone in the result,
    /// the lookup's ttr beside it (httpget.c:2038-2043, 862-866). A
    /// resolver that never answers ends the lookup when evdns's timeout and
    /// attempts run out. Starla's getaddrinfo() on the blocking pool held a
    /// thread until the system resolver gave up, and a failure reported
    /// nothing.
    #[tokio::test]
    async fn a_host_name_is_looked_up_as_tu_connect_to_name_looks_it_up() {
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = server.accept().await.unwrap();
            let mut req = vec![0u8; 512];
            let _ = s.read(&mut req).await.unwrap();
            s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });
        let (dns, mut asked) = target::local_resolver(
            Some(|name| (name == "echo.example").then(|| IpAddr::from([127, 0, 0, 1]))),
            Duration::from_secs(2),
            1,
        )
        .await;
        let fetch = |url: String, dns| async move {
            let url = parse_http_url(&url).unwrap();
            one(fetch_via(
                Some(dns),
                anywhere,
                &url,
                &opts(4, 0, Duration::from_secs(5), None),
            )
            .await
            .unwrap())
        };
        let out = fetch(format!("http://echo.example:{port}/"), &dns).await;
        assert!(out.done && out.dnserr.is_none(), "{out:?}");
        assert_eq!(out.dst_addr, Some(IpAddr::from([127, 0, 0, 1])));
        assert!(out.ttr.is_some(), "a name has its ttr");
        assert_eq!(
            asked.try_recv().unwrap(),
            ("echo.example".into(), hickory_proto::rr::RecordType::A)
        );

        let out = fetch(format!("http://nx.example:{port}/"), &dns).await;
        let ttr = out.ttr.expect("a failed lookup has its ttr too");
        let body = crate::http::result_body(12023, 1, &out);
        assert_eq!(
            body,
            format!(
                "\"id\":\"12023\", \"fw\":{}, \"mver\": \"2.6.4\", \"lts\":0, \"time\":1, \
                 \"ttr\":{ttr:.6}, \"result\":[ {{ \"dnserr\":\"nodename nor servname provided, \
                 or not known\" }} ]",
                starla_common::FIRMWARE_VERSION
            )
        );

        let (dns, _) = target::local_resolver(None, Duration::from_millis(200), 2).await;
        let start = Instant::now();
        let out = fetch(format!("http://echo.example:{port}/"), &dns).await;
        let took = start.elapsed();
        assert!(
            took >= Duration::from_millis(400) && took < Duration::from_secs(2),
            "{took:?}"
        );
        assert_eq!(
            out.dnserr.as_deref(),
            Some("non-recoverable failure in name resolution")
        );
    }

    /// A DER element: `tag`, the length, `content`.
    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            n if n < 0x80 => out.push(n as u8),
            n if n < 0x100 => out.extend([0x81, n as u8]),
            n => out.extend([0x82, (n >> 8) as u8, n as u8]),
        }
        out.extend_from_slice(content);
        out
    }

    /// A self-signed P-256 certificate and its key, the key derived from a
    /// fixed string as tls::tests derives its own, so no key material sits
    /// in the tree: the twin's certificate (tls::cert::tests) with its
    /// public key swapped for the derived one, of the same length, and
    /// signed again.
    fn self_signed() -> (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivateSec1KeyDer};
        use sha2::Digest;
        let scalar = sha2::Sha256::digest(b"starla evhttpget https test server");
        let mut sec1 = vec![0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20];
        sec1.extend_from_slice(&scalar);
        sec1.extend_from_slice(&[
            0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        ]);
        let key = PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(sec1));
        let signing = rustls::crypto::aws_lc_rs::default_provider()
            .key_provider
            .load_private_key(key.clone_key())
            .unwrap();
        let spki = signing.public_key().unwrap();

        let twin = crate::tls::cert::tests::ref_cert_der();
        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
        // signatureValue }, its length in two bytes, as the tbs's
        let tbs_len = 4 + usize::from(u16::from_be_bytes([twin[6], twin[7]]));
        let mut tbs = twin[4..4 + tbs_len].to_vec();
        let at = tbs
            .windows(spki.len())
            .position(|w| w.starts_with(&spki[..27]))
            .expect("a P-256 public key in the twin's certificate");
        tbs[at..at + spki.len()].copy_from_slice(&spki);
        let algorithm = &twin[4 + tbs_len..4 + tbs_len + 12];
        let signature = signing
            .choose_scheme(&[rustls::SignatureScheme::ECDSA_NISTP256_SHA256])
            .unwrap()
            .sign(&tbs)
            .unwrap();
        let mut bits = vec![0];
        bits.extend_from_slice(&signature);
        let mut content = tbs;
        content.extend_from_slice(algorithm);
        content.extend(der(0x03, &bits));
        (CertificateDer::from(der(0x30, &content)), key)
    }

    /// A TLS server on 127.0.0.1 for one connection, with a self-signed
    /// certificate: it answers one request with `reply`, then drops the
    /// connection with no close_notify, as servers do after
    /// `Connection: close`. The server name the client sent, once it has.
    async fn tls_server(
        reply: &'static [u8],
    ) -> (u16, tokio::sync::oneshot::Receiver<Option<String>>) {
        let (cert, key) = self_signed();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (sent, sni) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let _ = sent.send(tls.get_ref().1.server_name().map(str::to_string));
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match tls.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => request.extend_from_slice(&buf[..n]),
                }
            }
            assert!(request.starts_with(b"GET /x HTTP/1.1\r\nHost: "));
            tls.write_all(reply).await.unwrap();
            tls.flush().await.unwrap();
        });
        (port, sni)
    }

    /// An https:// URL is fetched as an http:// one, over TLS: the name
    /// looked up by Starla's evdns with its ttr, the header lines as the
    /// server sent them, the source address the connection's, the server
    /// name the host's or --sni's, and a certificate no one has signed
    /// taken as httpget takes it. Starla fetched it through reqwest, with
    /// none of that.
    #[tokio::test]
    async fn an_https_fetch_is_httpgets_over_tls() {
        const REPLY: &[u8] =
            b"HTTP/1.1 200 OK\r\nX-Client-IP: 127.0.0.1\r\nContent-Length: 9\r\nConnection: close\r\n\r\n127.0.0.1";
        let (dns, _) = target::local_resolver(
            Some(|name| (name == "secure.example").then(|| IpAddr::from([127, 0, 0, 1]))),
            Duration::from_secs(2),
            1,
        )
        .await;
        for (sni, sent) in [
            (None, "secure.example"),
            (Some("other.example"), "other.example"),
        ] {
            let (port, seen) = tls_server(REPLY).await;
            let url = parse_http_url(&format!("https://secure.example:{port}/x")).unwrap();
            let out = one(fetch_via(
                Some(&dns),
                anywhere,
                &url,
                &opts(4, 1024, Duration::from_secs(5), sni),
            )
            .await
            .unwrap());
            assert!(out.done && out.err.is_none(), "{out:?}");
            assert_eq!((out.res, out.ver.as_str(), out.bsize), (200, "1.1", 9));
            assert_eq!(
                out.header.unwrap(),
                [
                    "X-Client-IP: 127.0.0.1",
                    "Content-Length: 9",
                    "Connection: close",
                    ""
                ]
            );
            assert!(out.ttr.is_some(), "a name has its ttr");
            assert_eq!(out.dst_addr, Some(IpAddr::from([127, 0, 0, 1])));
            assert_eq!(out.src_addr, Some(IpAddr::from([127, 0, 0, 1])));
            assert_eq!(seen.await.unwrap().as_deref(), Some(sent));
        }

        // A name evdns does not know: dnserr, as for http://
        let url = parse_http_url("https://nx.example/x").unwrap();
        let out = one(fetch_via(
            Some(&dns),
            anywhere,
            &url,
            &opts(4, 0, Duration::from_secs(5), None),
        )
        .await
        .unwrap());
        assert_eq!(
            out.dnserr.as_deref(),
            Some("nodename nor servname provided, or not known")
        );
        assert!(out.ttr.is_some());
    }

    /// A handshake that fails, or does not end within the timeout, is a
    /// failed connect, as the openssl bufferevent's error and the timer
    /// while connecting make it (tcputil.c:514-531, httpget.c:347-362).
    #[tokio::test]
    async fn a_failed_handshake_is_a_failed_connect() {
        // Not TLS: answers in plain HTTP and closes
        let plain = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = plain.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = plain.accept().await.unwrap();
            let _ = s.write_all(b"HTTP/1.0 400 Bad Request\r\n\r\n").await;
        });
        let url = parse_http_url(&format!("https://127.0.0.1:{port}/x")).unwrap();
        let out = one(fetch_via(
            None,
            anywhere,
            &url,
            &opts(4, 0, Duration::from_secs(5), None),
        )
        .await
        .unwrap());
        let err = out.err.as_deref().unwrap();
        assert!(err.starts_with("connect: "), "{err}");
        assert!(!out.done);
        // httpget takes its source address in connected(), after the
        // handshake (httpget.c:2094-2119): none here
        assert_eq!(out.src_addr, None);
        let body = crate::http::result_body(12023, 1, &out);
        assert!(body.contains("\"err\":\"connect: "), "{body}");
        assert!(!body.contains("\"rt\""), "{body}");

        // Takes the connection and says nothing
        let mute = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = mute.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (s, _) = mute.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(s);
        });
        let url = parse_http_url(&format!("https://127.0.0.1:{port}/x")).unwrap();
        let out = one(fetch_via(
            None,
            anywhere,
            &url,
            &opts(4, 0, Duration::from_millis(300), None),
        )
        .await
        .unwrap());
        assert_eq!(out.err.as_deref(), Some("connect: timeout"));
    }

    /// The live echo server, the URLs of built-ins 12027 and 13027. Network,
    /// so ignored: `cargo test -p starla-measurements -- --ignored
    /// live_ip_echo`.
    #[tokio::test]
    #[ignore]
    async fn live_ip_echo() {
        for (url, af) in [
            ("http://193.0.6.141", 4),
            ("http://[2001:67c:2e8:16::c100:68d]", 6),
        ] {
            let out = one(fetch(
                &parse_http_url(url).unwrap(),
                &opts(af, 1024, Duration::from_secs(10), None),
            )
            .await
            .unwrap());
            println!("{url}: {out:?}");
            if out.err.is_some() {
                continue; // no route in that family from here
            }
            let header = out.header.unwrap();
            let echo = header
                .iter()
                .find_map(|h| h.strip_prefix("X-Client-IP: "))
                .expect("X-Client-IP");
            assert_eq!(out.bsize, echo.len(), "the body is the echoed address");
            assert_eq!(header.last().map(String::as_str), Some(""));
        }
    }
}
