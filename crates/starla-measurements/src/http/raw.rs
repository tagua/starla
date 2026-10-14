//! HTTP GET as the reference probe's evhttpget does it
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

/// The request httpget writes for a GET.
pub fn request(url: &HttpUrl, http10: bool) -> String {
    format!(
        "GET {} HTTP/1.{}\r\nHost: {}\r\nConnection: close\r\nUser-Agent: {}\r\n\r\n",
        url.path,
        if http10 { '0' } else { '1' },
        url.hostport,
        USER_AGENT
    )
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
}

/// Fetch `url` as evhttpget does. `af` is 4, 6, or 0 for either; `sni`,
/// `--sni`, the server name an https fetch sends in place of the host.
pub async fn fetch(
    url: &HttpUrl,
    af: u8,
    http10: bool,
    store_headers: usize,
    timeout: Duration,
    sni: Option<&str>,
) -> anyhow::Result<RawHttpOutcome> {
    fetch_via(
        None,
        target::address_allowed,
        url,
        af,
        http10,
        store_headers,
        timeout,
        sni,
    )
    .await
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
/// An address atlas_check_addr refuses (`allowed`, the probe's
/// [`target::address_allowed`]) is reported, not connected to
/// (tcputil.c:262-266). Starla fetched from 10/8, 127/8 and the like.
///
/// One timer, `timeout` long, runs from the connect to the end of the
/// response, as tu_connect_to_name arms it before each connect and nothing
/// arms it again for the read (tcputil.c:260); Starla gave the read a
/// timeout of its own on top. A failed connect is `"err":"connect: <why>"`
/// with strerror's words (tcputil.c:525-529), not Rust's, which add
/// " (os error N)".
///
/// Over TLS the handshake is part of the connect, as the openssl
/// bufferevent's CONNECTED event comes after it: its time is in rt, its
/// failure is `"err":"connect: <why>"` (eventcb, tcputil.c:514-531) —
/// rustls's words for why, where the reference has OpenSSL's — and a
/// handshake that outlasts the timeout is "connect: timeout"
/// (timeout_callback while connecting, httpget.c:347-362).
#[allow(clippy::too_many_arguments)]
async fn fetch_via(
    dns: Option<&Resolver>,
    allowed: fn(IpAddr) -> bool,
    url: &HttpUrl,
    af: u8,
    http10: bool,
    store_headers: usize,
    timeout: Duration,
    sni: Option<&str>,
) -> anyhow::Result<RawHttpOutcome> {
    let (dst, ttr) = match target::literal(&url.host, url.port, af) {
        Some(dst) => (dst, None),
        None => {
            let lookup = match dns {
                Some(dns) => dns.lookup(&url.host, af).await,
                None => target::lookup(&url.host, af).await,
            };
            let ttr = lookup.dst_name.ttr;
            match lookup.addr {
                Ok(ip) => (SocketAddr::new(ip, url.port), ttr),
                Err(e) => {
                    return Ok(RawHttpOutcome {
                        ttr,
                        af: if af == 6 { 6 } else { 4 },
                        dnserr: Some(e.to_string()),
                        ..Default::default()
                    })
                }
            }
        }
    };

    let mut out = RawHttpOutcome {
        ttr,
        af: if dst.is_ipv4() { 4 } else { 6 },
        dst_addr: Some(dst.ip()),
        ..Default::default()
    };
    if !allowed(dst.ip()) {
        out.refused = true;
        return Ok(out);
    }

    let start = Instant::now();
    let deadline = tokio::time::Instant::now() + timeout;
    let connect = async {
        let stream = TcpStream::connect(dst).await?;
        let src = stream.local_addr().ok().map(|a| a.ip());
        let stream = if url.tls {
            let name = sni.unwrap_or(&url.host);
            Conn::Tls(Box::new(tls_connect(name, stream).await?))
        } else {
            Conn::Plain(stream)
        };
        Ok::<_, std::io::Error>((stream, src))
    };
    let mut stream = match tokio::time::timeout_at(deadline, connect).await {
        Ok(Ok((stream, src))) => {
            out.src_addr = src;
            stream
        }
        Ok(Err(e)) => {
            out.err = Some(format!("connect: {}", crate::tls::strerror(&e)));
            return Ok(out);
        }
        Err(_) => {
            out.err = Some("connect: timeout".into());
            return Ok(out);
        }
    };

    let request = request(url, http10);
    let read = async {
        match &mut stream {
            Conn::Plain(s) => exchange(s, request.as_bytes()).await,
            Conn::Tls(s) => exchange(s.as_mut(), request.as_bytes()).await,
        }
    };
    let raw = match tokio::time::timeout_at(deadline, read).await {
        Ok(Ok(raw)) => raw,
        Ok(Err(e)) => {
            out.err = Some(format!("error reading response: {e}"));
            return Ok(out);
        }
        Err(_) => {
            out.err = Some("timeout reading status".into());
            return Ok(out);
        }
    };
    out.rt = start.elapsed().as_secs_f64() * 1000.0;

    match parse_response(&raw, store_headers) {
        Ok(p) => {
            out.res = p.res;
            out.ver = p.ver;
            out.hsize = p.hsize;
            out.bsize = p.bsize;
            out.header = p.header;
            out.done = true;
        }
        Err(e) => out.err = Some(e),
    }
    Ok(out)
}

/// A fetch's connection: TCP, or TLS over it.
enum Conn {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

/// Write the request, then read the response to its end, at most
/// [`MAX_RESPONSE_BYTES`].
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &[u8],
) -> std::io::Result<Vec<u8>> {
    stream.write_all(request).await?;
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 8192];
    loop {
        let n = match stream.read(&mut chunk).await {
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
        buf.extend_from_slice(&chunk[..n]);
        // Stop once the body is complete by Content-Length or a chunked
        // terminator, so a server that ignores `Connection: close` does
        // not make the whole-read timeout discard a complete response.
        if response_complete(&buf) {
            break;
        }
    }
    Ok(buf)
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
    let rest = status
        .get(..5)
        .filter(|p| p.eq_ignore_ascii_case("HTTP/"))
        .map(|_| &status[5..])
        .ok_or_else(|| format!("bad status line: {status}"))?;
    let (ver, code) = rest
        .split_once(' ')
        .ok_or_else(|| format!("bad status line: {status}"))?;
    let (major, minor) = ver
        .split_once('.')
        .and_then(|(a, b)| Some((a.parse::<u8>().ok()?, b.parse::<u8>().ok()?)))
        .ok_or_else(|| format!("bad status line: {status}"))?;
    let res: u16 = code
        .trim_start()
        .get(..3)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| format!("bad status line: {status}"))?;

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
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            if name.eq_ignore_ascii_case("Content-Length") {
                content_length = value.trim().parse().ok();
            } else if name.eq_ignore_ascii_case("Transfer-Encoding")
                && value.trim().to_ascii_lowercase().starts_with("chunked")
            {
                chunked = true;
            }
        }
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
        ver: format!("{major}.{minor}"),
        hsize,
        bsize,
        header: stored_headers(&lines, store_headers),
    })
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
        assert_eq!(
            request(&u, false),
            "GET / HTTP/1.1\r\nHost: [2001:67c:2e8:16::c100:68d]\r\nConnection: \
             close\r\nUser-Agent: httpget for atlas.ripe.net\r\n\r\n"
        );
        assert!(request(&u, true).starts_with("GET / HTTP/1.0\r\n"));
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
            let out = fetch_via(
                Some(&dns),
                target::address_allowed,
                &url,
                4,
                false,
                0,
                Duration::from_secs(5),
                None,
            )
            .await
            .unwrap();
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
        let out = fetch_via(
            None,
            anywhere,
            &url,
            4,
            false,
            0,
            Duration::from_millis(400),
            None,
        )
        .await
        .unwrap();
        let took = started.elapsed();
        assert_eq!(out.err.as_deref(), Some("timeout reading status"));
        assert!(took < Duration::from_millis(700), "{took:?}");

        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let url = parse_http_url(&format!("http://127.0.0.1:{port}/")).unwrap();
        let out = fetch_via(
            None,
            anywhere,
            &url,
            4,
            false,
            0,
            Duration::from_secs(2),
            None,
        )
        .await
        .unwrap();
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
        let out = fetch_via(
            None,
            anywhere,
            &url,
            4,
            false,
            1024,
            Duration::from_secs(5),
            None,
        )
        .await
        .unwrap();
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
            fetch_via(
                Some(dns),
                anywhere,
                &url,
                4,
                false,
                0,
                Duration::from_secs(5),
                None,
            )
            .await
            .unwrap()
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
            let out = fetch_via(
                Some(&dns),
                anywhere,
                &url,
                4,
                false,
                1024,
                Duration::from_secs(5),
                sni,
            )
            .await
            .unwrap();
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
        let out = fetch_via(
            Some(&dns),
            anywhere,
            &url,
            4,
            false,
            0,
            Duration::from_secs(5),
            None,
        )
        .await
        .unwrap();
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
        let out = fetch_via(
            None,
            anywhere,
            &url,
            4,
            false,
            0,
            Duration::from_secs(5),
            None,
        )
        .await
        .unwrap();
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
        let out = fetch_via(
            None,
            anywhere,
            &url,
            4,
            false,
            0,
            Duration::from_millis(300),
            None,
        )
        .await
        .unwrap();
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
            let out = fetch(
                &parse_http_url(url).unwrap(),
                af,
                false,
                1024,
                Duration::from_secs(10),
                None,
            )
            .await
            .unwrap();
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
