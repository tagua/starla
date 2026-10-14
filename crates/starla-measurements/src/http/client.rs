//! HTTP client logic

use super::HttpConfig;
use crate::target::Resolver;
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant};

/// HTTP measurement result in RIPE Atlas format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResult {
    /// Total round-trip time in ms
    pub rt: f64,
    /// HTTP status code
    #[serde(rename = "res")]
    pub status: u16,
    /// HTTP version (e.g., "1.1", "2")
    pub ver: String,
    /// Method used
    pub method: String,
    /// Destination name (URL host)
    pub dst_name: String,
    /// Response header size in bytes
    #[serde(rename = "hsize")]
    pub header_size: usize,
    /// Response body size in bytes
    #[serde(rename = "bsize")]
    pub body_size: usize,
    /// Time to first byte (TTFB) in ms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttfb: Option<f64>,
    /// Time to connect in ms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttc: Option<f64>,
    /// Request headers sent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<Vec<String>>,
    /// Response header lines, "name: value" (names as reqwest gives them)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_headers: Option<Vec<String>>,
    /// Readbuf - partial body content for debugging
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readbuf: Option<String>,
    /// Error message if request failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
    /// The address the response came from: the connection's peer
    #[serde(skip)]
    pub remote_addr: Option<SocketAddr>,
}

/// Starla's evdns as reqwest's resolver: an https:// host name is looked
/// up as an http:// one is (raw::fetch, tu_connect_to_name), by
/// [`Resolver`] on the runtime, for the measurement's family alone with -4
/// or -6. reqwest's own resolver was getaddrinfo on tokio's blocking pool,
/// where a lookup that never resolves holds a thread past the request's
/// timeout. Address literals never reach a resolver.
struct Evdns {
    resolver: Resolver,
    af: u8,
}

impl reqwest::dns::Resolve for Evdns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let (resolver, af) = (self.resolver.clone(), self.af);
        let name = name.as_str().to_string();
        Box::pin(async move {
            let addrs = resolver.addresses(&name, af).await?;
            // Port 0: reqwest puts in the URL's
            let addrs: reqwest::dns::Addrs =
                Box::new(addrs.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

/// A fetch through reqwest, its host name looked up by the probe's resolver
/// ([`Resolver::system`]).
pub async fn execute_http_request(config: &HttpConfig) -> anyhow::Result<HttpResult> {
    execute_http_request_with(config, Resolver::system()).await
}

/// A fetch through reqwest, its host name looked up by `resolver`.
pub(crate) async fn execute_http_request_with(
    config: &HttpConfig,
    resolver: Resolver,
) -> anyhow::Result<HttpResult> {
    let mut builder = Client::builder()
        .dns_resolver(std::sync::Arc::new(Evdns {
            resolver,
            af: config.af,
        }))
        .timeout(Duration::from_millis(config.timeout_ms))
        .danger_accept_invalid_certs(!config.verify_ssl)
        .redirect(reqwest::redirect::Policy::none()); // Usually probes follow redirects manually or not at all

    // -4/-6: connect over that family only, as httpget asks evdns for it
    // alone (httpget.c:2163-2170). A local address of one family makes the
    // connector try only the target's addresses of that family.
    match config.af {
        4 => builder = builder.local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        6 => builder = builder.local_address(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        _ => {}
    }

    if let Some(ref v) = config.version {
        if v == "2" {
            builder = builder.http2_prior_knowledge();
        } else if v == "1.1" {
            builder = builder.http1_only();
        }
    }

    let client = builder.build()?;

    let method = Method::from_str(&config.method.to_uppercase()).unwrap_or(Method::GET);

    // Extract host from URL
    let url = reqwest::Url::parse(&config.url)?;
    let dst_name = url.host_str().unwrap_or("unknown").to_string();

    let mut request = client.request(method.clone(), &config.url);

    // Track headers sent
    let mut headers_sent = Vec::new();
    if let Some(ref headers) = config.headers {
        for (k, v) in headers {
            request = request.header(k, v);
            headers_sent.push(format!("{}: {}", k, v));
        }
    }

    if let Some(ref body) = config.body {
        request = request.body(body.clone());
    }

    let start = Instant::now();
    let response = request.send().await?;
    let rtt = start.elapsed().as_secs_f64() * 1000.0;
    let remote_addr = response.remote_addr();

    let status = response.status().as_u16();
    let version = match response.version() {
        reqwest::Version::HTTP_09 => "0.9",
        reqwest::Version::HTTP_10 => "1.0",
        reqwest::Version::HTTP_11 => "1.1",
        reqwest::Version::HTTP_2 => "2",
        reqwest::Version::HTTP_3 => "3",
        _ => "unknown",
    }
    .to_string();

    // Calculate sizes
    let headers = response.headers();
    let response_headers: Vec<String> = headers
        .iter()
        .map(|(k, v)| format!("{}: {}", k, String::from_utf8_lossy(v.as_bytes())))
        .collect();
    let mut header_size = 0;
    for (k, v) in headers {
        header_size += k.as_str().len() + v.as_bytes().len() + 4; // key + ": "
                                                                  // + value + "
                                                                  // \r\n"
    }

    let body = response.bytes().await?;
    let body_size = body.len();

    // Get first 512 bytes of body for readbuf (for debugging)
    let readbuf = if body_size > 0 {
        let truncated = &body[..body_size.min(512)];
        String::from_utf8_lossy(truncated).to_string().into()
    } else {
        None
    };

    Ok(HttpResult {
        rt: rtt,
        status,
        ver: version,
        method: method.to_string(),
        dst_name,
        header_size,
        body_size,
        ttfb: None, // Would need streaming response to measure TTFB accurately
        ttc: None,  // Connection time not easily available in reqwest
        header: if headers_sent.is_empty() {
            None
        } else {
            Some(headers_sent)
        },
        response_headers: Some(response_headers),
        readbuf,
        err: None,
        remote_addr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::local_resolver;
    use hickory_proto::rr::RecordType;

    fn config(url: String, af: u8) -> HttpConfig {
        HttpConfig {
            url,
            method: "GET".into(),
            headers: None,
            body: None,
            timeout_ms: 2_000,
            verify_ssl: false,
            version: None,
            af,
            store_headers: 0,
            http10: false,
        }
    }

    /// An https:// host name is looked up by Starla's evdns, for the
    /// measurement's family: the name's address is connected to, and a
    /// name evdns does not know fails with its error, not getaddrinfo's.
    #[tokio::test]
    async fn an_https_name_is_looked_up_by_starlas_evdns() {
        let (resolver, mut asked) = local_resolver(
            Some(|name| (name == "secure.test").then(|| "127.0.0.1".parse().unwrap())),
            Duration::from_secs(1),
            1,
        )
        .await;
        // Takes the connection and closes it: the TLS handshake fails, after
        // the lookup and the connect
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = tokio::spawn(async move {
            let accept = tokio::time::timeout(Duration::from_secs(5), listener.accept());
            matches!(accept.await, Ok(Ok(_)))
        });

        let url = format!("https://secure.test:{port}/");
        let fetched = execute_http_request_with(&config(url, 4), resolver.clone()).await;
        assert!(fetched.is_err(), "no TLS server: {fetched:?}");
        assert!(
            accepted.await.unwrap(),
            "connected to secure.test's address"
        );
        assert_eq!(
            asked.recv().await,
            Some(("secure.test".to_string(), RecordType::A))
        );
        assert!(asked.try_recv().is_err(), "-4 asks for A alone");

        let url = "https://missing.test/".to_string();
        let error = execute_http_request_with(&config(url, 6), resolver)
            .await
            .unwrap_err();
        assert_eq!(
            asked.recv().await,
            Some(("missing.test".to_string(), RecordType::AAAA))
        );
        let chain = format!("{error:#}");
        assert!(
            chain.contains("nodename nor servname provided, or not known"),
            "{chain}"
        );
    }
}
