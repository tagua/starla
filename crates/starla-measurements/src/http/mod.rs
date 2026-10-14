//! HTTP measurement implementation

pub mod client;
pub mod raw;

use crate::traits::Measurement;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use starla_common::{
    MeasurementData, MeasurementId, MeasurementResult, MeasurementType, ProbeId, Timestamp,
};
use starla_network::get_source_addr_for_dest;
use std::fmt::Write;
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    pub url: String,
    pub method: String, // GET, POST, etc.
    pub headers: Option<std::collections::HashMap<String, String>>,
    pub body: Option<String>,
    pub timeout_ms: u64,
    pub verify_ssl: bool,
    pub version: Option<String>, // "1.1" or "2"
    /// `-4` / `-6`: the address family to fetch over (0: either)
    #[serde(default)]
    pub af: u8,
    /// `--store-headers N`: report response header lines within N bytes
    #[serde(default)]
    pub store_headers: usize,
    /// `-0`: send HTTP/1.0 instead of HTTP/1.1
    #[serde(default)]
    pub http10: bool,
}

pub struct Http {
    pub config: HttpConfig,
    pub probe_id: ProbeId,
    pub msm_id: MeasurementId,
}

/// evhttpget's RESULT body (probe-busybox/eperd/httpget.c report()): the
/// envelope is id, version, lts, time and (for a name) ttr, with everything
/// else inside the result object. "lts":0 is the placeholder the results
/// crate replaces with the lts the result was queued at.
///
/// 2026-10-13: RIPE had stored no HTTP result from either Starla probe
/// (1015560 in 33 days, 1018212), while a reference probe's 12023/12027/
/// 13023/13027 land hourly. Starla's line carried dst_name/af/dst_addr/proto
/// in the envelope and no stored headers, so the ip-echo built-ins never
/// told RIPE the probe's addresses.
pub fn result_body(msm_id: u64, gstart: i64, out: &raw::RawHttpOutcome) -> String {
    let mut r = String::from("{ ");
    if let Some(dnserr) = &out.dnserr {
        // reporterr()'s TU_DNS_ERR: report() adds nothing to it
        let _ = write!(r, "\"dnserr\":{} }}", raw::quoted(dnserr));
        return envelope(msm_id, gstart, out, &r);
    }
    if let Some(header) = &out.header {
        r.push_str("\"header\": [");
        for (i, line) in header.iter().enumerate() {
            if i > 0 {
                r.push(',');
            }
            r.push(' ');
            r.push_str(&raw::quoted(line));
        }
        r.push_str(" ], ");
    }
    if let Some(err) = &out.err {
        let _ = write!(r, "\"err\":{}, ", raw::quoted(err));
    }
    let _ = write!(r, "\"method\":\"GET\", \"af\": {}", out.af);
    if let Some(dst) = out.dst_addr {
        let _ = write!(r, ", \"dst_addr\":\"{dst}\"");
    }
    if let Some(src) = out.src_addr {
        let _ = write!(r, ", \"src_addr\":\"{src}\"");
    }
    if out.done {
        let _ = write!(
            r,
            ", \"rt\":{:.6}, \"res\":{}, \"ver\":\"{}\", \"hsize\":{}, \"bsize\":{}",
            out.rt, out.res, out.ver, out.hsize, out.bsize
        );
    }
    r.push_str(" }");
    envelope(msm_id, gstart, out, &r)
}

/// report()'s line around the result object `r`.
fn envelope(msm_id: u64, gstart: i64, out: &raw::RawHttpOutcome, r: &str) -> String {
    let mut body = format!(
        "\"id\":\"{}\", \"fw\":{}, \"mver\": \"2.6.4\", \"lts\":0, \"time\":{}, ",
        msm_id,
        starla_common::FIRMWARE_VERSION,
        gstart
    );
    if let Some(ttr) = out.ttr {
        let _ = write!(body, "\"ttr\":{ttr:.6}, ");
    }
    let _ = write!(body, "\"result\":[ {r} ]");
    body
}

#[async_trait]
impl Measurement for Http {
    fn measurement_type(&self) -> starla_common::MeasurementType {
        starla_common::MeasurementType::Http
    }

    async fn execute(&self) -> anyhow::Result<MeasurementResult> {
        let gstart = Timestamp::now();
        let timeout = Duration::from_millis(self.config.timeout_ms);
        let out = match raw::parse_http_url(&self.config.url) {
            Ok(url) => {
                raw::fetch(
                    &url,
                    self.config.af,
                    self.config.http10,
                    self.config.store_headers,
                    timeout,
                )
                .await?
            }
            // https: still through reqwest, reported in the same shape.
            Err(_) => self.fetch_tls().await?,
        };

        let af = out.af;
        let dst_addr = out
            .dst_addr
            .unwrap_or_else(|| "0.0.0.0".parse().expect("literal"));
        Ok(MeasurementResult {
            fw: starla_common::FIRMWARE_VERSION,
            measurement_type: MeasurementType::Http,
            prb_id: self.probe_id,
            msm_id: self.msm_id,
            timestamp: gstart,
            af,
            dst_addr,
            dst_name: None,
            src_addr: out.src_addr,
            proto: None,
            ttl: None,
            size: None,
            data: MeasurementData::FullLine(result_body(self.msm_id.0, gstart.0, &out)),
        })
    }
}

impl Http {
    /// An https:// fetch through reqwest, its host name looked up by
    /// Starla's evdns as an http:// one is (client::Evdns). Header lines
    /// are rebuilt from the parsed map (names lowercased), so stored
    /// headers are approximate here.
    ///
    /// dst_addr is the address the connection went to, as httpget reports
    /// the one it connected to (beforeconnect, httpget.c:1980-1989, 910-918).
    /// Starla looked the host up a second time for it, with a blocking
    /// getaddrinfo on a runtime worker (`to_socket_addrs`), and reported
    /// that lookup's first address of the family, whichever one reqwest
    /// had fetched from.
    async fn fetch_tls(&self) -> anyhow::Result<raw::RawHttpOutcome> {
        let results = client::execute_http_request(&self.config).await?;
        let dst: Option<IpAddr> = results.remote_addr.map(|a| a.ip());
        Ok(raw::RawHttpOutcome {
            ttr: None,
            af: if dst.is_some_and(|d| d.is_ipv6()) {
                6
            } else {
                4
            },
            dst_addr: dst,
            src_addr: dst.and_then(|d| get_source_addr_for_dest(d).ok()),
            rt: results.rt,
            res: results.status,
            ver: results.ver,
            hsize: results.header_size,
            bsize: results.body_size,
            header: raw::stored_headers(
                results.response_headers.as_deref().unwrap_or(&[]),
                self.config.store_headers,
            ),
            err: None,
            dnserr: None,
            done: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape RIPE stored for reference probe 1000004's 13027 result.
    #[test]
    fn the_body_is_evhttpgets() {
        let p = raw::parse_response(
            b"HTTP/1.0 200 OK\r\nX-Client-IP: 2602:f337:ed:4174:2020:2041:746c:6173\r\nContent-Length: 37\r\n\r\n2602:f337:ed:4174:2020:2041:746c:6173",
            1024,
        )
        .unwrap();
        let out = raw::RawHttpOutcome {
            ttr: None,
            af: 6,
            dst_addr: Some("2001:67c:2e8:16::c100:68d".parse().unwrap()),
            src_addr: Some("2602:f337:ed:4174:2020:2041:746c:6173".parse().unwrap()),
            rt: 269.242169,
            res: p.res,
            ver: p.ver,
            hsize: p.hsize,
            bsize: p.bsize,
            header: p.header,
            err: None,
            dnserr: None,
            done: true,
        };
        let body = result_body(13027, 1791860335, &out);
        assert_eq!(
            body,
            format!(
                "\"id\":\"13027\", \"fw\":{}, \"mver\": \"2.6.4\", \"lts\":0, \"time\":1791860335, \
                 \"result\":[ {{ \"header\": [ \"X-Client-IP: 2602:f337:ed:4174:2020:2041:746c:6173\", \
                 \"Content-Length: 37\", \"\" ], \"method\":\"GET\", \"af\": 6, \
                 \"dst_addr\":\"2001:67c:2e8:16::c100:68d\", \
                 \"src_addr\":\"2602:f337:ed:4174:2020:2041:746c:6173\", \"rt\":269.242169, \
                 \"res\":200, \"ver\":\"1.0\", \"hsize\":72, \"bsize\":37 }} ]",
                starla_common::FIRMWARE_VERSION
            )
        );
        // RIPE parses it as JSON: it must be an object once wrapped.
        let line: serde_json::Value = serde_json::from_str(&format!("{{ {body} }}")).unwrap();
        assert_eq!(
            line["result"][0]["header"][0],
            "X-Client-IP: 2602:f337:ed:4174:2020:2041:746c:6173"
        );
        for gone in ["dst_name", "proto", "af", "dst_addr"] {
            assert!(
                line.get(gone).is_none(),
                "{gone} is not in evhttpget's envelope"
            );
        }
    }

    #[test]
    fn a_name_reports_ttr_and_a_failure_reports_err() {
        let out = raw::RawHttpOutcome {
            ttr: Some(1.5),
            af: 4,
            dst_addr: Some("193.0.6.141".parse().unwrap()),
            err: Some("connect: timeout".into()),
            ..Default::default()
        };
        let body = result_body(12023, 1, &out);
        assert!(body.contains("\"time\":1, \"ttr\":1.500000, \"result\":[ { \"err\":\"connect: timeout\", \"method\":\"GET\", \"af\": 4, \"dst_addr\":\"193.0.6.141\" } ]"), "{body}");
        assert!(!body.contains("\"rt\""), "{body}");
    }

    /// An HTTP server on `listener` that answers every request with `body`.
    fn serve(listener: tokio::net::TcpListener, body: &'static str) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buf[..n]),
                        }
                    }
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(reply.as_bytes()).await;
                });
            }
        });
    }

    /// reqwest's fetch reports the address its connection went to, of the
    /// family -4/-6 asked for, as httpget reports the address it connected
    /// to (httpget.c:1980-1989): a server on 127.0.0.1 and one on ::1, the
    /// same port, answer with bodies of different sizes. Starla looked the
    /// host up again with a blocking getaddrinfo on the worker for
    /// dst_addr, and reqwest connected over either family.
    #[tokio::test]
    async fn the_dst_addr_is_the_connections() {
        let v4 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = v4.local_addr().unwrap().port();
        let v6 = tokio::net::TcpListener::bind(("::1", port)).await.ok();
        // The -6 case needs "localhost" to name ::1 as well; some hosts' files
        // give it 127.0.0.1 only (aletheia's), and then -6 has no address.
        let localhost_v6 = tokio::net::lookup_host(("localhost", port))
            .await
            .is_ok_and(|mut a| a.any(|a| a.is_ipv6()));
        let mut cases = vec![(4, "127.0.0.1", 2)];
        serve(v4, "v4");
        if let Some(v6) = v6.filter(|_| localhost_v6) {
            serve(v6, "v6v6");
            cases.push((6, "::1", 4));
        }
        for (af, dst, bsize) in cases {
            let http = Http {
                config: HttpConfig {
                    url: format!("http://localhost:{port}/"),
                    method: "GET".into(),
                    headers: None,
                    body: None,
                    timeout_ms: 5000,
                    verify_ssl: true,
                    version: None,
                    af,
                    store_headers: 0,
                    http10: false,
                },
                probe_id: ProbeId(1018212),
                msm_id: MeasurementId(12023),
            };
            let out = http.fetch_tls().await.unwrap();
            assert_eq!(out.dst_addr, Some(dst.parse().unwrap()), "-{af}");
            assert_eq!(out.af, af);
            assert_eq!(out.bsize, bsize, "-{af}: the server that answered");
            assert_eq!(out.src_addr, Some(dst.parse().unwrap()));
        }
    }
}
