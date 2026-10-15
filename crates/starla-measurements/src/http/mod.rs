//! HTTP measurement implementation

pub mod raw;

use crate::traits::Measurement;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use starla_common::{
    MeasurementData, MeasurementId, MeasurementResult, MeasurementType, ProbeId, Timestamp,
};
use std::fmt::Write;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    pub url: String,
    pub method: String, // GET, HEAD or POST (--get, --head, --post)
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
    /// `--sni`: the server name an https fetch sends, the URL's host when
    /// None (httpget.c:773)
    #[serde(default)]
    pub sni: Option<String>,
    /// `--all`: fetch from each address the name has, each fetch reported
    #[serde(default)]
    pub all: bool,
    /// `--combine`: with `--all`, the fetches in one line
    #[serde(default)]
    pub combine: bool,
    /// `--etim` (1): "ttr", "ttc" and "ttfb" in the result; `--eetim` (2):
    /// "readtiming" too (httpget.c:782-787)
    #[serde(default)]
    pub etim: u8,
    /// `-b`: the bundle, reported as "bundle"
    #[serde(default)]
    pub bundle: Option<u64>,
}

pub struct Http {
    pub config: HttpConfig,
    pub probe_id: ProbeId,
    pub msm_id: MeasurementId,
}

/// What evhttpget's report() writes around each fetch's outcome: the
/// line's id and start, and the options that shape its lines.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub msm_id: u64,
    /// httpget_start's atlas_time(), the envelope's "time"
    pub gstart: i64,
    /// `-b`
    pub bundle: Option<u64>,
    /// `--all`, `--combine`
    pub all: bool,
    pub combine: bool,
    /// `--etim` 1, `--eetim` 2
    pub etim: u8,
}

/// evhttpget's RESULT body (probe-busybox/eperd/httpget.c report()) for a
/// line with none of `-b`, `--all`, `--combine`, `--etim`, `--eetim`: the
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
    let report = Report {
        msm_id,
        gstart,
        ..Default::default()
    };
    envelope(&report, out.ttr, &entry(&report, out))
}

/// report()'s RESULT bodies for a run's fetches: a line for each, or with
/// `--all --combine` one line for them all, held back until the last
/// fetch (httpget.c:838-843, 977-983). Without `--all` a run has one.
pub fn result_lines(report: &Report, outs: &[raw::RawHttpOutcome]) -> Vec<String> {
    let Some(first) = outs.first() else {
        return Vec::new();
    };
    if report.all && report.combine {
        let entries: Vec<String> = outs.iter().map(|out| entry(report, out)).collect();
        vec![envelope(report, first.ttr, &entries.join(", "))]
    } else {
        outs.iter()
            .map(|out| envelope(report, out.ttr, &entry(report, out)))
            .collect()
    }
}

/// One fetch's object in "result", its fields in report()'s order
/// (httpget.c:885-975).
fn entry(report: &Report, out: &raw::RawHttpOutcome) -> String {
    let mut r = String::from("{ ");
    if let Some(dnserr) = &out.dnserr {
        // reporterr()'s TU_DNS_ERR: report() adds nothing to it
        let _ = write!(r, "\"dnserr\":{} }}", raw::quoted(dnserr));
        return r;
    }
    if let (true, Some(dst)) = (out.refused, out.dst_addr) {
        // reporterr()'s TU_BAD_ADDR, nothing added either
        let _ = write!(
            r,
            "\"error\": \"address not allowed\", \"dst_addr\":\"{dst}\" }}"
        );
        return r;
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
    if report.all {
        if report.combine {
            let _ = write!(r, "\"time\":{}, ", out.started);
        } else {
            let _ = write!(r, "\"subid\":{}, \"submax\":{}, ", out.subid, out.submax);
        }
    }
    let _ = write!(
        r,
        "\"method\":\"{}\", \"af\": {}",
        out.method.as_str(),
        out.af
    );
    if let Some(dst) = out.dst_addr {
        let _ = write!(r, ", \"dst_addr\":\"{dst}\"");
    }
    // The reference closes its readtiming even when nothing was read (a
    // failed connect, a server that said nothing), with a stray " ]" that
    // leaves the line no JSON: Starla writes none then.
    if report.etim >= 2 && !out.reads.is_empty() {
        r.push_str(", \"readtiming\": [");
        for (i, (o, t)) in out.reads.iter().enumerate() {
            if i > 0 {
                r.push(',');
            }
            let _ = write!(r, " {{ \"o\": {o}, \"t\": {t:.6} }}");
        }
        r.push_str(" ]");
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
        if report.etim >= 1 {
            let _ = write!(
                r,
                ", \"ttr\":{:.6}, \"ttc\":{:.6}, \"ttfb\":{:.6}",
                out.connect_ttr,
                out.ttc,
                out.ttfb()
            );
        }
    }
    r.push_str(" }");
    r
}

/// report()'s line around the result objects `entries`.
fn envelope(report: &Report, ttr: Option<f64>, entries: &str) -> String {
    let mut body = format!(
        "\"id\":\"{}\", \"fw\":{}, \"mver\": \"2.6.4\", \"lts\":0, \"time\":{}, ",
        report.msm_id,
        starla_common::FIRMWARE_VERSION,
        report.gstart
    );
    if let Some(bundle) = report.bundle {
        let _ = write!(body, "\"bundle\":{bundle}, ");
    }
    if let Some(ttr) = ttr {
        let _ = write!(body, "\"ttr\":{ttr:.6}, ");
    }
    let _ = write!(body, "\"result\":[ {entries} ]");
    body
}

#[async_trait]
impl Measurement for Http {
    fn measurement_type(&self) -> starla_common::MeasurementType {
        starla_common::MeasurementType::Http
    }

    async fn execute(&self) -> anyhow::Result<MeasurementResult> {
        let gstart = Timestamp::now();
        // http:// and https:// alike, as httpget fetches both; another URL
        // is httpget_init's "bad prefix", and nothing runs
        let url = raw::parse_http_url(&self.config.url)?;
        let opts = raw::FetchOptions {
            af: self.config.af,
            http10: self.config.http10,
            store_headers: self.config.store_headers,
            timeout: Duration::from_millis(self.config.timeout_ms),
            sni: self.config.sni.clone(),
            method: raw::Method::from_name(&self.config.method),
            all: self.config.all,
        };
        let outs = match raw::fetch(&url, &opts).await {
            Ok(outs) => outs,
            // A fetch that fails outright is reported as an "err" result,
            // not dropped (httpget's reporterr writes one).
            Err(e) => vec![raw::RawHttpOutcome {
                err: Some(e.to_string()),
                af: self.config.af,
                method: opts.method,
                ..Default::default()
            }],
        };
        let report = Report {
            msm_id: self.msm_id.0,
            gstart: gstart.0,
            bundle: self.config.bundle,
            all: self.config.all,
            combine: self.config.combine,
            etim: self.config.etim,
        };
        let mut lines = result_lines(&report, &outs);
        let Some(out) = outs.last() else {
            anyhow::bail!("{}: no address to fetch from", self.config.url);
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
            // --all without --combine: a line for each fetch
            data: match lines.len() {
                1 => MeasurementData::FullLine(lines.remove(0)),
                _ => MeasurementData::FullLines(lines),
            },
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
            refused: false,
            done: true,
            ..Default::default()
        };
        let body = result_body(13027, 1791860335, &out);
        assert_eq!(
            body,
            format!(
                "\"id\":\"13027\", \"fw\":{}, \"mver\": \"2.6.4\", \"lts\":0, \
                 \"time\":1791860335, \"result\":[ {{ \"header\": [ \"X-Client-IP: \
                 2602:f337:ed:4174:2020:2041:746c:6173\", \"Content-Length: 37\", \"\" ], \
                 \"method\":\"GET\", \"af\": 6, \"dst_addr\":\"2001:67c:2e8:16::c100:68d\", \
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
        assert!(
            body.contains(
                "\"time\":1, \"ttr\":1.500000, \"result\":[ { \"err\":\"connect: timeout\", \
                 \"method\":\"GET\", \"af\": 4, \"dst_addr\":\"193.0.6.141\" } ]"
            ),
            "{body}"
        );
        assert!(!body.contains("\"rt\""), "{body}");
    }

    /// reporterr()'s TU_BAD_ADDR line, with the name's ttr in the envelope
    /// (httpget.c:2073-2087, 872-876)
    #[test]
    fn a_refused_address_is_reported_as_httpget_reports_it() {
        let out = raw::RawHttpOutcome {
            ttr: Some(0.5),
            af: 4,
            dst_addr: Some("10.1.2.3".parse().unwrap()),
            refused: true,
            ..Default::default()
        };
        assert_eq!(
            result_body(12023, 1, &out),
            format!(
                "\"id\":\"12023\", \"fw\":{}, \"mver\": \"2.6.4\", \"lts\":0, \"time\":1, \
                 \"ttr\":0.500000, \"result\":[ {{ \"error\": \"address not allowed\", \
                 \"dst_addr\":\"10.1.2.3\" }} ]",
                starla_common::FIRMWARE_VERSION
            )
        );
    }

    /// The result object of `body`, a RESULT line's, as RIPE parses it.
    fn parsed(body: &str) -> serde_json::Value {
        serde_json::from_str(&format!("{{ {body} }}")).unwrap()
    }

    /// A fetch from 193.0.6.139 that read `reads`, done.
    fn fetched(method: raw::Method, reads: Vec<(usize, f64)>) -> raw::RawHttpOutcome {
        raw::RawHttpOutcome {
            af: 4,
            dst_addr: Some("193.0.6.139".parse().unwrap()),
            src_addr: Some("192.0.2.10".parse().unwrap()),
            rt: 4.5,
            res: 200,
            ver: "1.1".into(),
            hsize: 120,
            bsize: if method == raw::Method::Head { 0 } else { 2048 },
            done: true,
            method,
            subid: 1,
            submax: 1,
            started: 3600,
            connect_ttr: 0.25,
            ttc: 1.0,
            reads,
            ..Default::default()
        }
    }

    /// `--head`: "method":"HEAD", and no body read (httpget.c:903-905,
    /// 1505-1514). Starla wrote "GET" whatever the line asked.
    #[test]
    fn a_head_line_says_head() {
        let out = fetched(raw::Method::Head, vec![(0, 1.5)]);
        assert_eq!(
            result_body(1001, 1, &out),
            format!(
                "\"id\":\"1001\", \"fw\":{}, \"mver\": \"2.6.4\", \"lts\":0, \"time\":1, \
                 \"result\":[ {{ \"method\":\"HEAD\", \"af\": 4, \"dst_addr\":\"193.0.6.139\", \
                 \"src_addr\":\"192.0.2.10\", \"rt\":4.500000, \"res\":200, \"ver\":\"1.1\", \
                 \"hsize\":120, \"bsize\":0 }} ]",
                starla_common::FIRMWARE_VERSION
            )
        );
        let post = fetched(raw::Method::Post, vec![]);
        assert!(result_body(1001, 1, &post).contains("{ \"method\":\"POST\", \"af\": 4"));
    }

    /// `--etim`: the fetch's ttr, ttc and ttfb after bsize; `--eetim`:
    /// readtiming too, between dst_addr and src_addr, each read's offset an
    /// integer (report() and get_input, httpget.c:923-931, 959-971,
    /// 1063-1075).
    #[test]
    fn etim_and_eetim_report_the_fetchs_times() {
        let out = raw::RawHttpOutcome {
            ttr: Some(0.125),
            ..fetched(raw::Method::Get, vec![(0, 1.5), (1448, 2.25), (2896, 3.0)])
        };
        let line = |etim| {
            let report = Report {
                msm_id: 1001,
                gstart: 1,
                etim,
                ..Default::default()
            };
            result_lines(&report, std::slice::from_ref(&out)).remove(0)
        };
        assert_eq!(
            line(1),
            format!(
                "\"id\":\"1001\", \"fw\":{}, \"mver\": \"2.6.4\", \"lts\":0, \"time\":1, \
                 \"ttr\":0.125000, \"result\":[ {{ \"method\":\"GET\", \"af\": 4, \
                 \"dst_addr\":\"193.0.6.139\", \"src_addr\":\"192.0.2.10\", \"rt\":4.500000, \
                 \"res\":200, \"ver\":\"1.1\", \"hsize\":120, \"bsize\":2048, \
                 \"ttr\":0.250000, \"ttc\":1.000000, \"ttfb\":1.500000 }} ]",
                starla_common::FIRMWARE_VERSION
            )
        );
        let eetim = line(2);
        assert!(
            eetim.contains(
                "\"dst_addr\":\"193.0.6.139\", \"readtiming\": [ { \"o\": 0, \"t\": 1.500000 }, \
                 { \"o\": 1448, \"t\": 2.250000 }, { \"o\": 2896, \"t\": 3.000000 } ], \
                 \"src_addr\":\"192.0.2.10\", \"rt\":4.500000"
            ),
            "{eetim}"
        );
        assert!(eetim.ends_with("\"ttr\":0.250000, \"ttc\":1.000000, \"ttfb\":1.500000 } ]"));
        let line_json = parsed(&eetim);
        let reads = &line_json["result"][0]["readtiming"];
        assert!(reads[1]["o"].is_u64() && reads[1]["t"].is_f64(), "{reads}");
        assert_eq!(
            line(0),
            result_body(1001, 1, &out),
            "no timing without them"
        );

        // A connect that failed: nothing read, no times, still JSON
        let failed = raw::RawHttpOutcome {
            af: 4,
            dst_addr: Some("193.0.6.139".parse().unwrap()),
            err: Some("connect: timeout".into()),
            ..Default::default()
        };
        let report = Report {
            etim: 2,
            ..Default::default()
        };
        let body = result_lines(&report, &[failed]).remove(0);
        assert!(body.ends_with("{ \"err\":\"connect: timeout\", \"method\":\"GET\", \"af\": 4, \"dst_addr\":\"193.0.6.139\" } ]"), "{body}");
        parsed(&body);
    }

    /// `--all`: a line for each address with its "subid" and "submax";
    /// with `--combine` one line, each fetch with the "time" its connect
    /// started at (report(), httpget.c:838-843, 885-897, 977-983). `-b`'s
    /// bundle is in the envelope, after "time" (:869-873).
    #[test]
    fn all_and_combine_report_each_address() {
        let refused = raw::RawHttpOutcome {
            ttr: Some(3.0),
            af: 6,
            dst_addr: Some("2001:67c:2e8:22::c100:68b".parse().unwrap()),
            err: Some("connect: Connection refused".into()),
            subid: 1,
            submax: 2,
            started: 3599,
            connect_ttr: 3.5,
            ..Default::default()
        };
        let fetched = raw::RawHttpOutcome {
            ttr: Some(3.0),
            subid: 2,
            submax: 2,
            ..fetched(raw::Method::Get, vec![(0, 1.5)])
        };
        let outs = [refused, fetched];
        let mut report = Report {
            msm_id: 1001,
            gstart: 1,
            bundle: Some(7),
            all: true,
            ..Default::default()
        };
        let envelope = format!(
            "\"id\":\"1001\", \"fw\":{}, \"mver\": \"2.6.4\", \"lts\":0, \"time\":1, \
             \"bundle\":7, \"ttr\":3.000000, \"result\":[ ",
            starla_common::FIRMWARE_VERSION
        );
        let first = "{ \"err\":\"connect: Connection refused\", \"subid\":1, \"submax\":2, \
                     \"method\":\"GET\", \"af\": 6, \"dst_addr\":\"2001:67c:2e8:22::c100:68b\" }";
        let second = "{ \"subid\":2, \"submax\":2, \"method\":\"GET\", \"af\": 4, \
                      \"dst_addr\":\"193.0.6.139\", \"src_addr\":\"192.0.2.10\", \
                      \"rt\":4.500000, \"res\":200, \"ver\":\"1.1\", \"hsize\":120, \"bsize\":2048 }";
        assert_eq!(
            result_lines(&report, &outs),
            [
                format!("{envelope}{first} ]"),
                format!("{envelope}{second} ]")
            ]
        );

        report.combine = true;
        let combined = result_lines(&report, &outs);
        assert_eq!(
            combined,
            [format!(
                "{envelope}{{ \"err\":\"connect: Connection refused\", \"time\":3599, \
                 \"method\":\"GET\", \"af\": 6, \"dst_addr\":\"2001:67c:2e8:22::c100:68b\" }}, \
                 {{ \"time\":3600, \"method\":\"GET\", \"af\": 4, \"dst_addr\":\"193.0.6.139\", \
                 \"src_addr\":\"192.0.2.10\", \"rt\":4.500000, \"res\":200, \"ver\":\"1.1\", \
                 \"hsize\":120, \"bsize\":2048 }} ]"
            )]
        );
        let line = parsed(&combined[0]);
        assert_eq!(line["bundle"], 7);
        assert_eq!(line["result"][1]["time"], 3600);

        // --combine alone changes nothing (httpget.c:841, 886)
        report.all = false;
        assert_eq!(
            result_lines(&report, &outs[1..]),
            [format!(
                "{envelope}{} ]",
                second.replace("\"subid\":2, \"submax\":2, ", "")
            )]
        );
    }
}
