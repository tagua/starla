//! NTP measurement implementation

pub mod client;

use crate::target::{DstName, LookupError};
use crate::traits::Measurement;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use starla_common::{
    MeasurementData, MeasurementId, MeasurementResult, MeasurementType, ProbeId, Timestamp,
};
use std::fmt::Write;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtpConfig {
    /// The address looked up for the target (or the target, an address)
    pub target: IpAddr,
    /// `-w`: how long to wait for each reply
    pub timeout_ms: u64,
    pub port: u16,
    /// `-c`: requests to send
    pub count: u32,
    /// `-g`: minimum time between requests (5130)
    pub gap_ms: u64,
}

/// evntp's RESULT line (probe-busybox/eperd/ntp.c report(), 363-481), as
/// Starla writes it: the envelope, `"dst_name"` and, for a name, `"ttr"`
/// (400-416); `"dst_addr"` and `"src_addr"` when a server was picked
/// (418-435); proto and af (437-441); the server's header fields once one
/// answered (443-479); the result entries (481).
struct Report<'a> {
    msm_id: u64,
    time: i64,
    dst_name: &'a DstName,
    dst_addr: Option<IpAddr>,
    src_addr: Option<&'a str>,
    af: u8,
    header: Option<&'a client::NtpHeader>,
    /// The entries, without the brackets
    result: &'a str,
}

impl Report<'_> {
    /// "lts":0 is a placeholder the results crate replaces with the lts
    /// the result was queued at.
    fn body(&self) -> String {
        let mut s = format!(
            "\"id\":\"{}\", \"fw\":{}, \"mver\": \"2.6.4\", \"lts\":0, \"time\":{}, \
             \"dst_name\":{}",
            self.msm_id,
            starla_common::FIRMWARE_VERSION,
            self.time,
            // The controller names the target: quote it so a \" cannot
            // break the RESULT line.
            crate::http::raw::quoted(&self.dst_name.name),
        );
        if let Some(ttr) = self.dst_name.ttr {
            let _ = write!(s, ", \"ttr\":{ttr:.6}");
        }
        if let Some(dst) = self.dst_addr {
            let _ = write!(s, ", \"dst_addr\":\"{dst}\"");
            if let Some(src) = self.src_addr {
                let _ = write!(s, ", \"src_addr\":\"{src}\"");
            }
        }
        let _ = write!(s, ", \"proto\":\"UDP\", \"af\": {}", self.af);
        if let Some(h) = self.header {
            s.push_str(&header_fields(h));
        }
        let _ = write!(s, ", \"result\": [ {} ]", self.result);
        s
    }
}

/// The server's header fields, from its first reply, as report() writes
/// them (ntp.c:443-479): each `"name": value`, a space after the colon,
/// after ", ".
fn header_fields(h: &client::NtpHeader) -> String {
    [
        li(h.flags),
        version(h.flags),
        mode(h.flags),
        stratum(h.stratum),
        eight_bit("poll", h.poll),
        eight_bit("precision", h.precision),
        short_ts("root-delay", h.root_delay),
        short_ts("root-dispersion", h.root_dispersion),
        ref_id(h.ref_id, h.stratum),
        ts("ref-ts", h.ref_ts),
    ]
    .iter()
    .map(|field| format!(", {field}"))
    .collect()
}

/// What ready_callback writes at the start of a reply's entry, before
/// "origin-ts" (ntp.c:768-875): each of the reply's header fields that
/// differs from the first reply's, in ntp.c's order, formatted as report()
/// formats it, then, if it wrote any, the ", " before "origin-ts". A reply
/// whose header is the first reply's, as the first reply's own is, writes
/// nothing. The ref-id is in the form of the reply's own stratum
/// (:848-856).
///
/// The separators are ntp.c's, but for one: ntp.c puts ", " before
/// "version" whether or not a field came before it (:779-787), so a reply
/// whose version differs and whose leap indicator does not starts its entry
/// `{ , "version": 3, ` — not JSON, which RIPE cannot store. Starla writes
/// `{ "version": 3, ` there; every other separator is ntp.c's.
fn changed_fields(first: &client::NtpHeader, h: &client::NtpHeader) -> String {
    let mut out = String::new();
    let mut head = true;
    if h.leap() != first.leap() {
        out.push_str(&li(h.flags));
        head = false;
    }
    if h.version() != first.version() {
        // ntp.c writes ", " here even when nothing came before (:779-787),
        // which makes the entry `{ , "version": …` and the line not JSON;
        // RIPE could not store it. As with traceroute's "out of addresses",
        // Starla writes the valid form.
        if !head {
            out.push_str(", ");
        }
        out.push_str(&version(h.flags));
        head = false;
    }
    let others = [
        (h.mode() != first.mode()).then(|| mode(h.flags)),
        (h.stratum != first.stratum).then(|| stratum(h.stratum)),
        (h.poll != first.poll).then(|| eight_bit("poll", h.poll)),
        (h.precision != first.precision).then(|| eight_bit("precision", h.precision)),
        (h.root_delay != first.root_delay).then(|| short_ts("root-delay", h.root_delay)),
        (h.root_dispersion != first.root_dispersion)
            .then(|| short_ts("root-dispersion", h.root_dispersion)),
        (h.ref_id != first.ref_id).then(|| ref_id(h.ref_id, h.stratum)),
        (h.ref_ts != first.ref_ts).then(|| ts("ref-ts", h.ref_ts)),
    ];
    for field in others.into_iter().flatten() {
        if !head {
            out.push_str(", ");
        }
        out.push_str(&field);
        head = false;
    }
    if !head {
        out.push_str(", ");
    }
    out
}

/// format_li (ntp.c:238-250)
fn li(flags: u8) -> String {
    let li = match flags >> 6 {
        0 => "no",
        1 => "61",
        2 => "59",
        _ => "unknown",
    };
    format!("\"li\": \"{li}\"")
}

/// The version, as report() and ready_callback write it with %d
/// (ntp.c:447-449, 779-787)
fn version(flags: u8) -> String {
    format!("\"version\": {}", (flags >> 3) & 0x7)
}

/// format_mode (ntp.c:252-268)
fn mode(flags: u8) -> String {
    let mode = match flags & 0x7 {
        0 => "reserved",
        1 => "sym. active",
        2 => "sym. passive",
        3 => "client",
        4 => "server",
        5 => "broadcast",
        6 => "control",
        _ => "private",
    };
    format!("\"mode\": \"{mode}\"")
}

/// format_stratum (ntp.c:270-295): 0 is "invalid", 16 "unsynchronized",
/// above it "reserved (n)".
fn stratum(stratum: u8) -> String {
    match stratum {
        0 => "\"stratum\": \"invalid\"".into(),
        16 => "\"stratum\": \"unsynchronized\"".into(),
        s if s < 16 => format!("\"stratum\": {s}"),
        s => format!("\"stratum\": \"reserved ({s})\""),
    }
}

/// format_short_ts (ntp.c:310-314): %g of a 16.16 value
fn short_ts(label: &str, value: u32) -> String {
    format!("\"{label}\": {}", format_g(f64::from(value) / 65536.0))
}

/// format_ref_id (ntp.c:316-352): stratum 0 (a kiss code) and 1 (a
/// source) are text, its bytes up to the first NUL, each control byte,
/// `"`, `\` and byte from 127 up as `\\xhh`; any other stratum is the
/// address or its hash, 8 hex digits.
fn ref_id(value: u32, stratum: u8) -> String {
    let id = if stratum == 0 || stratum == 1 {
        let mut text = String::new();
        for &b in value.to_be_bytes().iter().take_while(|&&b| b != 0) {
            if b < 32 || b == b'"' || b == b'\\' || b >= 127 {
                let _ = write!(text, "\\\\x{b:02x}");
            } else {
                text.push(char::from(b));
            }
        }
        text
    } else {
        format!("{value:08x}")
    };
    format!("\"ref-id\": \"{id}\"")
}

/// format_ts (ntp.c:354-361): %.9f of seconds + fraction / 2^32
fn ts(label: &str, value: u64) -> String {
    format!("\"{label}\": {:.9}", client::ntp_ts_to_f64(value))
}

/// format_8bit (ntp.c:297-307), poll's and precision's log2 byte: 1 << v
/// for 0..32, else pow(2, v) with %g.
fn eight_bit(label: &str, value: i8) -> String {
    if (0..32).contains(&value) {
        format!("\"{label}\": {}", 1u32 << value)
    } else {
        format!("\"{label}\": {}", format_g(2f64.powi(i32::from(value))))
    }
}

/// C's `%g`: six significant digits, in exponent form when the exponent
/// is below -4 or six and up, trailing zeros dropped (C11 7.21.6.1). The
/// exponent is the one the value has once rounded to six digits, as C
/// decides it.
fn format_g(x: f64) -> String {
    if x == 0.0 {
        return if x.is_sign_negative() { "-0" } else { "0" }.into();
    }
    if !x.is_finite() {
        return if x.is_nan() {
            "nan"
        } else if x > 0.0 {
            "inf"
        } else {
            "-inf"
        }
        .into();
    }
    let e = format!("{x:.5e}");
    let (mantissa, exponent) = e.split_once('e').unwrap_or((&e, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let trim = |s: &str| -> String {
        if s.contains('.') {
            s.trim_end_matches('0').trim_end_matches('.').to_string()
        } else {
            s.to_string()
        }
    };
    if !(-4..6).contains(&exponent) {
        let sign = if exponent < 0 { '-' } else { '+' };
        format!("{}e{sign}{:02}", trim(mantissa), exponent.abs())
    } else {
        trim(&format!("{x:.*}", (5 - exponent) as usize))
    }
}

/// evntp's RESULT body for a run (probe-busybox/eperd/ntp.c report()).
/// A run whose socket could not be made reports create_socket's error
/// alone, with dst_addr and, as no socket was connected, no src_addr
/// (ntp.c:1225-1238, 1255-1274).
fn result_body(
    msm_id: u64,
    config: &NtpConfig,
    dst_name: &DstName,
    af: u8,
    timestamp: i64,
    results: &client::NtpResult,
) -> String {
    let src_addr = results.src_addr.map(|ip| ip.to_string());
    if let Some(error) = &results.error {
        return Report {
            msm_id,
            time: timestamp,
            dst_name,
            dst_addr: Some(config.target),
            src_addr: src_addr.as_deref(),
            af,
            header: None,
            result: &format!("{{ \"error\":\"{error}\" }}"),
        }
        .body();
    }
    // The first reply's header is the result's, as ready_callback keeps it
    // (ntp.c:755-767); none answered, report() writes none (`state->first`,
    // :443).
    let first = results.samples.iter().flatten().next().map(|s| &s.header);
    // Format samples array: a timeout is { "x":"*" }, as evntp writes it;
    // a reply's entry starts with its header fields that differ from the
    // first reply's
    let mut samples_str = String::new();
    for (i, s) in results.samples.iter().enumerate() {
        if i > 0 {
            write!(samples_str, ", ").unwrap();
        }
        match s {
            Some(s) => write!(
                samples_str,
                "{{ {}\"origin-ts\": {:.9}, \"receive-ts\": {:.9}, \"transmit-ts\": {:.9}, \
                 \"final-ts\": {:.9}, \"rtt\": {:.6}, \"offset\": {:.6} }}",
                first.map_or_else(String::new, |first| changed_fields(first, &s.header)),
                s.origin_ts,
                s.receive_ts,
                s.transmit_ts,
                s.final_ts,
                s.rtt,
                s.offset,
            )
            .unwrap(),
            None => write!(samples_str, "{{ \"x\":\"*\" }}").unwrap(),
        }
    }

    Report {
        msm_id,
        time: timestamp,
        dst_name,
        dst_addr: Some(config.target),
        src_addr: Some(src_addr.as_deref().unwrap_or_default()),
        af,
        header: first,
        result: &samples_str,
    }
    .body()
}

pub struct Ntp {
    pub config: NtpConfig,
    pub probe_id: ProbeId,
    pub msm_id: MeasurementId,
    /// The target as the result names it: the controller's name for it,
    /// and the time its lookup took.
    pub dst_name: DstName,
}

impl Ntp {
    fn af(&self) -> u8 {
        if self.config.target.is_ipv4() {
            4
        } else {
            6
        }
    }

    fn result(&self, time: i64, src_addr: Option<IpAddr>, body: String) -> MeasurementResult {
        MeasurementResult {
            fw: starla_common::FIRMWARE_VERSION,
            measurement_type: MeasurementType::Ntp,
            prb_id: self.probe_id,
            msm_id: self.msm_id,
            timestamp: Timestamp(time),
            af: self.af(),
            dst_addr: self.config.target,
            dst_name: None,
            src_addr,
            proto: Some("UDP".to_string()),
            ttl: None,
            size: None,
            data: MeasurementData::FullLine(body),
        }
    }

    /// dns_cb's reports, which run no request (ntp.c:1353-1366,
    /// 1417-1432): starttime is when the lookup ended; the name and ttr,
    /// dst_addr only for an address refused (report_dst), no src_addr (no
    /// socket yet), the family asked for, no header fields, one error.
    fn dns_cb_result(&self, dst_addr: Option<IpAddr>, error: &str) -> MeasurementResult {
        let time = Timestamp::now().0;
        let body = Report {
            msm_id: self.msm_id.0,
            time,
            dst_name: &self.dst_name,
            dst_addr,
            src_addr: None,
            af: self.af(),
            header: None,
            result: &format!("{{ \"error\":\"{error}\" }}"),
        }
        .body();
        self.result(time, None, body)
    }
}

#[async_trait]
impl Measurement for Ntp {
    fn measurement_type(&self) -> starla_common::MeasurementType {
        starla_common::MeasurementType::Ntp
    }

    /// The line's "time" is when the run starts, once the target is looked
    /// up: ntp_start2's starttime, before its socket and first request
    /// (ntp.c:1195; report() prints it, 386-395). Starla took it once the
    /// run was over, -c requests -g apart later (8 s and more with evntp's
    /// defaults).
    async fn execute(&self) -> anyhow::Result<MeasurementResult> {
        let timestamp = Timestamp::now().0;
        let results = client::execute_ntp_query(&self.config).await?;

        let body = result_body(
            self.msm_id.0,
            &self.config,
            &self.dst_name,
            self.af(),
            timestamp,
            &results,
        );
        Ok(self.result(timestamp, results.src_addr, body))
    }

    /// The result evntp reports when the target's lookup fails: dns_cb's
    /// "name resolution failed" with evutil_gai_strerror's text
    /// (ntp.c:1353-1366) — RIPE stores `"dst_name":"2.africa.pool.ntp.org",
    /// "ttr":15002.35762, "proto":"UDP", "af":6, "result":[{"error":"name
    /// resolution failed: non-recoverable failure in name resolution"}]`
    /// from 5130 probe 1001634 (msm 58749906). An empty answer (a hosts
    /// file entry of the other family only) leaves dns_cb with no address
    /// at all; its "out of addresses" line closes the result array twice
    /// (ntp.c:1442-1449), which RIPE cannot parse, so nothing is reported.
    fn lookup_failed(&self, error: LookupError) -> Option<MeasurementResult> {
        if error == LookupError::NoAddress {
            return None;
        }
        Some(self.dns_cb_result(None, &format!("name resolution failed: {error}")))
    }

    /// The result evntp reports when atlas_check_addr refuses the address
    /// looked up: "address not allowed" with dst_addr (report_dst), and no
    /// request sent (ntp.c:1417-1432).
    fn address_not_allowed(&self) -> Option<MeasurementResult> {
        Some(self.dns_cb_result(Some(self.config.target), "address not allowed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> NtpConfig {
        NtpConfig {
            target: "193.0.0.229".parse().unwrap(),
            timeout_ms: 1000,
            port: 123,
            count: 3,
            gap_ms: 4000,
        }
    }

    fn literal(addr: &str) -> DstName {
        DstName {
            name: addr.into(),
            ttr: None,
        }
    }

    fn ntp(target: &str, dst_name: DstName) -> Ntp {
        Ntp {
            config: NtpConfig {
                target: target.parse().unwrap(),
                ..config()
            },
            probe_id: ProbeId(1018212),
            msm_id: MeasurementId(58749906),
            dst_name,
        }
    }

    fn body(result: MeasurementResult) -> String {
        match result.data {
            MeasurementData::FullLine(body) => body,
            other => panic!("{other:?}"),
        }
    }

    /// No answer at all: evntp prints no header, one { "x":"*" } per request.
    #[test]
    fn an_unanswered_measurement_is_reported_not_dropped() {
        let results = client::NtpResult {
            samples: vec![None, None, None],
            src_addr: Some("199.184.91.28".parse().unwrap()),
            error: None,
        };
        let body = result_body(13023, &config(), &literal("193.0.0.229"), 4, 1, &results);
        assert!(
            body.starts_with("\"id\":\"13023\", \"fw\":5130, "),
            "{body}"
        );
        assert!(body.contains("\"lts\":0, "), "the placeholder: {body}");
        assert!(
            body.contains("\"dst_name\":\"193.0.0.229\", \"dst_addr\":\"193.0.0.229\""),
            "{body}"
        );
        assert!(!body.contains("\"li\""), "{body}");
        assert!(
            body.ends_with("\"result\": [ { \"x\":\"*\" }, { \"x\":\"*\" }, { \"x\":\"*\" } ]"),
            "{body}"
        );
    }

    /// A stratum 1 server's header: LI 0, version 4, mode 4, "GPS"
    fn gps() -> client::NtpHeader {
        client::NtpHeader {
            flags: 0x24,
            stratum: 1,
            poll: 3,
            precision: -20,
            root_delay: 0,
            root_dispersion: 0,
            ref_id: u32::from_be_bytes(*b"GPS\0"),
            ref_ts: 1 << 32,
        }
    }

    #[test]
    fn a_timeout_between_answers_keeps_its_place() {
        let sample = client::NtpSample {
            header: gps(),
            origin_ts: 1.0,
            receive_ts: 1.5,
            transmit_ts: 1.5,
            final_ts: 1.0,
            rtt: 0.0,
            offset: 0.5,
        };
        let results = client::NtpResult {
            samples: vec![Some(sample.clone()), None, Some(sample)],
            src_addr: Some("199.184.91.28".parse().unwrap()),
            error: None,
        };
        let body = result_body(13023, &config(), &literal("193.0.0.229"), 4, 1, &results);
        assert!(
            body.contains(", \"li\": \"no\", \"version\": 4, \"mode\": \"server\", \"stratum\": 1"),
            "{body}"
        );
        let result = &body[body.find("\"result\"").unwrap()..];
        assert_eq!(
            result.matches("\"offset\": 0.500000").count(),
            2,
            "{result}"
        );
        assert!(result.contains(" }, { \"x\":\"*\" }, { "), "{result}");
    }

    /// A name is reported with the time its lookup took, after dst_name
    /// (ntp.c:400-416), as RIPE stores 5130 probe 1000767's line of msm
    /// 58749909: `"dst_name": "2.europe.pool.ntp.org", "ttr": 14.52592,
    /// "dst_addr": "2001:ac8:30:68:0:1:0:2", "src_addr": …`. Starla wrote no
    /// ttr.
    #[test]
    fn a_name_is_reported_with_its_ttr() {
        let results = client::NtpResult {
            samples: vec![None],
            src_addr: Some("2001:871:23d:897e:2a0:98ff:fe35:eb0d".parse().unwrap()),
            error: None,
        };
        let dst_name = DstName {
            name: "2.europe.pool.ntp.org".into(),
            ttr: Some(14.52592),
        };
        let config = NtpConfig {
            target: "2001:ac8:30:68:0:1:0:2".parse().unwrap(),
            ..config()
        };
        let body = result_body(58749909, &config, &dst_name, 6, 1791942167, &results);
        assert_eq!(
            body,
            "\"id\":\"58749909\", \"fw\":5130, \"mver\": \"2.6.4\", \"lts\":0, \"time\":1791942167, \
             \"dst_name\":\"2.europe.pool.ntp.org\", \"ttr\":14.525920, \
             \"dst_addr\":\"2001:ac8:30:68:0:1:0:2\", \
             \"src_addr\":\"2001:871:23d:897e:2a0:98ff:fe35:eb0d\", \"proto\":\"UDP\", \"af\": 6, \
             \"result\": [ { \"x\":\"*\" } ]"
        );
    }

    /// A lookup that fails is reported as dns_cb reports it
    /// (ntp.c:1353-1366): the name and ttr, no dst_addr or src_addr, the
    /// family asked for, no header, one error — RIPE stores exactly these
    /// fields from 5130 probe 1001634 for msm 58749906. Starla reported
    /// nothing.
    #[test]
    fn a_failed_lookup_is_reported() {
        let dst_name = DstName {
            name: "2.africa.pool.ntp.org".into(),
            ttr: Some(15002.35762),
        };
        let line = body(
            ntp("::", dst_name)
                .lookup_failed(LookupError::Fail)
                .unwrap(),
        );
        let tail = line.split_once(", \"time\":").unwrap().1;
        let tail = tail.split_once(", ").unwrap().1;
        assert_eq!(
            tail,
            "\"dst_name\":\"2.africa.pool.ntp.org\", \"ttr\":15002.357620, \"proto\":\"UDP\", \
             \"af\": 6, \"result\": [ { \"error\":\"name resolution failed: non-recoverable \
             failure in name resolution\" } ]"
        );
        let wrapped: serde_json::Value = serde_json::from_str(&format!("{{ {line} }}")).unwrap();
        assert_eq!(wrapped["af"], 6);
        // dns_cb's "out of addresses" line is not JSON: nothing reported.
        assert!(ntp("0.0.0.0", literal("x"))
            .lookup_failed(LookupError::NoAddress)
            .is_none());
    }

    /// An address atlas_check_addr refuses: "address not allowed" with
    /// dst_addr and no src_addr (ntp.c:1417-1432).
    #[test]
    fn a_refused_address_is_reported_not_measured() {
        let line = body(
            ntp("10.0.0.1", literal("10.0.0.1"))
                .address_not_allowed()
                .unwrap(),
        );
        assert!(
            line.ends_with(
                "\"dst_name\":\"10.0.0.1\", \"dst_addr\":\"10.0.0.1\", \"proto\":\"UDP\", \
                 \"af\": 4, \"result\": [ { \"error\":\"address not allowed\" } ]"
            ),
            "{line}"
        );
    }

    /// The line of a run with answers, byte for byte as report() writes it
    /// (ntp.c:363-481): an address literal, so no ttr, the first reply's
    /// header fields, a timeout between two samples. RIPE stores this
    /// server's answer to probe 1000767 (msm 58749909, timestamp
    /// 1791942167; root delay 2567/65536, root dispersion 2055/65536,
    /// precision -23, poll 0) as "poll":1, "precision":1.19209e-7,
    /// "root-delay":0.0391693, "root-dispersion":0.0313568: format_8bit's
    /// 1 << poll and %g (ntp.c:297-314). Starla wrote the raw poll
    /// exponent, the others at full precision, and none of report()'s
    /// spaces after the colons.
    #[test]
    fn a_run_is_reported_as_before() {
        let sample = |o: f64, r: f64, t: f64, f: f64| client::NtpSample {
            header: client::NtpHeader {
                flags: 0x24,
                stratum: 2,
                poll: 0,
                precision: -23,
                root_delay: 2567,
                root_dispersion: 2055,
                ref_id: 0xed11cc5f,
                // 4000929981.045177, the f64 nearest RIPE's value
                ref_ts: 0xee79_58bd_0b90_b800,
            },
            origin_ts: o,
            receive_ts: r,
            transmit_ts: t,
            final_ts: f,
            rtt: (f - o) - (t - r),
            offset: ((r - o) + (t - f)) / 2.0,
        };
        let results = client::NtpResult {
            samples: vec![
                Some(sample(
                    4000930967.838104,
                    4000930967.8634777,
                    4000930967.8635993,
                    4000930967.884358,
                )),
                None,
                Some(sample(
                    4000930971.838104,
                    4000930971.8634777,
                    4000930971.8635993,
                    4000930971.884358,
                )),
            ],
            src_addr: Some("2001:871:23d:897e:2a0:98ff:fe35:eb0d".parse().unwrap()),
            error: None,
        };
        let config = NtpConfig {
            target: "2001:ac8:30:68:0:1:0:2".parse().unwrap(),
            ..config()
        };
        let dst_name = literal("2001:ac8:30:68:0:1:0:2");
        assert_eq!(
            result_body(58749909, &config, &dst_name, 6, 1791942167, &results),
            "\"id\":\"58749909\", \"fw\":5130, \"mver\": \"2.6.4\", \"lts\":0, \
             \"time\":1791942167, \"dst_name\":\"2001:ac8:30:68:0:1:0:2\", \
             \"dst_addr\":\"2001:ac8:30:68:0:1:0:2\", \
             \"src_addr\":\"2001:871:23d:897e:2a0:98ff:fe35:eb0d\", \"proto\":\"UDP\", \
             \"af\": 6, \"li\": \"no\", \"version\": 4, \"mode\": \"server\", \"stratum\": 2, \
             \"poll\": 1, \"precision\": 1.19209e-07, \"root-delay\": 0.0391693, \
             \"root-dispersion\": 0.0313568, \"ref-id\": \"ed11cc5f\", \
             \"ref-ts\": 4000929981.045176983, \
             \"result\": [ { \"origin-ts\": 4000930967.838103771, \
             \"receive-ts\": 4000930967.863477707, \"transmit-ts\": 4000930967.863599300, \
             \"final-ts\": 4000930967.884357929, \"rtt\": 0.046133, \"offset\": 0.002308 }, \
             { \"x\":\"*\" }, { \"origin-ts\": 4000930971.838103771, \
             \"receive-ts\": 4000930971.863477707, \"transmit-ts\": 4000930971.863599300, \
             \"final-ts\": 4000930971.884357929, \"rtt\": 0.046133, \"offset\": 0.002308 } ]"
        );
    }

    /// format_stratum, format_8bit, format_mode and format_short_ts
    /// (ntp.c:252-314) for what RIPE's servers rarely send: a kiss of
    /// death (stratum 0), an unsynchronized server, a reserved stratum,
    /// polls past 31 and below 0, every mode.
    #[test]
    fn header_fields_are_formatted_as_report_formats_them() {
        let header = |stratum: u8, mode: u8, poll: i8, precision: i8| client::NtpHeader {
            flags: 3 << 6 | 3 << 3 | mode,
            stratum,
            poll,
            precision,
            root_delay: 0,
            root_dispersion: u32::MAX,
            ref_id: u32::from_be_bytes(*b"RATE"),
            ref_ts: 0,
        };
        assert_eq!(
            header_fields(&header(0, 4, 4, -20)),
            ", \"li\": \"unknown\", \"version\": 3, \"mode\": \"server\", \
             \"stratum\": \"invalid\", \"poll\": 16, \"precision\": 9.53674e-07, \
             \"root-delay\": 0, \"root-dispersion\": 65536, \"ref-id\": \"RATE\", \
             \"ref-ts\": 0.000000000"
        );
        let fields = header_fields(&header(16, 4, 31, 0));
        assert!(
            fields.contains(
                "\"stratum\": \"unsynchronized\", \"poll\": 2147483648, \"precision\": 1,"
            ),
            "{fields}"
        );
        let fields = header_fields(&header(17, 4, 32, -1));
        assert!(
            fields.contains(
                "\"stratum\": \"reserved (17)\", \"poll\": 4.29497e+09, \"precision\": 0.5,"
            ),
            "{fields}"
        );
        let fields = header_fields(&header(15, 4, 127, -128));
        assert!(
            fields.contains("\"stratum\": 15, \"poll\": 1.70141e+38, \"precision\": 2.93874e-39,"),
            "{fields}"
        );
        let modes = [
            "reserved",
            "sym. active",
            "sym. passive",
            "client",
            "server",
            "broadcast",
            "control",
            "private",
        ];
        for (mode, name) in modes.iter().enumerate() {
            let fields = header_fields(&header(2, mode as u8, 6, -20));
            assert!(
                fields.contains(&format!("\"mode\": \"{name}\", ")),
                "{fields}"
            );
        }
    }

    /// format_ref_id (ntp.c:316-352): stratum 0 and 1 are text up to the
    /// first NUL, what it cannot print plainly as `\\xhh`; any other stratum
    /// is hex. Starla kept bytes after a NUL and wrote the others as UTF-8.
    #[test]
    fn the_reference_id_is_written_as_format_ref_id_writes_it() {
        let id = |stratum: u8, id: [u8; 4]| ref_id(u32::from_be_bytes(id), stratum);
        assert_eq!(id(0, *b"RATE"), r#""ref-id": "RATE""#);
        assert_eq!(id(1, *b"GPS\0"), r#""ref-id": "GPS""#);
        assert_eq!(id(1, *b"A\0BC"), r#""ref-id": "A""#);
        assert_eq!(
            id(1, [b'"', b'\\', 0x7f, 0x01]),
            r#""ref-id": "\\x22\\x5c\\x7f\\x01""#
        );
        assert_eq!(
            id(1, [0xc3, 0xa9, b'~', b' ']),
            r#""ref-id": "\\xc3\\xa9~ ""#
        );
        assert_eq!(id(2, [0xed, 0x11, 0xcc, 0x5f]), r#""ref-id": "ed11cc5f""#);
        assert_eq!(id(16, *b"INIT"), r#""ref-id": "494e4954""#);
    }

    /// What ready_callback writes before a later reply's origin-ts, built
    /// from its code (ntp.c:768-875): each header field that differs from
    /// the first reply's, by its bits, in ntp.c's order, as report() formats
    /// it, then ", ". "li", being first, has no separator. ntp.c also gives
    /// "version" a ", " before it when nothing came before, which is not
    /// JSON; Starla leaves that one out. The ref-id is written in the form
    /// of the reply's own stratum.
    #[test]
    fn a_later_replys_header_fields_are_written_as_ready_callback_writes_them() {
        fn changed(first: client::NtpHeader, f: impl FnOnce(&mut client::NtpHeader)) -> String {
            let mut h = first;
            f(&mut h);
            changed_fields(&first, &h)
        }
        let first = client::NtpHeader {
            flags: 0x24,
            stratum: 2,
            poll: 6,
            precision: -20,
            root_delay: 1343,
            root_dispersion: 2354,
            ref_id: 0x83bc03dc,
            ref_ts: 0xee78_0f71_ac51_2000,
        };
        assert_eq!(changed(first, |_| {}), "");
        assert_eq!(
            changed(first, |h| h.root_dispersion = 2358),
            r#""root-dispersion": 0.0359802, "#
        );
        assert_eq!(changed(first, |h| h.flags = 0x64), r#""li": "61", "#);
        assert_eq!(changed(first, |h| h.flags = 0x1c), r#""version": 3, "#);
        assert_eq!(
            changed(first, |h| h.flags = 0xdc),
            r#""li": "unknown", "version": 3, "#
        );
        assert_eq!(changed(first, |h| h.flags = 0x23), r#""mode": "client", "#);
        assert_eq!(
            changed(first, |h| {
                h.flags = 0x1c;
                h.root_delay = 0;
            }),
            r#""version": 3, "root-delay": 0, "#
        );
        assert_eq!(
            changed(first, |h| {
                h.poll = -1;
                h.precision = -22;
                h.ref_ts += 1 << 32;
            }),
            r#""poll": 0.5, "precision": 2.38419e-07, "ref-ts": 4000845682.673112869, "#
        );
        // the stratum alone: the ref-id's bits are the same, and it is not
        // written, though its text would now be another
        assert_eq!(changed(first, |h| h.stratum = 1), r#""stratum": 1, "#);
        // bits that differ, though the text up to the NUL is the same
        let gp = client::NtpHeader {
            stratum: 1,
            ref_id: u32::from_be_bytes(*b"GP\0S"),
            ..first
        };
        assert_eq!(
            changed(gp, |h| h.ref_id = u32::from_be_bytes(*b"GP\0X")),
            r#""ref-id": "GP", "#
        );
        // a ref-id in the form of the reply's own stratum
        assert_eq!(
            changed(first, |h| {
                h.stratum = 1;
                h.ref_id = u32::from_be_bytes(*b"PPS\0");
            }),
            r#""stratum": 1, "ref-id": "PPS", "#
        );
        // every field, in ntp.c's order
        assert_eq!(
            changed(first, |h| {
                *h = client::NtpHeader {
                    flags: 0x9d, // LI 2, version 3, mode 5
                    stratum: 17,
                    poll: 4,
                    precision: -6,
                    root_delay: 0,
                    root_dispersion: 65536,
                    ref_id: 0x0a000001,
                    ref_ts: 0,
                }
            }),
            r#""li": "59", "version": 3, "mode": "broadcast", "stratum": "reserved (17)", "#
                .to_owned()
                + r#""poll": 16, "precision": 0.015625, "root-delay": 0, "root-dispersion": 1, "#
                + r#""ref-id": "0a000001", "ref-ts": 0.000000000, "#
        );
    }

    /// Every reply is compared with the first reply, which ready_callback
    /// keeps (state->ntp_*, set once, ntp.c:755-767), not with the one
    /// before it; a timeout before it is not a reply. The first reply's
    /// fields are the result's (report(), :443-479). Starla wrote the first
    /// reply's header alone.
    #[test]
    fn each_reply_is_compared_with_the_first() {
        let sample = |dispersion: u32| {
            Some(client::NtpSample {
                header: client::NtpHeader {
                    root_dispersion: dispersion,
                    ..gps()
                },
                origin_ts: 1.0,
                receive_ts: 1.5,
                transmit_ts: 1.5,
                final_ts: 1.0,
                rtt: 0.0,
                offset: 0.5,
            })
        };
        let results = client::NtpResult {
            samples: vec![None, sample(1), sample(2), sample(1), sample(2)],
            src_addr: Some("199.184.91.28".parse().unwrap()),
            error: None,
        };
        let body = result_body(13023, &config(), &literal("193.0.0.229"), 4, 1, &results);
        let (header, result) = body.split_once(", \"result\": ").unwrap();
        assert!(
            header.ends_with(
                ", \"root-delay\": 0, \"root-dispersion\": 1.52588e-05, \"ref-id\": \"GPS\", \
                 \"ref-ts\": 1.000000000"
            ),
            "{header}"
        );
        let entry = "\"origin-ts\": 1.000000000, \"receive-ts\": 1.500000000, \
                     \"transmit-ts\": 1.500000000, \"final-ts\": 1.000000000, \"rtt\": 0.000000, \
                     \"offset\": 0.500000 }";
        assert_eq!(
            result,
            format!(
                "[ {{ \"x\":\"*\" }}, {{ {entry}, {{ \"root-dispersion\": 3.05176e-05, {entry}, \
                 {{ {entry}, {{ \"root-dispersion\": 3.05176e-05, {entry} ]"
            )
        );
    }

    /// 5130 probe 1001347's line of msm 112928959 (timestamp 1791858003),
    /// as RIPE stores it. time.mediainvent.at's root dispersion grows 4/65536
    /// s between the replies, and each later reply's entry starts with its
    /// own, before origin-ts (ready_callback, ntp.c:838-846). RIPE stores
    /// such fields in 1,243 of the 1,337 lines 5130 probes sent for that msm
    /// in the results at hand, and in 4 of 9 of msm 48548663
    /// (time.zav.cloud); all are root-dispersion.
    const RIPE_112928959_1001347: &str = r#"{"fw": 5130, "mver": "2.6.4", "lts": 6, "dst_name": "time.mediainvent.at", "ttr": 173.463833, "dst_addr": "2a02:1748:0:1500:3::2005", "src_addr": "2a02:5cc0::1:181", "proto": "UDP", "af": 6, "li": "no", "version": 4, "mode": "server", "stratum": 2, "poll": 1, "precision": 2.38419e-07, "root-delay": 0.0204926, "root-dispersion": 0.0359192, "ref-id": "83bc03dc", "ref-ts": 4000845681.673113, "result": [{"origin-ts": 4000846803.371649, "receive-ts": 4000846803.3807797, "transmit-ts": 4000846803.380834, "final-ts": 4000846803.393106, "rtt": 0.021403, "offset": -0.001571}, {"root-dispersion": 0.0359802, "origin-ts": 4000846807.374107, "receive-ts": 4000846807.38323, "transmit-ts": 4000846807.3832736, "final-ts": 4000846807.395476, "rtt": 0.021326, "offset": -0.00154}, {"root-dispersion": 0.0360413, "origin-ts": 4000846811.375257, "receive-ts": 4000846811.3844166, "transmit-ts": 4000846811.384443, "final-ts": 4000846811.396611, "rtt": 0.021328, "offset": -0.001504}], "msm_id": 112928959, "prb_id": 1001347, "timestamp": 1791858003, "msm_name": "Ntp", "from": "2a02:5cc0::1:181", "type": "ntp", "group_id": 112928958, "stored_timestamp": 1791858181}"#;

    /// The line of RIPE_112928959_1001347's run, byte for byte as ntp.c
    /// writes it, and, read back, what RIPE stores: every field, in its
    /// order, the later entries' root-dispersion first. Starla wrote the
    /// entries without it.
    #[test]
    fn a_later_replys_root_dispersion_is_in_its_entry_as_ripe_stores_it() {
        let sample = |dispersion: u32, [o, r, t, f]: [f64; 4], rtt: f64, offset: f64| {
            Some(client::NtpSample {
                header: client::NtpHeader {
                    flags: 0x24,
                    stratum: 2,
                    poll: 0,
                    precision: -22,
                    root_delay: 1343,
                    root_dispersion: dispersion,
                    ref_id: 0x83bc03dc,
                    // 4000845681.673113, the f64 nearest RIPE's value
                    ref_ts: 0xee78_0f71_ac51_2000,
                },
                origin_ts: o,
                receive_ts: r,
                transmit_ts: t,
                final_ts: f,
                rtt,
                offset,
            })
        };
        let results = client::NtpResult {
            samples: vec![
                sample(
                    2354,
                    [
                        4000846803.371649,
                        4000846803.3807797,
                        4000846803.380834,
                        4000846803.393106,
                    ],
                    0.021403,
                    -0.001571,
                ),
                sample(
                    2358,
                    [
                        4000846807.374107,
                        4000846807.38323,
                        4000846807.3832736,
                        4000846807.395476,
                    ],
                    0.021326,
                    -0.00154,
                ),
                sample(
                    2362,
                    [
                        4000846811.375257,
                        4000846811.3844166,
                        4000846811.384443,
                        4000846811.396611,
                    ],
                    0.021328,
                    -0.001504,
                ),
            ],
            src_addr: Some("2a02:5cc0::1:181".parse().unwrap()),
            error: None,
        };
        let config = NtpConfig {
            target: "2a02:1748:0:1500:3::2005".parse().unwrap(),
            ..config()
        };
        let dst_name = DstName {
            name: "time.mediainvent.at".into(),
            ttr: Some(173.463833),
        };
        let body = result_body(112928959, &config, &dst_name, 6, 1791858003, &results);
        assert_eq!(
            body,
            "\"id\":\"112928959\", \"fw\":5130, \"mver\": \"2.6.4\", \"lts\":0, \
             \"time\":1791858003, \"dst_name\":\"time.mediainvent.at\", \"ttr\":173.463833, \
             \"dst_addr\":\"2a02:1748:0:1500:3::2005\", \"src_addr\":\"2a02:5cc0::1:181\", \
             \"proto\":\"UDP\", \"af\": 6, \"li\": \"no\", \"version\": 4, \"mode\": \"server\", \
             \"stratum\": 2, \"poll\": 1, \"precision\": 2.38419e-07, \"root-delay\": 0.0204926, \
             \"root-dispersion\": 0.0359192, \"ref-id\": \"83bc03dc\", \
             \"ref-ts\": 4000845681.673112869, \
             \"result\": [ { \"origin-ts\": 4000846803.371648788, \
             \"receive-ts\": 4000846803.380779743, \"transmit-ts\": 4000846803.380834103, \
             \"final-ts\": 4000846803.393105984, \"rtt\": 0.021403, \"offset\": -0.001571 }, \
             { \"root-dispersion\": 0.0359802, \"origin-ts\": 4000846807.374106884, \
             \"receive-ts\": 4000846807.383230209, \"transmit-ts\": 4000846807.383273602, \
             \"final-ts\": 4000846807.395475864, \"rtt\": 0.021326, \"offset\": -0.001540 }, \
             { \"root-dispersion\": 0.0360413, \"origin-ts\": 4000846811.375257015, \
             \"receive-ts\": 4000846811.384416580, \"transmit-ts\": 4000846811.384442806, \
             \"final-ts\": 4000846811.396611214, \"rtt\": 0.021328, \"offset\": -0.001504 } ]"
        );

        // Read back, what RIPE stores: the same fields, in the same order,
        // but for those RIPE puts in place of id, lts and time
        let ours = format!("{{ {body} }}");
        let ours: serde_json::Value = serde_json::from_str(&ours).unwrap();
        let ripe: serde_json::Value = serde_json::from_str(RIPE_112928959_1001347).unwrap();
        assert_eq!(ours["id"], ripe["msm_id"].to_string());
        assert_eq!(ours["time"], ripe["timestamp"]);
        assert_eq!(
            canonical(&format!("{{ {body} }}"), &["id", "lts", "time"]),
            canonical(
                RIPE_112928959_1001347,
                &[
                    "lts",
                    "msm_id",
                    "prb_id",
                    "timestamp",
                    "msm_name",
                    "from",
                    "type",
                    "group_id",
                    "stored_timestamp",
                ]
            )
        );
    }

    /// A JSON text, its objects' keys in their order but for `skip` (at the
    /// top), each number as the double it is read as — by Rust's parse:
    /// serde_json's own, best effort, is off by an ulp for some of these
    /// timestamps.
    fn canonical(json: &str, skip: &[&str]) -> String {
        use serde_json::value::RawValue;
        use std::collections::BTreeMap;
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        match value {
            serde_json::Value::Object(object) => {
                let raw: BTreeMap<String, Box<RawValue>> = serde_json::from_str(json).unwrap();
                let fields: Vec<String> = object
                    .keys()
                    .filter(|key| !skip.contains(&key.as_str()))
                    .map(|key| format!("{key:?}:{}", canonical(raw[key].get(), &[])))
                    .collect();
                format!("{{{}}}", fields.join(","))
            }
            serde_json::Value::Array(_) => {
                let raw: Vec<Box<RawValue>> = serde_json::from_str(json).unwrap();
                let items: Vec<String> = raw.iter().map(|v| canonical(v.get(), &[])).collect();
                format!("[{}]", items.join(","))
            }
            serde_json::Value::Number(_) => format!("{:?}", json.trim().parse::<f64>().unwrap()),
            other => other.to_string(),
        }
    }

    /// A run's line, end to end: the server's root dispersion grows
    /// between its replies, and each later entry starts with its own.
    #[tokio::test]
    async fn a_runs_later_entries_carry_their_replys_root_dispersion() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 48];
            for n in 0..3u32 {
                let (_, from) = server.recv_from(&mut buf).await.unwrap();
                let mut reply = buf;
                reply[0] = 0x24; // LI 0, VN 4, mode 4 (server)
                reply[1] = 2;
                reply[8..12].copy_from_slice(&(2354 + 4 * n).to_be_bytes());
                reply[12..16].copy_from_slice(&0x83bc03dc_u32.to_be_bytes());
                reply[24..32].copy_from_slice(&buf[40..48]); // origin = T1
                reply[32..40].copy_from_slice(&buf[40..48]); // T2 = T1
                reply[40..48].copy_from_slice(&buf[40..48]); // T3 = T1
                let _ = server.send_to(&reply, from).await;
            }
        });
        let ntp = Ntp {
            config: NtpConfig {
                target: "127.0.0.1".parse().unwrap(),
                timeout_ms: 500,
                port,
                count: 3,
                gap_ms: 150,
            },
            probe_id: ProbeId(1018212),
            msm_id: MeasurementId(1),
            dst_name: literal("127.0.0.1"),
        };
        let line = body(ntp.execute().await.unwrap());
        let (header, result) = line.split_once(", \"result\": ").unwrap();
        assert!(
            header.ends_with(
                ", \"root-dispersion\": 0.0359192, \"ref-id\": \"83bc03dc\", \
                              \"ref-ts\": 0.000000000"
            ),
            "{header}"
        );
        assert!(result.starts_with("[ { \"origin-ts\": "), "{result}");
        let entries: Vec<&str> = result.split(" }, { ").collect();
        assert_eq!(entries.len(), 3, "{result}");
        assert!(
            entries[1].starts_with("\"root-dispersion\": 0.0359802, \"origin-ts\": "),
            "{result}"
        );
        assert!(
            entries[2].starts_with("\"root-dispersion\": 0.0360413, \"origin-ts\": "),
            "{result}"
        );
    }

    /// C's %g, six significant digits (ntp.c:297-314's), as glibc prints it.
    #[test]
    fn format_g_is_cs_percent_g() {
        for (x, g) in [
            (2567.0 / 65536.0, "0.0391693"),
            (2055.0 / 65536.0, "0.0313568"),
            (2f64.powi(-23), "1.19209e-07"),
            (1.0 / 65536.0, "1.52588e-05"),
            (0.0001, "0.0001"),
            (0.5, "0.5"),
            (1.0, "1"),
            (123456.0, "123456"),
            (999999.5, "1e+06"),
            (1234567.0, "1.23457e+06"),
            (65535.0 + 65535.0 / 65536.0, "65536"),
            (-0.25, "-0.25"),
            (0.0, "0"),
        ] {
            assert_eq!(format_g(x), g, "{x}");
        }
    }

    /// A socket that cannot be connected (no route, say) is create_socket's
    /// error line: dst_addr, no src_addr, nothing else (ntp.c:1255-1274).
    #[test]
    fn a_connect_failure_is_reported() {
        let results = client::NtpResult {
            samples: Vec::new(),
            src_addr: None,
            error: Some("connect failed: Network is unreachable".into()),
        };
        let config = NtpConfig {
            target: "2001:ac8:30:68:0:1:0:2".parse().unwrap(),
            ..config()
        };
        let body = result_body(
            1,
            &config,
            &literal("2001:ac8:30:68:0:1:0:2"),
            6,
            1,
            &results,
        );
        assert!(
            body.ends_with(
                "\"dst_addr\":\"2001:ac8:30:68:0:1:0:2\", \"proto\":\"UDP\", \"af\": 6, \
                 \"result\": [ { \"error\":\"connect failed: Network is unreachable\" } ]"
            ),
            "{body}"
        );
    }

    /// A run that lasts over a second reports the second it started.
    #[tokio::test]
    async fn the_time_is_when_the_run_starts() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 48];
            while let Ok((_, from)) = server.recv_from(&mut buf).await {
                let mut reply = buf;
                reply[0] = 0x24; // LI 0, VN 4, mode 4 (server)
                reply[24..32].copy_from_slice(&buf[40..48]); // origin = T1
                reply[32..40].copy_from_slice(&buf[40..48]); // T2 = T1
                reply[40..48].copy_from_slice(&buf[40..48]); // T3 = T1
                let _ = server.send_to(&reply, from).await;
            }
        });
        let ntp = Ntp {
            config: NtpConfig {
                target: "127.0.0.1".parse().unwrap(),
                timeout_ms: 200,
                port,
                count: 2,
                gap_ms: 1200,
            },
            probe_id: ProbeId(1018212),
            msm_id: MeasurementId(1),
            dst_name: literal("127.0.0.1"),
        };
        let before = Timestamp::now().0;
        let result = ntp.execute().await.unwrap();
        let after = Timestamp::now().0;
        assert!(after > before, "the run took over a second");
        assert!(
            result.timestamp.0 < after,
            "{} {before}..{after}",
            result.timestamp.0
        );
        let line = body(result);
        assert!(
            line.contains(&format!(", \"time\":{before}, "))
                || line.contains(&format!(", \"time\":{}, ", before + 1)),
            "{line}"
        );
        assert_eq!(line.matches("\"origin-ts\"").count(), 2, "{line}");
    }
}
