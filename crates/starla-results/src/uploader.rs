//! Result uploader for sending measurements to the controller
//!
//! Sends result data over a transport that implements `UploadTransport`.
//! In production this is an SSH channel; for testing it can be anything.

use super::format::AtlasResult;
use super::host_telemetry::HostTelemetry;
use super::queue::QueuedResult;
use super::spool::{Spool, HTTPPOST_OUT};
use super::time_sync::TimeSyncTracker;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, trace, warn};

/// The target of the trace event that carries a whole upload body: a
/// target of its own, so that the body can be left out
/// (`starla_results::uploader::body=off`) while the rest of the uploader
/// traces. A directive for `starla_results::uploader` still takes it, as an
/// EnvFilter directive names a prefix of the target: the debug drop-in's
/// `starla_results::uploader=trace` logs it as before.
pub const UPLOAD_BODY_TARGET: &str = "starla_results::uploader::body";

/// How many results go into a body between yields: a batch after an outage
/// can be thousands, each cloned and serialised, on the runtime that also
/// runs the controller's SSH session and telnet.
const RESULTS_PER_YIELD: usize = 64;

/// Append each result's RESULT line to an upload body, yielding every
/// [`RESULTS_PER_YIELD`].
async fn append_result_lines(body: &mut Vec<u8>, results: &[QueuedResult]) {
    for (i, queued) in results.iter().enumerate() {
        if i > 0 && i.is_multiple_of(RESULTS_PER_YIELD) {
            tokio::task::yield_now().await;
        }
        body.extend_from_slice(result_line(queued).as_bytes());
    }
}

/// [`append_result_lines`] under a post's [`Budget`]: each result's line
/// that fits is appended. The results whose lines went in, those left for
/// the next post, and how many were dropped as too big ever to fit.
async fn append_fitting_result_lines(
    body: &mut Vec<u8>,
    results: Vec<QueuedResult>,
    budget: &mut Budget,
) -> (Vec<QueuedResult>, Vec<QueuedResult>, usize) {
    let (mut sent, mut deferred, mut dropped) = (Vec::new(), Vec::new(), 0);
    for (i, queued) in results.into_iter().enumerate() {
        if i > 0 && i.is_multiple_of(RESULTS_PER_YIELD) {
            tokio::task::yield_now().await;
        }
        let line = result_line(&queued);
        match budget.fit(line.len()) {
            Fit::Take => {
                body.extend_from_slice(line.as_bytes());
                sent.push(queued);
            }
            Fit::Later => deferred.push(queued),
            Fit::Delete => dropped += 1,
        }
    }
    (sent, deferred, dropped)
}

/// A queued result's RESULT line, with the lts it was measured at.
fn result_line(queued: &QueuedResult) -> String {
    AtlasResult::from_measurement(queued.result.clone(), None)
        .with_lts(queued.lts)
        .to_result_line()
}

/// The main post's header, httppost's `--post-header` file.
const POST_HEADER: &[u8] = b"P_TO_C_REPORT\n";

/// httppost's `--maxpostsize` without the option (httppost.c:129); the same
/// for eooqd's one-off posts, whose lines name none.
pub const DEFAULT_MAX_POST_SIZE: u64 = 1_000_000;

/// What do_dir makes of a file for a post (httppost.c:1118-1131).
#[derive(Debug, PartialEq, Eq)]
enum Fit {
    /// In this post
    Take,
    /// "too big to fit this time": left for the next post
    Later,
    /// More than half the most a post may hold: deleted, never posted
    Delete,
}

/// do_dir's running total (httppost.c:1057-1140): what a post holds so far,
/// header and footer first (cLength before do_dir), against
/// `--maxpostsize`. Each file of the directory that fits is added; one that
/// does not is left, or deleted if it never could, and the scan goes on, so
/// a smaller one after it may still fit. Starla's units are the files'
/// lines: each telemetry line, each spool file of data/out, each result.
/// do_dir's MAX_FILES (1000 files a post) is a count of files, of which
/// Starla's results are none, and is left out.
struct Budget {
    used: u64,
    max: u64,
}

impl Budget {
    fn new(max: u64, header_and_footer: usize) -> Self {
        Self {
            used: header_and_footer as u64,
            max,
        }
    }

    fn fit(&mut self, size: usize) -> Fit {
        let size = size as u64;
        if self.used.saturating_add(size) > self.max {
            if size > self.max / 2 {
                Fit::Delete
            } else {
                Fit::Later
            }
        } else {
            self.used += size;
            Fit::Take
        }
    }
}

/// What a main post did with the results it was handed.
pub(crate) struct MainPost {
    /// The results the body carried: posted on an OK, for the caller to
    /// requeue otherwise
    pub(crate) sent: Vec<QueuedResult>,
    /// The results that did not fit under `--maxpostsize`: left for the
    /// next post, as do_dir leaves a file, the attempt not counted
    pub(crate) deferred: Vec<QueuedResult>,
    /// How many results were dropped as more than half the most a post may
    /// hold, as do_dir unlinks such a file
    pub(crate) dropped: usize,
    /// The controller's answer
    pub(crate) outcome: anyhow::Result<()>,
}

/// An async bidirectional stream for upload transport.
pub trait UploadStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> UploadStream for T {}

/// The controller answered 429: the batch is refused, not failed, and the
/// caller holds uploads before re-posting it (lib.rs). A typed error rather
/// than a message string, so classification cannot drift. `retry_after` is the
/// header's seconds, when it sent one.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("rate limited")]
pub struct RateLimited {
    pub retry_after: Option<u64>,
}

/// The numeric HTTP status code from a response's status line, e.g. 429 from
/// `HTTP/1.1 429 Too Many Requests`. Substring matching treated a body that
/// happened to contain "429" as a refusal.
fn status_code(status_line: &str) -> Option<u16> {
    status_line.split_whitespace().nth(1)?.parse().ok()
}

/// A transport that opens streams to the controller's result endpoint
/// (127.0.0.1:8080 on the remote side of the SSH tunnel).
pub trait UploadTransport: Send + Sync {
    /// Open a new bidirectional stream to the controller.
    fn open(
        &self,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Box<dyn UploadStream>>> + Send + '_>>;
}

/// Configuration for the result uploader
#[derive(Debug, Clone)]
pub struct UploaderConfig {
    /// URL path and query for the HTTP POST (e.g.,
    /// "/?PROBE_ID=123&SESSION_ID=abc")
    pub endpoint_path: String,
    /// Request timeout
    pub timeout: Duration,
}

impl Default for UploaderConfig {
    fn default() -> Self {
        Self {
            endpoint_path: String::new(),
            timeout: Duration::from_secs(15),
        }
    }
}

/// Where one httppost run posts, and the options that change its request
/// or what it makes of the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostTarget {
    /// `Host:`, the URL's host without port or brackets (httppost.c
    /// parse_url, 686-790)
    pub host: String,
    /// The request target: the URL's path and query
    pub path: String,
    /// `--set-time N`: judge the clock against the answer's Date, N seconds
    /// tolerance. None (or 0) judges nothing (httppost.c:470).
    pub set_time: Option<i64>,
    /// `--local-time`: a `Unix-Date:` header (httppost.c:404-408)
    pub local_time: bool,
    /// `--maxpostsize N`: the most the body may hold, header and footer
    /// included (httppost.c:197-205, 1118)
    pub max_post_size: u64,
}

/// The tunnel's one endpoint: the reference reaches the controller through
/// `ssh -L 8080:127.0.0.1:8080`, Starla through a direct-tcpip channel to
/// the same 127.0.0.1:8080.
const TUNNEL_PORT: u16 = 8080;

impl PostTarget {
    /// The target of an httppost URL, split as httppost.c's parse_url splits
    /// it (686-790): `http://` (any case), the authority up to the first
    /// `/`, the rest (or `/`) as the path; the host is the authority less a
    /// `:port` and the brackets of an IPv6 literal. Only the tunnel's port
    /// is reachable: a URL naming another is refused, not posted to 8080.
    /// The most a post may hold is httppost's own; a line's `--maxpostsize`
    /// replaces it.
    pub fn from_url(url: &str, set_time: Option<i64>, local_time: bool) -> anyhow::Result<Self> {
        let rest = url
            .get(..7)
            .filter(|p| p.eq_ignore_ascii_case("http://"))
            .map(|_| &url[7..])
            .ok_or_else(|| anyhow::anyhow!("bad prefix in url '{url}'"))?;
        let (hostport, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
            let (h, after) = v6
                .split_once(']')
                .filter(|(h, _)| !h.is_empty())
                .ok_or_else(|| anyhow::anyhow!("malformed IPv6 literal in url '{url}'"))?;
            (h, after.strip_prefix(':'))
        } else {
            match hostport.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (hostport, None),
            }
        };
        if host.is_empty() {
            anyhow::bail!("missing host part in url '{url}'");
        }
        let port: u16 = port.unwrap_or("80").parse()?;
        if port != TUNNEL_PORT {
            anyhow::bail!("url '{url}' is not the tunnel's port {TUNNEL_PORT}");
        }
        if path.contains(['\r', '\n']) || host.contains(['\r', '\n']) {
            anyhow::bail!("url contains invalid characters");
        }
        Ok(Self {
            host: host.to_string(),
            path: path.to_string(),
            set_time: set_time.filter(|&t| t != 0),
            local_time,
            max_post_size: DEFAULT_MAX_POST_SIZE,
        })
    }
}

/// Uploads measurement results to the controller
pub struct ResultUploader {
    transport: Box<dyn UploadTransport>,
    config: UploaderConfig,
    /// Host telemetry registry; pending lines are drained per upload batch.
    host_telemetry: Arc<HostTelemetry>,
    /// Marked synced when an accepted upload's Date agrees with our clock.
    time_sync: Arc<TimeSyncTracker>,
    /// perd's spool files: httppost's own lines go to data/new/main, and
    /// the main post takes data/out
    spool: Arc<Spool>,
    metrics: starla_metrics::MetricsRegistry,
}

impl ResultUploader {
    /// Create a new uploader with the given transport
    pub fn new(
        transport: Box<dyn UploadTransport>,
        config: UploaderConfig,
        metrics: starla_metrics::MetricsRegistry,
        host_telemetry: Arc<HostTelemetry>,
        time_sync: Arc<TimeSyncTracker>,
    ) -> Self {
        Self {
            transport,
            config,
            host_telemetry,
            time_sync,
            spool: Arc::default(),
            metrics,
        }
    }

    /// The spool files this uploader posts from and writes httppost's own
    /// lines to, for crons/main's condmv to move.
    pub(crate) fn spool(&self) -> Arc<Spool> {
        Arc::clone(&self.spool)
    }

    /// Set the endpoint path (call after controller connection).
    /// Path must start with '/' (e.g., "/?PROBE_ID=123&SESSION_ID=abc").
    pub fn set_endpoint_path(&mut self, path: String) -> anyhow::Result<()> {
        if !path.starts_with('/') {
            anyhow::bail!("endpoint path must start with '/', got: {}", path);
        }
        if path.contains('\n') || path.contains('\r') {
            anyhow::bail!("endpoint path contains invalid characters");
        }
        self.config.endpoint_path = path;
        Ok(())
    }

    /// Check if an endpoint path is configured
    pub fn has_endpoint(&self) -> bool {
        !self.config.endpoint_path.is_empty()
    }

    /// Starla's own httppost line until the controller's arrives: the
    /// session's endpoint, `src` appended (`&SRC=timesync`), judged with
    /// `--set-time 2` as the controller's lines are.
    pub fn default_target(&self, src: Option<&str>) -> PostTarget {
        let mut path = self.config.endpoint_path.clone();
        if let Some(src) = src {
            // `?SRC=…` on an endpoint with no query yet, `&SRC=…` otherwise.
            path.push(if path.contains('?') { '&' } else { '?' });
            path.push_str("SRC=");
            path.push_str(src);
        }
        PostTarget {
            host: "127.0.0.1".into(),
            path,
            set_time: Some(SET_TIME_TOLERANCE_SECS),
            local_time: false,
            max_post_size: DEFAULT_MAX_POST_SIZE,
        }
    }

    /// Upload a batch of results
    ///
    /// Builds the POST body (P_TO_C_REPORT header, RESULT lines, SESSION_ID
    /// footer), writes a raw HTTP/1.1 POST over the transport stream, and
    /// reads the response.
    pub async fn upload_batch(
        &self,
        results: &[QueuedResult],
        session_id: Option<&str>,
    ) -> anyhow::Result<()> {
        self.upload_batch_to(&self.default_target(None), results.to_vec(), session_id)
            .await
            .outcome
    }

    /// [`upload_batch`](Self::upload_batch) as an httppost line with
    /// `--post-dir` posts it: to `target`, under its `--maxpostsize`. The
    /// body is the header, then what fits of the host telemetry, the spool
    /// files of data/out and the results, each in turn ([`Budget`]), then
    /// the footer. Posted spool files are deleted on an OK
    /// (`--delete-file`); telemetry lines go back for the next post unless
    /// they went out with an OK; the results are the caller's to requeue.
    pub(crate) async fn upload_batch_to(
        &self,
        target: &PostTarget,
        results: Vec<QueuedResult>,
        session_id: Option<&str>,
    ) -> MainPost {
        // An empty batch is still posted (header, telemetry, footer), as the
        // reference probe's minutely httppost is with an empty data/out.
        if !self.has_endpoint() {
            return MainPost {
                sent: results,
                deferred: Vec::new(),
                dropped: 0,
                outcome: Err(anyhow::anyhow!("No upload endpoint configured")),
            };
        }

        self.metrics.record_upload_attempt();
        let start_time = std::time::Instant::now();

        let footer = session_id
            .map(|sid| format!("\nSESSION_ID {sid}\n"))
            .unwrap_or_default();
        let mut budget = Budget::new(target.max_post_size, POST_HEADER.len() + footer.len());
        let mut body = POST_HEADER.to_vec();

        // Host telemetry RESULT lines (buddyinfo, rptaddrs, the status
        // lines) accumulated since the last upload. Pushed by HostTelemetry's
        // periodic reporters, and put back if this upload fails (below).
        let mut telemetry = Vec::new();
        for line in self.host_telemetry.drain().await {
            let took = match budget.fit(line.len()) {
                Fit::Take => {
                    body.extend_from_slice(line.as_bytes());
                    true
                }
                Fit::Later => false,
                Fit::Delete => {
                    warn!(
                        "Dropping a {}-byte telemetry line: more than half of --maxpostsize {}",
                        line.len(),
                        target.max_post_size
                    );
                    continue;
                }
            };
            telemetry.push((line, took));
        }

        // data/out's files: perd's condmv moved them there
        let (mut posted_files, mut too_big) = (Vec::new(), Vec::new());
        for (name, content) in self.spool.outgoing().await {
            match budget.fit(content.len()) {
                Fit::Take => {
                    body.extend_from_slice(content.as_bytes());
                    posted_files.push(name);
                }
                Fit::Later => {}
                Fit::Delete => {
                    warn!(
                        "Deleting {name}, {} bytes: too big ever to post",
                        content.len()
                    );
                    too_big.push(name);
                }
            }
        }
        self.spool.delete(&too_big).await;

        let (sent, deferred, dropped) =
            append_fitting_result_lines(&mut body, results, &mut budget).await;
        if dropped > 0 {
            warn!(
                "Dropping {dropped} results: each more than half of --maxpostsize {}",
                target.max_post_size
            );
        }
        if !deferred.is_empty() {
            debug!(
                "{} results wait for the next post: --maxpostsize {}",
                deferred.len(),
                target.max_post_size
            );
        }

        body.extend_from_slice(footer.as_bytes());

        debug!(
            "Uploading batch of {} results ({} bytes)",
            sent.len(),
            body.len(),
        );
        trace!(target: UPLOAD_BODY_TARGET, "Upload body:\n{}", String::from_utf8_lossy(&body));

        let outcome = self.post(target, &body, sent.len(), start_time).await;
        // The lines this post carried are gone with an OK; any other line
        // goes back, ahead of those queued since, in the order it came.
        let ok = outcome.is_ok();
        let back: Vec<String> = telemetry
            .into_iter()
            .filter(|&(_, took)| !(ok && took))
            .map(|(line, _)| line)
            .collect();
        self.host_telemetry.restore(back).await;
        if ok {
            self.spool.delete(&posted_files).await;
        }
        MainPost {
            sent,
            deferred,
            dropped,
            outcome,
        }
    }

    /// The controller's 900 s `httppost … &SRC=timesync` line: header and
    /// footer only, so the clock is judged even when nothing else is posted.
    pub async fn post_timesync(&self, session_id: Option<&str>) -> anyhow::Result<()> {
        self.post_header_only(&self.default_target(Some("timesync")), session_id)
            .await
    }

    /// An httppost line without `--post-dir` (the timesync line): its
    /// `--post-header` and `--post-footer` files only.
    pub async fn post_header_only(
        &self,
        target: &PostTarget,
        session_id: Option<&str>,
    ) -> anyhow::Result<()> {
        if !self.has_endpoint() {
            anyhow::bail!("No upload endpoint configured");
        }
        let mut body = b"P_TO_C_REPORT\n".to_vec();
        if let Some(sid) = session_id {
            body.extend_from_slice(format!("\nSESSION_ID {sid}\n").as_bytes());
        }
        self.post(target, &body, 0, std::time::Instant::now()).await
    }

    /// eooqd's post of one-off results (eooqd.c:792-820): `httppost -A 9015
    /// --delete-file --post-header <P_TO_C_REPORT> --post-dir <ooq out>
    /// --post-footer <session> -O ooq_sent
    /// http://127.0.0.1:8080/?PROBE_ID=%d&SESSION_ID=%s&SRC=oneoff`. The URL
    /// is built from the probe id and the session, not taken from a
    /// CRONLINE; the body is header, the one-offs' RESULT lines, footer (no
    /// telemetry, no condmv marker: eooqd's spool is its own); and with no
    /// `--set-time` the answer's Date is not judged.
    pub async fn post_oneoff(
        &self,
        results: &[QueuedResult],
        session_id: Option<&str>,
    ) -> anyhow::Result<()> {
        if !self.has_endpoint() {
            anyhow::bail!("No upload endpoint configured");
        }
        let mut body = b"P_TO_C_REPORT\n".to_vec();
        append_result_lines(&mut body, results).await;
        if let Some(sid) = session_id {
            body.extend_from_slice(format!("\nSESSION_ID {sid}\n").as_bytes());
        }
        let target = PostTarget {
            set_time: None,
            ..self.default_target(Some("oneoff"))
        };
        self.post(&target, &body, results.len(), std::time::Instant::now())
            .await
    }

    /// httppost --set-time N: compare the answer's Date with our clock. In
    /// step and answered within a second: a time sync (lts restarts from 0).
    /// Otherwise a RESULT 9015 line on httppost's stdout, which the line's
    /// `>> /home/atlas/data/new/main` appends to that spool file: crons/main's
    /// condmv moves it to data/out with its 9901 marker, for a later post
    /// to take. Starla never sets the clock.
    async fn judge_clock(&self, response: &str, rtt: Duration, tolerance: i64) {
        let Some(server) = response
            .lines()
            .take_while(|l| !l.is_empty())
            .find_map(|l| l.strip_prefix("Date:").or_else(|| l.strip_prefix("date:")))
            .and_then(parse_http_date)
        else {
            return;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        match clock_verdict(now, server, rtt.as_secs_f64(), tolerance) {
            ClockVerdict::InSync => self.time_sync.mark_synced(),
            ClockVerdict::NotInSync => {
                warn!("Clock not in sync with the controller: local {now}, remote {server}");
                self.spool
                    .append(
                        HTTPPOST_OUT,
                        &format!(
                            "RESULT 9015 ongoing {now} httppost not in sync, local {now}, \
                             remote {server}\n"
                        ),
                    )
                    .await;
            }
            ClockVerdict::SlowAnswer => {
                self.spool
                    .append(
                        HTTPPOST_OUT,
                        &format!(
                            "RESULT 9015 ongoing {now} httppost rtt {} ms\n",
                            format_g(rtt.as_secs_f64() * 1000.0)
                        ),
                    )
                    .await;
            }
        }
    }

    /// POST one built body over a fresh transport stream and judge the
    /// controller's answer. Any error is the whole batch's failure.
    async fn post(
        &self,
        target: &PostTarget,
        body: &[u8],
        count: usize,
        start_time: std::time::Instant,
    ) -> anyhow::Result<()> {
        // Open transport stream and send raw HTTP/1.1 POST
        let mut stream = tokio::time::timeout(self.config.timeout, self.transport.open())
            .await
            .map_err(|_| {
                anyhow::anyhow!("Transport open timed out after {:?}", self.config.timeout)
            })??;

        let local_time = target.local_time.then(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
        });
        let request = request_head(target, local_time, body.len());

        stream.write_all(request.as_bytes()).await?;
        stream.write_all(body).await?;
        stream.flush().await?;

        // Read HTTP response
        let mut response = Vec::with_capacity(256);
        let mut buf = [0u8; 1024];
        loop {
            match tokio::time::timeout(self.config.timeout, stream.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => response.extend_from_slice(&buf[..n]),
                Ok(Err(e)) => {
                    // Read error after we got some data is OK (connection close)
                    if response.is_empty() {
                        return Err(e.into());
                    }
                    break;
                }
                Err(_) => {
                    if response.is_empty() {
                        anyhow::bail!("Response timed out after {:?}", self.config.timeout);
                    }
                    break;
                }
            }
            // Don't read forever: response should be short
            if response.len() > 4096 {
                break;
            }
        }

        let response_str = String::from_utf8_lossy(&response);
        trace!("Upload response: {:?}", response_str);

        // Parse HTTP status
        if let Some(status_line) = response_str.lines().next() {
            match status_code(status_line) {
                Some(429) => {
                    // Parse Retry-After header if present
                    let retry_after = response_str
                        .lines()
                        .find(|l| l.to_lowercase().starts_with("retry-after:"))
                        .and_then(|l| l.split(':').nth(1))
                        .and_then(|v| v.trim().parse::<u64>().ok());
                    if let Some(secs) = retry_after {
                        warn!("Rate limited (429), Retry-After: {}s", secs);
                    } else {
                        warn!("Rate limited (429)");
                    }
                    return Err(RateLimited { retry_after }.into());
                }
                Some(200) => {
                    // Check body for OK/ERR
                    if let Some(body_start) = response_str.find("\r\n\r\n") {
                        let resp_body = response_str[body_start + 4..].trim();
                        if resp_body == "OK" {
                            debug!("Batch upload successful: {} results", count);
                            self.metrics
                                .record_upload_duration(start_time.elapsed().as_secs_f64());
                            if let Some(tolerance) = target.set_time {
                                self.judge_clock(&response_str, start_time.elapsed(), tolerance)
                                    .await;
                            }
                            return Ok(());
                        } else {
                            debug!("Upload rejected: {:?}", resp_body);
                            anyhow::bail!("Upload rejected: {}", resp_body);
                        }
                    }
                    // No body separator found but status was 200: treat as success
                    debug!("Batch upload successful (no body): {} results", count);
                    self.metrics
                        .record_upload_duration(start_time.elapsed().as_secs_f64());
                    if let Some(tolerance) = target.set_time {
                        self.judge_clock(&response_str, start_time.elapsed(), tolerance)
                            .await;
                    }
                    return Ok(());
                }
                _ => anyhow::bail!("Upload failed: {}", status_line),
            }
        }

        anyhow::bail!("Empty response from controller")
    }
}

/// The controller's crontab runs httppost with `--set-time 2`.
const SET_TIME_TOLERANCE_SECS: i64 = 2;

/// httppost's request line and headers, in its order (httppost.c:395-417):
/// Host, Connection, User-Agent, Content-Type, `Unix-Date` with
/// `--local-time`, Content-Length. The twin's reference probe sent exactly
/// this on all 15 of its posts; Starla sent Content-Type second and
/// Connection fourth.
fn request_head(target: &PostTarget, local_time: Option<i64>, content_length: usize) -> String {
    let mut head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: httppost for \
         atlas.ripe.net\r\nContent-Type: application/x-www-form-urlencoded\r\n",
        target.path, target.host,
    );
    if let Some(t) = local_time {
        head.push_str(&format!("Unix-Date: {t}\r\n"));
    }
    head.push_str(&format!("Content-Length: {content_length}\r\n\r\n"));
    head
}

#[derive(Debug, PartialEq)]
enum ClockVerdict {
    InSync,
    NotInSync,
    SlowAnswer,
}

/// httppost's test: out of step if `now` is outside
/// `server ± (tolerance + rtt)`; in step and `rtt <= 1 s` is a sync.
fn clock_verdict(now: i64, server: i64, rtt: f64, tolerance: i64) -> ClockVerdict {
    let (now, server, tol) = (now as f64, server as f64, tolerance as f64);
    if now < server - tol - rtt || now > server + tol + rtt {
        ClockVerdict::NotInSync
    } else if rtt <= 1.0 {
        ClockVerdict::InSync
    } else {
        ClockVerdict::SlowAnswer
    }
}

/// An HTTP Date (`Mon, 12 Oct 2026 20:20:51 GMT`) as unix seconds.
fn parse_http_date(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc2822(value.trim())
        .ok()
        .map(|t| t.timestamp())
}

/// C's `%g` for the positive values httppost prints: six significant
/// digits, trailing zeros dropped.
fn format_g(x: f64) -> String {
    let int_digits = if x >= 1.0 {
        x.log10().floor() as i32 + 1
    } else {
        1
    };
    let decimals = (6 - int_digits).max(0) as usize;
    let s = format!("{x:.decimals$}");
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starla_common::{
        MeasurementData, MeasurementId, MeasurementResult, MeasurementType, ProbeId, Timestamp,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_default_config() {
        let config = UploaderConfig::default();
        assert!(config.endpoint_path.is_empty());
    }

    /// A controller that answers every POST with `reply`, and hands back each
    /// request it read.
    struct FakeController {
        reply: &'static str,
        seen: tokio::sync::mpsc::UnboundedSender<String>,
    }

    impl UploadTransport for FakeController {
        fn open(
            &self,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<Box<dyn UploadStream>>> + Send + '_>>
        {
            let (probe, mut ctrl) = tokio::io::duplex(1 << 20);
            let reply = self.reply;
            let seen = self.seen.clone();
            tokio::spawn(async move {
                let mut req = Vec::new();
                let mut buf = [0u8; 8192];
                // Read until the request's Content-Length is satisfied.
                loop {
                    let n = ctrl.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&req);
                    if let Some(h) = text.find("\r\n\r\n") {
                        let len: usize = text
                            .lines()
                            .find_map(|l| l.strip_prefix("Content-Length: "))
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        if req.len() >= h + 4 + len {
                            break;
                        }
                    }
                }
                let _ = seen.send(String::from_utf8_lossy(&req).into_owned());
                let _ = ctrl.write_all(reply.as_bytes()).await;
                let _ = ctrl.shutdown().await;
            });
            Box::pin(async move { Ok(Box::new(probe) as Box<dyn UploadStream>) })
        }
    }

    fn uploader(
        reply: &'static str,
    ) -> (
        ResultUploader,
        Arc<HostTelemetry>,
        tokio::sync::mpsc::UnboundedReceiver<String>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let telemetry = HostTelemetry::new();
        let mut u = ResultUploader::new(
            Box::new(FakeController { reply, seen: tx }),
            UploaderConfig::default(),
            starla_metrics::MetricsRegistry::new().unwrap(),
            Arc::clone(&telemetry),
            Arc::new(TimeSyncTracker::new()),
        );
        u.set_endpoint_path("/?PROBE_ID=1".into()).unwrap();
        (u, telemetry, rx)
    }

    fn one_result() -> Vec<QueuedResult> {
        vec![QueuedResult {
            result: MeasurementResult {
                fw: 5120,
                measurement_type: MeasurementType::Ping,
                prb_id: ProbeId(1),
                msm_id: MeasurementId(1001),
                timestamp: Timestamp::now(),
                af: 4,
                dst_addr: "193.0.14.129".parse().unwrap(),
                dst_name: None,
                src_addr: None,
                proto: Some("ICMP".to_string()),
                ttl: Some(64),
                size: Some(32),
                data: MeasurementData::Generic(serde_json::json!([{"rtt": 4.2}])),
            },
            queued_at: 0,
            attempts: 0,
            last_attempt_at: None,
            lts: -1,
        }]
    }

    const REPORT: &str = "RESULT { \"id\": \"9104\", \"time\": 1 }\n";

    /// A batch after an outage can be thousands of results, each cloned and
    /// serialised into the body on the background runtime: the body is
    /// built 64 results at a time. On a current-thread runtime, another
    /// task runs only when the building yields.
    #[tokio::test]
    async fn a_large_body_is_built_a_slice_at_a_time() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let results: Vec<QueuedResult> = (0..640).flat_map(|_| one_result()).collect();
        let polls = Arc::new(AtomicUsize::new(0));
        let other = tokio::spawn({
            let polls = polls.clone();
            async move {
                loop {
                    polls.fetch_add(1, SeqCst);
                    tokio::task::yield_now().await;
                }
            }
        });
        tokio::task::yield_now().await;

        let before = polls.load(SeqCst);
        let mut body = Vec::new();
        append_result_lines(&mut body, &results).await;
        let between = polls.load(SeqCst) - before;
        other.abort();

        assert_eq!(String::from_utf8(body).unwrap().lines().count(), 640);
        assert!(between >= 640 / RESULTS_PER_YIELD - 1, "{between} slices");
    }

    /// Log output as the probe's stdout carries it.
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// What one upload logs with RUST_LOG set to `spec`.
    ///
    /// tracing caches whether a callsite is enabled, for the whole process.
    /// While one dispatcher is registered, it fills the cache from the
    /// default of the thread that hits the callsite: hit first by another
    /// test's thread, which has no subscriber, a callsite stayed off on
    /// this one too, and nothing was logged. A second dispatcher kept
    /// registered, which takes nothing, leaves every callsite to ask the
    /// subscriber of the thread it is hit on.
    fn logged_by_an_upload(spec: &str) -> String {
        use starla_common::logging::{fmt, EnvFilter};
        static ASK_EACH_THREAD: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();
        ASK_EACH_THREAD
            .get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()));
        let out = Captured::default();
        let subscriber = fmt::Subscriber::builder()
            .with_env_filter(EnvFilter::new(spec))
            .with_ansi(false)
            .with_writer({
                let out = out.clone();
                move || out.clone()
            })
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let (u, _telemetry, _seen) = uploader("HTTP/1.1 200 \r\n\r\nOK\n");
                u.upload_batch(&one_result(), None).await.unwrap();
            });
        });
        let logged = out.0.lock().unwrap().clone();
        String::from_utf8(logged).unwrap()
    }

    /// The whole body goes on a target of its own, under the uploader's. The
    /// debug drop-in on enodia (90-debug.conf) still logs it: an EnvFilter
    /// directive names a prefix of the target, and the longest one that
    /// matches decides. A directive for the body's target alone leaves it
    /// out and the uploader's other traces in.
    #[test]
    fn the_upload_body_has_a_target_of_its_own() {
        const DROP_IN: &str =
            "starla=debug,starla_results::uploader=trace,starla_controller::ssh=trace";
        let body = "Upload body:\nP_TO_C_REPORT\nRESULT { ";
        let response = "Upload response: \"HTTP/1.1 200";
        let batch = "Uploading batch of 1 results";

        let logged = logged_by_an_upload(DROP_IN);
        for line in [body, response, batch] {
            assert!(logged.contains(line), "{line:?} not in:\n{logged}");
        }
        assert!(logged.contains(UPLOAD_BODY_TARGET), "{logged}");

        let logged = logged_by_an_upload(&format!("{DROP_IN},{UPLOAD_BODY_TARGET}=off"));
        assert!(!logged.contains("Upload body:"), "{logged}");
        for line in [response, batch] {
            assert!(logged.contains(line), "{line:?} not in:\n{logged}");
        }

        // starla=debug alone takes the uploader's debug lines, not its traces
        let logged = logged_by_an_upload("starla=debug");
        assert!(logged.contains(batch), "{logged}");
        assert!(!logged.contains("Upload body:"), "{logged}");
        assert!(!logged.contains("Upload response:"), "{logged}");
    }

    /// 2026-10-12: RIPE answered a probe's first-ever address report with 429,
    /// and the line was gone. A failed upload puts its telemetry back.
    #[tokio::test]
    async fn a_rate_limited_upload_keeps_its_telemetry() {
        let (u, telemetry, mut seen) = uploader("HTTP/1.1 429 Too Many Requests\r\n\r\n");
        telemetry.push(REPORT.into()).await;
        let err = u.upload_batch(&one_result(), None).await.unwrap_err();
        assert!(err.to_string().contains("rate limited"), "{err}");
        assert!(
            seen.recv().await.unwrap().contains(REPORT),
            "the report was in the request"
        );
        assert_eq!(telemetry.drain().await, [REPORT], "and is pending again");
    }

    #[tokio::test]
    async fn an_accepted_upload_consumes_its_telemetry() {
        let (u, telemetry, mut seen) = uploader("HTTP/1.1 200 OK\r\n\r\nOK");
        telemetry.push(REPORT.into()).await;
        u.upload_batch(&one_result(), None).await.unwrap();
        assert!(seen.recv().await.unwrap().contains(REPORT));
        assert!(telemetry.drain().await.is_empty());
    }

    #[test]
    fn the_clock_is_judged_as_httppost_judges_it() {
        let t = 1_791_836_451;
        assert_eq!(clock_verdict(t, t + 1, 0.2, 2), ClockVerdict::InSync);
        // Tolerance widens by the round trip.
        assert_eq!(clock_verdict(t, t + 2, 0.6, 2), ClockVerdict::InSync);
        assert_eq!(clock_verdict(t, t + 5, 0.2, 2), ClockVerdict::NotInSync);
        assert_eq!(clock_verdict(t, t - 5, 0.2, 2), ClockVerdict::NotInSync);
        assert_eq!(clock_verdict(t, t, 1.5, 2), ClockVerdict::SlowAnswer);
    }

    #[test]
    fn http_dates_and_g_format() {
        // RIPE's own header, 2026-10-12.
        assert_eq!(
            parse_http_date(" Mon, 12 Oct 2026 20:20:51 GMT"),
            Some(1_791_836_451)
        );
        assert_eq!(parse_http_date("yesterday"), None);
        assert_eq!(format_g(1523.456789), "1523.46");
        assert_eq!(format_g(60000.0), "60000");
        assert_eq!(format_g(2000.5), "2000.5");
    }

    fn reply_dated(offset_secs: i64) -> &'static str {
        let date = (chrono::Utc::now() + chrono::Duration::seconds(offset_secs))
            .format("%a, %d %b %Y %H:%M:%S GMT");
        Box::leak(
            format!(
                "HTTP/1.1 200 \r\nContent-Length: 3\r\nDate: {date}\r\nConnection: \
                 close\r\n\r\nOK\n"
            )
            .into_boxed_str(),
        )
    }

    fn with_time_sync(
        reply: &'static str,
    ) -> (ResultUploader, Arc<HostTelemetry>, Arc<TimeSyncTracker>) {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let telemetry = HostTelemetry::new();
        let sync = Arc::new(TimeSyncTracker::new());
        let mut u = ResultUploader::new(
            Box::new(FakeController { reply, seen: tx }),
            UploaderConfig::default(),
            starla_metrics::MetricsRegistry::new().unwrap(),
            Arc::clone(&telemetry),
            Arc::clone(&sync),
        );
        u.set_endpoint_path("/?PROBE_ID=1".into()).unwrap();
        (u, telemetry, sync)
    }

    #[tokio::test]
    async fn an_accepted_upload_in_step_is_a_time_sync() {
        let (u, telemetry, sync) = with_time_sync(reply_dated(0));
        assert_eq!(sync.lts(), -1);
        u.upload_batch(&[], Some("s")).await.unwrap();
        assert!((0..2).contains(&sync.lts()), "{}", sync.lts());
        assert!(telemetry.drain().await.is_empty());
    }

    /// httppost's 9015 line is its stdout, appended to data/new/main
    /// (`>> /home/atlas/data/new/main`): no marker of its own, and not in
    /// the next post until crons/main's condmv has moved it to data/out.
    #[tokio::test]
    async fn an_answer_an_hour_off_is_reported_not_trusted() {
        let (u, telemetry, sync) = with_time_sync(reply_dated(3600));
        u.upload_batch(&[], Some("s")).await.unwrap();
        assert_eq!(sync.lts(), -1);
        assert!(telemetry.drain().await.is_empty());
        let main = u.spool().file(HTTPPOST_OUT).await.unwrap();
        assert!(
            main.starts_with("RESULT 9015 ongoing ")
                && main.contains(" httppost not in sync, local ")
                && main.ends_with('\n')
                && main.lines().count() == 1,
            "{main}"
        );
        assert!(u.spool().outgoing().await.is_empty(), "not moved yet");
    }

    /// The reference sends status lines from its 180 s loop, not with every
    /// upload. A post writes no condmv marker either: eperd's 9907 is
    /// crons/7's condmv's to append (starla-scheduler), perd's 9901
    /// crons/main's (spool.rs), and each comes only from its line.
    #[tokio::test]
    async fn an_upload_carries_results_and_no_marker() {
        let (u, _telemetry, mut seen) = uploader("HTTP/1.1 200 \r\n\r\nOK\n");
        u.upload_batch(&one_result(), Some("s")).await.unwrap();
        let req = seen.recv().await.unwrap();
        let body = &req[req.find("\r\n\r\n").unwrap() + 4..];
        let line = result_line(&one_result()[0]);
        assert_eq!(body, format!("P_TO_C_REPORT\n{line}\nSESSION_ID s\n"));
        for gone in ["\"7001\"", "\"9018\"", "\"9002\"", "9907", "9901"] {
            assert!(!body.contains(gone), "{gone} in {body}");
        }
    }

    /// do_dir's test of each file against --maxpostsize, header and footer
    /// counted first (httppost.c:1118-1131).
    #[test]
    fn a_post_holds_what_maxpostsize_lets_it() {
        let mut b = Budget::new(100, 20);
        assert_eq!(b.fit(30), Fit::Take);
        assert_eq!(b.fit(50), Fit::Take, "exactly 100");
        assert_eq!(b.fit(1), Fit::Later, "one byte over: next time");
        assert_eq!(b.fit(50), Fit::Later, "half: next time");
        assert_eq!(b.fit(51), Fit::Delete, "more than half: never");
        assert_eq!(b.fit(0), Fit::Take);
        // httppost's default
        let mut b = Budget::new(DEFAULT_MAX_POST_SIZE, 14);
        assert_eq!(b.fit(500_000), Fit::Take);
        assert_eq!(b.fit(500_001), Fit::Delete);
        assert_eq!(b.fit(499_986), Fit::Take);
        assert_eq!(b.fit(1), Fit::Later);
    }

    /// A post under --maxpostsize: what fits goes, in order, and the scan
    /// goes on past what does not; a result that does not fit waits for
    /// the next post, and one that never could is dropped.
    #[tokio::test]
    async fn a_post_leaves_the_results_that_do_not_fit_for_the_next() {
        let (u, _telemetry, mut seen) = uploader("HTTP/1.1 200 \r\n\r\nOK\n");
        let mut results: Vec<QueuedResult> = (0..3).flat_map(|_| one_result()).collect();
        results[1].result.msm_id = MeasurementId(1002);
        results[1].result.data =
            MeasurementData::Generic(serde_json::json!([{"rtt": 4.2, "x": 1}]));
        results[2].result.msm_id = MeasurementId(1003);
        let small = result_line(&results[0]).len();
        let big = result_line(&results[1]).len();
        // Room for the header, the two small results and the footer, not
        // the big one, which is no more than half of it
        let max = (POST_HEADER.len() + 2 * small + "\nSESSION_ID s\n".len()) as u64;
        assert!(big > small && big as u64 <= max / 2, "{small} {big} {max}");
        let target = PostTarget {
            max_post_size: max,
            ..u.default_target(None)
        };

        let post = u.upload_batch_to(&target, results, Some("s")).await;
        post.outcome.unwrap();
        let req = seen.recv().await.unwrap();
        let body = &req[req.find("\r\n\r\n").unwrap() + 4..];
        assert_eq!(body.len() as u64, max);
        let ids = |rs: &[QueuedResult]| rs.iter().map(|r| r.result.msm_id.0).collect::<Vec<_>>();
        assert_eq!(ids(&post.sent), [1001, 1003], "past the one that waits");
        assert_eq!(ids(&post.deferred), [1002]);
        assert_eq!(post.dropped, 0);

        // A result more than half of it is dropped
        let target = PostTarget {
            max_post_size: small as u64 + 20,
            ..target
        };
        let post = u.upload_batch_to(&target, one_result(), Some("s")).await;
        post.outcome.unwrap();
        assert!(post.sent.is_empty() && post.deferred.is_empty());
        assert_eq!(post.dropped, 1);
        let req = seen.recv().await.unwrap();
        assert!(
            req.ends_with("\r\n\r\nP_TO_C_REPORT\n\nSESSION_ID s\n"),
            "{req}"
        );
    }

    /// Telemetry under --maxpostsize: a line that does not fit goes back
    /// for the next post, even with an OK, in its place; one too big ever
    /// to fit is dropped.
    #[tokio::test]
    async fn telemetry_that_does_not_fit_waits_for_the_next_post() {
        let (u, telemetry, mut seen) = uploader("HTTP/1.1 200 \r\n\r\nOK\n");
        const LATER: &str = "RESULT { \"later\": 1 }\n";
        let huge = format!("RESULT {{ \"x\": \"{}\" }}\n", "z".repeat(3000));
        let max = (POST_HEADER.len() + REPORT.len() + 10) as u64;
        assert!(LATER.len() as u64 <= max / 2);
        let target = PostTarget {
            max_post_size: max,
            ..u.default_target(None)
        };
        for line in [REPORT, &huge, LATER] {
            telemetry.push(line.to_string()).await;
        }
        u.upload_batch_to(&target, Vec::new(), None)
            .await
            .outcome
            .unwrap();
        let req = seen.recv().await.unwrap();
        assert!(
            req.ends_with(&format!("\r\n\r\nP_TO_C_REPORT\n{REPORT}")),
            "{req}"
        );
        assert_eq!(telemetry.drain().await, [LATER], "the huge one is gone");
    }

    /// The main post takes data/out's files, which crons/main's condmv put
    /// there (`--post-dir /home/atlas/data/out`), and deletes them once the
    /// controller has answered OK (`--delete-file`); a failed post leaves
    /// them for the next, and a file too big ever to post is deleted.
    #[tokio::test]
    async fn the_main_post_takes_data_out_and_deletes_it_on_an_ok() {
        use crate::spool::Condmv;
        let crons_main = Condmv {
            append: Some("RESULT 9901 ongoing".into()),
            from: "/home/atlas/data/new/main".into(),
            from_file: HTTPPOST_OUT.into(),
            to_file: "data/out/main".into(),
            force: false,
        };
        let moved = "RESULT 9015 ongoing 10 httppost rtt 1523.46 ms\nRESULT 9901 ongoing 60 \
                     /home/atlas/data/new/main\n";
        for (reply, kept) in [
            ("HTTP/1.1 500 \r\n\r\n", true),
            ("HTTP/1.1 200 \r\n\r\nOK\n", false),
        ] {
            let (u, _telemetry, mut seen) = uploader(reply);
            let spool = u.spool();
            spool
                .append(
                    HTTPPOST_OUT,
                    "RESULT 9015 ongoing 10 httppost rtt 1523.46 ms\n",
                )
                .await;
            assert!(spool.condmv(&crons_main, 60).await);
            let post = u
                .upload_batch_to(&u.default_target(None), one_result(), Some("s"))
                .await;
            assert_eq!(post.outcome.is_ok(), !kept);
            let req = seen.recv().await.unwrap();
            let body = &req[req.find("\r\n\r\n").unwrap() + 4..];
            let line = result_line(&one_result()[0]);
            assert_eq!(
                body,
                format!("P_TO_C_REPORT\n{moved}{line}\nSESSION_ID s\n")
            );
            assert_eq!(spool.file("data/out/main").await.is_some(), kept, "{reply}");
        }

        let (u, _telemetry, mut seen) = uploader("HTTP/1.1 200 \r\n\r\nOK\n");
        u.spool().append(HTTPPOST_OUT, &"x".repeat(600)).await;
        assert!(u.spool().condmv(&crons_main, 60).await);
        // ~650 bytes with its marker: more than the post may hold, and more
        // than half of it
        let target = PostTarget {
            max_post_size: 600,
            ..u.default_target(None)
        };
        u.upload_batch_to(&target, Vec::new(), None)
            .await
            .outcome
            .unwrap();
        assert_eq!(u.spool().file("data/out/main").await, None, "deleted");
        let req = seen.recv().await.unwrap();
        assert!(req.ends_with("\r\n\r\nP_TO_C_REPORT\n"), "{req}");
    }

    /// The twin's reference probe, 2026-10-13 (wire-ctrl.jsonl): its
    /// timesync post, head and body byte for byte.
    const REF_SESSION: &str = "b6c053a85ee60b777fa64503f459764141780eea4c80d096c75cb2300531a15d";

    #[test]
    fn the_request_head_is_httpposts_byte_for_byte() {
        let url = format!(
            "http://127.0.0.1:8080/?PROBE_ID=1018212&SESSION_ID={REF_SESSION}&SRC=timesync"
        );
        let target = PostTarget::from_url(&url, Some(2), false).unwrap();
        assert_eq!(
            request_head(&target, None, 91),
            format!(
                "POST /?PROBE_ID=1018212&SESSION_ID={REF_SESSION}&SRC=timesync HTTP/1.1\r\nHost: \
                 127.0.0.1\r\nConnection: close\r\nUser-Agent: httppost for \
                 atlas.ripe.net\r\nContent-Type: \
                 application/x-www-form-urlencoded\r\nContent-Length: 91\r\n\r\n"
            )
        );
        // --local-time: Unix-Date after Content-Type (httppost.c:404-408).
        let head = request_head(&target, Some(1_791_871_521), 91);
        assert!(
            head.contains(
                "Content-Type: application/x-www-form-urlencoded\r\nUnix-Date: \
                 1791871521\r\nContent-Length: 91\r\n\r\n"
            ),
            "{head}"
        );
    }

    #[tokio::test]
    async fn an_upload_goes_out_in_httpposts_header_order() {
        let (u, _telemetry, mut seen) = uploader("HTTP/1.1 200 \r\n\r\nOK\n");
        u.upload_batch(&one_result(), Some("s")).await.unwrap();
        let req = seen.recv().await.unwrap();
        let (head, body) = req.split_once("\r\n\r\n").unwrap();
        let names: Vec<&str> = head
            .lines()
            .skip(1)
            .map(|l| l.split_once(':').unwrap().0)
            .collect();
        assert_eq!(
            names,
            [
                "Host",
                "Connection",
                "User-Agent",
                "Content-Type",
                "Content-Length"
            ]
        );
        assert!(head.ends_with(&format!("Content-Length: {}", body.len())));
    }

    #[test]
    fn a_url_splits_as_parse_url_splits_it() {
        let t = PostTarget::from_url(
            &format!("http://127.0.0.1:8080/?PROBE_ID=1018212&SESSION_ID={REF_SESSION}"),
            Some(2),
            false,
        )
        .unwrap();
        assert_eq!(t.host, "127.0.0.1");
        assert_eq!(
            t.path,
            format!("/?PROBE_ID=1018212&SESSION_ID={REF_SESSION}")
        );
        assert_eq!(t.set_time, Some(2));

        let t = PostTarget::from_url("HTTP://[::1]:8080", None, false).unwrap();
        assert_eq!((t.host.as_str(), t.path.as_str()), ("::1", "/"));
        let t = PostTarget::from_url("http://localhost:8080/x", Some(0), true).unwrap();
        assert_eq!(t.host, "localhost");
        assert_eq!(t.set_time, None, "--set-time 0 judges nothing");
        assert!(t.local_time);

        for bad in [
            "https://127.0.0.1:8080/",
            "http://127.0.0.1/?PROBE_ID=1",
            "http://127.0.0.1:8081/",
            "http://:8080/",
            "http://[]:8080/",
            "http://127.0.0.1:8080/\r\nX: y",
        ] {
            assert!(PostTarget::from_url(bad, None, false).is_err(), "{bad}");
        }
    }

    /// eooqd posts one-offs with no --set-time: header, the one-offs, footer,
    /// to `&SRC=oneoff`, and the answer's Date is not judged.
    #[tokio::test]
    async fn a_one_off_post_is_eooqds() {
        let (tx, mut seen) = tokio::sync::mpsc::unbounded_channel();
        let telemetry = HostTelemetry::new();
        let sync = Arc::new(TimeSyncTracker::new());
        let mut u = ResultUploader::new(
            Box::new(FakeController {
                reply: reply_dated(3600),
                seen: tx,
            }),
            UploaderConfig::default(),
            starla_metrics::MetricsRegistry::new().unwrap(),
            Arc::clone(&telemetry),
            Arc::clone(&sync),
        );
        u.set_endpoint_path(format!("/?PROBE_ID=1018212&SESSION_ID={REF_SESSION}"))
            .unwrap();
        telemetry.push(REPORT.into()).await;
        let results = one_result();
        u.post_oneoff(&results, Some(REF_SESSION)).await.unwrap();

        let req = seen.recv().await.unwrap();
        let (head, body) = req.split_once("\r\n\r\n").unwrap();
        assert!(
            head.starts_with(&format!(
                "POST /?PROBE_ID=1018212&SESSION_ID={REF_SESSION}&SRC=oneoff HTTP/1.1\r\n"
            )),
            "{head}"
        );
        let line = AtlasResult::from_measurement(results[0].result.clone(), None)
            .with_lts(-1)
            .to_result_line();
        assert_eq!(
            body,
            format!("P_TO_C_REPORT\n{line}\nSESSION_ID {REF_SESSION}\n")
        );
        assert_eq!(sync.lts(), -1, "an hour off, and not judged");
        assert_eq!(telemetry.drain().await, [REPORT], "no 9015, report kept");
    }
}
