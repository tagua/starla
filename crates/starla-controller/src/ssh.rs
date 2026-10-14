//! SSH connection management for RIPE Atlas controller communication
//!
//! This module provides:
//! - SSH tunnel management with automatic reconnection
//! - Registration protocol (INIT command)
//! - Keepalive handling (KEEP command)
//! - Reverse port forwarding for telnet interface

use russh::client::{self, Handle, Msg};
use russh::keys::ssh_key::{self, Algorithm};
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyBase64};
use russh::{Channel, ChannelMsg, Preferred};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout, timeout_at, Instant};
use tracing::{debug, error, info, trace, warn};

/// SSH connection configuration
///
/// The session's liveness is the reference probe's ssh's: `ssh -o
/// "ServerAliveInterval 60"` (bin/arch/linux/linux-functions.sh:151), with
/// ServerAliveCountMax at its default of 3 and no inactivity timeout. A
/// keepalive goes out after 60 s with nothing from the server; any answer,
/// or anything else from the server, starts the count again; the fourth
/// interval without one, 240 s of silence, drops the session.
#[derive(Debug, Clone)]
pub struct SshConfig {
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Drop the session after this long without anything from the server,
    /// keepalive answers included. None, as the reference's ssh has no
    /// such timeout: with one of 120 s, a probe stalled for two minutes (a
    /// host suspended, the process stopped) found it expired before the
    /// keepalive that would have been answered went out, and dropped a
    /// healthy KEEP session (the twin's pause, 2026-10-13, W13).
    pub inactivity_timeout: Option<Duration>,
    /// Send a keepalive after this long without anything from the server
    /// (ServerAliveInterval)
    pub keepalive_interval: Duration,
    /// Keepalives sent without anything from the server before the session
    /// is dropped (ServerAliveCountMax)
    pub keepalive_max: usize,
    /// Reconnection delay (base)
    pub reconnect_delay: Duration,
    /// Maximum reconnection delay
    pub max_reconnect_delay: Duration,
    /// Number of reconnection attempts before giving up (0 = infinite)
    pub max_reconnect_attempts: u32,
}

impl SshConfig {
    /// How long the login may wait for the server, from the key exchange's
    /// end to the server's answer to the key: one ServerAliveInterval, 60 s
    /// (the connect timeout if the interval is 0).
    ///
    /// The reference's ssh bounds each packet its login waits for by
    /// ServerAliveInterval × ServerAliveCountMax, 180 s (ssh.c,
    /// ssh_packet_set_timeout). Starla's bound is the interval alone:
    /// russh counts keepalives only once the session is authenticated, and
    /// before then, once an interval has passed with nothing from the
    /// server, its session task spins on the expired keepalive timer,
    /// re-arming the inactivity timer each time, so neither ends it. Past
    /// one interval a stalled login burns a core of the background thread
    /// until the bound; up to it, nothing. A login takes about a second.
    /// Starla had no bound: a server that never answered the key held a
    /// spinning task until the server or TCP gave up.
    pub fn login_timeout(&self) -> Duration {
        if self.keepalive_interval.is_zero() {
            self.connect_timeout
        } else {
            self.keepalive_interval
        }
    }

    /// When the identification strings and the key exchange must be done
    /// by: the connect timeout from now. Every packet from the server
    /// re-arms russh's keepalive timer, so a key exchange spins only after
    /// a whole keepalive interval of silence from the server; with the
    /// defaults (30 s against 60 s) it never does. A timeout too large for
    /// the clock is a year.
    fn connected_by(&self) -> Instant {
        let now = Instant::now();
        now.checked_add(self.connect_timeout)
            .unwrap_or_else(|| now + Duration::from_secs(365 * 86_400))
    }
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            inactivity_timeout: None,
            keepalive_interval: Duration::from_secs(60),
            keepalive_max: 3,
            reconnect_delay: Duration::from_secs(5),
            max_reconnect_delay: Duration::from_secs(300),
            max_reconnect_attempts: 0, // Infinite
        }
    }
}

/// Controller information returned from INIT
#[derive(Debug, Clone, PartialEq)]
pub struct ControllerInfo {
    pub host: String,
    pub port: u16,
    pub probe_id: u32,
    /// `REREGISTER <secs>`: how long the assignment holds before the probe
    /// must ask the registration server again.
    pub rereg_secs: Option<u64>,
}

/// INIT response variants
#[derive(Debug, Clone)]
pub enum InitResponse {
    /// Registration server responded with controller assignment
    Controller(ControllerInfo),
    /// Controller responded with remote port and session ID (ready for KEEP)
    ControllerReady {
        remote_port: u16,
        session_id: String,
    },
    /// Probe key is recognized but not yet fully registered (from reg server)
    Ok,
    /// Server tells us to wait and retry after timeout seconds
    Wait { timeout_secs: u32 },
    /// `REFUSED` (the line after it is the reason): the reference probe waits
    /// and then registers again (atlasinit writes force_reg.sh).
    Refused { reason: String },
}

/// Probe information sent during registration INIT
#[derive(Debug, Clone)]
pub struct ProbeInitInfo {
    /// Firmware version (e.g., 5120)
    pub firmware_version: u32,
    /// Reason for registration (e.g., "NEW", "REREG_TIMER_EXPIRED")
    pub reason: String,
}

impl ProbeInitInfo {
    /// Create probe init info for a new registration
    pub fn new(firmware_version: u32) -> Self {
        Self {
            firmware_version,
            reason: "NEW".to_string(),
        }
    }

    /// Create probe init info for re-registration
    pub fn reregister(firmware_version: u32, reason: &str) -> Self {
        Self {
            firmware_version,
            reason: reason.to_string(),
        }
    }

    /// Format as P_TO_R_INIT message for INIT command stdin
    ///
    /// Uses the software probe format matching the official generic
    /// software probe: `TOKEN_SPECS fluffy 1000 <fw> <sub_arch>`
    pub fn to_init_message(&self) -> String {
        let mut msg = String::new();
        msg.push_str("P_TO_R_INIT\n");

        let sub_arch = detect_sub_arch();

        msg.push_str(&format!(
            "TOKEN_SPECS fluffy 1000 {} {}\n",
            self.firmware_version, sub_arch
        ));

        msg.push_str(&format!("REASON_FOR_REGISTRATION {}\n", self.reason));
        msg
    }
}

/// Which registration entry to try first: uniform over the list, as the
/// reference's reginit picks one with `rchoose $REG_1_HOST … $REG_6_HOST`.
///
/// The list is a hostname, its IPv4 literal and its IPv6 literal for each of
/// two servers, and a hostname resolves to IPv6 first on a dual-stack host,
/// so the reference registers over IPv4 one time in three. Starla walked
/// the list from the top, so it always registered over IPv6: on 2026-10-13
/// every connection RIPE had logged from probes 1018212 and 1015560
/// (msm 7000) was IPv6, and neither has an IPv4 address in RIPE's view.
fn random_start(len: usize) -> usize {
    use rand::RngExt;
    if len == 0 {
        0
    } else {
        rand::rng().random_range(0..len)
    }
}

/// The entries from `start`, then the ones before it: the first is the
/// reference's single choice, the rest are Starla's fallbacks.
fn from_random_start<T>(items: &[T], start: usize) -> impl Iterator<Item = &T> {
    let start = start.min(items.len());
    items[start..].iter().chain(items[..start].iter())
}

/// Detect the probe sub-architecture string sent during registration.
///
/// Format: `<os_id>/<os_version>/<arch>/starla/<starla_version>`,
/// e.g. `debian/13/x86_64/starla/0.3.0`. Mirrors the original C probe's
/// `get_sub_arch` (sourced `/etc/os-release`, `uname -m`) with
/// platform fallbacks so the same binary works on Linux, macOS, and Windows.
fn detect_sub_arch() -> String {
    let (id, version_id) = detect_os_id_version();
    let arch = std::env::consts::ARCH;
    let starla_version = env!("CARGO_PKG_VERSION");
    format!("{}/{}/{}/starla/{}", id, version_id, arch, starla_version)
}

fn detect_os_id_version() -> (String, String) {
    #[cfg(target_os = "linux")]
    {
        let (id, version_id) = read_os_release();
        return (
            id.unwrap_or_else(|| "generic".to_string()),
            version_id.unwrap_or_else(|| "unknown".to_string()),
        );
    }

    #[cfg(target_os = "macos")]
    {
        let version = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        return ("macos".to_string(), version);
    }

    #[cfg(target_os = "windows")]
    return ("windows".to_string(), "unknown".to_string());

    #[allow(unreachable_code)]
    ("generic".to_string(), "unknown".to_string())
}

/// Parse `/etc/os-release`, returning `ID` and `VERSION_ID` independently.
/// Each is `None` if the file is unreadable or the line is absent, letting
/// the caller apply per-field defaults (matching the original Bash, which
/// pre-set ID=generic / VERSION_ID=unknown before sourcing the file).
#[cfg(target_os = "linux")]
fn read_os_release() -> (Option<String>, Option<String>) {
    let Ok(content) = std::fs::read_to_string("/etc/os-release") else {
        return (None, None);
    };
    let mut id = None;
    let mut version_id = None;
    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
        match key.trim() {
            "ID" => id = Some(value.to_string()),
            "VERSION_ID" => version_id = Some(value.to_string()),
            _ => {}
        }
    }
    (id, version_id)
}

/// Known SSH host keys for server verification (TOFU model)
///
/// On first connection to a server, the key is saved to a known_hosts file.
/// On subsequent connections, the presented key is verified against the saved
/// one. This prevents MITM attacks after the initial connection.
#[derive(Clone)]
pub struct KnownHosts {
    path: PathBuf,
    hosts: Arc<Mutex<HashMap<String, String>>>,
}

impl KnownHosts {
    /// Load known hosts from file, or create empty if file doesn't exist
    pub fn load(path: &Path) -> Self {
        let mut hosts = HashMap::new();

        if path.exists() {
            if let Ok(contents) = std::fs::read_to_string(path) {
                for line in contents.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    // Format: "host:port key_type base64_key"
                    let parts: Vec<&str> = line.splitn(3, ' ').collect();
                    if parts.len() == 3 {
                        let host_port = parts[0].to_string();
                        let key_str = format!("{} {}", parts[1], parts[2]);
                        hosts.insert(host_port, key_str);
                    }
                }
            }
        }

        Self {
            path: path.to_path_buf(),
            hosts: Arc::new(Mutex::new(hosts)),
        }
    }

    /// Check a server's public key against known hosts.
    /// Returns Ok(true) if the key matches or was newly saved (TOFU).
    /// Returns Ok(false) if the key does NOT match a previously saved key
    /// (possible MITM).
    pub async fn verify(
        &self,
        host: &str,
        port: u16,
        key: &PublicKey,
    ) -> Result<bool, anyhow::Error> {
        let host_port = format!("{}:{}", host, port);
        let key_algo = key.algorithm();
        let key_type = key_algo.as_str();
        let key_b64 = key.public_key_base64();
        let presented = format!("{} {}", key_type, key_b64);

        let mut hosts = self.hosts.lock().await;

        if let Some(saved) = hosts.get(&host_port) {
            // Match on key blob only: RFC 8332 reuses the ssh-rsa blob for
            // rsa-sha2-{256,512}.
            let saved_blob = saved.split_whitespace().nth(1).unwrap_or("");
            if saved_blob == key_b64 {
                debug!("Host key for {} matches known key", host_port);
                Ok(true)
            } else {
                error!(
                    "HOST KEY MISMATCH for {}! Possible MITM attack.\nExpected: {}\nGot:      {}",
                    host_port, saved, presented
                );
                Ok(false)
            }
        } else {
            // TOFU: first time seeing this host, save the key.
            //
            // Debug, not info: this fires once per registration server on
            // first run -- six lines with the default server list -- which
            // is exactly when the log is also carrying the key the user
            // has to go and register. A first sighting is routine; the
            // mismatch above is the security event, and that stays loud.
            debug!(
                "New host key for {} ({}), saving to known_hosts (TOFU)",
                host_port, key_type
            );
            hosts.insert(host_port.clone(), presented);

            // Write back to file atomically (write temp then rename)
            if let Some(parent) = self.path.parent() {
                let _ = std::fs::create_dir_all(parent);
                let tmp_path = parent.join(".known_hosts.tmp");
                let mut lines: Vec<String> = Vec::new();
                lines.push("# Starla known hosts - do not edit manually".to_string());
                for (hp, k) in hosts.iter() {
                    lines.push(format!("{} {}", hp, k));
                }
                match std::fs::write(&tmp_path, lines.join("\n") + "\n") {
                    Ok(()) => {
                        if let Err(e) = std::fs::rename(&tmp_path, &self.path) {
                            warn!("Failed to rename known_hosts: {}", e);
                            let _ = std::fs::remove_file(&tmp_path);
                        }
                    }
                    Err(e) => warn!("Failed to save known_hosts: {}", e),
                }
            }

            Ok(true)
        }
    }
}

/// Client handler for russh
struct AtlasClientHandler {
    /// Known hosts for server key verification
    known_hosts: KnownHosts,
    /// The host we're connecting to (for key verification)
    connect_host: String,
    /// The port we're connecting to
    connect_port: u16,
    /// Command sender for telnet handler (forwarded connections go here
    /// directly)
    command_tx: Option<tokio::sync::mpsc::Sender<crate::telnet::TelnetCommand>>,
    /// Probe ID for telnet authentication
    probe_id: u32,
    /// Session ID for telnet authentication
    session_id: Arc<tokio::sync::RwLock<Option<String>>>,
}

impl AtlasClientHandler {
    fn new(
        host: &str,
        port: u16,
        known_hosts: KnownHosts,
        telnet_state: Option<TelnetState>,
    ) -> Self {
        let (command_tx, probe_id, session_id) = match telnet_state {
            Some(ts) => (Some(ts.command_tx), ts.probe_id, ts.session_id),
            None => (None, 0, Arc::new(tokio::sync::RwLock::new(None))),
        };
        Self {
            known_hosts,
            connect_host: host.to_string(),
            connect_port: port,
            command_tx,
            probe_id,
            session_id,
        }
    }
}

impl client::Handler for AtlasClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        self.known_hosts
            .verify(&self.connect_host, self.connect_port, server_public_key)
            .await
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        debug!(
            "Forwarded connection from {}:{} to {}:{}",
            originator_address, originator_port, connected_address, connected_port
        );

        // Convert SSH channel to an async stream and handle directly :
        // no local TCP port needed
        let stream = crate::channel_stream::channel_to_stream(channel);
        let command_tx = self.command_tx.clone();
        let probe_id = self.probe_id;
        let session_id = self.session_id.clone();

        tokio::spawn(async move {
            if let Err(e) =
                crate::telnet::handle_connection(stream, command_tx, probe_id, session_id).await
            {
                error!("Error handling forwarded telnet connection: {}", e);
            }
            debug!("Forwarded telnet connection ended");
        });

        Ok(())
    }
}

/// State needed for handling telnet connections directly in the SSH handler
#[derive(Clone)]
pub struct TelnetState {
    pub command_tx: tokio::sync::mpsc::Sender<crate::telnet::TelnetCommand>,
    pub probe_id: u32,
    pub session_id: Arc<tokio::sync::RwLock<Option<String>>>,
}

/// The russh client configuration for every registration-server and
/// controller connection.
///
/// RIPE's registration servers offer diffie-hellman-group1-sha1 and
/// diffie-hellman-group-exchange-sha256 (plus ext-info-s and
/// kex-strict-s-v00@openssh.com; read from reg03 and reg-05 on 2026-10-10).
/// russh's default list includes group exchange, so the 1024-bit group1 is
/// never needed. Keep the default whole: a custom list also drops the
/// ext-info-c and kex-strict-c markers, and with them the Terrapin
/// (CVE-2023-48795) countermeasure.
///
/// russh counts keepalives as OpenSSH's server_alive_check does: each
/// interval without data from the server adds one, any data clears the
/// count, and the interval that takes it past `keepalive_max` drops the
/// session (client/mod.rs run_inner).
fn client_config(config: &SshConfig) -> client::Config {
    client::Config {
        inactivity_timeout: config.inactivity_timeout,
        keepalive_interval: Some(config.keepalive_interval),
        keepalive_max: config.keepalive_max,
        preferred: Preferred::DEFAULT,
        ..Default::default()
    }
}

/// A session's stream, which [`SshConnection::login`] can cut: from then
/// on a read ends as at the end of the stream and a write fails, so the
/// session task reading and writing it ends.
struct Cuttable<S> {
    inner: S,
    cut: Arc<Cut>,
}

/// The switch that cuts a [`Cuttable`] stream.
#[derive(Debug, Default)]
struct Cut {
    done: AtomicBool,
    /// The reader's, woken by the cut
    reader: futures::task::AtomicWaker,
}

impl Cut {
    fn cut(&self) {
        self.done.store(true, Ordering::Release);
        self.reader.wake();
    }

    fn is_cut(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }
}

impl<S> Cuttable<S> {
    fn new(inner: S) -> (Self, Arc<Cut>) {
        let cut = Arc::new(Cut::default());
        (
            Self {
                inner,
                cut: Arc::clone(&cut),
            },
            cut,
        )
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Cuttable<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.cut.reader.register(cx.waker());
        if self.cut.is_cut() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Cuttable<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.cut.is_cut() {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// SSH connection to RIPE Atlas controller
pub struct SshConnection {
    session: Arc<Mutex<Handle<AtlasClientHandler>>>,
    host: String,
    port: u16,
}

impl SshConnection {
    /// Connect to a controller server
    ///
    /// If `telnet_state` is provided, forwarded SSH connections (reverse
    /// tunnel) will be handled directly by the telnet command parser
    /// without a local TCP listener.
    pub async fn connect(
        host: &str,
        port: u16,
        key: &PrivateKey,
        config: SshConfig,
        known_hosts: KnownHosts,
        telnet_state: Option<TelnetState>,
    ) -> anyhow::Result<Self> {
        let handler = AtlasClientHandler::new(host, port, known_hosts, telnet_state);

        let addr = format!("{}:{}", host, port);
        debug!("Connecting to SSH controller at {}", addr);

        // As russh's client::connect, with the TCP connection Starla's own,
        // so that the login can cut it
        let connected_by = config.connected_by();
        let stream = timeout_at(connected_by, tokio::net::TcpStream::connect(&addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;
        Self::login(stream, connected_by, host, port, key, &config, handler).await
    }

    /// [`connect`](Self::connect) over a stream of the test's own, in place
    /// of a TCP connection to `host:port`.
    #[cfg(test)]
    async fn connect_stream(
        stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        host: &str,
        port: u16,
        key: &PrivateKey,
        config: SshConfig,
        known_hosts: KnownHosts,
    ) -> anyhow::Result<Self> {
        let handler = AtlasClientHandler::new(host, port, known_hosts, None);
        let connected_by = config.connected_by();
        Self::login(stream, connected_by, host, port, key, &config, handler).await
    }

    /// The SSH session over `stream`: the identification strings and the
    /// key exchange by `connected_by`, then the login within
    /// [`SshConfig::login_timeout`]. A login that fails or runs out of
    /// time cuts the stream, which ends russh's session task. Dropping the
    /// session's handle ends it too, but connect_stream returns the handle
    /// only once the key exchange is done, and russh's JoinHandle cannot
    /// abort the task: a connect dropped at its timeout during the
    /// exchange left the task behind, waiting on the server for good.
    async fn login(
        stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        connected_by: Instant,
        host: &str,
        port: u16,
        key: &PrivateKey,
        config: &SshConfig,
        handler: AtlasClientHandler,
    ) -> anyhow::Result<Self> {
        let (stream, cut) = Cuttable::new(stream);
        let login_timeout = config.login_timeout();
        let login = async {
            let session = timeout_at(
                connected_by,
                client::connect_stream(Arc::new(client_config(config)), stream, handler),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;
            timeout(login_timeout, Self::authenticate(session, host, port, key))
                .await
                .map_err(|_| {
                    anyhow::anyhow!("SSH login: no answer from the server in {login_timeout:?}")
                })?
        };
        let logged_in = login.await;
        if logged_in.is_err() {
            cut.cut();
        }
        logged_in
    }

    /// Log in as `atlas` with the probe's key, on a session just set up.
    async fn authenticate(
        mut session: Handle<AtlasClientHandler>,
        host: &str,
        port: u16,
        key: &PrivateKey,
    ) -> anyhow::Result<Self> {
        // Authenticate. Ed25519 keys don't need an RSA hash; pass None.
        let auth_res = session
            .authenticate_publickey(
                "atlas",
                PrivateKeyWithHashAlg::new(Arc::new(key.clone()), None),
            )
            .await?;

        if !auth_res.success() {
            anyhow::bail!("SSH authentication failed");
        }

        debug!("SSH authentication successful");

        Ok(Self {
            session: Arc::new(Mutex::new(session)),
            host: host.to_string(),
            port,
        })
    }

    /// Connect with automatic retry
    pub async fn connect_with_retry(
        host: &str,
        port: u16,
        key: &PrivateKey,
        config: SshConfig,
        known_hosts: KnownHosts,
        telnet_state: Option<TelnetState>,
    ) -> anyhow::Result<Self> {
        let mut attempts = 0u32;
        let mut delay = config.reconnect_delay;

        loop {
            attempts += 1;

            match Self::connect(
                host,
                port,
                key,
                config.clone(),
                known_hosts.clone(),
                telnet_state.clone(),
            )
            .await
            {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    if config.max_reconnect_attempts > 0
                        && attempts >= config.max_reconnect_attempts
                    {
                        return Err(anyhow::anyhow!(
                            "Failed to connect after {} attempts: {}",
                            attempts,
                            e
                        ));
                    }

                    warn!(
                        "Connection attempt {} failed: {}. Retrying in {:?}...",
                        attempts, e, delay
                    );

                    sleep(delay).await;

                    // Exponential backoff
                    delay = std::cmp::min(delay * 2, config.max_reconnect_delay);
                }
            }
        }
    }

    /// Try connecting to multiple servers in order
    pub async fn connect_to_servers(
        servers: &[&str],
        key: &PrivateKey,
        config: SshConfig,
        known_hosts: KnownHosts,
    ) -> anyhow::Result<Self> {
        fn parse_server(server: &str) -> (&str, u16) {
            if let Some(rest) = server.strip_prefix('[') {
                if let Some((host, tail)) = rest.split_once(']') {
                    if let Some(port_str) = tail.strip_prefix(':') {
                        if let Ok(port) = port_str.parse() {
                            return (host, port);
                        }
                    }
                    return (host, 443);
                }
            }

            if let Some((host, port_str)) = server.rsplit_once(':') {
                if let Ok(port) = port_str.parse() {
                    return (host, port);
                }
            }

            (server, 443)
        }

        let mut last_error: Option<anyhow::Error> = None;

        for server in from_random_start(servers, random_start(servers.len())) {
            let (host, port) = parse_server(server);

            match Self::connect(host, port, key, config.clone(), known_hosts.clone(), None).await {
                Ok(conn) => {
                    info!("Connected to {}", server);
                    return Ok(conn);
                }
                Err(e) => {
                    // Debug, not warn: the default server list is six
                    // entries (hostname, IPv4 and IPv6 for each of two
                    // registration servers), so a single unreachable
                    // network warned six lines per retry, forever, and
                    // buried the one thing the user needs to read -- the
                    // key to register. The caller sees the summary below
                    // and decides how loudly to say it.
                    debug!("Failed to connect to {}: {}", server, e);
                    last_error = Some(e);
                }
            }
        }

        match last_error {
            Some(e) => Err(e.context(format!(
                "failed to connect to any of {} registration servers",
                servers.len()
            ))),
            None => anyhow::bail!("no registration servers configured"),
        }
    }

    /// Execute the INIT command and parse response
    ///
    /// The RIPE Atlas protocol requires sending probe identification data
    /// to the server when running INIT on a registration server.
    pub async fn init(&self, probe_info: Option<&ProbeInitInfo>) -> anyhow::Result<InitResponse> {
        let output = if let Some(info) = probe_info {
            // Send probe info to registration server
            let stdin_data = info.to_init_message();
            debug!("Sending INIT with probe info:\n{}", stdin_data);
            self.execute_with_stdin("INIT", &stdin_data).await?
        } else {
            // Controller INIT - no stdin data needed
            self.execute("INIT").await?
        };

        parse_init_response(&output)
    }
}

/// Parse a registration server's or controller's INIT reply.
pub fn parse_init_response(output: &str) -> anyhow::Result<InitResponse> {
    {
        // Parse response line by line - the actual response may have multiple lines
        let lines: Vec<&str> = output.lines().collect();

        if lines.is_empty() {
            anyhow::bail!("Empty INIT response");
        }

        let first_line = lines[0].trim();
        debug!("INIT response: {} ({} lines)", first_line, lines.len());
        for (i, line) in lines.iter().enumerate().skip(1) {
            trace!("INIT response line {}: {}", i + 1, line);
        }

        match first_line {
            "OK" => {
                // Parse additional lines for various info
                // Registration server format: OK\nCONTROLLER <host> <port> ssh-rsa
                // <key>\nREREGISTER <secs> Controller format: OK\nREMOTE_PORT
                // <port>\nSESSION_ID <id>
                // Parse all registration response fields before returning
                let mut controller_host: Option<String> = None;
                let mut controller_port: Option<u16> = None;
                let mut probe_id: u32 = 0;
                let mut rereg_secs: Option<u64> = None;

                for line in lines.iter().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.is_empty() {
                        continue;
                    }

                    if parts[0] == "CONTROLLER" && parts.len() >= 4 {
                        controller_host = Some(parts[1].to_string());
                        controller_port = parts[2].parse().ok();
                    }

                    if parts[0] == "REREGISTER" && parts.len() >= 2 {
                        rereg_secs = parts[1].parse().ok();
                    }

                    if parts[0] == "PROBE_ID" && parts.len() >= 2 {
                        if let Ok(id) = parts[1].parse() {
                            probe_id = id;
                            debug!("Got probe ID: {}", id);
                        }
                    }
                }

                if let (Some(host), Some(port)) = (controller_host, controller_port) {
                    debug!("Got controller: {}:{}", host, port);
                    return Ok(InitResponse::Controller(ControllerInfo {
                        host,
                        port,
                        probe_id,
                        rereg_secs,
                    }));
                }

                // Parse controller response with REMOTE_PORT and SESSION_ID
                let mut remote_port: Option<u16> = None;
                let mut session_id: Option<String> = None;

                for line in lines.iter().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.is_empty() {
                        continue;
                    }

                    if parts[0] == "REMOTE_PORT" && parts.len() >= 2 {
                        remote_port = parts[1].parse().ok();
                        if let Some(port) = remote_port {
                            debug!("Controller assigned remote port: {}", port);
                        }
                    }

                    if parts[0] == "SESSION_ID" && parts.len() >= 2 {
                        session_id = Some(parts[1].to_string());
                        debug!("Controller assigned session ID: {}", parts[1]);
                    }
                }

                if let (Some(port), Some(sid)) = (remote_port, session_id) {
                    return Ok(InitResponse::ControllerReady {
                        remote_port: port,
                        session_id: sid,
                    });
                }

                // Just OK with no additional info
                // This could mean:
                // 1. From reg server: probe key recognized but not registered yet
                // 2. From controller: should have REMOTE_PORT but doesn't
                // Return Ok and let caller decide what to do
                debug!("Got OK without CONTROLLER or REMOTE_PORT/SESSION_ID info");
                Ok(InitResponse::Ok)
            }
            "WAIT" => {
                // Parse TIMEOUT from next line
                // Format: WAIT\nTIMEOUT <seconds>
                let mut timeout_secs = 60u32; // Default timeout
                for line in lines.iter().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 && parts[0] == "TIMEOUT" {
                        timeout_secs = parts[1].parse().unwrap_or(60);
                        break;
                    }
                }
                debug!("Server requested wait: {} seconds", timeout_secs);
                Ok(InitResponse::Wait { timeout_secs })
            }
            "REFUSED" => {
                let reason = lines.get(1).map(|l| l.trim()).unwrap_or("").to_string();
                debug!("Server refused us: {}", reason);
                Ok(InitResponse::Refused { reason })
            }
            _ => {
                anyhow::bail!("Unknown INIT response: {}", output);
            }
        }
    }
}

/// A KEEP reply as a log line shows it: escaped, the first 256 bytes.
fn keep_reply(data: &[u8]) -> String {
    let shown = &data[..data.len().min(256)];
    format!(
        "{:?} ({} bytes)",
        String::from_utf8_lossy(shown),
        data.len()
    )
}

/// The most of a KEEP reply [`KeepRefused`] keeps.
const KEEP_REPLY_KEPT: usize = 4096;

/// How long a KEEP channel may stay open once the controller has written on
/// it. The reference does not wait for ssh to exit: its main loop kills ssh
/// as soon as it finds con_keep_reply.vol non-empty (ripe-atlas.in:217-221),
/// at its next pass, up to 180 s on. RIPE's controller closes the channel
/// at once (2026-10-14: within 0.2 s); this bounds one that does not.
const KEEP_REPLY_GRACE: Duration = Duration::from_secs(30);

/// The controller wrote on KEEP: it has kicked us out of the session
/// (CON_KEEP_BROKEN).
///
/// A KEEP the controller takes says nothing for as long as the session
/// lasts. The reference probe sends KEEP's stdout to con_keep_reply.vol and
/// its stderr to $SSH_ERR (reginit.sh.in:523), and its main loop, finding
/// con_keep_reply.vol non-empty, kills ssh and forces a new registration
/// with REASON=CON_KEEP_BROKEN (ripe-atlas.in:217-226): a registration INIT,
/// then a controller INIT for a new SESSION_ID. So only stdout counts here;
/// stderr is logged and is not a refusal. KEEP again on the same session
/// is refused each time: after a hot swap on 2026-10-14 the controller
/// answered KEEP with 18 bytes and exit status 0 within 0.2 s, then every
/// same-session retry with 4, and the probe stayed off for ~4 minutes,
/// until a restart.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("controller kicked us out from KEEP: {reply:?} ({bytes} bytes)")]
pub struct KeepRefused {
    /// What the controller wrote on stdout: the first 4 KiB, as UTF-8
    /// (lossy).
    pub reply: String,
    /// How many bytes it wrote on stdout in all.
    pub bytes: usize,
}

/// What the controller writes on a KEEP channel's stdout, gathered for
/// [`KeepRefused`]: every byte counted, the first [`KEEP_REPLY_KEPT`] kept.
#[derive(Debug, Default)]
struct KeepReply {
    kept: Vec<u8>,
    bytes: usize,
}

impl KeepReply {
    fn add(&mut self, data: &[u8]) {
        self.bytes += data.len();
        let room = KEEP_REPLY_KEPT.saturating_sub(self.kept.len());
        self.kept.extend_from_slice(&data[..data.len().min(room)]);
    }

    /// Whether the controller has written anything yet.
    fn written(&self) -> bool {
        self.bytes > 0
    }

    /// The refusal, if the controller wrote anything at all (the
    /// reference's `[ -s con_keep_reply.vol ]`).
    fn refusal(self) -> Option<KeepRefused> {
        self.written().then(|| KeepRefused {
            reply: String::from_utf8_lossy(&self.kept).into_owned(),
            bytes: self.bytes,
        })
    }
}

impl SshConnection {
    /// Start the KEEP session and monitor it.
    ///
    /// Opens a channel with the KEEP command and blocks until the channel
    /// closes, which is the connection health signal. A KEEP the controller
    /// takes writes nothing on stdout: if it wrote anything, the error is a
    /// [`KeepRefused`] carrying what it wrote (the caller registers again),
    /// once the channel has ended or at most 30 s after the first byte;
    /// otherwise the connection was lost, and the error says "KEEP session
    /// ended".
    pub async fn run_keep_session(&self) -> anyhow::Result<()> {
        self.keep_session(KEEP_REPLY_GRACE).await
    }

    /// [`run_keep_session`](Self::run_keep_session), the channel let stay
    /// open for `grace` once the controller has written on it.
    async fn keep_session(&self, grace: Duration) -> anyhow::Result<()> {
        debug!("Starting KEEP session");
        let session = self.session.lock().await;
        let mut channel = session.channel_open_session().await?;
        channel.exec(true, "KEEP").await?;
        drop(session); // Release lock so other operations can use the session

        debug!("KEEP session started, monitoring channel");

        // What the controller says on KEEP's stdout, which the reference
        // probe keeps in con_keep_reply.vol (reginit.sh.in:523): a reply
        // ends the session, and its words are the reason
        let mut reply = KeepReply::default();
        // Set at the first byte of a reply: the channel is waited for no
        // later than this, as the reference kills ssh without waiting for
        // it to exit (ripe-atlas.in:220)
        let mut answered_by: Option<Instant> = None;

        // Block until the KEEP channel closes: this is our connection health signal
        loop {
            let msg = match answered_by {
                None => channel.wait().await,
                Some(by) => match timeout_at(by, channel.wait()).await {
                    Ok(msg) => msg,
                    Err(_) => {
                        debug!(
                            "KEEP channel still open {:?} after the controller wrote on it",
                            grace
                        );
                        break;
                    }
                },
            };
            let Some(msg) = msg else { break };
            match msg {
                ChannelMsg::Data { data } => {
                    debug!("KEEP channel data: {}", keep_reply(&data));
                    reply.add(&data);
                    if answered_by.is_none() && reply.written() {
                        answered_by = Some(Instant::now() + grace);
                    }
                }
                ChannelMsg::ExtendedData { data, ext } => {
                    // The reference's $SSH_ERR, not con_keep_reply.vol: not a
                    // refusal
                    debug!(ext, "KEEP channel stderr: {}", keep_reply(&data));
                }
                ChannelMsg::Eof => {
                    debug!("KEEP channel EOF: connection lost");
                    break;
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    debug!("KEEP channel exit status: {}", exit_status);
                }
                _ => {}
            }
        }

        if let Some(refused) = reply.refusal() {
            // The caller logs it, with what it does about it
            debug!("KEEP session ended: {}", refused);
            return Err(refused.into());
        }
        warn!("KEEP session ended: controller disconnected");
        anyhow::bail!("KEEP session ended")
    }

    /// Request reverse port forwarding
    pub async fn request_reverse_tunnel(&self, bind_port: u16) -> anyhow::Result<()> {
        debug!("Requesting reverse tunnel on port {}", bind_port);

        let session = self.session.lock().await;

        // Check if session is still connected
        if session.is_closed() {
            anyhow::bail!("SSH session is closed, cannot setup tunnel");
        }

        // Use "localhost" as the bind address, matching OpenSSH behavior
        // The server will listen on localhost:bind_port
        session.tcpip_forward("localhost", bind_port as u32).await?;

        Ok(())
    }

    /// Cancel reverse port forwarding
    pub async fn cancel_reverse_tunnel(&self, bind_port: u16) -> anyhow::Result<()> {
        debug!("Cancelling reverse tunnel on port {}", bind_port);

        let session = self.session.lock().await;
        session
            .cancel_tcpip_forward("127.0.0.1", bind_port as u32)
            .await?;

        Ok(())
    }

    /// Create a direct-tcpip channel to forward data to the controller
    /// This opens an SSH channel that connects to the specified host:port on
    /// the server side
    pub async fn open_direct_tcpip(
        &self,
        remote_host: &str,
        remote_port: u16,
    ) -> anyhow::Result<Channel<Msg>> {
        debug!(
            "Opening direct-tcpip channel to {}:{}",
            remote_host, remote_port
        );

        let session = self.session.lock().await;

        // Open a direct-tcpip channel
        // This tells the SSH server to connect to remote_host:remote_port
        // and forward data through this channel
        let channel = session
            .channel_open_direct_tcpip(
                remote_host,
                remote_port as u32,
                "127.0.0.1",
                ephemeral_port() as u32,
            )
            .await?;

        Ok(channel)
    }

    /// Get the controller host we're connected to
    pub fn controller_host(&self) -> &str {
        &self.host
    }

    /// Get the controller port we're connected to
    pub fn controller_port(&self) -> u16 {
        self.port
    }

    /// Start a local HTTP proxy that forwards to the controller via SSH
    /// direct-tcpip
    ///
    /// This sets up a local TCP listener on the specified port. When
    /// connections come in, they are forwarded through the SSH connection
    /// to the controller's HTTP endpoint.
    ///
    /// This mimics the behavior of `ssh -L local_port:127.0.0.1:remote_port`
    /// The Atlas protocol uses: `-L 8080:127.0.0.1:8080` to forward local:8080
    /// to controller's 127.0.0.1:8080
    ///
    /// The `reconnect_signal` token will be cancelled if the proxy detects the
    /// SSH session is dead (e.g., consecutive channel open failures or
    /// timeouts). The caller should watch this token and reconnect when
    /// it's cancelled.
    pub async fn start_http_proxy(
        &self,
        local_port: u16,
        remote_port: u16,
        reconnect_signal: tokio_util::sync::CancellationToken,
    ) -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicU32, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(format!("127.0.0.1:{}", local_port)).await?;
        debug!(
            "HTTP proxy started: localhost:{} -> controller:{}",
            local_port, remote_port
        );

        let session = self.session.clone();
        let remote_port = remote_port as u32;

        // Track consecutive failures to detect dead sessions
        let consecutive_failures = Arc::new(AtomicU32::new(0));
        const MAX_CONSECUTIVE_FAILURES: u32 = 3;

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut local_stream, peer_addr)) => {
                        debug!(
                            "HTTP proxy accepted connection from {} (local:{} -> remote:{})",
                            peer_addr, local_port, remote_port
                        );

                        let session = session.clone();
                        let failures = consecutive_failures.clone();
                        let reconnect = reconnect_signal.clone();

                        tokio::spawn(async move {
                            // Open SSH direct-tcpip channel to controller's localhost:remote_port
                            debug!("Opening SSH channel for HTTP forward");
                            let session_guard = session.lock().await;
                            if session_guard.is_closed() {
                                error!(
                                    "SSH session closed before opening HTTP channel (local:{} -> \
                                     remote:{})",
                                    local_port, remote_port
                                );
                                let count = failures.fetch_add(1, Ordering::SeqCst) + 1;
                                if count >= MAX_CONSECUTIVE_FAILURES {
                                    error!(
                                        "Too many channel failures ({}), signaling reconnection \
                                         needed",
                                        count
                                    );
                                    reconnect.cancel();
                                }
                                return;
                            }

                            // Add timeout to channel open to detect dead SSH sessions
                            let channel_result = tokio::time::timeout(
                                std::time::Duration::from_secs(10),
                                session_guard.channel_open_direct_tcpip(
                                    "127.0.0.1",
                                    remote_port,
                                    // The forwarded connection's own end,
                                    // as ssh -L names it.
                                    peer_addr.ip().to_string(),
                                    peer_addr.port() as u32,
                                ),
                            )
                            .await;

                            let mut channel = match channel_result {
                                Ok(Ok(ch)) => {
                                    debug!("SSH channel opened successfully");
                                    // Reset failure counter on success
                                    failures.store(0, Ordering::SeqCst);
                                    ch
                                }
                                Ok(Err(e)) => {
                                    error!("Failed to open SSH channel for HTTP forward: {}", e);
                                    let count = failures.fetch_add(1, Ordering::SeqCst) + 1;
                                    if count >= MAX_CONSECUTIVE_FAILURES {
                                        error!(
                                            "Too many channel failures ({}), signaling \
                                             reconnection needed",
                                            count
                                        );
                                        reconnect.cancel();
                                    }
                                    return;
                                }
                                Err(_) => {
                                    error!("Timeout opening SSH channel - SSH session may be dead");
                                    let count = failures.fetch_add(1, Ordering::SeqCst) + 1;
                                    if count >= MAX_CONSECUTIVE_FAILURES {
                                        error!(
                                            "Too many channel timeouts ({}), signaling \
                                             reconnection needed",
                                            count
                                        );
                                        reconnect.cancel();
                                    }
                                    return;
                                }
                            };
                            drop(session_guard);

                            // Bridge local stream with SSH channel.
                            // Supports TCP half-close: when the local client finishes
                            // sending (read returns 0), we send EOF to the SSH side
                            // but keep reading the SSH response back to the client.
                            let mut local_buf = [0u8; 8192];
                            let mut local_done = false;

                            loop {
                                tokio::select! {
                                    biased; // Prioritize SSH data over local reads

                                    // Read from SSH -> send to local
                                    msg = channel.wait() => {
                                        match msg {
                                            Some(ChannelMsg::Data { data }) => {
                                                failures.store(0, Ordering::SeqCst);
                                                if let Err(e) = local_stream.write_all(&data).await {
                                                    debug!("Local write error: {}", e);
                                                    break;
                                                }
                                            }
                                            Some(ChannelMsg::Eof) | None => {
                                                debug!("SSH channel closed");
                                                break;
                                            }
                                            _ => {}
                                        }
                                    }

                                    // Read from local -> send to SSH
                                    result = local_stream.read(&mut local_buf), if !local_done => {
                                        match result {
                                            Ok(0) => {
                                                // Local finished sending: half-close the SSH side
                                                // but keep looping to read the response
                                                let _ = channel.eof().await;
                                                local_done = true;
                                            }
                                            Ok(n) => {
                                                if let Err(e) = channel.data(&local_buf[..n]).await {
                                                    debug!("SSH write error: {}", e);
                                                    let count = failures.fetch_add(1, Ordering::SeqCst) + 1;
                                                    if count >= MAX_CONSECUTIVE_FAILURES {
                                                        reconnect.cancel();
                                                    }
                                                    break;
                                                }
                                            }
                                            Err(e) => {
                                                debug!("Local read error: {}", e);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!("HTTP proxy accept error: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// Execute a command and return output
    pub async fn execute(&self, command: &str) -> anyhow::Result<String> {
        self.execute_with_stdin(command, "").await
    }

    /// Execute a command with stdin data and return output
    pub async fn execute_with_stdin(
        &self,
        command: &str,
        stdin_data: &str,
    ) -> anyhow::Result<String> {
        let session = self.session.lock().await;

        // Check if session is still open
        if session.is_closed() {
            anyhow::bail!("SSH session is closed");
        }

        let mut channel = session
            .channel_open_session()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to open SSH channel: {}", e))?;

        channel
            .exec(true, command)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to execute command '{}': {}", command, e))?;

        // Send stdin data if provided
        if !stdin_data.is_empty() {
            channel
                .data(stdin_data.as_bytes())
                .await
                .map_err(|e| anyhow::anyhow!("Failed to send stdin data: {}", e))?;
            channel
                .eof()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to send EOF: {}", e))?;
        }

        let mut output = String::new();
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { ref data } => {
                    output.push_str(&String::from_utf8_lossy(data));
                }
                ChannelMsg::Eof => break,
                ChannelMsg::ExitStatus { exit_status } if exit_status != 0 => {
                    debug!("Command exited with status {}", exit_status);
                }
                _ => {}
            }
        }

        Ok(output)
    }

    /// Check if connection is still alive
    pub async fn is_connected(&self) -> bool {
        let session = self.session.lock().await;
        !session.is_closed()
    }

    /// Get the host we're connected to
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get the port we're connected to
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// The originator port of an upload's direct-tcpip channel. The reference
/// posts through `ssh -L 8080:127.0.0.1:8080`, so its channel names the
/// local end of httppost's connection: 127.0.0.1 and the port the kernel
/// gave it. The twin's reference probe named 15 such ports, all even and in
/// 36898..=58654 (Linux's connect() favours even ports from
/// ip_local_port_range, 32768-60999 by default); Starla named port 0 on all
/// 11 of its channels. Starla has no local connection, so it names a port
/// as the kernel would pick one.
fn ephemeral_port() -> u16 {
    let range = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|s| parse_port_range(&s))
        .unwrap_or(DEFAULT_EPHEMERAL_PORTS);
    even_port_in(range)
}

/// Linux's default ip_local_port_range.
const DEFAULT_EPHEMERAL_PORTS: (u16, u16) = (32768, 60999);

/// `ip_local_port_range`: two numbers, low and high.
fn parse_port_range(s: &str) -> Option<(u16, u16)> {
    let mut it = s.split_whitespace().map(|n| n.parse::<u16>().ok());
    let (lo, hi) = (it.next()??, it.next()??);
    (lo > 0 && lo <= hi).then_some((lo, hi))
}

/// A uniformly chosen even port in `[lo, hi]` (`lo` if there is none).
fn even_port_in((lo, hi): (u16, u16)) -> u16 {
    use rand::RngExt;
    let first = lo + lo % 2;
    if first > hi {
        return lo;
    }
    first + 2 * rand::rng().random_range(0..=(hi - first) / 2)
}

#[cfg(test)]
mod originator_tests {
    use super::*;

    #[test]
    fn an_upload_channel_names_a_port_as_the_kernel_picks_one() {
        assert_eq!(parse_port_range("32768\t60999\n"), Some((32768, 60999)));
        assert_eq!(parse_port_range("1024 65535"), Some((1024, 65535)));
        assert_eq!(parse_port_range("60999 32768"), None);
        assert_eq!(parse_port_range("x"), None);

        let ports: Vec<u16> = (0..2000).map(|_| ephemeral_port()).collect();
        assert!(ports.iter().all(|&p| p != 0 && p % 2 == 0), "{ports:?}");
        // On this host's range, or Linux's default where there is none.
        let (lo, hi) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
            .ok()
            .and_then(|s| parse_port_range(&s))
            .unwrap_or(DEFAULT_EPHEMERAL_PORTS);
        assert!(ports.iter().all(|&p| (lo..=hi).contains(&p)), "{ports:?}");
        let distinct: std::collections::BTreeSet<_> = ports.iter().collect();
        assert!(distinct.len() > 1500, "a port per connection");

        assert_eq!(even_port_in((32768, 32768)), 32768);
        assert_eq!(even_port_in((32769, 32769)), 32769);
        for _ in 0..100 {
            assert!([32770, 32772].contains(&even_port_in((32769, 32773))));
        }
    }
}

/// Compute the SHA256 fingerprint of a public key (e.g., "SHA256:abc123...")
pub fn key_fingerprint(key: &PrivateKey) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};

    let public_key = key.public_key();
    let key_algo = public_key.algorithm();
    let key_type = key_algo.as_str();
    let key_b64 = public_key.public_key_base64();

    // The SSH fingerprint is SHA256 of the raw public key wire format
    // (type string length + type string + key data), which is what base64 decodes
    // to
    use base64::Engine;
    let raw_bytes = base64::engine::general_purpose::STANDARD.decode(&key_b64)?;
    let hash = Sha256::digest(&raw_bytes);
    let fingerprint = base64::engine::general_purpose::STANDARD_NO_PAD.encode(hash);

    Ok(format!("{} SHA256:{}", key_type, fingerprint))
}

/// Load SSH key from file
pub async fn load_key(path: &Path) -> anyhow::Result<PrivateKey> {
    let key_data = tokio::fs::read(path).await?;
    let key = russh::keys::decode_secret_key(&String::from_utf8(key_data)?, None)?;
    Ok(key)
}

/// Load SSH key pair from a PEM string (e.g. from an environment variable)
pub fn load_key_from_string(pem: &str) -> anyhow::Result<PrivateKey> {
    let key = russh::keys::decode_secret_key(pem, None)?;
    Ok(key)
}

/// Generate a new SSH key pair
pub fn generate_key() -> anyhow::Result<PrivateKey> {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;
    Ok(key)
}

/// The probe's public key in OpenSSH `authorized_keys` form.
///
/// This is the exact string RIPE Atlas wants pasted into the registration
/// form, and the one written to `probe_key.pub`. Derived from the private
/// key rather than read back from that file, so it is also available when
/// the key arrived through `STARLA_SSH_KEY` or a systemd credential --
/// neither of which writes a `.pub` file, which is why those two key
/// sources previously left the user with no way to see the key at all.
pub fn public_key_openssh(key: &PrivateKey) -> String {
    let public_key = key.public_key();
    format!(
        "{} {} starla",
        public_key.algorithm().as_str(),
        public_key.public_key_base64()
    )
}

/// Save SSH key pair to files
pub async fn save_key(key: &PrivateKey, path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // Save public key in OpenSSH format: "<algo> <base64> starla"
    let pub_path = path.with_extension("pub");
    let pub_key_str = public_key_openssh(key);
    tokio::fs::write(&pub_path, pub_key_str.as_bytes()).await?;
    debug!("Public key: {}", pub_key_str);

    // Save private key in OpenSSH format. It is created 0600 from the first
    // byte (never written under the umask and chmodded afterwards, which left
    // a window -- or, after a crash, a key -- readable by others) and renamed
    // into place, so a reader never sees a half-written key.
    let openssh_pem = key.to_openssh(ssh_key::LineEnding::LF)?;
    write_private_file(path, openssh_pem.as_bytes())?;

    Ok(())
}

/// Write `contents` to `path` through a `0600` temp file and a rename.
fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&tmp)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)
}

/// Load the probe key from `path`, or create it there if there is none.
///
/// Returns the key and whether it was just generated. The key IS the probe's
/// identity at RIPE Atlas: a new one registers as a different probe, with
/// none of the old one's history or credits. So a key file that exists but
/// cannot be read or parsed is an error -- it is never replaced -- and so is
/// a new key that cannot be saved, since an unsaved key would change on
/// every restart.
pub async fn load_or_create_key(path: &Path) -> anyhow::Result<(PrivateKey, bool)> {
    let exists = path.try_exists().map_err(|e| {
        anyhow::anyhow!(
            "cannot check for the probe key at {}: {}",
            path.display(),
            e
        )
    })?;
    if exists {
        let key = load_key(path).await.map_err(|e| {
            anyhow::anyhow!(
                "the probe key at {} exists but cannot be loaded ({}). Refusing to replace it: \
                 the key is this probe's identity at RIPE Atlas. Restore or fix the file, or move \
                 it aside deliberately to start a new probe",
                path.display(),
                e
            )
        })?;
        return Ok((key, false));
    }
    let key = generate_key()?;
    save_key(&key, path).await.map_err(|e| {
        anyhow::anyhow!(
            "generated a probe key but cannot save it to {} ({}); an unsaved key would change at \
             every restart",
            path.display(),
            e
        )
    })?;
    Ok((key, true))
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn public_key_openssh_matches_the_pub_file() {
        // The banner shows this string and probe_key.pub holds it; if the
        // two ever drift, a user registers one key and the probe presents
        // another, which fails as an opaque auth error at RIPE.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe_key");
        let key = generate_key().unwrap();

        save_key(&key, &path).await.unwrap();

        let written = std::fs::read_to_string(path.with_extension("pub")).unwrap();
        assert_eq!(written, public_key_openssh(&key));
    }

    #[test]
    fn public_key_openssh_is_authorized_keys_shaped() {
        let key = generate_key().unwrap();
        let rendered = public_key_openssh(&key);
        let mut parts = rendered.split(' ');

        assert_eq!(parts.next(), Some("ssh-ed25519"));
        assert!(!parts.next().unwrap().is_empty(), "base64 body");
        assert_eq!(parts.next(), Some("starla"));
        assert_eq!(parts.next(), None);
        assert!(!rendered.contains('\n'), "must stay on one line");
    }

    use super::*;

    #[test]
    fn key_exchange_never_offers_group1_and_keeps_strict_kex() {
        let cfg = client_config(&SshConfig::default());
        let kex = &cfg.preferred.kex;
        assert!(
            !kex.contains(&russh::kex::DH_G1_SHA1),
            "1024-bit diffie-hellman-group1-sha1 must not be offered"
        );
        assert!(
            kex.contains(&russh::kex::DH_GEX_SHA256),
            "RIPE's servers need group exchange"
        );
        assert!(
            kex.contains(&russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT),
            "dropping the strict-kex marker disables the Terrapin countermeasure"
        );
    }

    #[test]
    fn test_default_config() {
        let config = SshConfig::default();
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        // ssh -o "ServerAliveInterval 60", ServerAliveCountMax 3, and no
        // inactivity timeout (linux-functions.sh:151)
        assert_eq!(config.keepalive_interval, Duration::from_secs(60));
        assert_eq!(config.keepalive_max, 3);
        assert_eq!(config.inactivity_timeout, None);
        let russh = client_config(&config);
        assert_eq!(russh.keepalive_interval, Some(Duration::from_secs(60)));
        assert_eq!(russh.keepalive_max, 3);
        assert_eq!(russh.inactivity_timeout, None);
    }

    /// A controller over an in-memory wire: it takes `atlas` with any key,
    /// answers each exec with "pong\n", and sends nothing of its own — no
    /// keepalives, no timeout — so the client's timers are all there is.
    struct Controller {
        channels: Vec<Channel<russh::server::Msg>>,
    }

    impl russh::server::Handler for Controller {
        type Error = anyhow::Error;

        async fn auth_publickey(
            &mut self,
            user: &str,
            _: &PublicKey,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(if user == "atlas" {
                russh::server::Auth::Accept
            } else {
                russh::server::Auth::reject()
            })
        }

        async fn channel_open_session(
            &mut self,
            channel: Channel<russh::server::Msg>,
            _: &mut russh::server::Session,
        ) -> Result<bool, Self::Error> {
            self.channels.push(channel);
            Ok(true)
        }

        async fn exec_request(
            &mut self,
            channel: russh::ChannelId,
            _: &[u8],
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            session.data(channel, b"pong\n".to_vec())?;
            session.eof(channel)?;
            session.close(channel)?;
            Ok(())
        }
    }

    /// The probe's end of the wire, which can go silent: from then on
    /// nothing the controller sends arrives, and whatever the probe sends
    /// is lost, as on a path that has died.
    struct Wire {
        inner: tokio::io::DuplexStream,
        silent: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Wire {
        fn is_silent(&self) -> bool {
            self.silent.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl tokio::io::AsyncRead for Wire {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.is_silent() {
                return std::task::Poll::Pending;
            }
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for Wire {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.is_silent() {
                return std::task::Poll::Ready(Ok(buf.len()));
            }
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// A server that takes the key exchange and never answers the key.
    struct Mute;

    impl russh::server::Handler for Mute {
        type Error = anyhow::Error;

        async fn auth_publickey(
            &mut self,
            _: &str,
            _: &PublicKey,
        ) -> Result<russh::server::Auth, Self::Error> {
            std::future::pending().await
        }
    }

    /// The probe's end of a wire, which tells when it is dropped: when the
    /// session task that owns it has ended.
    struct Owned {
        inner: tokio::io::DuplexStream,
        dropped: Option<tokio::sync::oneshot::Sender<()>>,
    }

    impl Owned {
        fn new(inner: tokio::io::DuplexStream) -> (Self, tokio::sync::oneshot::Receiver<()>) {
            let (dropped, gone) = tokio::sync::oneshot::channel();
            (
                Self {
                    inner,
                    dropped: Some(dropped),
                },
                gone,
            )
        }
    }

    impl Drop for Owned {
        fn drop(&mut self) {
            if let Some(dropped) = self.dropped.take() {
                let _ = dropped.send(());
            }
        }
    }

    impl tokio::io::AsyncRead for Owned {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for Owned {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// The default configuration on a short clock: keepalives every 200 ms,
    /// so the login has 200 ms.
    fn quick_config() -> SshConfig {
        SshConfig {
            connect_timeout: Duration::from_millis(500),
            keepalive_interval: Duration::from_millis(200),
            ..SshConfig::default()
        }
    }

    /// One keepalive interval, before russh's pre-login spin can start; a
    /// connect timeout too large for the clock saturates.
    #[test]
    fn the_login_ends_before_russh_would_spin() {
        assert_eq!(
            SshConfig::default().login_timeout(),
            Duration::from_secs(60)
        );
        assert_eq!(quick_config().login_timeout(), Duration::from_millis(200));
        let by = quick_config().connected_by();
        assert!(by <= Instant::now() + Duration::from_millis(500));
        let silly = SshConfig {
            connect_timeout: Duration::MAX,
            keepalive_interval: Duration::MAX,
            ..SshConfig::default()
        };
        assert!(silly.connected_by() > Instant::now() + Duration::from_secs(86_400));
        let none = SshConfig {
            keepalive_interval: Duration::ZERO,
            ..SshConfig::default()
        };
        assert_eq!(none.login_timeout(), Duration::from_secs(30));
    }

    /// A server that takes the key exchange and never answers the key: the
    /// login gives up after one keepalive interval, before russh's session
    /// task would start spinning on its expired keepalive timer, and the
    /// task ends with it. Starla waited for good, the task spinning from
    /// the first interval on. Dropping the session's handle at the timeout
    /// ends the task here; the cut is for the key exchange, when russh does
    /// not read its handle (the test below).
    #[tokio::test]
    async fn a_login_the_server_never_answers_ends_with_its_session() {
        let (probe, controller) = tokio::io::duplex(1 << 16);
        let server = russh::server::Config {
            keys: vec![generate_key().unwrap()],
            inactivity_timeout: None,
            keepalive_interval: None,
            ..Default::default()
        };
        tokio::spawn(async move {
            if let Ok(running) = russh::server::run_stream(Arc::new(server), controller, Mute).await
            {
                let _ = running.await;
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let (wire, gone) = Owned::new(probe);
        let key = generate_key().unwrap();
        let started = tokio::time::Instant::now();
        let login = SshConnection::connect_stream(
            wire,
            "ctr-test",
            443,
            &key,
            quick_config(),
            KnownHosts::load(&dir.path().join("known_hosts")),
        );
        let Err(e) = timeout(Duration::from_secs(10), login)
            .await
            .expect("no bound")
        else {
            panic!("logged in");
        };
        let took = started.elapsed();
        assert!(e.to_string().contains("no answer from the server"), "{e}");
        assert!(
            (Duration::from_millis(200)..Duration::from_secs(3)).contains(&took),
            "gave up after {took:?}"
        );
        timeout(Duration::from_secs(2), gone)
            .await
            .expect("the session task still runs")
            .unwrap();
    }

    /// A server that sends its identification and nothing more: the key
    /// exchange runs out of the connect's time, and the session task russh
    /// spawned for it ends. Dropping the connect at its timeout left the
    /// task behind.
    #[tokio::test]
    async fn a_key_exchange_that_stalls_ends_with_its_session() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (probe, mut controller) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            controller.write_all(b"SSH-2.0-stall\r\n").await.unwrap();
            let mut sink = [0u8; 4096];
            while matches!(controller.read(&mut sink).await, Ok(n) if n > 0) {}
            // keeps its end open
            std::future::pending::<()>().await;
        });
        let dir = tempfile::tempdir().unwrap();
        let (wire, gone) = Owned::new(probe);
        let key = generate_key().unwrap();
        let login = SshConnection::connect_stream(
            wire,
            "ctr-test",
            443,
            &key,
            quick_config(),
            KnownHosts::load(&dir.path().join("known_hosts")),
        );
        let Err(e) = timeout(Duration::from_secs(10), login)
            .await
            .expect("no bound")
        else {
            panic!("logged in");
        };
        assert_eq!(e.to_string(), "Connection timeout");
        timeout(Duration::from_secs(2), gone)
            .await
            .expect("the session task still runs")
            .unwrap();
    }

    /// A session with the default configuration to a [`Controller`], and
    /// the switch that silences its wire.
    async fn keep_session() -> (
        SshConnection,
        Arc<std::sync::atomic::AtomicBool>,
        tempfile::TempDir,
    ) {
        let (probe, controller) = tokio::io::duplex(1 << 16);
        let server = russh::server::Config {
            keys: vec![generate_key().unwrap()],
            inactivity_timeout: None,
            keepalive_interval: None,
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        };
        tokio::spawn(async move {
            let running = russh::server::run_stream(
                Arc::new(server),
                controller,
                Controller {
                    channels: Vec::new(),
                },
            )
            .await;
            if let Ok(running) = running {
                let _ = running.await;
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let silent = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let wire = Wire {
            inner: probe,
            silent: silent.clone(),
        };
        let conn = SshConnection::connect_stream(
            wire,
            "ctr-test",
            443,
            &generate_key().unwrap(),
            SshConfig::default(),
            KnownHosts::load(&dir.path().join("known_hosts")),
        )
        .await
        .unwrap();
        assert_eq!(conn.execute("KEEP").await.unwrap(), "pong\n");
        (conn, silent, dir)
    }

    /// W13: the twin paused both probes for more than two minutes
    /// (2026-10-13). The reference's ssh, with ServerAliveInterval 60 and no
    /// inactivity timeout, sent a keepalive when it woke, had it answered,
    /// and kept its session. Starla's 120 s inactivity timeout had run out
    /// during the pause, and fired before the answer could arrive: KEEP was
    /// dropped and the probe reconnected.
    #[tokio::test(start_paused = true)]
    async fn a_two_minute_stall_keeps_a_session_whose_keepalives_are_answered() {
        let (conn, _silent, _dir) = keep_session().await;

        // Nothing runs for 130 s, then every timer due meanwhile fires at
        // once, as when a stopped process or a suspended host resumes
        tokio::time::advance(Duration::from_secs(130)).await;
        tokio::time::sleep(Duration::from_secs(1)).await;

        assert!(conn.is_connected().await, "the stall dropped the session");
        assert_eq!(conn.execute("KEEP").await.unwrap(), "pong\n");

        // and so does a quiet hour, keepalives answered every minute
        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert!(conn.is_connected().await);
        assert_eq!(conn.execute("KEEP").await.unwrap(), "pong\n");
    }

    /// A controller that has gone (nothing arrives, nothing sent reaches
    /// it) is given up on as the reference's ssh gives it up: a keepalive
    /// each 60 s, and the fourth interval without an answer, 240 s on,
    /// drops the session — not 120 s on, as the inactivity timeout did.
    #[tokio::test(start_paused = true)]
    async fn a_dead_controller_is_dropped_after_three_unanswered_keepalives() {
        let (conn, silent, _dir) = keep_session().await;

        silent.store(true, std::sync::atomic::Ordering::SeqCst);
        let gone = tokio::time::Instant::now();
        tokio::time::sleep(Duration::from_secs(239)).await;
        assert!(conn.is_connected().await, "dropped before 240 s");

        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            !conn.is_connected().await,
            "still up {:?} after the controller went",
            gone.elapsed()
        );
    }

    /// A controller whose KEEP writes `stdout` and `stderr` (either may be
    /// empty) and, if `closes`, exits 0 and closes the channel: RIPE's after
    /// the hot swap of 2026-10-14, or, with nothing written, a KEEP that
    /// just ends. One that does not close leaves the channel open.
    struct KeepEnds {
        stdout: &'static [u8],
        stderr: &'static [u8],
        closes: bool,
        channels: Vec<Channel<russh::server::Msg>>,
    }

    impl russh::server::Handler for KeepEnds {
        type Error = anyhow::Error;

        async fn auth_publickey(
            &mut self,
            _: &str,
            _: &PublicKey,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            channel: Channel<russh::server::Msg>,
            _: &mut russh::server::Session,
        ) -> Result<bool, Self::Error> {
            self.channels.push(channel);
            Ok(true)
        }

        async fn exec_request(
            &mut self,
            channel: russh::ChannelId,
            command: &[u8],
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            assert_eq!(command, b"KEEP");
            session.channel_success(channel)?;
            if !self.stdout.is_empty() {
                session.data(channel, self.stdout.to_vec())?;
            }
            if !self.stderr.is_empty() {
                session.extended_data(channel, 1, self.stderr.to_vec())?;
            }
            if self.closes {
                session.exit_status_request(channel, 0)?;
                session.eof(channel)?;
                session.close(channel)?;
            }
            Ok(())
        }
    }

    /// How a KEEP session against a [`KeepEnds`] controller ends, the
    /// channel let stay open for `grace` once written on; None if it has
    /// not ended within `within`.
    async fn keep_ends(
        stdout: &'static [u8],
        stderr: &'static [u8],
        closes: bool,
        grace: Duration,
        within: Duration,
    ) -> Option<anyhow::Error> {
        let (probe, controller) = tokio::io::duplex(1 << 16);
        let server = russh::server::Config {
            keys: vec![generate_key().unwrap()],
            inactivity_timeout: None,
            keepalive_interval: None,
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        };
        let handler = KeepEnds {
            stdout,
            stderr,
            closes,
            channels: Vec::new(),
        };
        tokio::spawn(async move {
            if let Ok(running) =
                russh::server::run_stream(Arc::new(server), controller, handler).await
            {
                let _ = running.await;
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let conn = SshConnection::connect_stream(
            probe,
            "ctr-test",
            443,
            &generate_key().unwrap(),
            SshConfig::default(),
            KnownHosts::load(&dir.path().join("known_hosts")),
        )
        .await
        .unwrap();
        let ended = timeout(within, conn.keep_session(grace)).await.ok()?;
        Some(ended.expect_err("a KEEP session only ever ends in an error"))
    }

    /// How `run_keep_session` ends against a [`KeepEnds`] controller that
    /// closes the channel.
    async fn keep_against(stdout: &'static [u8], stderr: &'static [u8]) -> anyhow::Error {
        let e = keep_ends(
            stdout,
            stderr,
            true,
            KEEP_REPLY_GRACE,
            Duration::from_secs(10),
        )
        .await;
        e.expect("KEEP did not end")
    }

    /// CON_KEEP_BROKEN: the controller answers KEEP with a line and exit
    /// status 0, and closes it. That is a refusal, carrying what it said,
    /// not a lost connection: KEEP again on the same session would be
    /// refused again (ripe-atlas.in:217-226).
    #[tokio::test]
    async fn a_keep_the_controller_answers_is_a_refusal_with_its_words() {
        let e = keep_against(b"session not known\n", b"").await;
        let refused = e
            .downcast_ref::<KeepRefused>()
            .unwrap_or_else(|| panic!("not a KeepRefused: {e:#}"));
        assert_eq!(refused.reply, "session not known\n");
        assert_eq!(refused.bytes, 18);
        assert_eq!(
            e.to_string(),
            r#"controller kicked us out from KEEP: "session not known\n" (18 bytes)"#
        );

        // its stderr, the reference's $SSH_ERR, is not part of the reply
        let e = keep_against(b"session not known\n", b"noise\n").await;
        let refused = e.downcast_ref::<KeepRefused>().expect("not a KeepRefused");
        assert_eq!(refused.reply, "session not known\n");
        assert_eq!(refused.bytes, 18);
    }

    /// Only stdout is con_keep_reply.vol (reginit.sh.in:523): a KEEP that
    /// ends with something on stderr alone is a lost session, as the
    /// reference KEEPs again on its cached session.
    #[tokio::test]
    async fn a_keep_answered_only_on_stderr_is_a_lost_session() {
        let e = keep_against(b"", b"go away\n").await;
        assert!(e.downcast_ref::<KeepRefused>().is_none(), "{e:#}");
        assert_eq!(e.to_string(), "KEEP session ended");
    }

    /// A KEEP that ends with nothing written is a lost session, as before:
    /// the caller KEEPs again on the same session.
    #[tokio::test]
    async fn a_keep_that_ends_with_nothing_said_is_a_lost_session() {
        let e = keep_against(b"", b"").await;
        assert!(e.downcast_ref::<KeepRefused>().is_none(), "{e:#}");
        assert_eq!(e.to_string(), "KEEP session ended");
    }

    /// A controller that writes on KEEP but leaves the channel open has
    /// still kicked us out: the reference kills ssh without waiting for it
    /// (ripe-atlas.in:217-221). The refusal comes once the grace is up.
    /// A KEEP that stays open and silent is a healthy session, and goes on.
    #[tokio::test]
    async fn a_keep_answered_and_left_open_is_a_refusal_after_the_grace() {
        let grace = Duration::from_millis(300);
        let started = std::time::Instant::now();
        let e = keep_ends(
            b"session not known\n",
            b"",
            false,
            grace,
            Duration::from_secs(10),
        )
        .await
        .expect("a KEEP answered and left open must end");
        let refused = e
            .downcast_ref::<KeepRefused>()
            .unwrap_or_else(|| panic!("not a KeepRefused: {e:#}"));
        assert_eq!(refused.reply, "session not known\n");
        assert!(started.elapsed() >= grace, "ended before the grace");

        // silent and open: still up after many graces
        let e = keep_ends(b"", b"", false, grace, grace * 5).await;
        assert!(e.is_none(), "a silent KEEP ended: {:#}", e.unwrap());
        // and so with only stderr written
        let e = keep_ends(b"", b"noise\n", false, grace, grace * 5).await;
        assert!(
            e.is_none(),
            "a KEEP with stderr only ended: {:#}",
            e.unwrap()
        );
    }

    /// Every byte the controller writes is counted, and the first 4 KiB
    /// kept, across chunks.
    #[test]
    fn a_keep_reply_keeps_its_first_4_kib() {
        assert_eq!(KeepReply::default().refusal(), None);

        let mut reply = KeepReply::default();
        reply.add(b"");
        assert_eq!(reply.refusal(), None, "an empty chunk is not a reply");

        let mut reply = KeepReply::default();
        reply.add(&[b'a'; 3000]);
        reply.add(&[b'b'; 3000]);
        let refused = reply.refusal().unwrap();
        assert_eq!(refused.bytes, 6000);
        assert_eq!(refused.reply.len(), KEEP_REPLY_KEPT);
        assert!(refused.reply.starts_with(&"a".repeat(3000)));
        assert!(refused.reply.ends_with(&"b".repeat(KEEP_REPLY_KEPT - 3000)));
    }

    #[test]
    fn test_generate_key() {
        let key = generate_key().unwrap();
        let public = key.public_key();
        // Just verify we can get the public key
        assert_eq!(public.algorithm(), Algorithm::Ed25519);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_private_key_is_written_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe_key");
        save_key(&generate_key().unwrap(), &path).await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(
            !path.with_extension("tmp").exists(),
            "temp file renamed away"
        );
    }

    #[tokio::test]
    async fn a_missing_key_is_created_and_then_reused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe_key");
        let (first, generated) = load_or_create_key(&path).await.unwrap();
        assert!(generated);
        let (again, generated) = load_or_create_key(&path).await.unwrap();
        assert!(!generated);
        assert_eq!(
            first.public_key().public_key_base64(),
            again.public_key().public_key_base64()
        );
    }

    #[tokio::test]
    async fn an_unreadable_key_is_an_error_and_is_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe_key");
        std::fs::write(&path, "not a key\n").unwrap();
        let err = load_or_create_key(&path).await.unwrap_err().to_string();
        assert!(err.contains("Refusing to"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not a key\n");
        assert!(!path.with_extension("pub").exists());
    }

    fn tmp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "starla-kh-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[tokio::test]
    async fn test_verify_matches_on_blob_across_algorithm_names() {
        let path = tmp_path("xalgo");
        let kh = KnownHosts::load(&path);

        let priv_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let pub_key = priv_key.public_key();
        let blob = pub_key.public_key_base64();

        kh.hosts
            .lock()
            .await
            .insert("atlas.example.com:443".into(), format!("ssh-rsa {}", blob));

        let ok = kh.verify("atlas.example.com", 443, pub_key).await.unwrap();
        assert!(ok, "blob match should win over algorithm-prefix difference");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_verify_rejects_different_blob() {
        let path = tmp_path("mitm");
        let kh = KnownHosts::load(&path);

        let pinned = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let attacker = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();

        kh.hosts.lock().await.insert(
            "atlas.example.com:443".into(),
            format!("ssh-ed25519 {}", pinned.public_key().public_key_base64()),
        );

        let ok = kh
            .verify("atlas.example.com", 443, attacker.public_key())
            .await
            .unwrap();
        assert!(!ok, "verify must reject a different key blob");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_verify_tofu_on_first_sight() {
        let path = tmp_path("tofu");
        let kh = KnownHosts::load(&path);

        let priv_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let ok = kh
            .verify("atlas.example.com", 443, priv_key.public_key())
            .await
            .unwrap();
        assert!(ok, "first sight should TOFU-trust the key");

        let ok = kh
            .verify("atlas.example.com", 443, priv_key.public_key())
            .await
            .unwrap();
        assert!(ok, "subsequent verifications with the same key must match");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn registration_starts_at_a_random_entry_and_keeps_the_rest_as_fallbacks() {
        let servers = [
            "reg-05",
            "193.0.19.75",
            "[2001::b]",
            "reg-06",
            "193.0.19.76",
            "[2001::c]",
        ];
        let order: Vec<_> = from_random_start(&servers, 4).copied().collect();
        assert_eq!(
            order,
            [
                "193.0.19.76",
                "[2001::c]",
                "reg-05",
                "193.0.19.75",
                "[2001::b]",
                "reg-06"
            ]
        );
        assert_eq!(from_random_start(&servers, 0).count(), 6);
        assert_eq!(from_random_start::<&str>(&[], 0).count(), 0);

        // Uniform like rchoose: every entry comes first, the IPv4 literals
        // about one time in three between them.
        let mut first = [0usize; 6];
        for _ in 0..6000 {
            first[random_start(6)] += 1;
        }
        assert!(first.iter().all(|&n| (800..1200).contains(&n)), "{first:?}");
        let v4 = first[1] + first[4];
        assert!((1700..2300).contains(&v4), "{v4}");
    }
}
