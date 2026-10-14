//! Logging infrastructure for Starla
//!
//! Provides flexible logging with:
//! - stdout output by default (journalctl-friendly)
//! - Optional file output with rotation
//! - Feature-gated JSON structured logging
//! - Environment-based log level configuration
//!
//! Logging never blocks the thread that logs. An event is formatted where it
//! is emitted and handed to one writer thread through a bounded queue
//! ([`BUFFERED_LINES_LIMIT`] lines). If the output stops taking lines --
//! journald not reading its stream, a full disk -- the queue fills, and
//! further lines are dropped and counted rather than waited for; a warning
//! with the count follows once the output takes lines again. Before, each
//! event was a write(2) to the journal stream under the process-wide stdout
//! lock, made by the runtime worker that emitted it, so a slow journal
//! delayed timers and receive stamps for every measurement on that worker.
//!
//! Stderr is not queued. Under systemd both streams go to the journal, so
//! what is written to stderr directly -- a panic's message, a failure
//! tracing-appender reports itself -- can land ahead of lines logged
//! before it that were still queued for stdout. The lines that led to a
//! panic may follow it in the journal.

use crate::priority::{Nice, BACKGROUND_NICE_INCREMENT};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;
use tracing::Subscriber;
use tracing_appender::non_blocking::{ErrorCounter, NonBlocking, NonBlockingBuilder, WorkerGuard};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;
pub use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Lines the writer thread may have queued before new ones are dropped.
///
/// The largest burst Starla logs is a crontab push under the debug drop-in,
/// which also has `starla_controller::telnet=trace`: each CRONLINE is five
/// events — telnet's "received" line (debug), its "CRONLINE: interval="
/// and command parse lines (trace), and the command handler's "Processing
/// command" and "Scheduled <type> measurement" (debug). ~800 CRONLINEs are
/// ~4,000 lines a crontab, and three crontabs can come back to back,
/// ~12,000 lines within milliseconds. 32,768 holds that with room for as
/// much again if the output stalls just as it starts; 16,384 left ~4,400.
/// The queue's slots are allocated up front, 32 bytes each: 1 MiB here,
/// where tracing-appender's default of 128,000 lines would be 4 MiB. A full
/// queue of ordinary ~150-byte lines holds another ~5 MiB of text.
pub const BUFFERED_LINES_LIMIT: usize = 32 * 1024;

/// The writer thread's name, as `top -H` shows it (at most 15 bytes).
const WRITER_THREAD: &str = "starla-log";

/// How long dropping the [`LogGuard`] waits for the queue to be written. An
/// output that has stopped taking lines must not hold up the exit.
///
/// The wait is for the writer thread to end (see [`stop_writer`]), not for
/// tracing-appender's own guard, which gives up after ~1.1 s.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// Logging configuration
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Optional log directory for file output
    pub log_dir: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    pub level: String,

    /// Whether to use JSON format
    pub json_format: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            log_dir: None,
            level: "info".to_string(),
            json_format: cfg!(feature = "json"),
        }
    }
}

/// Keeps the log's writer thread running. Hold it for the life of the
/// process.
///
/// Dropping it writes out what is still queued, waiting at most
/// [`FLUSH_TIMEOUT`], and stops the writer thread; anything logged after that
/// is lost. So are lines still queued when the wait runs out, and nothing
/// reports them: a report would go to the same output that is not taking
/// lines. `init_logging` used to drop its guard on return, which stopped
/// the file writer right after start-up and silently discarded every line
/// logged with `--log-dir`.
#[must_use = "the log is written only while the guard is held"]
#[derive(Debug)]
pub struct LogGuard {
    /// Shared with the SIGTERM thread; whichever comes first stops the
    /// writer.
    worker: Arc<Mutex<Option<Writer>>>,
    dropped: ErrorCounter,
}

/// The writer thread, as the guard holds it.
#[derive(Debug)]
struct Writer {
    /// tracing-appender's guard: dropping it queues the shutdown.
    guard: WorkerGuard,
    /// Disconnected when the writer thread ends: its [`Output`] holds the
    /// sender.
    finished: mpsc::Receiver<()>,
}

impl LogGuard {
    /// Lines dropped so far because the queue was full.
    pub fn dropped_lines(&self) -> usize {
        self.dropped.dropped_lines()
    }

    /// Makes a SIGTERM write out the queued lines before the process dies of
    /// it.
    ///
    /// systemd stops Starla with SIGTERM, which Starla does not handle: the
    /// default action ends the process at once, and with the log written by
    /// a thread of its own, the lines still queued would end with it. Here
    /// the signal wakes a thread that stops the writer as dropping the guard
    /// does, then ends the process by SIGTERM's default action: systemd still
    /// sees a process killed by SIGTERM, a clean stop, and at most
    /// [`FLUSH_TIMEOUT`] later than before.
    ///
    /// If Starla ever shuts down gracefully on SIGTERM, as it does on
    /// SIGINT, this hook has to go: it would end the process under that
    /// shutdown.
    #[cfg(unix)]
    fn flush_on_sigterm(&self) -> io::Result<()> {
        use std::io::Read;
        use std::os::unix::net::UnixStream;

        let (mut woken, wake) = UnixStream::pair()?;
        wake.set_nonblocking(true)?;
        let worker = Arc::clone(&self.worker);
        std::thread::Builder::new()
            .name("starla-log-term".to_string())
            .spawn(move || {
                let mut byte = [0u8; 1];
                loop {
                    match woken.read(&mut byte) {
                        Ok(1) => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        // The handler is gone: it was never registered.
                        _ => return,
                    }
                }
                stop_writer(&worker);
                die_of_sigterm();
            })?;
        // SAFETY: the action is async-signal-safe: one write to a
        // non-blocking socket, no allocation, no lock. signal-hook-registry
        // saves and restores errno around it.
        unsafe {
            signal_hook_registry::register(libc::SIGTERM, move || {
                let _ = (&wake).write(&[1]);
            })?;
        }
        Ok(())
    }
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        stop_writer(&self.worker);
    }
}

/// Ends the process as an unhandled SIGTERM would have.
///
/// As PID 1 — the twin's container runs Starla so, with no init — the
/// kernel ignores a signal whose action is the default: raise() returns,
/// and the process exits with 128 + SIGTERM, 143, the status a shell gives
/// a process SIGTERM killed. Before the hook Starla ignored SIGTERM there
/// and was SIGKILLed at the end of docker's grace period (137).
#[cfg(unix)]
fn die_of_sigterm() -> ! {
    // SAFETY: libc calls on a local signal set; the default action of
    // SIGTERM then ends the process inside raise().
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
        let mut term: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut term);
        libc::sigaddset(&mut term, libc::SIGTERM);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &term, std::ptr::null_mut());
        libc::raise(libc::SIGTERM);
    }
    std::process::exit(128 + libc::SIGTERM)
}

/// Stops the writer thread once it has written what is queued, giving up
/// after [`FLUSH_TIMEOUT`]. The first call does it, and holds the lock
/// while it waits: main's drop and the SIGTERM thread can both come, and
/// the second waits on the lock for the flush the first started, then
/// finds nothing to stop. It returned at once, and the process could end
/// with the lines still being written.
///
/// Dropping tracing-appender's `WorkerGuard` queues a shutdown behind the
/// lines (waiting up to 100 ms for room), then waits up to 1 s for the
/// writer thread to reach it, and returns either way. Waiting for that
/// return would cut a slow output off after ~1.1 s, not FLUSH_TIMEOUT. So
/// the guard is dropped on a thread of its own, and the wait here is for
/// the writer thread itself to end: it drops its [`Output`], whose sender
/// disconnects `finished`. Once the guard has given up, the writer thread
/// still ends as soon as it has written the lines queued before the
/// shutdown.
///
/// The guard's own thread is also needed because dropping it can block for
/// good: if the queue stays full for 100 ms it println!s that it failed, to
/// the same stdout that is not being read.
fn stop_writer(worker: &Mutex<Option<Writer>>) {
    let mut writer = worker.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(Writer { guard, finished }) = writer.take() else {
        return;
    };
    drop_elsewhere(guard, |drop_it| {
        std::thread::Builder::new()
            .name("starla-log-stop".to_string())
            .spawn(drop_it)
            .map(|_| ())
    });
    // Nothing is ever sent: Err(Disconnected) is the writer thread's end.
    let _ = finished.recv_timeout(FLUSH_TIMEOUT);
}

/// Drops `value` on the thread `spawn` starts, or never, if it starts none.
///
/// The value goes to the thread through a channel once the thread is
/// running, so a failed spawn — TasksMax reached as the probe stops — still
/// has it here, and it is forgotten, not dropped on this thread: the
/// guard's drop could block for good (see [`stop_writer`]), with SIGTERM's
/// exit or main's behind it. Without the shutdown the guard would have
/// queued, the writer thread goes on writing the queue while the stop
/// waits for it, and the lines are written all the same; the wait is then
/// the whole [`FLUSH_TIMEOUT`]. The guard used to be moved into the
/// closure, which a failed spawn drops where it fails.
fn drop_elsewhere<T: Send + 'static>(
    value: T,
    spawn: impl FnOnce(Box<dyn FnOnce() + Send>) -> io::Result<()>,
) {
    let (hand, take) = mpsc::channel::<T>();
    match spawn(Box::new(move || drop(take.recv()))) {
        Ok(()) => {
            let _ = hand.send(value);
        }
        Err(_) => std::mem::forget(value),
    }
}

/// Initialize logging subsystem
///
/// Returns the guard that keeps the log written: hold it until the process
/// exits.
///
/// # Arguments
///
/// * `config` - Logging configuration
///
/// # Examples
///
/// ```no_run
/// use starla_common::logging::{init_logging, LogConfig};
///
/// // Default: stdout with info level
/// let _log = init_logging(LogConfig::default()).unwrap();
///
/// // With custom log directory
/// let config = LogConfig {
///     log_dir: Some("/var/log/starla".into()),
///     level: "debug".to_string(),
///     json_format: false,
/// };
/// let _log = init_logging(config).unwrap();
/// ```
pub fn init_logging(config: LogConfig) -> anyhow::Result<LogGuard> {
    // Build filter from config and RUST_LOG env var
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.level));
    let json = cfg!(feature = "json") && config.json_format;

    let guard = match config.log_dir {
        None => {
            // Colour only for a terminal. Under systemd stdout is journald's
            // stream, where escape codes are bytes in every line.
            let ansi = use_ansi(io::stdout().is_terminal(), std::env::var_os("NO_COLOR"));
            // Buffered: the writer thread flushes after each batch, one
            // write(2) for many lines where stdout's own line buffering
            // made one per line.
            let (writer, guard) = spawn_writer(io::BufWriter::new(io::stdout()), json);
            tracing_subscriber::registry()
                .with(filter)
                .with(stdout_layer(writer, json, ansi))
                .init();
            guard
        }
        Some(dir) => {
            // Ensure log directory exists
            std::fs::create_dir_all(&dir)?;
            // Create daily rolling file appender
            let file_appender = tracing_appender::rolling::daily(dir, "probe.log");
            let (writer, guard) = spawn_writer(file_appender, json);
            tracing_subscriber::registry()
                .with(filter)
                .with(file_layer(writer, json))
                .init();
            guard
        }
    };

    #[cfg(unix)]
    if let Err(e) = guard.flush_on_sigterm() {
        tracing::warn!("A SIGTERM will lose the log lines still queued: {}", e);
    }

    Ok(guard)
}

/// Whether stdout's text is coloured: only on a terminal, and not when
/// `NO_COLOR` is set to anything but the empty string (no-color.org).
/// tracing-subscriber's default honours NO_COLOR the same way, but
/// `with_ansi(true)` overrides it, so it is checked here.
fn use_ansi(terminal: bool, no_color: Option<std::ffi::OsString>) -> bool {
    terminal && no_color.is_none_or(|v| v.is_empty())
}

/// The stdout layer: compact text, coloured if `ansi`, or JSON.
#[allow(unused_variables)]
fn stdout_layer<S>(writer: NonBlocking, json: bool, ansi: bool) -> Box<dyn Layer<S> + Send + Sync>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    #[cfg(feature = "json")]
    {
        if json {
            return json_layer(writer);
        }
    }

    // Default text format
    fmt::layer()
        .compact()
        .with_target(true)
        .with_thread_ids(false)
        .with_ansi(ansi)
        .with_writer(writer)
        .boxed()
}

/// The file layer: full text, or JSON.
#[allow(unused_variables)]
fn file_layer<S>(writer: NonBlocking, json: bool) -> Box<dyn Layer<S> + Send + Sync>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    #[cfg(feature = "json")]
    {
        if json {
            return json_layer(writer);
        }
    }

    // Default text format for files
    fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_ansi(false) // No ANSI colors in log files
        .with_writer(writer)
        .boxed()
}

/// The JSON layer, the same for stdout and files. tracing-subscriber's
/// `json()` never writes ANSI colours.
#[cfg(feature = "json")]
fn json_layer<S>(writer: NonBlocking) -> Box<dyn Layer<S> + Send + Sync>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fmt::layer()
        .json()
        .with_target(true)
        .with_current_span(true)
        .with_span_list(false)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_writer(writer)
        .boxed()
}

/// Starts the thread that writes the log to `output`, and returns the writer
/// the layer formats into and the guard that keeps the thread running.
///
/// The writer never blocks: it hands each formatted line to the thread
/// through a queue of [`BUFFERED_LINES_LIMIT`] lines, and a line that finds
/// the queue full is dropped and counted.
fn spawn_writer<W>(output: W, json: bool) -> (NonBlocking, LogGuard)
where
    W: Write + Send + 'static,
{
    let counter = Arc::new(OnceLock::new());
    let (finished_tx, finished) = mpsc::channel();
    // From the thread that starts logging, the main thread, whose priority
    // the measurement threads keep. No logger to report a failure to yet.
    let nice = Nice::below_this_thread(BACKGROUND_NICE_INCREMENT)
        .ok()
        .flatten();
    let (writer, worker) = NonBlockingBuilder::default()
        .lossy(true)
        .buffered_lines_limit(BUFFERED_LINES_LIMIT)
        .thread_name(WRITER_THREAD)
        .finish(Output {
            inner: output,
            dropped: Arc::clone(&counter),
            reported: 0,
            json,
            nice,
            _finished: finished_tx,
        });
    let dropped = writer.error_counter();
    // The thread may already be running; it reports drops once this is set,
    // and there can be none before the writer is in use.
    let _ = counter.set(dropped.clone());
    let guard = LogGuard {
        worker: Arc::new(Mutex::new(Some(Writer {
            guard: worker,
            finished,
        }))),
        dropped,
    };
    (writer, guard)
}

/// The writer thread's end of the queue: the real output, and the report of
/// the lines the queue dropped.
struct Output<W> {
    inner: W,
    /// The queue's drop counter, set once the queue exists.
    dropped: Arc<OnceLock<ErrorCounter>>,
    /// Drops already reported.
    reported: usize,
    /// Whether the log is JSON, for the report's format.
    json: bool,
    /// The nice value the writer thread lowers itself to at its first
    /// line, the background threads' (crate::priority): the threads that
    /// measure keep the process's (0 under the unit), so when they and a
    /// burst being written want the same CPU -- on enodia the probe has two
    /// hyperthreads of one core -- the measurement runs first. Writing is
    /// never urgent: lines wait in the queue, and a full queue drops them.
    /// None once lowered, and where a thread's priority cannot be set on
    /// its own (Linux only).
    nice: Option<Nice>,
    /// Dropped with the Output when the writer thread ends, after its last
    /// flush, which tells [`stop_writer`] the queue is written. Declared
    /// last, so it goes after `inner`, whose own drop may flush.
    _finished: mpsc::Sender<()>,
}

impl<W: Write> Output<W> {
    /// Lowers the writer thread's priority, from the thread itself (the
    /// only code of Starla's that runs on it), at its first line.
    ///
    /// Only ever lower, as every thread of Starla's that lowers itself
    /// (Nice::lower_this_thread). Best effort: if it fails, the thread
    /// keeps the priority it had.
    fn lower_priority_once(&mut self) {
        if let Some(nice) = self.nice.take() {
            let _ = nice.lower_this_thread();
        }
    }

    /// Writes a warning for the lines dropped since the last one.
    ///
    /// The thread flushes after each batch, that is, when it has emptied the
    /// queue: an output that stalled is taking lines again, and the warning
    /// lands right after the last line queued before the gap. It is written
    /// here, not logged, so it can be neither dropped nor left queued
    /// behind the shutdown.
    fn report_drops(&mut self) -> io::Result<()> {
        let Some(total) = self.dropped.get().map(ErrorCounter::dropped_lines) else {
            return Ok(());
        };
        if total > self.reported {
            let notice = drop_notice(total - self.reported, total, self.json);
            self.inner.write_all(notice.as_bytes())?;
            self.reported = total;
        }
        Ok(())
    }
}

impl<W: Write> Write for Output<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.lower_priority_once();
        self.inner.write(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.lower_priority_once();
        self.inner.write_all(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.report_drops()?;
        self.inner.flush()
    }
}

/// The warning for `lost` dropped lines, `total` since start, as one line of
/// the log in its format.
fn drop_notice(lost: usize, total: usize, json: bool) -> String {
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let message = format!(
        "{lost} log lines dropped: the log output was not taking them ({total} since start)"
    );
    if json {
        let mut line = serde_json::json!({
            "timestamp": timestamp,
            "level": "WARN",
            "fields": {
                "message": message,
                "dropped": lost,
                "dropped_total": total,
            },
            "target": module_path!(),
        })
        .to_string();
        line.push('\n');
        line
    } else {
        format!("{timestamp}  WARN {}: {message}\n", module_path!())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, Read};
    use std::process::{Command, Stdio};
    use std::sync::{Condvar, Mutex};
    use std::time::Instant;

    /// Set in a child process to the name of the child test it is to run.
    const CHILD: &str = "STARLA_LOGGING_TEST_CHILD";
    /// The child's log directory, for the file tests.
    const CHILD_LOG_DIR: &str = "STARLA_LOGGING_TEST_LOG_DIR";

    #[test]
    fn test_default_config() {
        let config = LogConfig::default();
        assert_eq!(config.level, "info");
        assert!(config.log_dir.is_none());
    }

    /// An output that takes nothing until it is opened, as a journald that
    /// has stopped reading its stream; then it keeps what it is given.
    #[derive(Clone, Default)]
    struct Gate(Arc<(Mutex<(bool, Vec<u8>)>, Condvar)>);

    impl Gate {
        fn open(&self) {
            let (state, opened) = &*self.0;
            state.lock().unwrap().0 = true;
            opened.notify_all();
        }

        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0 .0.lock().unwrap().1).into_owned()
        }
    }

    impl Write for Gate {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let (state, opened) = &*self.0;
            let mut state = opened
                .wait_while(state.lock().unwrap(), |(open, _)| !*open)
                .unwrap();
            state.1.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Waits up to 30 s for `found` to return something.
    fn wait_for<T>(what: &str, mut found: impl FnMut() -> Option<T>) -> T {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(it) = found() {
                return it;
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// The thread that logs never waits for the output. With the output
    /// stalled, a burst of twice the queue's size goes through at the cost
    /// of formatting each line; the lines past the queue's room are dropped
    /// and counted; and once the output takes lines again it gets them all,
    /// then one warning with the count.
    #[test]
    fn a_stalled_output_never_blocks_the_thread_that_logs() {
        let output = Gate::default();
        let (writer, guard) = spawn_writer(output.clone(), false);
        let burst = 2 * BUFFERED_LINES_LIMIT;

        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let subscriber =
                tracing_subscriber::registry().with(stdout_layer(writer, false, false));
            let mut each = Vec::with_capacity(burst);
            tracing::subscriber::with_default(subscriber, || {
                for i in 0..burst {
                    let started = Instant::now();
                    tracing::info!("burst line {i}");
                    each.push(started.elapsed());
                }
            });
            let _ = done.send(each);
        });
        let mut each = finished
            .recv_timeout(Duration::from_secs(30))
            .expect("the burst blocked on the stalled output");
        each.sort();
        let p99 = each[each.len() * 99 / 100];
        assert!(
            p99 < Duration::from_millis(1),
            "an event took {p99:?} at the 99th percentile, {:?} at most",
            each.last()
        );

        // The queue's room is taken, plus at most the one line the writer
        // thread took and is stuck writing; the rest is counted.
        let dropped = guard.dropped_lines();
        assert!(
            (burst - BUFFERED_LINES_LIMIT - 1..=burst - BUFFERED_LINES_LIMIT).contains(&dropped),
            "{dropped} of {burst} lines dropped"
        );

        output.open();
        let notice = wait_for("the drop warning", || {
            let text = output.text();
            text.lines()
                .find(|line| line.contains("log lines dropped"))
                .map(str::to_owned)
        });
        assert!(
            notice.contains(&format!(
                "  WARN starla_common::logging: {dropped} log lines dropped"
            )),
            "{notice}"
        );

        drop(guard);
        let text = output.text();
        let written = text.lines().filter(|l| l.contains("burst line")).count();
        assert_eq!(written + dropped, burst, "every line written or counted");
        assert_eq!(text.lines().last(), Some(notice.as_str()), "warning last");
    }

    /// Logs `lines` lines into a fresh writer on `output`, then returns its
    /// guard.
    fn queue_lines(output: &Gate, lines: usize) -> LogGuard {
        let (writer, guard) = spawn_writer(output.clone(), false);
        let subscriber = tracing_subscriber::registry().with(stdout_layer(writer, false, false));
        tracing::subscriber::with_default(subscriber, || {
            for i in 0..lines {
                tracing::info!("queued line {i}");
            }
        });
        guard
    }

    /// Dropping the guard waits for the queue to be written for up to
    /// FLUSH_TIMEOUT, not the ~1.1 s tracing-appender's guard waits. The
    /// output takes nothing for 1.3 s, as a journal slow to read; by the
    /// time the drop returns, every line has reached it.
    #[test]
    fn the_exit_waits_for_a_slow_output_up_to_the_flush_timeout() {
        const LINES: usize = 200;
        const STALL: Duration = Duration::from_millis(1_300);
        let output = Gate::default();
        let guard = queue_lines(&output, LINES);
        let opener = std::thread::spawn({
            let output = output.clone();
            move || {
                std::thread::sleep(STALL);
                output.open();
            }
        });

        let started = Instant::now();
        drop(guard);
        let waited = started.elapsed();
        let written = output
            .text()
            .lines()
            .filter(|l| l.contains("queued line"))
            .count();
        opener.join().unwrap();
        assert!(waited >= STALL, "returned after {waited:?}");
        assert_eq!(
            written, LINES,
            "written when the drop returned, after {waited:?}"
        );
    }

    /// The SIGTERM thread and main's drop can both stop the writer: the
    /// second waits for the flush the first started instead of returning
    /// while lines are still being written.
    #[test]
    fn a_second_stop_waits_for_the_first_ones_flush() {
        const LINES: usize = 200;
        const STALL: Duration = Duration::from_millis(1_000);
        let output = Gate::default();
        let guard = queue_lines(&output, LINES);
        let worker = Arc::clone(&guard.worker);
        let first = std::thread::spawn(move || drop(guard));
        // the first stop has taken the writer, and waits on the closed
        // output (holding the lock as it does)
        wait_for("the first stop", || {
            (!worker.try_lock().is_ok_and(|writer| writer.is_some())).then_some(())
        });
        let opener = std::thread::spawn({
            let output = output.clone();
            move || {
                std::thread::sleep(STALL);
                output.open();
            }
        });

        stop_writer(&worker);
        let written = output
            .text()
            .lines()
            .filter(|l| l.contains("queued line"))
            .count();
        first.join().unwrap();
        opener.join().unwrap();
        assert_eq!(written, LINES, "written when the second stop returned");
    }

    /// A value is dropped on the thread started for it; if none can be
    /// started, it is forgotten rather than dropped on the calling thread,
    /// where the log guard's drop could block for good.
    #[test]
    fn a_value_is_dropped_on_its_own_thread_or_never() {
        struct Noted(mpsc::Sender<std::thread::ThreadId>);
        impl Drop for Noted {
            fn drop(&mut self) {
                let _ = self.0.send(std::thread::current().id());
            }
        }

        let (noted, drops) = mpsc::channel();
        drop_elsewhere(Noted(noted), |f| {
            std::thread::spawn(f);
            Ok(())
        });
        let on = drops.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_ne!(on, std::thread::current().id());

        let (noted, drops) = mpsc::channel();
        drop_elsewhere(Noted(noted), |_| Err(io::Error::other("no thread")));
        assert!(matches!(
            drops.recv_timeout(Duration::from_millis(200)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
    }

    /// An output that takes nothing at all holds the exit for FLUSH_TIMEOUT,
    /// then the drop gives up.
    #[test]
    fn a_stuck_output_holds_the_exit_for_the_flush_timeout_only() {
        let output = Gate::default();
        let guard = queue_lines(&output, 10);

        let started = Instant::now();
        drop(guard);
        let waited = started.elapsed();
        // Lets the writer thread end.
        output.open();
        assert!(
            waited >= FLUSH_TIMEOUT && waited < FLUSH_TIMEOUT + Duration::from_secs(1),
            "returned after {waited:?}"
        );
    }

    /// Colour on a terminal only, and not with NO_COLOR set to anything
    /// but the empty string.
    #[test]
    fn no_color_turns_colour_off_on_a_terminal() {
        use std::ffi::OsString;
        assert!(use_ansi(true, None));
        assert!(use_ansi(true, Some(OsString::new())));
        assert!(!use_ansi(true, Some(OsString::from("1"))));
        assert!(!use_ansi(false, None));
        assert!(!use_ansi(false, Some(OsString::from("1"))));
    }

    /// `ansi` is what decides colour: off, no escape codes; on, the level
    /// is coloured. (init_logging passes whether stdout is a terminal; the
    /// child tests see it off on a pipe.)
    #[test]
    fn colour_only_when_asked() {
        for ansi in [false, true] {
            let output = Gate::default();
            output.open();
            let (writer, guard) = spawn_writer(output.clone(), false);
            let subscriber = tracing_subscriber::registry().with(stdout_layer(writer, false, ansi));
            tracing::subscriber::with_default(subscriber, || tracing::warn!("coloured?"));
            drop(guard);
            let text = output.text();
            assert!(text.contains("coloured?"), "{text}");
            assert_eq!(text.contains('\x1b'), ansi, "ansi {ansi}: {text:?}");
        }
    }

    /// On Linux the writer thread lowers its own priority, and only its
    /// own: the thread that logs keeps the one it had.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_writer_thread_runs_below_the_threads_that_log() {
        /// Records the nice value of the thread that writes to it.
        struct SeesNice(Arc<Mutex<Option<libc::c_int>>>);

        impl Write for SeesNice {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                // SAFETY: reads the calling thread's own priority.
                let nice = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
                *self.0.lock().unwrap() = Some(nice);
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        // SAFETY: reads the calling thread's own priority.
        let before = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
        let seen = Arc::new(Mutex::new(None));
        let (writer, guard) = spawn_writer(SeesNice(Arc::clone(&seen)), false);
        let subscriber = tracing_subscriber::registry().with(stdout_layer(writer, false, false));
        tracing::subscriber::with_default(subscriber, || tracing::info!("a line"));
        drop(guard);

        let writer_nice = seen.lock().unwrap().expect("the line was written");
        // The background threads' level: BACKGROUND_NICE_INCREMENT below
        // the thread that started the writer, at most 19.
        assert_eq!(
            writer_nice,
            (before + BACKGROUND_NICE_INCREMENT).min(19),
            "writer thread at nice {writer_nice}, test thread at {before}"
        );
        // SAFETY: reads the calling thread's own priority.
        let after = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
        assert_eq!(after, before, "the thread that logs keeps its priority");
    }

    #[test]
    fn the_drop_warning_is_one_line_of_the_log() {
        let text = drop_notice(7, 12, false);
        assert!(text.ends_with('\n') && text.lines().count() == 1, "{text}");
        assert!(
            text.contains("Z  WARN starla_common::logging: 7 log lines dropped"),
            "{text}"
        );
        assert!(text.contains("(12 since start)"), "{text}");

        let json = drop_notice(7, 12, true);
        assert!(json.ends_with('\n') && json.lines().count() == 1, "{json}");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(value["level"], "WARN");
        assert_eq!(value["target"], "starla_common::logging");
        assert_eq!(value["fields"]["dropped"], 7);
        assert_eq!(value["fields"]["dropped_total"], 12);
    }

    /// The JSON warning has the keys of the JSON layer's own events.
    #[cfg(feature = "json")]
    #[test]
    fn the_json_drop_warning_has_the_layers_keys() {
        let output = Gate::default();
        output.open();
        let (writer, guard) = spawn_writer(output.clone(), true);
        let subscriber = tracing_subscriber::registry().with(stdout_layer(writer, true, false));
        tracing::subscriber::with_default(subscriber, || tracing::warn!("an event"));
        drop(guard);

        let text = output.text();
        let event: serde_json::Value =
            serde_json::from_str(text.lines().next().expect("the event")).expect("JSON");
        let notice: serde_json::Value =
            serde_json::from_str(&drop_notice(1, 1, true)).expect("JSON");
        for key in ["timestamp", "level", "fields", "target"] {
            assert!(event.get(key).is_some(), "the layer writes {key}: {event}");
            assert!(notice.get(key).is_some(), "the warning lacks {key}");
        }
        assert!(event["fields"].get("message").is_some(), "{event}");
    }

    /// Whether this process is the child running `name`. `init_logging`
    /// installs the process-wide subscriber, once, so every test of it runs
    /// in a process of its own: this test binary, run again for that one
    /// test.
    fn is_child(name: &str) -> bool {
        std::env::var(CHILD).as_deref() == Ok(name)
    }

    /// What a child prints to stderr when its burst is queued: a parent
    /// holding its stdout starts reading it then.
    const READY: &str = "child: burst queued";

    /// Runs the ignored test `name` in a child process of this test binary
    /// and returns what it wrote and how it ended. With `hold_stdout`, its
    /// stdout is not read until it prints [`READY`] to stderr: the pipe fills,
    /// the writer thread blocks on it, and the lines logged after that wait
    /// in the queue, as they do behind a journald that is slow to read. A
    /// child that hangs is killed after a minute, so a regression fails
    /// instead of stalling the suite.
    fn run_child(
        name: &str,
        env: &[(&str, &std::ffi::OsStr)],
        hold_stdout: bool,
    ) -> std::process::Output {
        let mut cmd = Command::new(std::env::current_exe().expect("test binary path"));
        cmd.args([
            "--exact",
            &format!("logging::tests::{name}"),
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, name)
        .env_remove("RUST_LOG")
        .env_remove("NO_COLOR")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        for (key, value) in env {
            cmd.env(key, value);
        }
        let mut child = cmd.spawn().expect("spawn the child test");
        let mut child_stdout = child.stdout.take().expect("piped stdout");
        let child_stderr = child.stderr.take().expect("piped stderr");

        // Released at READY, or when stderr closes (the sender drops).
        let (ready, released) = std::sync::mpsc::channel::<()>();
        let stderr = std::thread::spawn(move || {
            let mut stderr = io::BufReader::new(child_stderr);
            let mut bytes = Vec::new();
            let mut line = Vec::new();
            while matches!(stderr.read_until(b'\n', &mut line), Ok(n) if n > 0) {
                if String::from_utf8_lossy(&line).contains(READY) {
                    let _ = ready.send(());
                }
                bytes.append(&mut line);
            }
            bytes
        });
        let stdout = std::thread::spawn(move || {
            if hold_stdout {
                let _ = released.recv();
            }
            let mut bytes = Vec::new();
            let _ = child_stdout.read_to_end(&mut bytes);
            bytes
        });

        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll the child test") {
                break status;
            }
            if Instant::now() > deadline {
                // Still running after a minute: it hangs.
                let _ = child.kill();
                break child.wait().expect("reap the child test");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        std::process::Output {
            status,
            stdout: stdout.join().expect("stdout reader"),
            stderr: stderr.join().expect("stderr reader"),
        }
    }

    /// A fresh directory under the system's temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "starla-logging-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).expect("create the temp dir");
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const STDOUT_LINES: usize = 5_000;

    #[test]
    #[ignore = "a child process of stdout_log_keeps_every_line_to_exit"]
    fn child_stdout_log() {
        if !is_child("child_stdout_log") {
            return;
        }
        let log = init_logging(LogConfig {
            log_dir: None,
            level: "info".to_string(),
            json_format: false,
        })
        .expect("init logging");
        for i in 0..STDOUT_LINES {
            tracing::info!("stdout line {i} of {STDOUT_LINES}");
        }
        eprintln!("{READY}");
        // As main returns: the guard goes, then the process, at once.
        drop(log);
        std::process::exit(0);
    }

    /// Every line reaches stdout, including those still queued at the end:
    /// dropping the guard as main returns writes the queue out. The parent
    /// holds the pipe until the burst is queued, so most of it is.
    #[test]
    fn stdout_log_keeps_every_line_to_exit() {
        let out = run_child("child_stdout_log", &[], true);
        assert!(
            out.status.success(),
            "child failed: {}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        let log = String::from_utf8_lossy(&out.stdout);
        let lines = log.lines().filter(|l| l.contains("stdout line")).count();
        assert_eq!(lines, STDOUT_LINES, "{log}");
        assert!(log.contains(&format!(
            "stdout line {} of {STDOUT_LINES}",
            STDOUT_LINES - 1
        )));
        // The child's stdout is a pipe, as journald's stream is.
        assert!(!log.contains('\x1b'), "escape codes on a non-terminal");
    }

    #[cfg(unix)]
    const SIGTERM_LINES: usize = 5_000;

    #[cfg(unix)]
    #[test]
    #[ignore = "a child process of sigterm_writes_the_queue_out_then_dies_of_it"]
    fn child_sigterm() {
        if !is_child("child_sigterm") {
            return;
        }
        let _log = init_logging(LogConfig {
            log_dir: None,
            level: "info".to_string(),
            json_format: false,
        })
        .expect("init logging");
        for i in 0..SIGTERM_LINES {
            tracing::info!("term line {i} of {SIGTERM_LINES}");
        }
        eprintln!("{READY}");
        // As systemd stops the probe, with the lines just logged still
        // queued.
        // SAFETY: kill(2) of this process.
        unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    /// A SIGTERM writes out every queued line, and the process still dies
    /// of the SIGTERM, as systemd expects of a clean stop. The parent holds
    /// the pipe until the burst is queued, so most of it is when the signal
    /// comes.
    #[cfg(unix)]
    #[test]
    fn sigterm_writes_the_queue_out_then_dies_of_it() {
        use std::os::unix::process::ExitStatusExt;

        let out = run_child("child_sigterm", &[], true);
        assert_eq!(
            out.status.signal(),
            Some(libc::SIGTERM),
            "child ended {}:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        let log = String::from_utf8_lossy(&out.stdout);
        let lines = log.lines().filter(|l| l.contains("term line")).count();
        assert_eq!(lines, SIGTERM_LINES, "{log}");
    }

    const FILE_LINES: usize = 200;

    #[test]
    #[ignore = "a child process of file_log_keeps_every_line_after_init"]
    fn child_file_log() {
        if !is_child("child_file_log") {
            return;
        }
        let dir = std::env::var_os(CHILD_LOG_DIR).expect("the child's log dir");
        let _log = init_logging(LogConfig {
            log_dir: Some(dir.into()),
            level: "info".to_string(),
            json_format: false,
        })
        .expect("init logging");
        for i in 0..FILE_LINES {
            tracing::info!("file line {i} of {FILE_LINES}");
        }
    }

    /// With `--log-dir`, every line logged after `init_logging` reaches the
    /// file, through to the last one before the guard is dropped.
    #[test]
    fn file_log_keeps_every_line_after_init() {
        let dir = TempDir::new("file");
        let out = run_child(
            "child_file_log",
            &[(CHILD_LOG_DIR, dir.0.as_os_str())],
            false,
        );
        assert!(
            out.status.success(),
            "child failed: {}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );

        let mut log = String::new();
        for entry in std::fs::read_dir(&dir.0).expect("read the log dir") {
            let path = entry.expect("dir entry").path();
            if path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("probe.log"))
            {
                log.push_str(&std::fs::read_to_string(&path).expect("read the log"));
            }
        }
        for i in 0..FILE_LINES {
            assert!(
                log.contains(&format!("file line {i} of {FILE_LINES}")),
                "line {i} is missing from the file log:\n{log}"
            );
        }
        assert!(!log.contains('\x1b'), "no escape codes in a log file");
    }
}
