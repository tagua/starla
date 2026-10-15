//! Measurement Scheduler
//!
//! The scheduler is responsible for:
//! - Receiving measurement jobs from the command handler
//! - Executing measurements at the correct times
//! - Forwarding results to the result handler for upload

pub mod executor;
pub mod job;
mod lines;
pub mod task;

pub use job::{
    CondmvJobSpec, DnsJobSpec, HttpJobSpec, MeasurementJob, MeasurementSpec, NtpJobSpec,
    PingJobSpec, TlsJobSpec, TracerouteJobSpec,
};
pub use lines::{Crontab, CrontabLine};

use lines::{Due, InconsistentRecord, Lines};
use starla_common::{MeasurementData, MeasurementId, MeasurementResult, ProbeId, Timestamp};
use starla_results::{ResultHandler, ResultSink};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use task::Now;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Commands that can be sent to the scheduler
#[derive(Debug)]
pub enum SchedulerCommand {
    /// Schedule a measurement job on its own, outside any crontab (Starla's
    /// JSON commands): a recurring one replaces the one with its msm id
    Schedule(MeasurementJob),
    /// A crontab the controller finished: its file's recurring lines are
    /// now these, as eperd reads a crontab anew (eperd.c:513-645)
    Crontab(Crontab),
    /// Stop every line of a measurement
    Stop(u64),
    /// Execute a measurement immediately (one-shot)
    ExecuteNow(MeasurementJob),
}

/// How many of a crontab's lines the scheduler takes between yields. A push
/// of 800 lines took ~0.5 ms in one stretch (release build, 2026-10-14) on
/// a measurement worker, holding up every reply that worker would have
/// taken; a slice of 64 takes tens of microseconds.
const LINES_PER_YIELD: usize = 64;

pub struct Scheduler {
    /// The recurring lines, each crontab's and Starla's own. Only the
    /// scheduler takes them; the status gets their counts handed over
    /// (SchedulerStatus).
    lines: Mutex<Lines>,
    /// The counts the status shows
    status: SchedulerStatus,
    /// Probe ID for measurement results
    probe_id: ProbeId,
    /// Where the runs hand their results over for upload: without waiting,
    /// whatever the result handler's runtime is doing (ResultSink)
    results: Option<ResultSink>,
    /// Metrics registry for recording operations
    metrics: starla_metrics::MetricsRegistry,
    /// Command receiver
    cmd_rx: Arc<Mutex<Option<mpsc::Receiver<SchedulerCommand>>>>,
    /// Command sender (for cloning)
    cmd_tx: mpsc::Sender<SchedulerCommand>,
    /// Cancellation token for graceful shutdown
    cancel_token: CancellationToken,
    /// What holds the lines while the tray pauses the probe
    pause: Pause,
}

/// What tells the scheduler the probe is paused: the file the tray writes,
/// read at each tick ([`tray_paused`]), or a switch that something else sets
/// from it ([`Scheduler::pause_switch`]), or, in a test, a switch of its
/// own, so that no test reads the pause of the host it runs on.
enum Pause {
    Tray,
    Switch(PauseSwitch),
}

impl Pause {
    /// Whether the pause holds the lines now.
    fn on(&self) -> bool {
        match self {
            Pause::Tray => tray_paused(),
            Pause::Switch(switch) => switch.is_on(),
        }
    }
}

/// Whether the tray's pause holds now. A tray pause whose end has passed is
/// over: its file is cleared, so that the tray's status panel stops
/// claiming the probe is still paused.
fn tray_paused() -> bool {
    match starla_common::read_pause_state() {
        Some(state) if state.is_active(chrono::Utc::now()) => true,
        Some(_) => {
            let _ = starla_common::write_pause_state(None);
            false
        }
        None => false,
    }
}

/// The tray's pause as a switch the scheduler reads at each tick without a
/// system call. [`PauseSwitch::follow_tray`] reads the tray's file once a
/// second, off the measurement threads, and sets it: the scheduler's tick
/// read the file itself, a file system call on a measurement worker every
/// second.
#[derive(Clone, Default)]
pub struct PauseSwitch(Arc<AtomicBool>);

impl PauseSwitch {
    /// Whether the probe is paused
    pub fn is_on(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    /// Pause the probe, or end the pause
    pub fn set(&self, on: bool) {
        self.0.store(on, Ordering::Release);
    }

    /// Keep the switch set from the tray's pause file, read once a second
    /// (a pause whose end has passed is cleared, as the tick cleared it),
    /// until `cancel`. Run it on the background runtime.
    pub async fn follow_tray(self, cancel: CancellationToken) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tick.tick() => self.set(tray_paused()),
            }
        }
    }
}

/// Read-only handle to the scheduler's line counts. Exposed so the probe can
/// report active measurement counts to the tray without leaking the
/// internal task map type.
///
/// The scheduler hands the counts over when its lines change, and never
/// waits to: a reader holding them only delays the hand-over to the next
/// tick. It used to read the lines themselves, under the lock the
/// scheduler's tick takes, from the background runtime.
#[derive(Clone, Default)]
pub struct SchedulerStatus {
    counts: Arc<std::sync::Mutex<HashMap<String, u64>>>,
}

impl SchedulerStatus {
    /// Count active recurring measurement lines grouped by type ("ping",
    /// "dns", ...).
    pub async fn measurement_counts(&self) -> HashMap<String, u64> {
        self.counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl Scheduler {
    /// Create a new scheduler
    pub fn new(probe_id: ProbeId, metrics: starla_metrics::MetricsRegistry) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(100);
        Self {
            lines: Mutex::new(Lines::default()),
            status: SchedulerStatus::default(),
            probe_id,
            results: None,
            metrics,
            cmd_rx: Arc::new(Mutex::new(Some(cmd_rx))),
            cmd_tx,
            cancel_token: CancellationToken::new(),
            pause: Pause::Tray,
        }
    }

    /// Get a cancellation token for stopping the scheduler
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// Set the result handler for uploading measurement results: the runs
    /// hand their results to its [`ResultSink`]
    pub fn set_result_handler(&mut self, handler: Arc<ResultHandler>) {
        self.results = Some(handler.sink());
    }

    /// Get a command sender for scheduling measurements
    pub fn command_sender(&self) -> mpsc::Sender<SchedulerCommand> {
        self.cmd_tx.clone()
    }

    /// The line counts for read-only status snapshots. Hands out a
    /// SchedulerStatus rather than the line set itself so it can stay
    /// private to this crate.
    pub fn status_handle(&self) -> SchedulerStatus {
        self.status.clone()
    }

    /// Take the tray's pause from the returned switch from now on, instead
    /// of reading the tray's file at every tick; it starts as the file is
    /// now. Keep it set with [`PauseSwitch::follow_tray`].
    pub fn pause_switch(&mut self) -> PauseSwitch {
        let switch = PauseSwitch::default();
        switch.set(tray_paused());
        self.pause = Pause::Switch(switch.clone());
        switch
    }

    /// Hand the status the lines' counts, if lines came or went: never
    /// waiting, as the reader is on another runtime. If it is reading just
    /// now, the next tick hands them over.
    fn publish_counts(&self, lines: &mut Lines) {
        if !lines.take_changed() {
            return;
        }
        let mut counts = match self.status.counts.try_lock() {
            Ok(counts) => counts,
            Err(std::sync::TryLockError::Poisoned(counts)) => counts.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                lines.mark_changed();
                return;
            }
        };
        *counts = lines.counts();
    }

    /// Schedule a measurement job on its own
    ///
    /// DNS resolution is deferred to execution time to handle transient
    /// failures and ensure fresh resolution for each measurement execution.
    pub async fn schedule(&self, job: MeasurementJob) -> anyhow::Result<()> {
        self.schedule_at(job, Now::read()).await;
        Ok(())
    }

    /// A job of Starla's own at `now`, and the runs it starts at once: a
    /// one-off's, which a pause does not hold (eooqd's, beside the lines,
    /// as before), or, unless the probe is paused (run_due), a recurring
    /// job's whose first time is already past (synchronize_at).
    async fn schedule_at(&self, job: MeasurementJob, now: Now) -> Vec<JoinHandle<()>> {
        if job.is_one_shot() {
            // Execute immediately - resolve DNS now - beside the lines, not
            // in their way (spawn_run)
            debug!(msm_id = job.msm_id, "Executing one-shot measurement");
            vec![self.spawn_run(job, None)]
        } else {
            // Add to scheduled tasks - DNS resolution deferred to execution
            debug!(
                msm_id = job.msm_id,
                interval = job.interval,
                "Scheduling recurring measurement"
            );
            self.lines.lock().await.schedule(job, now);
            // a first time already past fires at once (synchronize_at)
            self.run_due(now).await
        }
    }

    /// A crontab the controller finished: its file's lines become the
    /// crontab's. Lines it repeats keep their slots, its new lines wait for
    /// their first, and lines it no longer has stop; other files' lines are
    /// untouched. Taken [`LINES_PER_YIELD`] lines at a time, yielding to
    /// the measurements between them; the lines stay locked throughout, so
    /// no tick sees a crontab half taken.
    pub async fn synchronize(&self, crontab: Crontab) {
        self.synchronize_at(crontab, Now::read()).await;
    }

    /// The crontab's lines at `now`, and then, unless the probe is paused
    /// (run_due), the lines whose timers fire at once, in the same second:
    /// eperd reads the crontab (SynchronizeFile, on cron.update) and
    /// libevent runs, in its loop's next pass, each timer set meanwhile for
    /// a time already past — set_timeout's wait of 0 (eperd.c:764-765): a
    /// line that had stopped at its old end time, set again by Insert for
    /// the time it had (:815-824), or a new line whose offset put its first
    /// time at or before now (Start, :838-848). Taken at the next tick, a
    /// second on, a stopped line set again for exactly 10 s ago gave a
    /// record where eperd runs it.
    async fn synchronize_at(&self, crontab: Crontab, now: Now) -> Vec<JoinHandle<()>> {
        let Crontab {
            file,
            lines: crontab_lines,
        } = crontab;
        let count = crontab_lines.len();
        let synced = {
            let mut lines = self.lines.lock().await;
            let mut sync = lines.begin_sync(&file, now);
            for (i, line) in crontab_lines.into_iter().enumerate() {
                if i > 0 && i.is_multiple_of(LINES_PER_YIELD) {
                    tokio::task::yield_now().await;
                }
                lines.insert(&mut sync, line);
            }
            lines.end_sync(sync)
        };
        if synced.added + synced.dropped > 0 {
            info!(
                "Crontab {}: {} lines, {} new, {} kept, {} dropped",
                file, count, synced.added, synced.kept, synced.dropped
            );
        } else {
            debug!("Crontab {}: {} lines, all kept", file, count);
        }
        self.publish_condmv_line().await;
        self.run_due(now).await
    }

    /// Stop a measurement: every line with its id, in every crontab
    pub async fn stop(&self, msm_id: u64) {
        let mut lines = self.lines.lock().await;
        let stopped = lines.stop(msm_id);
        self.publish_counts(&mut lines);
        drop(lines);
        self.publish_condmv_line().await;
        match stopped {
            0 => warn!(msm_id, "Measurement not found"),
            lines => info!(msm_id, lines, "Stopped measurement"),
        }
    }

    /// Tell the results whether crons/7 has a condmv line: with one, they
    /// hold eperd's results until its runs move them, as the reference's
    /// httppost posts only data/out; without one, each post takes all
    /// (ResultSink::set_condmv_line).
    async fn publish_condmv_line(&self) {
        if let Some(results) = &self.results {
            results.set_condmv_line(self.lines.lock().await.has_eperd_condmv());
        }
    }

    /// Run a job on a task of its own, and report its result. A run holds
    /// its own copy of the job, so it finishes and reports whatever becomes
    /// of its line meanwhile, as a busy eperd line is kept until its test is
    /// done (DeleteFile, eperd.c:875-883). Nothing waits for it: a one-off is
    /// eooqd's, a daemon of its own beside eperd (bin/ripe-atlas.in:130-137),
    /// and eperd's tests are events on its loop, none of which holds up a
    /// line's timer.
    ///
    /// A line's run starts at its offset's microseconds (`start`): it
    /// sleeps them first, on its own task, as libevent fires each eperd
    /// timer at its own moment (task::Start). A one-off starts at once. A
    /// line that goes while its run sleeps — a push leaves it out, a STOP
    /// takes it — does not start it (task::LineGone).
    fn spawn_run(
        &self,
        job: MeasurementJob,
        start: Option<(task::Start, task::LineGone)>,
    ) -> JoinHandle<()> {
        let results = self.results.clone();
        let metrics = self.metrics.clone();
        let probe_id = self.probe_id;
        tokio::spawn(async move {
            let measurement = match job.to_measurement(probe_id) {
                Ok(measurement) => measurement,
                Err(e) => {
                    error!(msm_id = job.msm_id, "Failed to create measurement: {}", e);
                    return;
                }
            };
            if let Some((start, gone)) = start {
                let wait = start.wait(task::wall_now());
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                }
                if gone.is_set() {
                    debug!(
                        msm_id = job.msm_id,
                        "Line gone before its run started: not run"
                    );
                    return;
                }
            }
            let start_time = std::time::Instant::now();
            let msm_type = measurement.measurement_type().to_string();
            match measurement.execute().await {
                Ok(result) => {
                    let duration = start_time.elapsed().as_secs_f64();
                    debug!(msm_id = result.msm_id.0, "Measurement completed");
                    metrics.record_measurement_completed(&msm_type, duration);
                    match results {
                        Some(results) => results.submit(result),
                        None => warn!("No result handler configured!"),
                    }
                }
                Err(e) => {
                    let duration = start_time.elapsed().as_secs_f64();
                    error!(msm_id = job.msm_id, "Measurement failed: {}", e);
                    metrics.record_measurement_failed(&msm_type, duration);
                }
            }
        })
    }

    /// Run the scheduler loop
    pub async fn run(&self) {
        info!("Scheduler started");

        // Take the receiver out of the Option
        let mut cmd_rx = {
            let mut guard = self.cmd_rx.lock().await;
            guard.take()
        };

        // Track if the command channel is closed
        let mut channel_closed = false;

        // The tick comes just after each second of the wall clock begins,
        // and a line's run then sleeps its offset's microseconds
        // (spawn_run): runs due in one second start spread over it, as
        // eperd's timers fire. An interval ticked wherever in the second
        // the scheduler happened to start.
        let tick = tokio::time::sleep(task::until_next_tick(task::wall_now()));
        tokio::pin!(tick);

        loop {
            tokio::select! {
                // Check for cancellation
                _ = self.cancel_token.cancelled() => {
                    info!("Scheduler received cancellation signal, stopping");
                    break;
                }

                // Process incoming commands (only if channel is open)
                cmd = async {
                    if channel_closed {
                        // Channel is closed, just wait forever (let other select branches run)
                        std::future::pending().await
                    } else {
                        match cmd_rx.as_mut() {
                            Some(rx) => rx.recv().await,
                            None => std::future::pending().await,
                        }
                    }
                } => {
                    match cmd {
                        Some(SchedulerCommand::Schedule(job)) => {
                            if let Err(e) = self.schedule(job).await {
                                error!("Failed to schedule job: {}", e);
                            }
                        }
                        Some(SchedulerCommand::Crontab(crontab)) => {
                            self.synchronize(crontab).await;
                        }
                        Some(SchedulerCommand::Stop(msm_id)) => {
                            self.stop(msm_id).await;
                        }
                        Some(SchedulerCommand::ExecuteNow(job)) => {
                            // Run beside the lines: awaited here, a one-off
                            // held up every tick until it was done (spawn_run)
                            self.spawn_run(job, None);
                        }
                        None => {
                            // Channel closed - this can happen during shutdown
                            // Continue running scheduled tasks, but don't accept new commands
                            warn!("Command channel closed, scheduler will continue running scheduled tasks");
                            channel_closed = true;
                        }
                    }
                }

                // Check for due tasks
                () = &mut tick => {
                    self.check_due_tasks().await;

                    // Update metrics
                    let count = self.lines.lock().await.len() as i64;
                    self.metrics.update_scheduler_tasks(count);

                    let next = task::until_next_tick(task::wall_now());
                    tick.as_mut().reset(tokio::time::Instant::now() + next);
                }
            }
        }

        info!("Scheduler stopped");
    }

    /// Check and execute due tasks. `now` is the wall clock when the tick is
    /// taken, not when it was due, as RunJob reads it when its timer fires
    /// (gettimeofday, eperd.c:1264): a tick held up past a line's time by
    /// more than 10 s — the host suspended, the runtime stalled — finds that
    /// line's time inconsistent. A pause holds the ticks up the same way
    /// (run_due). The monotonic clock read with it is what the lines' waits
    /// run out on, as libevent's timeouts (ScheduledTask::is_due).
    async fn check_due_tasks(&self) {
        self.run_due(Now::read()).await;
    }

    /// Start the runs due at `now`, each on a task of its own (spawn_run),
    /// and queue the records of the lines found more than 10 s off their
    /// time. RunJob appends those to eperd's out file, data/new/7
    /// (eperd.c:1270-1303), the spool of the lines' own results; a condmv
    /// line's run appends its 9907 marker after them and moves the file
    /// out, for the next main upload.
    ///
    /// While the tray pauses the probe, nothing runs and nothing is
    /// recorded, whatever comes due: a tick, a crontab's push, a job of
    /// Starla's own (synchronize_at, schedule_at). A push still sets the
    /// lines, and its timers wait with the others. Once the pause ends,
    /// each line whose time passed meanwhile, by more than 10 s, gives one
    /// record and waits for its next slot, as after a suspend. Only the
    /// tick consulted the pause: a push during one ran the lines it set
    /// for a time past and queued their records.
    async fn run_due(&self, now: Now) -> Vec<JoinHandle<()>> {
        let mut lines = self.lines.lock().await;
        if self.pause.on() {
            self.publish_counts(&mut lines);
            return Vec::new();
        }
        // Collect due jobs first (to avoid holding lock during execution)
        let Due {
            jobs,
            starts,
            gone,
            inconsistent,
            condmvs,
        } = lines.take_due(now);
        self.publish_counts(&mut lines);
        drop(lines);
        if !inconsistent.is_empty() {
            warn!(
                lines = inconsistent.len(),
                "Lines more than 10 s off their time: not run, their next cycles drawn"
            );
            if let Some(results) = &self.results {
                for record in inconsistent {
                    results.submit(self.inconsistent_result(now.wall, record));
                }
            }
        }
        // eperd's condmv: its marker goes to data/new/7 after the results
        // taken before it, at time(NULL) of its run, and the file moves to
        // data/out/7.<minute> for the next post (condmv_start,
        // eperd/condmv.c:115-136). Results taken after it wait for its next
        // run.
        if let Some(results) = &self.results {
            for condmv in &condmvs {
                let marker = condmv.marker(now.wall);
                results.condmv(marker.map(|m| self.spool_line(now.wall, m)));
            }
        }
        jobs.into_iter()
            .zip(starts.into_iter().zip(gone))
            .map(|(job, start)| {
                debug!(msm_id = job.msm_id, "Executing scheduled measurement");
                self.spawn_run(job, Some(start))
            })
            .collect()
    }

    /// A spool line of eperd's own (condmv's marker) as the results queue
    /// takes a result: written as it is, under eperd's id.
    fn spool_line(&self, now: i64, line: String) -> MeasurementResult {
        MeasurementResult {
            data: MeasurementData::Line(line),
            ..self.inconsistent_result(
                now,
                InconsistentRecord {
                    body: String::new(),
                },
            )
        }
    }

    /// A line's "inconsistent time" record as the results queue takes a
    /// result: its whole line's body, under eperd's id. The record is
    /// eperd's own and of no measurement (a condmv line's measures
    /// nothing): the type is the envelope's, which a FullLine does not
    /// write (AtlasResult::to_result_line), and any gives the same line.
    fn inconsistent_result(&self, now: i64, record: InconsistentRecord) -> MeasurementResult {
        MeasurementResult {
            fw: starla_common::FIRMWARE_VERSION,
            measurement_type: starla_common::MeasurementType::Ping,
            prb_id: self.probe_id,
            msm_id: MeasurementId(task::EPERD_ID),
            timestamp: Timestamp(now),
            af: 0,
            dst_addr: std::net::Ipv4Addr::UNSPECIFIED.into(),
            dst_name: None,
            src_addr: None,
            proto: None,
            ttl: None,
            size: None,
            data: MeasurementData::FullLine(record.body),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::at;
    use starla_results::{ResultHandlerConfig, UploadStream, UploadTransport, UploaderConfig};

    struct NoTransport;
    impl UploadTransport for NoTransport {
        fn open(
            &self,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = anyhow::Result<Box<dyn UploadStream>>> + Send + '_,
            >,
        > {
            Box::pin(async { anyhow::bail!("no transport") })
        }
    }

    /// Probe 1018212's scheduler, its results queued in `handler`, and the
    /// switch that pauses it: a test never reads the host's tray pause.
    fn scheduler_for(
        handler: &Arc<ResultHandler>,
        metrics: starla_metrics::MetricsRegistry,
    ) -> (Scheduler, PauseSwitch) {
        let mut scheduler = Scheduler::new(ProbeId(1018212), metrics);
        scheduler.set_result_handler(handler.clone());
        let paused = PauseSwitch::default();
        scheduler.pause = Pause::Switch(paused.clone());
        (scheduler, paused)
    }

    fn no_transport(metrics: &starla_metrics::MetricsRegistry) -> Arc<ResultHandler> {
        Arc::new(ResultHandler::new(
            Box::new(NoTransport),
            UploaderConfig::default(),
            ResultHandlerConfig::default(),
            metrics.clone(),
        ))
    }

    /// An evtdig line to a server that never answers: its run is under way
    /// for its whole timeout, then reports the timeout.
    async fn slow_dns_line(server: &tokio::net::UdpSocket) -> CrontabLine {
        CrontabLine {
            command: "evtdig -4 --timeout 3000 -A \"5009\" 127.0.0.1".into(),
            job: MeasurementJob {
                msm_id: 5009,
                interval: 60,
                start_time: 7,
                end_time: 2_000_000_000,
                spread: 0,
                spec: MeasurementSpec::Dns(DnsJobSpec {
                    server: "127.0.0.1".into(),
                    port: server.local_addr().unwrap().port(),
                    query: "example.com.".into(),
                    timeout_ms: 3000,
                    disable_check_addr: true,
                    ..Default::default()
                }),
            },
        }
    }

    /// The runs a tick takes start spread over its second, each at its
    /// offset's microseconds, and none in another second: lines' runs, each
    /// to a server of its own, taken as a second of the wall clock begins
    /// (the tick's 2 ms in), reach their servers at those microseconds, as
    /// eperd's timers fire (set_timeout's tv_usec, eperd.c:758-762).
    /// Starla started every run a tick took in that tick's millisecond.
    #[tokio::test]
    async fn the_runs_a_tick_takes_start_at_their_microseconds_in_its_second() {
        let metrics = starla_metrics::MetricsRegistry::new().unwrap();
        let handler = no_transport(&metrics);
        let (scheduler, _) = scheduler_for(&handler, metrics);
        let usecs = [100_000, 250_000, 400_000, 550_000, 700_000, 850_000];
        let mut servers = Vec::new();
        for _ in usecs {
            servers.push(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        }
        tokio::time::sleep(task::until_next_tick(task::wall_now())).await;
        let second = task::wall_now().as_secs();
        let mut runs = Vec::new();
        for (server, usec) in servers.iter().zip(usecs) {
            let job = slow_dns_line(server).await.job;
            let start = task::Start {
                second: second as i64,
                usec,
            };
            runs.push(scheduler.spawn_run(job, Some((start, task::LineGone::default()))));
        }
        for (server, usec) in servers.iter().zip(usecs) {
            let mut query = [0u8; 512];
            server.recv(&mut query).await.unwrap();
            let came = task::wall_now();
            let due = Duration::from_secs(second) + Duration::from_micros(usec.into());
            assert_eq!(came.as_secs(), second, "{usec} µs: in another second");
            assert!(
                came + Duration::from_millis(1) >= due && came < due + Duration::from_millis(100),
                "{usec} µs: came {:?} in",
                came - Duration::from_secs(second)
            );
        }
        runs.into_iter().for_each(|run| run.abort());
    }

    /// A run taken at the tick whose line goes while it sleeps to its
    /// microseconds does not start, as eperd's line goes with its timer
    /// unfired (eperd.c:875-883, 1258-1262); a run beside it, whose line
    /// stays, starts at its microseconds.
    #[tokio::test]
    async fn a_run_whose_line_goes_before_its_microseconds_does_not_start() {
        let metrics = starla_metrics::MetricsRegistry::new().unwrap();
        let handler = no_transport(&metrics);
        let (scheduler, _) = scheduler_for(&handler, metrics);
        let kept = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dropped = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        tokio::time::sleep(task::until_next_tick(task::wall_now())).await;
        let start = task::Start {
            second: task::wall_now().as_secs() as i64,
            usec: 500_000,
        };
        let (stays, goes) = (task::LineGone::default(), task::LineGone::default());
        let runs = [
            scheduler.spawn_run(slow_dns_line(&kept).await.job, Some((start, stays))),
            scheduler.spawn_run(
                slow_dns_line(&dropped).await.job,
                Some((start, goes.clone())),
            ),
        ];
        // A push leaves the line out, in the run's second, before its
        // microseconds
        goes.set();

        let mut query = [0u8; 512];
        tokio::time::timeout(Duration::from_secs(2), kept.recv(&mut query))
            .await
            .expect("the kept line's run starts")
            .unwrap();
        let none = tokio::time::timeout(Duration::from_millis(1_500), dropped.recv(&mut query));
        assert!(none.await.is_err(), "the gone line's run started");
        runs.into_iter().for_each(|run| run.abort());
    }

    /// A line the next crontab drops while its run is under way stops, and
    /// that run still reports: DeleteFile keeps a busy line until its test
    /// is done, and RunJob starts it no more (eperd.c:875-883, 1258-1262).
    #[tokio::test]
    async fn a_dropped_lines_run_under_way_still_reports() {
        let metrics = starla_metrics::MetricsRegistry::new().unwrap();
        let handler = Arc::new(ResultHandler::new(
            Box::new(NoTransport),
            UploaderConfig::default(),
            ResultHandlerConfig::default(),
            metrics.clone(),
        ));
        let (scheduler, _) = scheduler_for(&handler, metrics);

        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let line = slow_dns_line(&server).await;
        let file = "/var/spool/ripe-atlas/crons/7".to_string();
        let slot = 1_791_836_407; // 7 + k * 60
        scheduler
            .synchronize_at(
                Crontab {
                    file: file.clone(),
                    lines: vec![line],
                },
                at(slot - 30),
            )
            .await;
        assert!(scheduler.run_due(at(slot - 1)).await.is_empty());
        let runs = scheduler.run_due(at(slot)).await;
        assert_eq!(runs.len(), 1);

        // The query is out, the run waiting for its answer: the crontab
        // comes again without the line
        let mut query = [0u8; 512];
        server.recv(&mut query).await.unwrap();
        scheduler
            .synchronize_at(
                Crontab {
                    file,
                    lines: Vec::new(),
                },
                at(slot + 1),
            )
            .await;
        assert!(scheduler
            .status_handle()
            .measurement_counts()
            .await
            .is_empty());
        assert_eq!(handler.queue_stats().await.count, 0);

        for run in runs {
            run.await.unwrap();
        }
        assert_eq!(handler.queue_stats().await.count, 1, "the run reported");
        // and the line runs no more
        for now in slot + 1..slot + 600 {
            assert!(scheduler.run_due(at(now)).await.is_empty(), "{now}");
        }
    }

    /// A crontab that sets a line's timer for a time already past fires it
    /// in the same second, as libevent runs a timer set with set_timeout's
    /// wait of 0 in its loop's next pass (eperd.c:764-765): a line stopped
    /// at its old end time and sent again with a later one, 10 s after the
    /// time it stopped at, runs, as RunJob runs a line within 10 s of its
    /// time (eperd.c:1268); 11 s after, it gives its record. Taken at the
    /// next tick, a second on, the 10 s line gave the record.
    #[tokio::test]
    async fn a_push_fires_the_timers_it_sets_for_a_time_past_in_its_second() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let file = "/var/spool/ripe-atlas/crons/7".to_string();
        let slot = 1_791_836_407; // 7 + k * 60
        for (late, runs) in [(10, true), (11, false)] {
            let metrics = starla_metrics::MetricsRegistry::new().unwrap();
            let handler = Arc::new(ResultHandler::new(
                Box::new(NoTransport),
                UploaderConfig::default(),
                ResultHandlerConfig::default(),
                metrics.clone(),
            ));
            let (scheduler, _) = scheduler_for(&handler, metrics);
            // It runs at its slot, and stops at the next, past its end time
            let mut line = slow_dns_line(&server).await;
            line.job.end_time = slot + 30;
            let pushed = scheduler
                .synchronize_at(
                    Crontab {
                        file: file.clone(),
                        lines: vec![line.clone()],
                    },
                    at(slot - 30),
                )
                .await;
            assert!(pushed.is_empty());
            let ran = scheduler.run_due(at(slot)).await;
            assert_eq!(ran.len(), 1);
            ran.into_iter().for_each(|run| run.abort());
            assert!(scheduler.run_due(at(slot + 60)).await.is_empty());

            // sent again, with a later end time
            line.job.end_time = 2_000_000_000;
            let pushed = scheduler
                .synchronize_at(
                    Crontab {
                        file: file.clone(),
                        lines: vec![line],
                    },
                    at(slot + 60 + late),
                )
                .await;
            assert_eq!(pushed.len(), usize::from(runs), "sent {late} s late");
            pushed.into_iter().for_each(|run| run.abort());
            assert_eq!(
                handler.queue_stats().await.count,
                usize::from(!runs),
                "sent {late} s late"
            );
            // and nothing more in that second, or until its next slot
            for now in slot + 60 + late..slot + 120 {
                assert!(scheduler.run_due(at(now)).await.is_empty(), "{now}");
            }
            assert_eq!(scheduler.run_due(at(slot + 120)).await.len(), 1);
        }
    }

    /// While the tray pauses the probe, a push runs nothing and records
    /// nothing, as the tick does not: the line of the test above, stopped
    /// at its end time and sent again 10 s after its time (which the push
    /// runs, unpaused) or 11 s after (whose record it queues) waits with
    /// the pause. The push still sets the line. When the pause ends, the
    /// first tick finds it more than 10 s off its time: one record, and
    /// then its next slot. Only the tick consulted the pause, and the push
    /// ran the line or queued its record.
    #[tokio::test]
    async fn a_push_during_a_pause_runs_and_records_nothing() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let file = "/var/spool/ripe-atlas/crons/7".to_string();
        let slot = 1_791_836_407; // 7 + k * 60
        for late in [10, 11] {
            let metrics = starla_metrics::MetricsRegistry::new().unwrap();
            let handler = no_transport(&metrics);
            let (scheduler, paused) = scheduler_for(&handler, metrics);
            let mut line = slow_dns_line(&server).await;
            line.job.end_time = slot + 30;
            scheduler
                .synchronize_at(
                    Crontab {
                        file: file.clone(),
                        lines: vec![line.clone()],
                    },
                    at(slot - 30),
                )
                .await;
            let ran = scheduler.run_due(at(slot)).await;
            assert_eq!(ran.len(), 1);
            ran.into_iter().for_each(|run| run.abort());
            assert!(scheduler.run_due(at(slot + 60)).await.is_empty());

            // paused, the line is sent again with a later end time
            paused.set(true);
            line.job.end_time = 2_000_000_000;
            let pushed = scheduler
                .synchronize_at(
                    Crontab {
                        file: file.clone(),
                        lines: vec![line],
                    },
                    at(slot + 60 + late),
                )
                .await;
            assert!(pushed.is_empty(), "sent {late} s late");
            assert_eq!(
                scheduler.status_handle().measurement_counts().await["dns"],
                1
            );
            for now in slot + 60 + late..slot + 100 {
                assert!(scheduler.run_due(at(now)).await.is_empty(), "{now}");
            }
            assert_eq!(handler.queue_stats().await.count, 0, "sent {late} s late");

            // the pause ends
            paused.set(false);
            assert!(scheduler.run_due(at(slot + 100)).await.is_empty());
            assert_eq!(handler.queue_stats().await.count, 1, "sent {late} s late");
            for now in slot + 101..slot + 120 {
                assert!(scheduler.run_due(at(now)).await.is_empty(), "{now}");
            }
            let ran = scheduler.run_due(at(slot + 120)).await;
            assert_eq!(ran.len(), 1);
            ran.into_iter().for_each(|run| run.abort());
            assert_eq!(handler.queue_stats().await.count, 1);
        }
    }

    /// A job of Starla's own scheduled during a pause runs nothing, though
    /// its first time is already past, and runs once the pause ends.
    /// Thirty-two jobs on a 1 s interval with a spread of 20 s: each draws
    /// its first time within the 10 s before now with a chance of 10 in
    /// 21, so some are due at once (all but 0.524^32 of the time, 1e-9).
    /// Only the tick consulted the pause, and scheduling one ran it.
    #[tokio::test]
    async fn a_job_scheduled_during_a_pause_runs_nothing() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let metrics = starla_metrics::MetricsRegistry::new().unwrap();
        let handler = no_transport(&metrics);
        let (scheduler, paused) = scheduler_for(&handler, metrics);
        let now = 1_791_836_407;
        paused.set(true);
        for msm_id in 0..32 {
            let mut job = slow_dns_line(&server).await.job;
            job.msm_id = 1_000_000 + msm_id;
            job.interval = 1;
            job.spread = 20;
            let ran = scheduler.schedule_at(job, at(now)).await;
            assert!(ran.is_empty(), "{msm_id}");
        }
        assert!(scheduler.run_due(at(now)).await.is_empty());

        paused.set(false);
        let ran = scheduler.run_due(at(now)).await;
        assert!(!ran.is_empty(), "none of them due");
        ran.into_iter().for_each(|run| run.abort());
        assert_eq!(handler.queue_stats().await.count, 0, "no record");
    }

    /// A one-off under way holds up nothing: eooqd runs it beside eperd
    /// (bin/ripe-atlas.in:130-137). The scheduler loop awaited it, and every
    /// command and tick waited until it was done, so a line due meanwhile ran
    /// as late as the one-off was long — a traceroute, minutes.
    #[tokio::test]
    async fn a_one_off_under_way_holds_up_no_tick() {
        let metrics = starla_metrics::MetricsRegistry::new().unwrap();
        let handler = Arc::new(ResultHandler::new(
            Box::new(NoTransport),
            UploaderConfig::default(),
            ResultHandlerConfig::default(),
            metrics.clone(),
        ));
        let (scheduler, _) = scheduler_for(&handler, metrics);
        let scheduler = Arc::new(scheduler);
        let commands = scheduler.command_sender();
        let status = scheduler.status_handle();
        let looping = tokio::spawn({
            let scheduler = scheduler.clone();
            async move { scheduler.run().await }
        });

        // A one-off whose server never answers: under way for its 3 s
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let line = slow_dns_line(&server).await;
        let mut oneoff = line.job.clone();
        oneoff.interval = 0;
        commands
            .send(SchedulerCommand::ExecuteNow(oneoff))
            .await
            .unwrap();
        let mut query = [0u8; 512];
        server.recv(&mut query).await.unwrap();

        // A crontab sent meanwhile is taken at once, not 3 s on
        commands
            .send(SchedulerCommand::Crontab(Crontab {
                file: "/var/spool/ripe-atlas/crons/7".into(),
                lines: vec![line],
            }))
            .await
            .unwrap();
        let taken = tokio::time::timeout(Duration::from_secs(1), async {
            while status.measurement_counts().await.is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(taken.is_ok(), "the loop waited for the one-off to finish");
        assert_eq!(handler.queue_stats().await.count, 0, "still under way");

        // and the one-off still reports
        tokio::time::timeout(Duration::from_secs(10), async {
            while handler.queue_stats().await.count == 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the one-off reported");
        scheduler.cancel_token().cancel();
        looping.await.unwrap();
    }

    /// `n` evping lines of crons/7, none due for a while.
    fn ping_crontab(n: u64, now: i64) -> Crontab {
        Crontab {
            file: "/var/spool/ripe-atlas/crons/7".into(),
            lines: (0..n)
                .map(|i| CrontabLine {
                    command: format!(
                        "evping -4 -c 3 -A \"{}\" -O /home/atlas/data/new/7 192.0.2.{}",
                        2_000_000 + i,
                        i % 250
                    ),
                    job: MeasurementJob {
                        msm_id: 2_000_000 + i,
                        interval: 240,
                        start_time: now + 1_000 + i as i64,
                        end_time: 2_000_000_000,
                        spread: 0,
                        spec: MeasurementSpec::Ping(PingJobSpec {
                            target: format!("192.0.2.{}", i % 250),
                            af: 4,
                            packets: 3,
                            packet_interval: 1000,
                            size: 0,
                            bundle: None,
                            kept: Default::default(),
                        }),
                    },
                })
                .collect(),
        }
    }

    /// The controller's crontabs come as one push of ~800 lines. Taken in
    /// one stretch, a push held a measurement worker for ~0.5 ms (release
    /// build); the scheduler now yields every 64 lines, and a task on the
    /// same worker runs between the slices. On a current-thread runtime,
    /// the other task runs only when the push yields.
    #[tokio::test]
    async fn a_crontab_is_taken_a_slice_at_a_time() {
        let metrics = starla_metrics::MetricsRegistry::new().unwrap();
        let handler = no_transport(&metrics);
        let (scheduler, _) = scheduler_for(&handler, metrics);
        let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let other = tokio::spawn({
            let polls = polls.clone();
            async move {
                loop {
                    polls.fetch_add(1, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                }
            }
        });
        tokio::task::yield_now().await;

        let now = 1_791_836_407;
        let before = polls.load(Ordering::SeqCst);
        let ran = scheduler
            .synchronize_at(ping_crontab(800, now), at(now))
            .await;
        let between = polls.load(Ordering::SeqCst) - before;
        other.abort();

        assert!(ran.is_empty());
        assert!(between >= 800 / LINES_PER_YIELD - 1, "{between} slices");
        assert_eq!(
            scheduler.status_handle().measurement_counts().await["ping"],
            800
        );
        // and a push that repeats it keeps every line
        scheduler
            .synchronize_at(ping_crontab(800, now), at(now + 1))
            .await;
        assert_eq!(
            scheduler.status_handle().measurement_counts().await["ping"],
            800
        );
    }

    /// The status's reader is on the background runtime. It used to read
    /// the lines under the lock the tick takes; now the scheduler hands it
    /// the counts, and a reader that holds them (the background thread
    /// preempted mid-read) never holds up a push or a tick: they are handed
    /// over at the next tick instead.
    #[tokio::test]
    async fn a_status_reader_never_holds_up_the_scheduler() {
        let metrics = starla_metrics::MetricsRegistry::new().unwrap();
        let handler = no_transport(&metrics);
        let (scheduler, _) = scheduler_for(&handler, metrics);
        let status = scheduler.status_handle();
        let now = 1_791_836_407;

        // A reader on another thread holds the counts until told
        let (release, released) = std::sync::mpsc::channel::<()>();
        let (holding, held) = std::sync::mpsc::channel();
        let reader = std::thread::spawn({
            let status = status.clone();
            move || {
                let reading = status.counts.lock().unwrap();
                holding.send(()).unwrap();
                released.recv().unwrap();
                reading.is_empty()
            }
        });
        held.recv().unwrap();
        let pushed = tokio::time::timeout(
            Duration::from_secs(5),
            scheduler.synchronize_at(ping_crontab(3, now), at(now)),
        )
        .await;
        assert!(pushed.is_ok(), "the push waited for the reader");
        release.send(()).unwrap();
        assert!(reader.join().unwrap(), "handed over while read");

        assert!(scheduler.run_due(at(now + 1)).await.is_empty());
        assert_eq!(status.measurement_counts().await["ping"], 3);
    }

    /// A controller that answers every POST 200 and hands over each body.
    struct Controller(tokio::sync::mpsc::UnboundedSender<String>);

    impl UploadTransport for Controller {
        fn open(
            &self,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = anyhow::Result<Box<dyn UploadStream>>> + Send + '_,
            >,
        > {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (probe, mut ctrl) = tokio::io::duplex(1 << 20);
            let bodies = self.0.clone();
            tokio::spawn(async move {
                let mut req = Vec::new();
                let mut buf = [0u8; 8192];
                let body = loop {
                    let n = ctrl.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    req.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&req).into_owned();
                    let Some(head) = text.find("\r\n\r\n") else {
                        continue;
                    };
                    let len: usize = text
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    if text.len() >= head + 4 + len {
                        break text[head + 4..].to_string();
                    }
                };
                let _ = bodies.send(body);
                let _ = ctrl
                    .write_all(b"HTTP/1.1 200 \r\nContent-Length: 3\r\n\r\nOK\n")
                    .await;
                let _ = ctrl.shutdown().await;
            });
            Box::pin(async move { Ok(Box::new(probe) as Box<dyn UploadStream>) })
        }
    }

    /// A line found more than 10 s late runs nothing, and its record is
    /// queued as eperd appends it to data/new/7: it goes with the next main
    /// upload, among the lines' results. With no condmv line in crons/7, as
    /// here, nothing holds it back, and nothing writes a 9907 marker: only
    /// that line's runs do.
    #[tokio::test]
    async fn a_late_lines_record_goes_with_the_next_upload() {
        let (bodies, mut posted) = tokio::sync::mpsc::unbounded_channel();
        let metrics = starla_metrics::MetricsRegistry::new().unwrap();
        let handler = Arc::new(ResultHandler::new(
            Box::new(Controller(bodies)),
            UploaderConfig::default(),
            ResultHandlerConfig::default(),
            metrics.clone(),
        ));
        handler
            .set_endpoint_path("/?PROBE_ID=1018212&SESSION_ID=s".into())
            .await
            .unwrap();
        handler.set_session_id("s".into()).await;
        let (scheduler, _) = scheduler_for(&handler, metrics);

        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let slot = 1_791_836_407; // 7 + 29863940 * 60
        scheduler
            .synchronize_at(
                Crontab {
                    file: "/var/spool/ripe-atlas/crons/7".into(),
                    lines: vec![slow_dns_line(&server).await],
                },
                at(slot - 30),
            )
            .await;
        assert!(scheduler.run_due(at(slot + 11)).await.is_empty(), "not run");
        assert_eq!(handler.queue_stats().await.count, 1);

        handler.upload_pending().await.unwrap();
        let body = posted.recv().await.unwrap();
        let (record, rest) = body
            .strip_prefix("P_TO_C_REPORT\n")
            .unwrap()
            .split_once('\n')
            .unwrap();
        assert_eq!(
            record,
            "RESULT { \"id\":\"9807\", \"fw\":5130, \"mver\": \"2.6.4\", \"time\":1791836418, \
             \"reason\": \"inconsistent time; now 1791836418; nexttime 1791836407; waittime 30; \
             cycle 29863940; generated 1791836377\", \"cmd\": \"evtdig -4 --timeout 3000 -A \
             \\\"5009\\\" 127.0.0.1\" }"
        );
        assert_eq!(rest, "\nSESSION_ID s\n", "no marker without a condmv line");
        assert_eq!(handler.queue_stats().await.count, 0);

        // and the line runs at its next slot
        assert!(scheduler.run_due(at(slot + 59)).await.is_empty());
        assert_eq!(scheduler.run_due(at(slot + 60)).await.len(), 1);
    }

    /// crons/7's condmv line, as ctr-dub-sw02 sent it on 2026-10-13 (spread
    /// 0 here, for its time): each run appends eperd's marker to data/new/7
    /// — time(NULL) of the run and the file rebased, as condmv_start writes
    /// them (eperd/condmv.c:128-130) — after the results taken before it,
    /// and the next main upload takes it with them. Nothing measures.
    #[tokio::test]
    async fn crons_7s_condmv_run_appends_eperds_marker() {
        let (bodies, mut posted) = tokio::sync::mpsc::unbounded_channel();
        let metrics = starla_metrics::MetricsRegistry::new().unwrap();
        let handler = Arc::new(ResultHandler::new(
            Box::new(Controller(bodies)),
            UploaderConfig::default(),
            ResultHandlerConfig::default(),
            metrics.clone(),
        ));
        handler
            .set_endpoint_path("/?PROBE_ID=1018212&SESSION_ID=s".into())
            .await
            .unwrap();
        handler.set_session_id("s".into()).await;
        let (scheduler, _) = scheduler_for(&handler, metrics);

        let crons_7 = |lines| Crontab {
            file: "/var/spool/ripe-atlas/crons/7".into(),
            lines,
        };
        let slot = 1_791_836_401; // 1 + 29863940 * 60
        scheduler
            .synchronize_at(
                crons_7(vec![condmv_line(Some("RESULT 9907 ongoing"))]),
                at(slot - 30),
            )
            .await;
        assert!(
            scheduler.run_due(at(slot)).await.is_empty(),
            "starts nothing"
        );
        assert!(scheduler.run_due(at(slot + 60)).await.is_empty());
        assert_eq!(handler.queue_stats().await.count, 2);

        handler.upload_pending().await.unwrap();
        assert_eq!(
            posted.recv().await.unwrap(),
            "P_TO_C_REPORT\n\
             RESULT 9907 ongoing 1791836401 /var/spool/ripe-atlas/data/new/7\n\
             RESULT 9907 ongoing 1791836461 /var/spool/ripe-atlas/data/new/7\n\
             \nSESSION_ID s\n"
        );

        // Without -A, condmv moves the file and appends nothing
        scheduler
            .synchronize_at(crons_7(vec![condmv_line(None)]), at(slot + 90))
            .await;
        assert!(scheduler.run_due(at(slot + 120)).await.is_empty());
        assert_eq!(handler.queue_stats().await.count, 0);
    }

    /// crons/7's condmv line as ctr-dub-sw02 sent it on 2026-10-13, with
    /// spread 0: it runs at second 1 of each minute.
    fn condmv_line(append: Option<&str>) -> CrontabLine {
        CrontabLine {
            command: format!(
                "condmv {}/home/atlas/data/new/7 /home/atlas/data/out/7",
                append.map_or(String::new(), |a| format!("-A \"{a}\" "))
            ),
            job: MeasurementJob {
                msm_id: 0,
                interval: 60,
                start_time: 1,
                end_time: 2_000_000_000,
                spread: 0,
                spec: MeasurementSpec::Condmv(CondmvJobSpec {
                    append: append.map(str::to_string),
                    from: "/var/spool/ripe-atlas/data/new/7".into(),
                }),
            },
        }
    }

    /// A post's lines between header and footer, each as what it is: a
    /// 9807 record, or a 9907 marker with its time after `base`.
    fn post_lines(body: &str, base: i64) -> Vec<String> {
        let lines = body
            .strip_prefix("P_TO_C_REPORT\n")
            .and_then(|b| b.strip_suffix("\nSESSION_ID s\n"))
            .unwrap_or_else(|| panic!("framing: {body}"));
        lines
            .lines()
            .map(|line| {
                if line.contains("\"id\":\"9807\"") {
                    "9807".to_string()
                } else if let Some(rest) = line.strip_prefix("RESULT 9907 ongoing ") {
                    let (time, from) = rest.split_once(' ').unwrap();
                    assert_eq!(from, "/var/spool/ripe-atlas/data/new/7");
                    format!("9907 +{}", time.parse::<i64>().unwrap() - base)
                } else {
                    panic!("unexpected line: {line}")
                }
            })
            .collect()
    }

    /// eperd appends its results to data/new/7, and only crons/7's condmv
    /// moves that file to data/out, the marker last; httppost posts
    /// data/out. So a post carries eperd's results up to a 9907 marker and
    /// never past it: one appended after condmv's last run waits for its
    /// next. In the twin of 2026-10-15 Starla posted results past the last
    /// 9907 in 7 of its 10 main posts, and the reference in none. With no
    /// condmv line in crons/7 nothing holds them: the reference would never
    /// post them, and a line Starla refused would look the same.
    #[tokio::test]
    async fn eperds_results_wait_for_crons_7s_next_condmv_run() {
        let (bodies, mut posted) = tokio::sync::mpsc::unbounded_channel();
        let metrics = starla_metrics::MetricsRegistry::new().unwrap();
        let handler = Arc::new(ResultHandler::new(
            Box::new(Controller(bodies)),
            UploaderConfig::default(),
            ResultHandlerConfig::default(),
            metrics.clone(),
        ));
        handler
            .set_endpoint_path("/?PROBE_ID=1018212&SESSION_ID=s".into())
            .await
            .unwrap();
        handler.set_session_id("s".into()).await;
        let (scheduler, _) = scheduler_for(&handler, metrics);
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let crons_7 = |lines| Crontab {
            file: "/var/spool/ripe-atlas/crons/7".into(),
            lines,
        };
        // condmv at second 1 of each minute, the DNS line at second 7
        let base = 1_791_836_400; // 29863940 * 60
        let dns = slow_dns_line(&server).await;
        let ripe_7 = vec![dns.clone(), condmv_line(Some("RESULT 9907 ongoing"))];
        scheduler
            .synchronize_at(crons_7(ripe_7.clone()), at(base - 30))
            .await;

        assert!(scheduler.run_due(at(base + 1)).await.is_empty());
        // 11 s late: its record goes to data/new/7, after condmv's run
        assert!(scheduler.run_due(at(base + 18)).await.is_empty());
        let stats = handler.queue_stats().await;
        assert_eq!((stats.count, stats.held), (2, 1));
        handler.upload_pending().await.unwrap();
        assert_eq!(
            post_lines(&posted.recv().await.unwrap(), base),
            ["9907 +1"],
            "the record waits for the next condmv run"
        );
        assert_eq!(handler.queue_stats().await.held, 1);

        // A post with nothing moved out is the header and footer
        handler.upload_pending().await.unwrap();
        assert!(post_lines(&posted.recv().await.unwrap(), base).is_empty());

        // condmv's next run moves the record, its marker after it
        scheduler
            .synchronize_at(crons_7(ripe_7), at(base + 40))
            .await;
        assert!(scheduler.run_due(at(base + 61)).await.is_empty());
        handler.upload_pending().await.unwrap();
        assert_eq!(
            post_lines(&posted.recv().await.unwrap(), base),
            ["9807", "9907 +61"]
        );

        // Two more minutes: condmv's run moves the first's record, and the
        // second's is still in data/new/7
        assert!(scheduler.run_due(at(base + 78)).await.is_empty());
        assert!(scheduler.run_due(at(base + 121)).await.is_empty());
        assert!(scheduler.run_due(at(base + 138)).await.is_empty());
        let stats = handler.queue_stats().await;
        assert_eq!((stats.count, stats.held), (3, 1));

        // Without the condmv line, nothing holds eperd's results: the next
        // post takes all there is, and no marker follows
        scheduler
            .synchronize_at(crons_7(vec![dns]), at(base + 140))
            .await;
        handler.upload_pending().await.unwrap();
        assert_eq!(
            post_lines(&posted.recv().await.unwrap(), base),
            ["9807", "9907 +121", "9807"]
        );
        assert!(scheduler.run_due(at(base + 198)).await.is_empty());
        handler.upload_pending().await.unwrap();
        assert_eq!(post_lines(&posted.recv().await.unwrap(), base), ["9807"]);
        assert_eq!(handler.queue_stats().await.count, 0);
    }
}
