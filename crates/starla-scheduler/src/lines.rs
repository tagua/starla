//! The recurring lines the scheduler runs, kept as eperd keeps the lines of
//! its crontab (eperd/eperd.c, LineBase).
//!
//! eperd tells one line from another by its interval, start time and
//! command text (cl_Shell), as Insert() compares them (eperd.c:782-836, at
//! 789-791 and 806-808), and never by the measurement id. RIPE's controller
//! sends msm 30002 as 26 lines, each a 30 s window ten minutes after the
//! last, one per `--query`. Keyed by msm id, Starla kept only the last of
//! them: on enodia, 2 results in 12 h of the 78 windows it was sent.
//!
//! A crontab the controller sends is read as SynchronizeFile reads one
//! (eperd.c:513-645): every line of that file is marked to delete
//! (:528-529); a line of the new file that the file already had keeps its
//! cycle, its offset and its test state, takes only the new end_time, and
//! has its timer set again for its time (Insert, :815-827) — so a line that
//! had stopped at its old end time and whose time has passed by more than
//! 10 s gives eperd's "inconsistent time" record at the push and waits
//! for its first slot after now (RunJob, :1268-1310); a new line waits for
//! its first slot after now, with an offset of its own (Start, :838-848,
//! and set_timeout, :736-777); and DeleteFile (:856-895) removes the lines
//! still marked.
//! RIPE's controller sends the whole crontab again on every session (the
//! hourly REREGISTER, each reconnect). Starla made each re-sent line a new
//! one, with a new offset, from the first slot after now, so a line that
//! had run early in its cycle (a negative offset) and was re-sent before
//! that cycle's slot ran in it again: two results for one slot.

use crate::job::{CondmvJobSpec, MeasurementSpec};
use crate::task::{Fired, LineGone, Now, ScheduledTask, Start};
use crate::MeasurementJob;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

/// A crontab file's recurring measurement lines, as the controller last
/// sent the file.
#[derive(Debug)]
pub struct Crontab {
    /// The crontab: the directory its CRONTAB line named, as telnetd
    /// rebases it (`/var/spool/ripe-atlas/crons/7`). Each directory's is a
    /// line set of its own, as each is a cron daemon's of its own: perd's
    /// `crons/main`, eperd's `crons/7` (bin/ripe-atlas.in:126-133; 5130 runs
    /// no eperd on `crons/2`, which RIPE's controller sends with a condmv
    /// line only).
    pub file: String,
    /// Its lines, in the order the file has them
    pub lines: Vec<CrontabLine>,
}

/// eperd's crontab: `eperd -c $CRON_DIR/7 -A 9807 … -O $ATLAS_DATA/new/7`
/// (bin/ripe-atlas.in:130-133), its directory rebased as telnetd rebases a
/// CRONTAB line's onto the spool directory (configure.ac:145).
const EPERD_CRONTAB: &str = "/var/spool/ripe-atlas/crons/7";

/// One line of a crontab, scheduled.
#[derive(Debug, Clone)]
pub struct CrontabLine {
    /// The line's command and arguments, eperd's cl_Shell (everything after
    /// its fifth field): with the job's interval and start time, what makes
    /// it the line it is.
    pub command: String,
    pub job: MeasurementJob,
}

/// Which line a scheduled task is.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum LineKey {
    /// A crontab's line, by eperd's identity within its file
    Crontab {
        /// Shared by every line of the file: a push of 800 lines makes one
        file: Arc<str>,
        interval: u64,
        start_time: i64,
        command: String,
    },
    /// A recurring job scheduled on its own, outside any crontab (Starla's
    /// JSON commands): by its msm id, as Starla has always kept those
    Own(u64),
}

impl LineKey {
    fn in_file(&self, name: &str) -> bool {
        matches!(self, LineKey::Crontab { file, .. } if &**file == name)
    }
}

/// What a crontab did to its file's lines.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Synchronized {
    /// Lines the file already had, kept with their slots
    pub kept: usize,
    /// New lines
    pub added: usize,
    /// Lines the file no longer has, removed
    pub dropped: usize,
}

/// A crontab being taken, a line at a time: what SynchronizeFile has done
/// so far ([`Lines::begin_sync`], [`Lines::insert`], [`Lines::end_sync`]).
pub(crate) struct Synchronizing {
    file: Arc<str>,
    now: Now,
    synced: Synchronized,
}

/// What the lines' timers did at a tick.
#[derive(Debug, Default)]
pub(crate) struct Due {
    /// The jobs to run
    pub jobs: Vec<MeasurementJob>,
    /// Where each job's run starts, in the jobs' order: the second its
    /// line's timer was set for, and the offset's microseconds in it
    pub starts: Vec<Start>,
    /// Each job's line, in the jobs' order: set if the line goes before
    /// the run starts, which then does not ([`LineGone`])
    pub gone: Vec<LineGone>,
    /// The records of the lines found more than 10 s from their time, in
    /// the order their timers were set to fire
    pub inconsistent: Vec<InconsistentRecord>,
    /// The condmv lines that ran: what each appends to data/new/7
    pub condmvs: Vec<CondmvJobSpec>,
}

/// RunJob's "inconsistent time" record of a crontab line (eperd.c:1268-1303)
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InconsistentRecord {
    /// The body of its RESULT line (InconsistentTime::record_body)
    pub body: String,
}

/// The passes of eperd's loop [`Lines::take_due`] makes at most in one
/// second. A pass fires a line again only when its last drew a time at or
/// before now, which needs an offset back past the next slot; a few passes
/// at most, unless the spread is many times the interval. The bound only
/// keeps such a line from holding up the tick: what is left is the next
/// tick's.
const TIMER_PASSES: usize = 64;

/// The recurring lines, every crontab's and Starla's own.
#[derive(Default)]
pub(crate) struct Lines {
    lines: HashMap<LineKey, ScheduledTask>,
    /// Lines were added or removed since the counts were last taken
    /// ([`Lines::take_changed`])
    changed: bool,
}

impl Lines {
    /// A job scheduled on its own replaces the one with its msm id, and
    /// starts afresh: the first slot after `now`. The one replaced has
    /// gone, as a crontab line a push leaves out has: a run of it taken and
    /// still sleeping to its microseconds does not start ([`LineGone`]).
    pub(crate) fn schedule(&mut self, job: MeasurementJob, now: Now) {
        if let Some(old) = self.lines.insert(LineKey::Own(job.msm_id), start(job, now)) {
            old.gone.set();
        }
        self.changed = true;
    }

    /// The file's lines are now the crontab's, as SynchronizeFile then
    /// DeleteFile leave them (eperd.c:513-645, 856-895). The other files'
    /// lines are untouched. All of it at once, for the tests; the scheduler
    /// takes a crontab a slice at a time, between its own yields
    /// (Scheduler::synchronize_at).
    #[cfg(test)]
    pub(crate) fn synchronize(&mut self, crontab: Crontab, now: Now) -> Synchronized {
        let Crontab { file, lines } = crontab;
        let mut sync = self.begin_sync(&file, now);
        for line in lines {
            self.insert(&mut sync, line);
        }
        self.end_sync(sync)
    }

    /// SynchronizeFile's start: every line of the file needs delete
    /// (eperd.c:528-529). A pass over the lines, hashing nothing.
    pub(crate) fn begin_sync(&mut self, file: &str, now: Now) -> Synchronizing {
        for (key, task) in &mut self.lines {
            if key.in_file(file) {
                task.needs_delete = true;
            }
        }
        Synchronizing {
            file: file.into(),
            now,
            synced: Synchronized::default(),
        }
    }

    /// Insert() for one line of the crontab: one lookup, and an insert for
    /// a new line.
    pub(crate) fn insert(&mut self, sync: &mut Synchronizing, line: CrontabLine) {
        let CrontabLine { command, job } = line;
        // condmv is a line of eperd's crontab, crons/7, which eperd arms
        // like any other (MeasurementSpec::Condmv). In crons/main it is
        // perd's, which runs a late line without a record
        // (perd.c:1226-1248); crons/2 no daemon reads.
        if !job.spec.measures() && &*sync.file != EPERD_CRONTAB {
            return;
        }
        let key = LineKey::Crontab {
            file: Arc::clone(&sync.file),
            interval: job.interval,
            start_time: job.start_time,
            command,
        };
        // Insert(): a line the file had keeps its cycle, its offset and its
        // job, whose test state (PingKept, TracerouteInstance) its runs
        // share; only the end time is the new line's, and
        // set_timeout(oldLine, 0) arms the timer it had (eperd.c:820-824) —
        // unless the line had stopped at its old end time and its time has
        // long passed (take_end_time). A line twice in one file is one
        // line, the first, with the later end time: Insert() finds the
        // first among the lines it has just inserted, which needs no
        // delete and is not counted again.
        match self.lines.get_mut(&key) {
            Some(task) => {
                sync.synced.kept += usize::from(std::mem::take(&mut task.needs_delete));
                task.take_end_time(job.end_time, sync.now);
            }
            // Start(): a new line, on the first slot after now
            // (set_timeout(line, 1), eperd.c:847)
            None => {
                sync.synced.added += 1;
                self.lines.insert(key, start(job, sync.now));
            }
        }
    }

    /// DeleteFile(): the file's lines still marked go. One whose test is
    /// still running stays until it is done, but never starts again (RunJob
    /// returns on needs_delete, eperd.c:1258-1262; DeleteFile, :875-883): a
    /// run under way here has its own copy of the job, and finishes and
    /// reports whatever becomes of its line.
    pub(crate) fn end_sync(&mut self, sync: Synchronizing) -> Synchronized {
        let Synchronizing {
            file, mut synced, ..
        } = sync;
        let before = self.lines.len();
        self.lines.retain(|key, task| {
            let goes = task.needs_delete && key.in_file(&file);
            if goes {
                task.gone.set();
            }
            !goes
        });
        synced.dropped = before - self.lines.len();
        self.changed |= synced.added + synced.dropped > 0;
        synced
    }

    /// STOP <msm_id>, Starla's own command: every line with that id, in
    /// any crontab. How many there were.
    pub(crate) fn stop(&mut self, msm_id: u64) -> usize {
        let before = self.lines.len();
        self.lines.retain(|_, task| {
            let goes = task.job.msm_id == msm_id;
            if goes {
                task.gone.set();
            }
            !goes
        });
        let stopped = before - self.lines.len();
        self.changed |= stopped > 0;
        stopped
    }

    /// The lines whose timers fire at `now`, each as RunJob takes it
    /// (eperd.c:1245-1339, ScheduledTask::fire): the jobs to run, each line
    /// once, its next cycle drawn; and the records of eperd's lines
    /// (crons/7) found more than 10 s off their time, which do not run and
    /// wait for their first slot after now. Another crontab's lines are
    /// perd's (crons/main; crons/2 no daemon of 5130's reads, and its lines
    /// run as perd's would): they run by the wall clock, however late, and
    /// give no record ([`ScheduledTask::fire_perd`]). A host back from a suspend gives one record for each
    /// line whose time passed meanwhile, and no burst of runs; a wall clock
    /// stepped back by more than 10 s, one for each line as its monotonic
    /// wait runs out, and runs on the clock as it now is.
    ///
    /// A crontab's line past its end time stays, never due again, until a
    /// push leaves it out: eperd removes lines only in DeleteFile (856-895),
    /// never on expiry. Dropped here instead, a line the controller then
    /// sends again with a later end time would come back as a new line, on
    /// a fresh first slot that can be the cycle it has just run.
    ///
    /// A job of Starla's own goes once its timer has fired past its end.
    /// It keeps RunJob's rule — its slots are eperd's, and a run more than
    /// 10 s off its time would be off its slot — but gives no record: eperd's record
    /// is of a line of its crontab, by the line's command (cl_Shell), and a
    /// job of Starla's own (a JSON command, never one of RIPE's) has none.
    pub(crate) fn take_due(&mut self, now: Now) -> Due {
        // libevent runs each timer that has run out, and then, in its loop's
        // next pass, microseconds on, a timer set meanwhile for a time
        // already past: set_timeout's wait of 0 (eperd.c:764-765) — a run's
        // next cycle, or a cycle drawn afresh, whose offset put it at or
        // before now. RunJob reads the same second for it. Taken at the next
        // tick, a second on, it would run or give its record by a clock a
        // second later than eperd's.
        let mut due = Due::default();
        for _ in 0..TIMER_PASSES {
            if self.fire_due(now, &mut due) == 0 {
                break;
            }
        }
        due
    }

    /// One pass of eperd's loop over the lines' timers: each line whose
    /// timer fires at `now`, once, its job or its record added to `due`.
    /// How many fired.
    fn fire_due(&mut self, now: Now, due: &mut Due) -> usize {
        let mut fired = 0;
        let mut inconsistent = Vec::new();
        let changed = &mut self.changed;
        self.lines.retain(|key, task| {
            let own = matches!(key, LineKey::Own(_));
            // An Own line whose next slot is already past its end time will
            // never run again: drop it rather than leave it in the map (and
            // counted in metrics) forever.
            if own && task.is_expired(now.wall) && !task.is_due(now) {
                info!(
                    msm_id = task.job.msm_id,
                    "Measurement expired, removing from schedule"
                );
                *changed = true;
                return false;
            }
            let start = task.start();
            let fire = match key {
                LineKey::Crontab { file, .. } if &**file != EPERD_CRONTAB => task.fire_perd(now),
                _ => task.fire(now),
            };
            if fire == Fired::NotYet {
                return true;
            }
            fired += 1;
            match fire {
                Fired::NotYet => {}
                // condmv's run measures nothing: it appends its marker
                Fired::Run if !task.job.spec.measures() => {
                    if let MeasurementSpec::Condmv(condmv) = &task.job.spec {
                        due.condmvs.push(condmv.clone());
                    }
                }
                Fired::Run => {
                    due.jobs.push(task.job.clone());
                    due.starts.push(start);
                    due.gone.push(task.gone.clone());
                }
                Fired::Expired => {}
                Fired::Inconsistent(times) => match key {
                    LineKey::Crontab { command, .. } => {
                        debug!(
                            msm_id = task.job.msm_id,
                            now = now.wall,
                            nexttime = times.nexttime,
                            "Inconsistent time: not run, next cycle drawn"
                        );
                        inconsistent.push((
                            times.nexttime,
                            InconsistentRecord {
                                body: times.record_body(command),
                            },
                        ));
                    }
                    LineKey::Own(msm_id) => info!(
                        msm_id,
                        now = now.wall,
                        nexttime = times.nexttime,
                        "Measurement more than 10 s off its time: not run, next cycle drawn"
                    ),
                },
            }
            if own && task.is_expired(now.wall) {
                info!(
                    msm_id = task.job.msm_id,
                    "Measurement expired, removing from schedule"
                );
                *changed = true;
                return false;
            }
            true
        });
        // libevent fires timers in the order of their time
        inconsistent.sort_by_key(|(nexttime, _)| *nexttime);
        due.inconsistent
            .extend(inconsistent.into_iter().map(|(_, record)| record));
        fired
    }

    pub(crate) fn len(&self) -> usize {
        self.lines.len()
    }

    /// Whether lines were added or removed since the last call: the counts
    /// the status shows are stale.
    pub(crate) fn take_changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }

    /// The counts the status shows are still stale.
    pub(crate) fn mark_changed(&mut self) {
        self.changed = true;
    }

    /// The lines by measurement type ("ping", "dns", ...): crons/7's
    /// condmv line, which measures nothing, is not one.
    pub(crate) fn counts(&self) -> HashMap<String, u64> {
        // A handful of types: a list beats hashing a name per line
        let mut counts: Vec<(&'static str, u64)> = Vec::new();
        for task in self.lines.values().filter(|task| task.job.spec.measures()) {
            let name = task.job.spec.type_name();
            match counts.iter_mut().find(|(n, _)| *n == name) {
                Some((_, count)) => *count += 1,
                None => counts.push((name, 1)),
            }
        }
        counts
            .into_iter()
            .map(|(name, n)| (name.to_string(), n))
            .collect()
    }

    /// The task of a crontab's line, if the file has it.
    #[cfg(test)]
    fn line(&self, file: &str, line: &CrontabLine) -> Option<&ScheduledTask> {
        self.lines.get(&LineKey::Crontab {
            file: file.into(),
            interval: line.job.interval,
            start_time: line.job.start_time,
            command: line.command.clone(),
        })
    }

    #[cfg(test)]
    fn line_mut(&mut self, file: &str, line: &CrontabLine) -> Option<&mut ScheduledTask> {
        self.lines.get_mut(&LineKey::Crontab {
            file: file.into(),
            interval: line.job.interval,
            start_time: line.job.start_time,
            command: line.command.clone(),
        })
    }
}

/// A line just loaded: its first slot after `now`, never `now` itself.
fn start(job: MeasurementJob, now: Now) -> ScheduledTask {
    ScheduledTask::new_at(
        now,
        job.msm_id,
        job.interval,
        job.start_time,
        job.end_time,
        job.spread,
        job,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::{DnsJobSpec, MeasurementSpec, PingJobSpec};
    use crate::task::{at, Now};

    const CRONS_2: &str = "/var/spool/ripe-atlas/crons/2";
    const CRONS_7: &str = "/var/spool/ripe-atlas/crons/7";
    const CRONS_MAIN: &str = "/var/spool/ripe-atlas/crons/main";

    /// crons/7's condmv line, as ctr-dub-sw02 sent it in the twin's scenario
    /// enodia-2026-10-13T0131: `CRONLINE 60 1 2000000000 UNIFORM 14 condmv
    /// -A "RESULT 9907 ongoing" /home/atlas/data/new/7
    /// /home/atlas/data/out/7`.
    fn condmv_line() -> CrontabLine {
        CrontabLine {
            command:
                r#"condmv -A "RESULT 9907 ongoing" /home/atlas/data/new/7 /home/atlas/data/out/7"#
                    .into(),
            job: MeasurementJob {
                msm_id: 0,
                interval: 60,
                start_time: 1,
                end_time: 2_000_000_000,
                spread: 14,
                spec: MeasurementSpec::Condmv(crate::job::CondmvJobSpec {
                    append: Some("RESULT 9907 ongoing".into()),
                    from: "/var/spool/ripe-atlas/data/new/7".into(),
                }),
            },
        }
    }

    fn crontab(file: &str, lines: &[CrontabLine]) -> Crontab {
        Crontab {
            file: file.to_string(),
            lines: lines.to_vec(),
        }
    }

    /// `CRONLINE <interval> <start> <end> UNIFORM <spread> <command>`, an
    /// evping line, as the controller sends one.
    fn ping_line(
        msm_id: u64,
        interval: u64,
        start_time: i64,
        end_time: i64,
        spread: u64,
        target: &str,
    ) -> CrontabLine {
        CrontabLine {
            command: format!("evping -4 -c 3 -A \"{msm_id}\" -O /home/atlas/data/new/7 {target}"),
            job: MeasurementJob {
                msm_id,
                interval,
                start_time,
                end_time,
                spread,
                spec: MeasurementSpec::Ping(PingJobSpec {
                    target: target.into(),
                    af: 4,
                    packets: 3,
                    packet_interval: 1000,
                    size: 0,
                    bundle: None,
                    kept: Default::default(),
                }),
            },
        }
    }

    /// The 26 lines of msm 30002 that ctr-dub-sw02 sent enodia on
    /// 2026-10-13 (the twin's scenario enodia-2026-10-13T0131): `CRONLINE
    /// 600 <start> <start + 30> UNIFORM 3 evtdig -4 --resolv --qbuf --type 1
    /// --class 1 --query <name> -A "30002" -O /home/atlas/data/new/7`, the
    /// starts ten minutes apart.
    fn msm_30002() -> Vec<CrontabLine> {
        let names = [
            "jd.com.",
            "google.co.uk.",
            "ebay.com.",
            "google.fr.",
            "msn.com.",
            "bing.com.",
            "google.ru.",
            "weibo.com.",
            "netflix.com.",
            "wordpress.com.",
            "microsoft.com.",
            "tumblr.com.",
            "hao123.com.",
            "amazon.co.jp.",
            "google.com.br.",
            "yandex.ru.",
            "imdb.com.",
            "google.it.",
            "stackoverflow.com.",
            "apple.com.",
            "onclkds.com.",
            "google.es.",
            "pinterest.com.",
            "office.com.",
            "google.com.hk.",
            "t.co.",
        ];
        names
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let start_time = 1_791_854_199 + 600 * i as i64;
                CrontabLine {
                    command: format!(
                        "evtdig -4 --resolv --qbuf --type 1 --class 1 --query {name} -A \"30002\" \
                         -O /home/atlas/data/new/7"
                    ),
                    job: MeasurementJob {
                        msm_id: 30002,
                        interval: 600,
                        start_time,
                        end_time: start_time + 30,
                        spread: 3,
                        spec: MeasurementSpec::Dns(DnsJobSpec {
                            resolv: true,
                            qbuf: true,
                            qtype: 1,
                            qclass: 1,
                            query: (*name).into(),
                            ..Default::default()
                        }),
                    },
                }
            })
            .collect()
    }

    /// The query of a msm 30002 run.
    fn query(job: &MeasurementJob) -> String {
        let MeasurementSpec::Dns(spec) = &job.spec else {
            panic!("{job:?}");
        };
        spec.query.clone()
    }

    /// Every run from `from` to `to`, a scheduler tick each second.
    fn runs(lines: &mut Lines, from: i64, to: i64) -> Vec<(i64, MeasurementJob)> {
        ticks(lines, from, to).0
    }

    /// Every run and every record from `from` to `to`, a tick each second.
    fn ticks(
        lines: &mut Lines,
        from: i64,
        to: i64,
    ) -> (Vec<(i64, MeasurementJob)>, Vec<InconsistentRecord>) {
        ticks_from(lines, at(from), to)
    }

    /// Every run and every record from `from` until the wall clock reads
    /// `to`, a tick each second of both clocks.
    fn ticks_from(
        lines: &mut Lines,
        from: Now,
        to: i64,
    ) -> (Vec<(i64, MeasurementJob)>, Vec<InconsistentRecord>) {
        let mut ran = Vec::new();
        let mut records = Vec::new();
        for now in from.wall..=to {
            let due = lines.take_due(Now {
                wall: now,
                usec: 0,
                mono: from.mono + std::time::Duration::from_secs((now - from.wall) as u64),
            });
            ran.extend(due.jobs.into_iter().map(|job| (now, job)));
            records.extend(due.inconsistent);
        }
        (ran, records)
    }

    /// RunJob's record of `line` (eperd.c:1268-1303).
    fn record(
        now: i64,
        nexttime: i64,
        waittime: i64,
        cycle: i64,
        generated: i64,
        line: &CrontabLine,
    ) -> InconsistentRecord {
        InconsistentRecord {
            body: crate::task::InconsistentTime {
                now,
                nexttime,
                waittime,
                cycle,
                generated,
            }
            .record_body(&line.command),
        }
    }

    #[test]
    fn every_line_of_one_msm_id_runs_in_its_own_window() {
        let push = msm_30002();
        let first = push[0].job.start_time;
        let last = push[25].job.start_time;

        // The crontab arrives two minutes before the first window: all 26
        // windows are ahead, and each line runs once, in its window — at
        // its slot, moved by UNIFORM 3's -1..=2 s (do_distr, eperd.c:489-511)
        let mut lines = Lines::default();
        let synced = lines.synchronize(crontab(CRONS_7, &push), at(first - 120));
        assert_eq!(synced.added, 26);
        assert_eq!(lines.len(), 26, "keyed by msm id, Starla kept 1");
        assert_eq!(lines.counts(), HashMap::from([("dns".to_string(), 26)]));
        let ran = runs(&mut lines, first - 120, last + 3_600);
        assert_eq!(ran.len(), 26, "{ran:?}");
        for (line, (at, job)) in push.iter().zip(&ran) {
            assert_eq!(query(job), query(&line.job));
            let slot = line.job.start_time;
            assert!(
                (slot - 1..=slot + 2).contains(at),
                "{} ran at {at}, its slot {slot}",
                query(job)
            );
        }

        // As enodia got it, at 1791855121: jd.com.'s and google.co.uk.'s
        // windows had passed (cycle 1 is after their end time,
        // set_timeout's first cycle after now, eperd.c:744-753), and the
        // 24 others each run once.
        let mut lines = Lines::default();
        let pushed = 1_791_855_121;
        lines.synchronize(crontab(CRONS_7, &push), at(pushed));
        let ran = runs(&mut lines, pushed, last + 3_600);
        let queries: Vec<String> = ran.iter().map(|(_, job)| query(job)).collect();
        let wanted: Vec<String> = push[2..].iter().map(|line| query(&line.job)).collect();
        assert_eq!(queries, wanted);
    }

    #[test]
    fn a_resent_line_keeps_its_cycle_and_offset_and_runs_once_a_cycle() {
        // `CRONLINE 900 312 … UNIFORM 20 evping …`: slots at 312 + k * 900,
        // each moved by -10..=10 s
        let line = ping_line(1001, 900, 312, 2_000_000_000, 20, "193.0.14.129");
        let slot = 1_791_836_412;
        let mut lines = Lines::default();
        lines.synchronize(
            crontab(CRONS_7, std::slice::from_ref(&line)),
            at(slot - 400),
        );
        let task = lines.line_mut(CRONS_7, &line).unwrap();
        assert!((slot - 10..=slot + 10).contains(&task.next_run));
        // This cycle's offset came out -8: the line runs 8 s before its slot
        task.set_next_run(slot - 8, at(slot - 400));
        assert!(runs(&mut lines, slot - 400, slot - 9).is_empty());
        assert_eq!(lines.take_due(at(slot - 8)).jobs.len(), 1);
        let task = lines.line(CRONS_7, &line).unwrap();
        let after_the_run = (task.cycle, task.next_run);
        assert!((slot + 890..=slot + 910).contains(&task.next_run));

        // The controller sends the crontab again 5 s later, before this
        // cycle's slot, the line as it was but for its end time. On main,
        // Starla made it a new task, whose first slot after now is this
        // cycle's: it would have run again.
        assert_eq!(
            ScheduledTask::new_at(
                at(slot - 3),
                1001,
                900,
                312,
                2_000_000_000,
                20,
                line.job.clone()
            )
            .cycle,
            after_the_run.0 - 1
        );
        let mut resent = line.clone();
        resent.job.end_time = 2_100_000_000;
        let synced = lines.synchronize(crontab(CRONS_7, &[resent]), at(slot - 3));
        assert_eq!(
            synced,
            Synchronized {
                kept: 1,
                added: 0,
                dropped: 0
            }
        );
        let task = lines.line(CRONS_7, &line).unwrap();
        assert_eq!((task.cycle, task.next_run), after_the_run);
        assert_eq!(task.end_time, 2_100_000_000);
        assert_eq!(task.job.end_time, 2_100_000_000);
        // Nothing more in this cycle; the next runs on the slot it had
        assert!(runs(&mut lines, slot - 3, after_the_run.1 - 1).is_empty());
        assert_eq!(lines.take_due(at(after_the_run.1)).jobs.len(), 1);

        // The same job is kept, and with it what its runs share: the
        // re-sent line's own (a PingKept of its own here) is dropped.
        let kept = |lines: &Lines| {
            let MeasurementSpec::Ping(spec) = &lines.line(CRONS_7, &line).unwrap().job.spec else {
                unreachable!()
            };
            spec.kept.clone()
        };
        let before = kept(&lines);
        let resent = ping_line(1001, 900, 312, 2_000_000_000, 20, "193.0.14.129");
        lines.synchronize(crontab(CRONS_7, &[resent]), at(slot + 1_000));
        assert!(std::sync::Arc::ptr_eq(&before, &kept(&lines)));

        // An end time moved before the next slot is taken: no more runs
        let task = lines.line(CRONS_7, &line).unwrap();
        let next = task.next_run;
        let mut ending = line.clone();
        ending.job.end_time = next - 1;
        lines.synchronize(crontab(CRONS_7, &[ending]), at(slot + 1_000));
        assert!(runs(&mut lines, slot + 1_000, next + 3_600).is_empty());
    }

    #[test]
    fn a_line_that_stopped_at_its_end_time_runs_on_its_slots_once_extended() {
        // `CRONLINE 900 312 <slot + 100> UNIFORM 20 evping …`: it runs in
        // the cycle of `slot`, and then stops, the next slot being past its
        // end time. It stays a line of its file, as it stays in eperd's
        // LineBase.
        let slot = 1_791_836_412;
        let times = |ran: Vec<(i64, MeasurementJob)>| ran.into_iter().map(|(at, _)| at).collect();
        let kept = |lines: &Lines, line: &CrontabLine| {
            let MeasurementSpec::Ping(spec) = &lines.line(CRONS_7, line).unwrap().job.spec else {
                unreachable!()
            };
            spec.kept.clone()
        };
        let line = ping_line(1001, 900, 312, slot + 100, 20, "193.0.14.129");
        let mut lines = Lines::default();
        lines.synchronize(
            crontab(CRONS_7, std::slice::from_ref(&line)),
            at(slot - 400),
        );
        let ran: Vec<i64> = times(runs(&mut lines, slot - 400, slot + 900 * 40));
        assert_eq!(ran.len(), 1);
        assert!((slot - 10..=slot + 10).contains(&ran[0]), "{ran:?}");
        assert_eq!(lines.len(), 1);
        let before = kept(&lines, &line);

        // The controller is away for 10 h, longer than the 8 h RIPE gives a
        // user measurement (end time = its session + 28800 in the twin's
        // scenario enodia-2026-10-13T0131), and comes back mid-cycle with
        // the line, its end time 8 h on. Kept with the next run it had, the
        // line ran at once, between slots, and again at the next: two
        // results in one interval. eperd's re-armed timer fires at once
        // and RunJob, finding the time inconsistent, writes its record, runs
        // nothing and draws the first cycle after now (eperd.c:1268-1310).
        let back = slot + 36_000 + 450;
        let next = slot + 36_900;
        let mut extended = line.clone();
        extended.job.end_time = back + 28_800;
        let synced = lines.synchronize(crontab(CRONS_7, &[extended]), at(back));
        assert_eq!(synced.kept, 1);
        let task = lines.line(CRONS_7, &line).unwrap();
        assert_eq!(task.end_time, back + 28_800);
        let stopped = (task.next_run, task.cycle);
        let due = lines.take_due(at(back));
        assert!(due.jobs.is_empty());
        assert_eq!(
            due.inconsistent,
            // the timer set at the push, for a time long past: no wait
            vec![record(back, stopped.0, 0, stopped.1, back, &line)]
        );
        let task = lines.line(CRONS_7, &line).unwrap();
        assert!(
            (next - 10..=next + 10).contains(&task.next_run),
            "{} is not the slot after {back}",
            task.next_run
        );
        let next_run = task.next_run;
        // (the cycle after starts at next + 890 at the earliest)
        assert_eq!(times(runs(&mut lines, back, next + 889)), vec![next_run]);
        // still the line it was, with its job
        assert!(std::sync::Arc::ptr_eq(&before, &kept(&lines, &line)));

        // Within 10 s of the time it stopped at, the line runs at once, as
        // RunJob runs a line within 10 s of its time (eperd.c:1268); from
        // 11 s on, it gives its record and waits for its next slot.
        for (late, runs_at_once) in [(10, true), (11, false)] {
            let line = ping_line(1001, 900, 312, slot + 100, 0, "193.0.14.129");
            let mut lines = Lines::default();
            lines.synchronize(
                crontab(CRONS_7, std::slice::from_ref(&line)),
                at(slot - 400),
            );
            assert_eq!(
                times(runs(&mut lines, slot - 400, slot + 900 + late - 1)),
                vec![slot]
            );
            let mut extended = line.clone();
            extended.job.end_time = 2_000_000_000;
            lines.synchronize(crontab(CRONS_7, &[extended]), at(slot + 900 + late));
            let due = lines.take_due(at(slot + 900 + late));
            assert_eq!(
                (due.jobs.len(), due.inconsistent.len()),
                (usize::from(runs_at_once), usize::from(!runs_at_once)),
                "re-sent {late} s after its time"
            );
            let ran = times(runs(&mut lines, slot + 900 + late + 1, slot + 1_800));
            assert_eq!(ran, vec![slot + 1_800], "re-sent {late} s after its time");
        }

        // A line that had not stopped, re-sent, keeps its time; a tick that
        // takes it more than 10 s after it finds the time inconsistent, as
        // RunJob does. (0025 ran it: the scheduler loop ran a one-off in
        // line then, and a tick held up behind it was Starla's own doing.)
        let line = ping_line(1001, 900, 312, 2_000_000_000, 0, "193.0.14.129");
        let mut lines = Lines::default();
        lines.synchronize(
            crontab(CRONS_7, std::slice::from_ref(&line)),
            at(slot - 400),
        );
        lines.synchronize(crontab(CRONS_7, std::slice::from_ref(&line)), at(slot + 30));
        assert_eq!(lines.line(CRONS_7, &line).unwrap().next_run, slot);
        let due = lines.take_due(at(slot + 30));
        assert!(due.jobs.is_empty());
        assert_eq!(
            due.inconsistent,
            vec![record(slot + 30, slot, 0, 1_990_929, slot + 30, &line)]
        );
    }

    /// A line that ran late in its last cycle, past its end time, stays;
    /// sent again with a later end time it keeps the cycle it is on, so the
    /// cycle it ran early in does not run twice (Insert, eperd.c:820-824).
    #[test]
    fn an_expired_line_stays_and_keeps_its_cycle_when_extended() {
        let line = ping_line(1001, 900, 312, 0, 20, "193.0.14.129");
        let slot = 1_791_836_412;
        let mut ending = line.clone();
        ending.job.end_time = slot - 7;
        let mut lines = Lines::default();
        lines.synchronize(
            crontab(CRONS_7, std::slice::from_ref(&ending)),
            at(slot - 400),
        );
        // This cycle's offset came out -8, inside the end time, and the
        // tick that runs it comes late, after the end time has passed
        lines
            .line_mut(CRONS_7, &line)
            .unwrap()
            .set_next_run(slot - 8, at(slot - 400));
        assert_eq!(lines.take_due(at(slot - 6)).jobs.len(), 1);
        assert!(runs(&mut lines, slot - 5, slot + 2_000).is_empty());
        let task = lines.line(CRONS_7, &line).expect("kept past its end time");
        let after_the_run = (task.cycle, task.next_run);

        // The controller sends the line again, before this cycle's slot,
        // with a later end time
        let mut extended = line.clone();
        extended.job.end_time = 2_000_000_000;
        let synced = lines.synchronize(crontab(CRONS_7, &[extended]), at(slot - 3));
        assert_eq!(synced.kept, 1);
        let task = lines.line(CRONS_7, &line).unwrap();
        assert_eq!((task.cycle, task.next_run), after_the_run);
        assert!(runs(&mut lines, slot - 3, after_the_run.1 - 1).is_empty());
        assert_eq!(lines.take_due(at(after_the_run.1)).jobs.len(), 1);

        // A push without it is what removes it
        lines.synchronize(crontab(CRONS_7, &[]), at(slot + 1_000));
        assert!(lines.line(CRONS_7, &line).is_none());
    }

    #[test]
    fn a_line_with_another_interval_start_or_command_is_another_line() {
        let line = ping_line(1001, 900, 312, 2_000_000_000, 20, "193.0.14.129");
        let now = 1_791_836_000;
        let changed = |f: &dyn Fn(&mut CrontabLine)| {
            let mut changed = line.clone();
            f(&mut changed);
            changed
        };
        for other in [
            changed(&|l| l.job.interval = 1800),
            changed(&|l| l.job.start_time = 313),
            changed(&|l| l.command = l.command.replace("-c 3", "-c 4")),
        ] {
            let mut lines = Lines::default();
            lines.synchronize(crontab(CRONS_7, std::slice::from_ref(&line)), at(now));
            let synced =
                lines.synchronize(crontab(CRONS_7, std::slice::from_ref(&other)), at(now + 1));
            assert_eq!(
                synced,
                Synchronized {
                    kept: 0,
                    added: 1,
                    dropped: 1
                },
                "{other:?}"
            );
            assert_eq!(lines.len(), 1);
            assert!(lines.line(CRONS_7, &line).is_none());
            let task = lines.line(CRONS_7, &other).unwrap();
            assert!(task.next_run > now + 1, "a new line waits for its slot");
        }

        // The end time and the spread are not what a line is: one that
        // changes only those is the same line, which keeps its spread and
        // offset and takes the end time (Insert, eperd.c:820)
        let mut lines = Lines::default();
        lines.synchronize(crontab(CRONS_7, std::slice::from_ref(&line)), at(now));
        let before = lines.line(CRONS_7, &line).unwrap().next_run;
        let other = changed(&|l| {
            l.job.end_time = 2_000_000_100;
            l.job.spread = 200;
        });
        let synced = lines.synchronize(crontab(CRONS_7, &[other]), at(now + 1));
        assert_eq!(synced.kept, 1);
        let task = lines.line(CRONS_7, &line).unwrap();
        assert_eq!((task.next_run, task.spread), (before, 20));
        assert_eq!(task.end_time, 2_000_000_100);

        // A line twice in one crontab is one line, with the later end time
        let mut lines = Lines::default();
        let twice = [line.clone(), changed(&|l| l.job.end_time = 2_000_000_200)];
        let synced = lines.synchronize(crontab(CRONS_7, &twice), at(now));
        assert_eq!((synced.added, lines.len()), (1, 1));
        assert_eq!(lines.line(CRONS_7, &line).unwrap().end_time, 2_000_000_200);
    }

    #[test]
    fn a_crontab_replaces_its_own_files_lines_only() {
        let now = 1_791_836_000;
        let a = ping_line(1001, 900, 312, 2_000_000_000, 20, "193.0.14.129");
        let b = ping_line(1002, 240, 17, 2_000_000_000, 3, "2001:7fd::1");
        let c = ping_line(1003, 240, 18, 2_000_000_000, 3, "192.0.2.1");
        let mut lines = Lines::default();
        lines.synchronize(crontab(CRONS_2, std::slice::from_ref(&c)), at(now));
        lines.synchronize(crontab(CRONS_7, &[a.clone(), b.clone()]), at(now));
        lines.schedule(ping_line(7, 60, 0, 0, 0, "192.0.2.7").job, at(now));
        assert_eq!(lines.len(), 4);

        // crons/7 again without b: b stops, a keeps its slot, crons/2's line
        // and Starla's own job are untouched
        let a_next = lines.line(CRONS_7, &a).unwrap().next_run;
        let c_next = lines.line(CRONS_2, &c).unwrap().next_run;
        let synced = lines.synchronize(crontab(CRONS_7, std::slice::from_ref(&a)), at(now + 10));
        assert_eq!(
            synced,
            Synchronized {
                kept: 1,
                added: 0,
                dropped: 1
            }
        );
        assert!(lines.line(CRONS_7, &b).is_none());
        assert_eq!(lines.line(CRONS_7, &a).unwrap().next_run, a_next);
        assert_eq!(lines.line(CRONS_2, &c).unwrap().next_run, c_next);
        assert_eq!(lines.len(), 3);
        let ran: Vec<u64> = runs(&mut lines, now + 10, now + 1_000)
            .into_iter()
            .map(|(_, job)| job.msm_id)
            .collect();
        assert!(!ran.contains(&1002), "{ran:?}");
        assert!(ran.contains(&1001) && ran.contains(&1003) && ran.contains(&7));

        // The same line in another file is another line
        lines.synchronize(crontab(CRONS_2, &[c.clone(), a.clone()]), at(now + 1_000));
        assert!(lines.line(CRONS_2, &a).is_some());
        assert!(lines.line(CRONS_7, &a).is_some());
        assert_eq!(lines.len(), 4);

        // An empty crontab empties its file
        let synced = lines.synchronize(crontab(CRONS_2, &[]), at(now + 1_001));
        assert_eq!(synced.dropped, 2);
        assert_eq!(lines.len(), 2);
    }

    /// Every line due in one second runs in it, each at its own offset's
    /// microseconds: with each job take_due hands over the second its
    /// line's timer was set for and the microseconds drawn with it
    /// (do_distr and set_timeout's tv_usec, eperd.c:507, 758-762), which
    /// its run sleeps (Scheduler::spawn_run). Starla started every run a
    /// tick took in that tick's millisecond.
    #[test]
    fn the_runs_due_in_one_second_start_at_their_lines_microseconds() {
        let slot = 1_791_836_412; // 312 + k * 900
        let pings: Vec<_> = (0..16)
            .map(|i| ping_line(1000 + i, 900, 312, 2_000_000_000, 20, "193.0.14.129"))
            .collect();
        let mut lines = Lines::default();
        lines.synchronize(crontab(CRONS_7, &pings), at(slot - 400));
        // every line's time the slot itself, its microseconds as drawn
        let mut drawn = HashMap::new();
        for task in lines.lines.values_mut() {
            task.set_next_run(slot, at(slot - 400));
            drawn.insert(task.job.msm_id, task.usec);
        }
        assert!(lines.take_due(at(slot - 1)).jobs.is_empty());
        let due = lines.take_due(at(slot));
        assert_eq!((due.jobs.len(), due.starts.len()), (16, 16));
        for (job, start) in due.jobs.iter().zip(&due.starts) {
            let usec = drawn[&job.msm_id];
            assert_eq!(*start, Start { second: slot, usec }, "{}", job.msm_id);
        }
        let usecs: std::collections::BTreeSet<_> = due.starts.iter().map(|s| s.usec).collect();
        assert!(usecs.len() > 14, "{usecs:?}");
    }

    #[test]
    fn stop_takes_every_line_with_the_id() {
        let now = 1_791_836_000;
        let mut push = msm_30002();
        let other = ping_line(1001, 900, 312, 2_000_000_000, 20, "193.0.14.129");
        push.push(other.clone());
        let mut lines = Lines::default();
        lines.synchronize(crontab(CRONS_7, &push), at(now));
        lines.synchronize(crontab(CRONS_2, &msm_30002()[..3]), at(now));
        lines.schedule(ping_line(30002, 60, 0, 0, 0, "192.0.2.7").job, at(now));
        assert_eq!(lines.len(), 31);
        assert_eq!(lines.stop(30002), 30);
        assert_eq!(lines.len(), 1);
        assert!(lines.line(CRONS_7, &other).is_some());
        assert_eq!(lines.stop(30002), 0);
    }

    #[test]
    fn a_job_of_its_own_replaces_the_one_with_its_id() {
        let now = 1_791_836_000;
        let mut lines = Lines::default();
        lines.schedule(ping_line(7, 60, 0, 0, 0, "192.0.2.7").job, at(now));
        lines.schedule(ping_line(7, 120, 0, 0, 0, "192.0.2.7").job, at(now));
        assert_eq!(lines.len(), 1);
        // and no crontab touches it
        lines.synchronize(crontab(CRONS_7, &[]), at(now));
        assert_eq!(lines.len(), 1);
    }

    /// A run taken at a tick carries its line's LineGone: set once a push
    /// of the line's file leaves it out, or a STOP takes it; not by a push
    /// that repeats it, nor by another file's push.
    #[test]
    fn a_taken_run_learns_when_its_line_goes() {
        let slot = 1_791_836_412;
        let line = ping_line(1001, 900, 312, 2_000_000_000, 0, "193.0.14.129");
        let other = ping_line(1002, 900, 312, 2_000_000_000, 0, "193.0.14.130");
        let taken = || {
            let mut lines = Lines::default();
            lines.synchronize(
                crontab(CRONS_7, std::slice::from_ref(&line)),
                at(slot - 400),
            );
            lines.synchronize(
                crontab(CRONS_MAIN, std::slice::from_ref(&other)),
                at(slot - 400),
            );
            let due = lines.take_due(at(slot));
            assert_eq!(due.jobs.len(), 2);
            assert_eq!(due.gone.len(), 2);
            let at_7 = due.jobs.iter().position(|j| j.msm_id == 1001).unwrap();
            let gone = due.gone[at_7].clone();
            assert!(!gone.is_set());
            (lines, gone)
        };

        // Repeated, and another file's push: the line stays
        let (mut lines, gone) = taken();
        lines.synchronize(crontab(CRONS_7, std::slice::from_ref(&line)), at(slot));
        lines.synchronize(crontab(CRONS_MAIN, &[]), at(slot));
        assert!(!gone.is_set());

        // Left out by its file's push
        lines.synchronize(crontab(CRONS_7, &[]), at(slot));
        assert!(gone.is_set());

        // Taken by a STOP
        let (mut lines, gone) = taken();
        assert_eq!(lines.stop(1001), 1);
        assert!(gone.is_set());
    }

    /// A job of Starla's own scheduled again replaces its line, and the
    /// run the old line had taken does not start: the replaced line has
    /// gone, as DeleteFile takes a line with its timer. Its new line starts
    /// on the first slot after now.
    #[test]
    fn a_run_of_a_replaced_job_of_its_own_does_not_start() {
        let slot = 1_791_836_412;
        let mut lines = Lines::default();
        let job = || ping_line(7, 900, 312, 2_000_000_000, 0, "192.0.2.7").job;
        lines.schedule(job(), at(slot - 400));
        let due = lines.take_due(at(slot));
        assert_eq!(due.jobs.len(), 1);
        let gone = due.gone[0].clone();
        assert!(!gone.is_set());

        lines.schedule(job(), at(slot));
        assert!(gone.is_set());
        assert_eq!(lines.len(), 1);
        assert!(lines.take_due(at(slot)).jobs.is_empty());
        assert_eq!(lines.take_due(at(slot + 900)).jobs.len(), 1);
    }

    /// RunJob runs a line whose timer fires within 10 s of its time; from
    /// 11 s on it runs nothing, appends its "inconsistent time" record and
    /// draws the first cycle after now (eperd.c:1268-1310). Starla ran any
    /// due line, however late.
    #[test]
    fn a_line_more_than_10_s_late_gives_eperds_record_and_waits_for_the_next_cycle() {
        // `CRONLINE 900 312 2000000000 UNIFORM 0 evping …`, loaded 400 s
        // before its slot, of cycle 1990929
        let slot = 1_791_836_412;
        let line = ping_line(1001, 900, 312, 2_000_000_000, 0, "193.0.14.129");
        let loaded = || {
            let mut lines = Lines::default();
            lines.synchronize(
                crontab(CRONS_7, std::slice::from_ref(&line)),
                at(slot - 400),
            );
            lines
        };
        for late in [0, 1, 9, 10] {
            let mut lines = loaded();
            let due = lines.take_due(at(slot + late));
            assert_eq!(due.jobs.len(), 1, "{late} s late");
            assert!(due.inconsistent.is_empty(), "{late} s late");
        }

        let mut lines = loaded();
        let due = lines.take_due(at(slot + 11));
        assert!(due.jobs.is_empty());
        assert_eq!(
            due.inconsistent,
            vec![InconsistentRecord {
                body: "\"id\":\"9807\", \"fw\":5130, \"mver\": \"2.6.4\", \"time\":1791836423, \
                       \"reason\": \"inconsistent time; now 1791836423; nexttime 1791836412; \
                       waittime 400; cycle 1990929; generated 1791836012\", \"cmd\": \"evping -4 \
                       -c 3 -A \\\"1001\\\" -O /home/atlas/data/new/7 193.0.14.129\""
                    .into(),
            }]
        );
        // It runs at the next slot, once a cycle, and gives no more records
        let (ran, records) = ticks(&mut lines, slot + 12, slot + 2_699);
        let ran: Vec<i64> = ran.into_iter().map(|(at, _)| at).collect();
        assert_eq!(ran, vec![slot + 900, slot + 1_800]);
        assert!(records.is_empty(), "{records:?}");

        // However late, one record: the cycle drawn is the first after now
        for late in [12, 60, 899, 900, 3_600 * 5 + 7] {
            let mut lines = loaded();
            let (ran, records) = ticks(&mut lines, slot + late, slot + late + 1_800);
            assert_eq!(records.len(), 1, "{late} s late");
            let next = slot + (late / 900 + 1) * 900;
            let ran: Vec<i64> = ran.into_iter().map(|(at, _)| at).collect();
            assert_eq!(ran, vec![next, next + 900], "{late} s late");
        }
    }

    /// perd, which runs crons/main, has no 10 s rule: a late line runs,
    /// with a log line only, and no record (perd.c:1226-1248). Starla gave
    /// every crontab's lines eperd's rule and record. The line then goes on
    /// from its first slot after now.
    #[test]
    fn a_late_line_of_perds_crontab_runs_and_gives_no_record() {
        let slot = 1_791_836_412;
        let line = ping_line(1001, 900, 312, 2_000_000_000, 0, "193.0.14.129");
        for late in [11, 60, 899, 3_600 * 5 + 7] {
            let mut lines = Lines::default();
            lines.synchronize(
                crontab(CRONS_MAIN, std::slice::from_ref(&line)),
                at(slot - 400),
            );
            let due = lines.take_due(at(slot + late));
            assert_eq!(due.jobs.len(), 1, "{late} s late");
            assert!(due.inconsistent.is_empty(), "{late} s late");
            let next = slot + (late / 900 + 1) * 900;
            let (ran, records) = ticks(&mut lines, slot + late + 1, next + 900);
            let ran: Vec<i64> = ran.into_iter().map(|(at, _)| at).collect();
            assert_eq!(ran, vec![next, next + 900], "{late} s late");
            assert!(records.is_empty(), "{records:?}");
        }

        // Its time and its end time both passed meanwhile: perd runs a
        // line only up to its end time (perd.c:814-818)
        let ending = ping_line(1001, 900, 312, slot + 30, 0, "193.0.14.129");
        let mut lines = Lines::default();
        lines.synchronize(crontab(CRONS_MAIN, &[ending]), at(slot - 400));
        let due = lines.take_due(at(slot + 60));
        assert!(due.jobs.is_empty() && due.inconsistent.is_empty());
    }

    /// perd's timer is the wall clock: stepped back by less than 10
    /// intervals, a crons/main line waits for its slot by the clock as it
    /// now is, where eperd's monotonic wait fires and draws a cycle afresh;
    /// by more, perd starts the line over and runs it at once
    /// (perd.c:783-791, 814-818).
    #[test]
    fn a_line_of_perds_crontab_keeps_its_slot_by_the_wall_clock() {
        let slot = 1_791_836_412;
        let line = ping_line(1001, 900, 312, 2_000_000_000, 0, "193.0.14.129");
        let loaded = || {
            let mut lines = Lines::default();
            lines.synchronize(
                crontab(CRONS_MAIN, std::slice::from_ref(&line)),
                at(slot - 400),
            );
            lines
        };

        // back 3 600 s, 4 intervals, a second on
        let mut lines = loaded();
        let stepped = Now {
            wall: slot - 3_700,
            usec: 0,
            mono: at(slot - 99).mono,
        };
        let (ran, records) = ticks_from(&mut lines, stepped, slot + 900);
        let ran: Vec<i64> = ran.into_iter().map(|(at, _)| at).collect();
        assert_eq!(ran, vec![slot, slot + 900], "its own slot, then on");
        assert!(records.is_empty(), "{records:?}");

        // back 11 intervals: at once, then the first slot after now
        let mut lines = loaded();
        let back = slot - 400 - 11 * 900;
        let stepped = Now {
            wall: back,
            usec: 0,
            mono: at(slot - 399).mono,
        };
        let (ran, records) = ticks_from(&mut lines, stepped, back + 900);
        let ran: Vec<i64> = ran.into_iter().map(|(at, _)| at).collect();
        assert_eq!(ran, vec![back, slot - 11 * 900], "{ran:?}");
        assert!(records.is_empty(), "{records:?}");
    }

    /// The workstation slept under the twin (wire comparison 2026-10-13,
    /// W12): on waking, the reference found every timer more than 10 s
    /// late and wrote one record for each, 191, running none, while Starla
    /// ran every overdue line at once. A host suspended for 3 h here: one
    /// record for each line whose timer was set for a time in the suspend —
    /// the timer of a line past its end time too, which RunJob checks for
    /// time before expiry — no run at the wake, and each line on from its
    /// first slot after it, once a cycle.
    #[test]
    fn a_suspended_host_gives_one_record_a_line_and_no_burst_of_runs() {
        let t0 = 1_791_836_000;
        let periodic = [
            ping_line(1001, 60, 1, 2_000_000_000, 14, "192.0.2.1"),
            ping_line(1002, 240, 17, 2_000_000_000, 2, "192.0.2.2"),
            ping_line(1003, 900, 312, 2_000_000_000, 20, "192.0.2.3"),
            ping_line(1004, 3_600, 3_000, 2_000_000_000, 60, "192.0.2.4"),
        ];
        // a 30 s window a minute on, as msm 30002's: it runs, and its
        // timer is then set for the next slot, past its end time
        let window = ping_line(30002, 600, t0 + 60, t0 + 90, 0, "192.0.2.5");
        // a daily line whose first slot comes after the wake. The wake is
        // more than half a spread before each periodic line's next slot, so
        // none's cycle drawn at the wake has a time at or before it (which
        // libevent would run at once, as a_timer_set_for_a_time_past_fires_
        // again_at_the_same_now): 1001's next slot is 31 s after it.
        let wake = t0 + 130 + 3 * 3_600;
        let daily = ping_line(1005, 86_400, wake + 599, 2_000_000_000, 0, "192.0.2.6");
        let mut all = periodic.to_vec();
        all.extend([window.clone(), daily.clone()]);
        let mut lines = Lines::default();
        lines.synchronize(crontab(CRONS_7, &all), at(t0));
        let (ran, records) = ticks(&mut lines, t0, t0 + 100);
        assert!(records.is_empty());
        assert!(ran.iter().any(|(_, job)| job.msm_id == 30002));

        // Asleep until `wake`: no tick
        let due = lines.take_due(at(wake));
        assert!(due.jobs.is_empty(), "a burst: {:?}", due.jobs);
        // one record for each line but the daily one, in the order their
        // timers were set to fire
        let ids: Vec<&str> = due
            .inconsistent
            .iter()
            .map(|r| {
                let at = r.body.find("-A \\\"").unwrap() + 5;
                &r.body[at..at + r.body[at..].find('\\').unwrap()]
            })
            .collect();
        assert_eq!(ids, ["1001", "1002", "1003", "30002", "1004"]);
        for record in &due.inconsistent {
            assert!(
                record
                    .body
                    .contains(&format!("inconsistent time; now {wake}; nexttime ")),
                "{}",
                record.body
            );
        }

        // On from the wake: each line once a cycle, from its first slot
        // after it; the window's line no more; no record
        let (ran, records) = ticks(&mut lines, wake + 1, wake + 3_600);
        assert!(records.is_empty(), "{records:?}");
        for line in periodic.iter().chain([&daily]) {
            let times: Vec<i64> = ran
                .iter()
                .filter(|(_, job)| job.msm_id == line.job.msm_id)
                .map(|(at, _)| *at)
                .collect();
            let interval = line.job.interval as i64;
            let half = (line.job.spread / 2) as i64;
            let first_slot = if wake < line.job.start_time {
                line.job.start_time
            } else {
                line.job.start_time + ((wake - line.job.start_time) / interval + 1) * interval
            };
            assert!(
                (first_slot - half..=first_slot + half + 1).contains(&times[0]),
                "{}: first run {} after the wake, its slot {first_slot}",
                line.job.msm_id,
                times[0]
            );
            for pair in times.windows(2) {
                assert!(
                    pair[1] - pair[0] >= interval - 2 * half - 1,
                    "{}: {times:?}",
                    line.job.msm_id
                );
            }
        }
        assert!(!ran.iter().any(|(_, job)| job.msm_id == 30002));
    }

    /// crons/7's condmv line is one of eperd's timed lines — condmv is an
    /// eperd built-in (eperd.c:932), so Start arms its line (:838-848) — and
    /// after a suspend RunJob writes its record with the other lines', in
    /// the order of their times: the record the twin's reference wrote
    /// (task.rs, a_timer_more_than_10_s_late_runs_nothing_and_gives_eperds_
    /// record). Starla parsed the line to Ignored and never wrote it. Its
    /// runs start nothing; each appends its 9907 marker (Due::condmvs). In
    /// crons/main condmv is perd's, which writes no record (perd.c:
    /// 1226-1248), and crons/2 no daemon reads: there it is no line.
    #[test]
    fn crons_7s_condmv_line_is_timed_runs_nothing_and_gives_its_record() {
        let t0 = 1_791_936_000;
        let condmv = condmv_line();
        let ping = ping_line(1002, 240, 17, 2_000_000_000, 2, "192.0.2.2");
        let mut lines = Lines::default();
        let synced = lines.synchronize(crontab(CRONS_7, &[ping.clone(), condmv.clone()]), at(t0));
        assert_eq!(synced.added, 2);
        assert_eq!(lines.counts(), HashMap::from([("ping".to_string(), 1)]));

        // It fires once a minute, and starts nothing
        let awake = t0 + 600;
        let (ran, records) = ticks(&mut lines, t0, awake);
        assert!(records.is_empty(), "{records:?}");
        assert!(ran.iter().all(|(_, job)| job.msm_id == 1002), "{ran:?}");
        assert_eq!(ran.len(), 3, "{ran:?}"); // slots 17 + k * 240
                                             // its slots are 1 + k * 60, each moved by -7..=7 s: the one after
                                             // `awake` is awake + 1, and the line has run in its cycle or not
        let task = lines.line(CRONS_7, &condmv).unwrap();
        assert!(
            (awake + 1..=awake + 1 + 60 + 7).contains(&task.next_run),
            "{} is not its next time after {awake}",
            task.next_run
        );
        let times = [&condmv, &ping].map(|line| lines.line(CRONS_7, line).unwrap().next_run);

        // Suspended for 3 h: a record of each line, condmv's among them, in
        // the order of their times; no run
        let wake = awake + 3 * 3_600;
        let due = lines.take_due(at(wake));
        assert!(due.jobs.is_empty(), "{:?}", due.jobs);
        let nexttime = |record: &InconsistentRecord| -> i64 {
            let at = record.body.find("nexttime ").unwrap() + "nexttime ".len();
            let len = record.body[at..].find(';').unwrap();
            record.body[at..at + len].parse().unwrap()
        };
        let got: Vec<i64> = due.inconsistent.iter().map(nexttime).collect();
        let mut wanted = times.to_vec();
        wanted.sort();
        assert_eq!(got, wanted);
        let condmvs = due
            .inconsistent
            .iter()
            .filter(|record| {
                record.body.ends_with(
                    r#""cmd": "condmv -A \"RESULT 9907 ongoing\" /home/atlas/data/new/7 /home/atlas/data/out/7""#,
                )
            })
            .count();
        assert_eq!(condmvs, 1, "{:?}", due.inconsistent);

        // and on from the wake, once a minute, with no record
        let (ran, records) = ticks(&mut lines, wake + 1, wake + 600);
        assert!(records.is_empty(), "{records:?}");
        assert!(ran.iter().all(|(_, job)| job.msm_id == 1002), "{ran:?}");

        // perd's and crons/2's condmv lines are no lines
        for file in [CRONS_MAIN, CRONS_2] {
            let mut lines = Lines::default();
            let synced = lines.synchronize(crontab(file, std::slice::from_ref(&condmv)), at(t0));
            assert_eq!((synced.added, lines.len()), (0, 0), "{file}");
        }
    }

    /// A line whose run, or whose cycle drawn afresh, sets its timer for a
    /// time at or before now fires again at the same now: libevent runs a
    /// timer set with set_timeout's wait of 0 in its loop's next pass,
    /// microseconds on (eperd.c:764-765), not a second later.
    #[test]
    fn a_timer_set_for_a_time_past_fires_again_at_the_same_now() {
        // `CRONLINE 5 0 …`, its tick 5 s late: RunJob runs it; its next
        // cycle's slot is now itself, which set_timeout sets the timer for
        // with no wait, and it runs again (eperd.c:1328-1338)
        let now = 1_791_836_000;
        let line = ping_line(1001, 5, 0, 2_000_000_000, 0, "192.0.2.1");
        let mut lines = Lines::default();
        lines.synchronize(crontab(CRONS_7, std::slice::from_ref(&line)), at(now));
        let first = lines.line(CRONS_7, &line).unwrap().next_run;
        assert_eq!(first, now + 5);
        let due = lines.take_due(at(first + 5));
        assert_eq!(due.jobs.len(), 2);
        assert!(due.inconsistent.is_empty());
        assert_eq!(lines.line(CRONS_7, &line).unwrap().next_run, first + 10);

        // Spreads many times the interval draw times well before now: after
        // each tick, no timer is left set for a time at or before it
        let wide: Vec<CrontabLine> = (0..20)
            .map(|i| ping_line(2000 + i, 7, i as i64, 2_000_000_000, 120, "192.0.2.2"))
            .collect();
        let mut lines = Lines::default();
        lines.synchronize(crontab(CRONS_7, &wide), at(now));
        let mut records = 0;
        for tick in now..now + 300 {
            records += lines.take_due(at(tick)).inconsistent.len();
            for line in &wide {
                let task = lines.line(CRONS_7, line).unwrap();
                assert!(
                    !task.is_due(at(tick)),
                    "{} left due at {tick}",
                    task.next_run
                );
            }
        }
        assert!(records > 0, "draws more than 10 s back give records");
    }

    /// A job of Starla's own keeps RunJob's rule — its slots are eperd's —
    /// but gives no record: eperd's names a line of its crontab by its
    /// command, which a JSON job does not have.
    #[test]
    fn a_job_of_its_own_more_than_10_s_late_waits_for_its_next_slot_without_a_record() {
        let now = 1_791_836_000;
        // `interval 60, start 0`: its first slot after now
        let slot = 1_791_836_040;
        let job = ping_line(7, 60, 0, 0, 0, "192.0.2.7").job;
        let mut lines = Lines::default();
        lines.schedule(job.clone(), at(now));
        assert_eq!(lines.take_due(at(slot + 9)).jobs.len(), 1);

        let mut lines = Lines::default();
        lines.schedule(job, at(now));
        let due = lines.take_due(at(slot + 11));
        assert!(due.jobs.is_empty() && due.inconsistent.is_empty());
        let ran: Vec<i64> = runs(&mut lines, slot + 12, slot + 120)
            .into_iter()
            .map(|(at, _)| at)
            .collect();
        assert_eq!(ran, vec![slot + 60, slot + 120]);

        // Past its end once its late timer fires, it goes
        let mut ending = ping_line(8, 60, 0, 0, 0, "192.0.2.8").job;
        ending.end_time = slot + 5;
        lines.schedule(ending, at(now));
        assert_eq!(lines.len(), 2);
        let due = lines.take_due(at(slot + 11));
        assert!(due.jobs.is_empty() && due.inconsistent.is_empty());
        assert_eq!(lines.len(), 1);
    }

    /// A wall clock stepped back by more than 10 s: the line's timer, a wait
    /// on the monotonic clock (libevent's, event_add, eperd.c:776), runs out
    /// at its time less the step by the wall clock; RunJob finds now <
    /// nexttime - 10, writes its record and draws the first cycle after now
    /// (eperd.c:1268-1310), and the line runs on from there, once a cycle.
    /// Starla's timer was the wall clock reaching next_run, which a clock
    /// stepped back an hour put off for that hour: here, the record and four
    /// runs of a 900 s line.
    #[test]
    fn a_clock_stepped_back_gives_eperds_record_and_runs_on_the_new_slots() {
        let slot = 1_791_836_412;
        let line = ping_line(1001, 900, 312, 2_000_000_000, 0, "193.0.14.129");
        let mut lines = Lines::default();
        lines.synchronize(
            crontab(CRONS_7, std::slice::from_ref(&line)),
            at(slot - 400),
        );
        let (ran, records) = ticks(&mut lines, slot - 400, slot - 100);
        assert!(ran.is_empty() && records.is_empty());
        // A second on, the wall clock steps back 3601 s; the monotonic clock
        // goes on. The timer's wait, 400 s from slot - 400, runs out at
        // slot - 3601 by the stepped clock.
        let stepped = Now {
            wall: slot - 3_700,
            usec: 0,
            mono: at(slot - 99).mono,
        };
        let (ran, records) = ticks_from(&mut lines, stepped, slot - 1);
        assert_eq!(
            records,
            vec![record(
                slot - 3_601,
                slot,
                400,
                1_990_929,
                slot - 400,
                &line
            )]
        );
        let ran: Vec<i64> = ran.into_iter().map(|(at, _)| at).collect();
        assert_eq!(
            ran,
            vec![slot - 3_600, slot - 2_700, slot - 1_800, slot - 900]
        );

        // Stepped back by up to 10 s, the timer fires as much early, and
        // RunJob runs the line; by 11 s, its record (eperd.c:1268)
        for (step, runs) in [(10, true), (11, false)] {
            let mut lines = Lines::default();
            lines.synchronize(
                crontab(CRONS_7, std::slice::from_ref(&line)),
                at(slot - 400),
            );
            let stepped = Now {
                wall: slot - 100 - step,
                usec: 0,
                mono: at(slot - 100).mono,
            };
            let (ran, records) = ticks_from(&mut lines, stepped, slot - step);
            let ran: Vec<i64> = ran.into_iter().map(|(at, _)| at).collect();
            if runs {
                assert_eq!(ran, vec![slot - step], "stepped back {step} s");
                assert!(records.is_empty(), "stepped back {step} s");
            } else {
                assert!(ran.is_empty(), "stepped back {step} s");
                assert_eq!(
                    records,
                    vec![record(slot - step, slot, 400, 1_990_929, slot - 400, &line)]
                );
            }
        }
    }
}
