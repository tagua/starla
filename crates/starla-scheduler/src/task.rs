//! Measurement Scheduler

use super::MeasurementJob;
use rand::RngExt;
use std::fmt::Write;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A recurring measurement on the reference probe's (eperd's) slots: cycle
/// `k` runs at `start_time + k * interval`, moved by a uniform offset in
/// `[-spread/2, +spread/2]` drawn afresh each cycle. The first run is the
/// first slot after the task was loaded, never "now", so a restart does not
/// run every measurement at once (2026-10-12: three restarts in 30 min sent
/// RIPE three runs of daily measurements within the half hour).
///
/// Its timer is eperd's line timer: set_timeout sets it for `next_run`
/// (eperd.c:736-776), and when it fires RunJob runs the line, or, more than
/// 10 s from `next_run`, runs nothing and writes its "inconsistent time"
/// record (eperd.c:1245-1339; [`ScheduledTask::fire`]). Starla's timer is
/// the scheduler's 1 s tick finding wall-clock now at or past `next_run`,
/// or the monotonic clock past the wait set_timeout set it for
/// ([`ScheduledTask::is_due`]).
pub struct ScheduledTask {
    pub id: u64,
    pub interval: u64,
    pub start_time: i64,
    pub end_time: i64,
    pub spread: u64,
    /// The job specification - DNS resolution happens at execution time
    pub job: MeasurementJob,
    /// The cycle `next_run` belongs to (eperd's nextcycle)
    pub cycle: i64,
    /// The cycle's slot moved by its offset (eperd's nexttime)
    pub next_run: i64,
    /// The timer is set (eperd's line->event pending). set_timeout sets it
    /// unless the line has expired (eperd.c:741-742); once it has fired,
    /// only set_timeout sets it again.
    armed: bool,
    /// When the timer was last set (debug_generated, eperd.c:772) and the
    /// whole seconds it was set to wait (waittime, :775), for RunJob's
    /// record
    generated: i64,
    waittime: i64,
    /// When the wait set_timeout set runs out on the monotonic clock: the
    /// timeout libevent counts, event_add(&line->event, &tv)
    /// (eperd.c:756-776)
    deadline: Instant,
}

/// A moment as eperd's loop sees one: the wall clock, which set_timeout and
/// RunJob read (gettimeofday, eperd.c:739, 1264), and the monotonic clock,
/// on which libevent 2.1 counts a timeout's wait (configure.ac:176). Read
/// together ([`Now::read`]); tests make their own, to step one clock and
/// not the other.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Now {
    /// Unix seconds
    pub wall: i64,
    pub mono: Instant,
}

impl Now {
    /// The two clocks, now: the wall clock first, so that a wait counted
    /// from the monotonic moment never runs out before the wall clock
    /// reaches its end.
    pub(crate) fn read() -> Self {
        let wall = unix_now();
        Self {
            wall,
            mono: Instant::now(),
        }
    }
}

/// A test's moment at `wall` with clocks that go together: the monotonic
/// clock as far on from a base of its own as the wall clock is from the
/// epoch, so a wait runs out as the wall clock reaches its end.
#[cfg(test)]
pub(crate) fn at(wall: i64) -> Now {
    static BASE: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let base = *BASE.get_or_init(Instant::now);
    Now {
        wall,
        mono: base + Duration::from_secs(u64::try_from(wall).expect("a test's wall clock")),
    }
}

/// What RunJob does when a line's timer fires (eperd.c:1245-1339).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Fired {
    /// The timer is not set, or its time has not come
    NotYet,
    /// Run the job: the next cycle is drawn and the timer set for it
    Run,
    /// Past its end time: runs no more, the timer not set again
    /// (eperd.c:1313-1317)
    Expired,
    /// More than 10 s from its time: not run; its record, and the first
    /// cycle after now drawn (eperd.c:1268-1310)
    Inconsistent(InconsistentTime),
}

impl ScheduledTask {
    pub fn new(
        id: u64,
        interval: u64,
        start_time: i64,
        end_time: i64,
        spread: u64,
        job: MeasurementJob,
    ) -> Self {
        Self::new_at(Now::read(), id, interval, start_time, end_time, spread, job)
    }

    /// Start(): set_timeout(line, 1) (eperd.c:838-848). A line already past
    /// its end time is left as SynchronizeFile's xzalloc left it (:568):
    /// cycle 0, no offset, its timer not set.
    pub(crate) fn new_at(
        now: Now,
        id: u64,
        interval: u64,
        start_time: i64,
        end_time: i64,
        spread: u64,
        job: MeasurementJob,
    ) -> Self {
        let mut task = Self {
            id,
            interval,
            start_time,
            end_time,
            spread,
            job,
            cycle: 0,
            next_run: start_time,
            armed: false,
            generated: 0,
            waittime: 0,
            deadline: now.mono,
        };
        task.draw_cycle(now);
        task
    }

    /// Whether the timer fires at `now`: once it is set, when the wall
    /// clock reaches `next_run` — Starla's 1 s tick — or when the wait
    /// set_timeout set it with has passed on the monotonic clock, as
    /// libevent's timeout fires (eperd.c:756-776), whichever comes first.
    ///
    /// The two agree while neither clock jumps: the deadline is the wait in
    /// whole seconds from the second set_timeout read, so it runs out up to
    /// a second after the wall clock reaches `next_run`, never before. A
    /// suspend stops the monotonic clock (CLOCK_MONOTONIC on Linux,
    /// CLOCK_UPTIME_RAW on macOS), so after one the wall clock is first: a
    /// line whose time the suspend passed over fires at the wake, more than
    /// 10 s late. A wall clock stepped back by X leaves the deadline where
    /// it was: the timer fires then, X early by the wall clock, as eperd's.
    pub(crate) fn is_due(&self, now: Now) -> bool {
        self.armed && (self.next_run <= now.wall || now.mono >= self.deadline)
    }

    /// RunJob, if the timer fires at `now` (eperd.c:1245-1339):
    ///
    /// - more than 10 s from `next_run`, either way, the time is
    ///   inconsistent: the job does not run, the line's record is returned,
    ///   and the first cycle after now is drawn, a new offset with it
    ///   (set_timeout(line, 1), :1268-1310). Late, it is a host suspended,
    ///   a process stalled or a clock stepped forward; early, a clock
    ///   stepped back, under the timer's monotonic wait. Within 10 s it
    ///   runs: the tick that takes a line comes up to a second after its
    ///   time.
    /// - past its end time, the line runs no more and its timer is not set
    ///   again (:1313-1317). eperd asks this of now, the moment its timer
    ///   fired: `next_run` to the microsecond when the wall clock reached
    ///   it, which Starla asks rather than the tick that took it, and now
    ///   itself when the monotonic wait ran out first.
    /// - otherwise it runs, and its next cycle is drawn — or, if that
    ///   cycle's slot has passed, the first after now (:1328-1338).
    ///
    /// A gap in time — a suspend, which stops the monotonic clock, or a
    /// clock stepped forward — moves every eperd timer off the wall clock
    /// by the gap, until the line is drawn again or a push sets its timer
    /// again (Insert): each line whose timer fires meanwhile gives a
    /// record. Here only the lines whose time the gap passed over do; the
    /// others run on their slots, the wall clock reaching their times
    /// before their monotonic waits run out.
    pub(crate) fn fire(&mut self, now: Now) -> Fired {
        if !self.is_due(now) {
            return Fired::NotYet;
        }
        self.armed = false;
        if now.wall < self.next_run - TIME_SLACK || now.wall > self.next_run + TIME_SLACK {
            let times = InconsistentTime {
                now: now.wall,
                nexttime: self.next_run,
                waittime: self.waittime,
                cycle: self.cycle,
                generated: self.generated,
            };
            self.draw_cycle(now);
            return Fired::Inconsistent(times);
        }
        if self.is_expired(self.next_run.min(now.wall)) {
            return Fired::Expired;
        }
        self.cycle += 1;
        if slot(self.start_time, self.interval, self.cycle) < now.wall {
            self.cycle = first_cycle_after(now.wall, self.start_time, self.interval);
        }
        self.next_run =
            slot(self.start_time, self.interval, self.cycle) + uniform_offset(self.spread);
        self.set_timeout(now);
        Fired::Run
    }

    /// A crontab repeats this line, with `end_time`. Insert() takes the end
    /// time and sets the line's timer again for the time it had,
    /// set_timeout(oldLine, 0) (eperd.c:815-824): the line keeps its cycle
    /// and offset. A line that had stopped — its timer fired past its old
    /// end time, and RunJob did not set it again (eperd.c:1313-1317) — is
    /// set again too, for a time that may have long passed: then the timer
    /// fires at once and RunJob, finding the time more than 10 s from
    /// nexttime, writes its record, runs nothing and draws the first cycle
    /// after now (eperd.c:1268-1310): [`fire`](Self::fire) in the push's
    /// own second (Scheduler::synchronize_at).
    /// Such a line does not run between slots.
    pub(crate) fn take_end_time(&mut self, end_time: i64, now: Now) {
        self.end_time = end_time;
        self.job.end_time = end_time;
        self.set_timeout(now);
    }

    /// A test's draw: this cycle's time moved to `next_run`, and the timer
    /// set for it at `now`, as do_distr and set_timeout(line, 0) would
    /// leave them — its monotonic wait with it.
    #[cfg(test)]
    pub(crate) fn set_next_run(&mut self, next_run: i64, now: Now) {
        self.next_run = next_run;
        self.set_timeout(now);
    }

    /// Check if the task has expired (past its end time)
    pub fn is_expired(&self, now: i64) -> bool {
        self.end_time > 0 && now > self.end_time
    }

    /// eperd's set_timeout(line, 1) (eperd.c:744-754): the first cycle
    /// after `now`, its offset drawn afresh (do_distr, :489-511), and the
    /// timer set for it — none of it once the line has expired (:741-742).
    fn draw_cycle(&mut self, now: Now) {
        if self.is_expired(now.wall) {
            return;
        }
        self.cycle = first_cycle_after(now.wall, self.start_time, self.interval);
        self.next_run =
            slot(self.start_time, self.interval, self.cycle) + uniform_offset(self.spread);
        self.set_timeout(now);
    }

    /// eperd's set_timeout(line, 0) (eperd.c:736-776): unless the line has
    /// expired, its timer is set for `next_run`, and when and for how long
    /// are kept for RunJob's record. The wait is the timeval set_timeout
    /// arms, tv_sec: nexttime less now, less a second when the offset's
    /// microseconds are fewer than now's (:756-763), 0 if that is negative
    /// (:764-765). Starla's offsets are whole seconds (do_distr adds
    /// random() % 1000000 µs, :507; Starla's lines run on a 1 s tick) and
    /// it reads the clock in whole seconds, the moment itself being some
    /// way into that second: always the second less.
    ///
    /// The timer's monotonic deadline is the wait event_add counts
    /// (:776): `next_run` less the second read, from the monotonic moment
    /// read with it — 0 for a time already past, which fires at once.
    fn set_timeout(&mut self, now: Now) {
        if self.is_expired(now.wall) {
            return;
        }
        self.armed = true;
        self.generated = now.wall;
        self.waittime = (self.next_run - now.wall - 1).max(0);
        self.deadline = now.mono + Duration::from_secs((self.next_run - now.wall).max(0) as u64);
    }
}

/// How far from its time RunJob still runs a line (eperd.c:1268): further,
/// the time is "inconsistent", and the line's cycle is drawn again.
const TIME_SLACK: i64 = 10;

/// eperd's `-A`, the id of its own records: `eperd -c $CRON_DIR/7 -A 9807
/// … -O $ATLAS_DATA/new/7` (bin/ripe-atlas.in:130-133).
pub(crate) const EPERD_ID: u64 = 9807;

/// The times RunJob's "inconsistent time" record gives of a line whose
/// timer fired more than 10 s from its time (eperd.c:1268-1303).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InconsistentTime {
    /// When the timer fired
    pub now: i64,
    /// The time it was set for
    pub nexttime: i64,
    /// The wait it was set with, in whole seconds
    pub waittime: i64,
    /// The cycle it was set for (debug_cycle)
    pub cycle: i64,
    /// When it was set (debug_generated)
    pub generated: i64,
}

impl InconsistentTime {
    /// The record RunJob appends to eperd's out file, data/new/7
    /// (eperd.c:1278-1301), less its `RESULT { ` and ` }\n`, which the
    /// results crate puts around a whole line's body (FullLine):
    ///
    /// `RESULT { "id":"9807", "fw":5130, "mver": "2.6.4", "time":<now>,
    /// "reason": "inconsistent time; now <now>; nexttime <t>; waittime <w>;
    /// cycle <c>; generated <g>", "cmd": "<the line's command>" }`
    ///
    /// "time" is time(NULL) there, the same second as now; the version is
    /// atlas_get_version_json_str() (libbb/atlas_version.c:56-64); `cmd` is
    /// the line's cl_Shell, escaped byte by byte: `"` and `\` behind a
    /// backslash, printable ASCII as it is, any other byte as `\u00XX`
    /// (isprint_asciionly, include/libbb.h:2175).
    pub(crate) fn record_body(&self, cmd: &str) -> String {
        let mut body = format!(
            "\"id\":\"{EPERD_ID}\", \"fw\":{}, \"mver\": \"2.6.4\", \"time\":{}, \
             \"reason\": \"inconsistent time; now {}; nexttime {}; waittime {}; cycle {}; \
             generated {}\", \"cmd\": \"",
            starla_common::FIRMWARE_VERSION,
            self.now,
            self.now,
            self.nexttime,
            self.waittime,
            self.cycle,
            self.generated,
        );
        for &c in cmd.as_bytes() {
            match c {
                b'"' | b'\\' => {
                    body.push('\\');
                    body.push(c as char);
                }
                0x20..=0x7e => body.push(c as char),
                _ => write!(body, "\\u{c:04x}").unwrap(),
            }
        }
        body.push('"');
        body
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// eperd's set_timeout: cycle 0 while `start_time` is still ahead, else the
/// first cycle whose slot is strictly after `now`.
fn first_cycle_after(now: i64, start_time: i64, interval: u64) -> i64 {
    if interval == 0 || now < start_time {
        0
    } else {
        now.saturating_sub(start_time) / interval as i64 + 1
    }
}

fn slot(start_time: i64, interval: u64, cycle: i64) -> i64 {
    start_time.saturating_add(cycle.saturating_mul(interval as i64))
}

/// eperd's do_distr for UNIFORM: an integer in `[0, spread]`, less
/// `spread / 2`.
fn uniform_offset(spread: u64) -> i64 {
    if spread == 0 {
        return 0;
    }
    rand::rng().random_range(0..=spread) as i64 - (spread / 2) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::{MeasurementSpec, PingJobSpec};

    fn job() -> MeasurementJob {
        MeasurementJob {
            msm_id: 1001,
            interval: 900,
            start_time: 312,
            end_time: 2_000_000_000,
            spread: 0,
            spec: MeasurementSpec::Ping(PingJobSpec {
                target: "193.0.14.129".into(),
                af: 4,
                packets: 3,
                packet_interval: 1000,
                size: 48,
                kept: Default::default(),
            }),
        }
    }

    fn task(now: i64, interval: u64, start_time: i64, spread: u64) -> ScheduledTask {
        ScheduledTask::new_at(
            at(now),
            1,
            interval,
            start_time,
            2_000_000_000,
            spread,
            job(),
        )
    }

    #[test]
    fn a_loaded_task_waits_for_its_next_slot() {
        // CRONLINE 900 312 …, loaded at 1791836000: slots are 312 + k*900.
        let now = 1_791_836_000;
        let t = task(now, 900, 312, 0);
        assert_eq!(t.next_run, 1_791_836_412);
        assert!(!t.is_due(at(now)), "a restart must not run it at once");

        // A daily one loaded just after its slot waits a day.
        let t = task(now, 86_400, 1_791_835_990, 0);
        assert_eq!(t.next_run, 1_791_835_990 + 86_400);

        // A start time still ahead is the first slot.
        let t = task(now, 900, now + 5_000, 0);
        assert_eq!(t.next_run, now + 5_000);

        // One loaded past its end time is never set: cycle 0, as xzalloc
        // left it
        let t = ScheduledTask::new_at(at(now), 1, 900, 312, now - 1, 0, job());
        assert_eq!((t.cycle, t.next_run), (0, 312));
        assert!(!t.is_due(at(now + 900)));
    }

    #[test]
    fn runs_advance_slot_by_slot() {
        let now = 1_791_836_000;
        let mut t = task(now, 900, 312, 0);
        let first = t.next_run;
        assert_eq!(t.fire(at(first - 1)), Fired::NotYet);
        assert_eq!(t.fire(at(first)), Fired::Run);
        assert_eq!(t.next_run, first + 900);
        assert_eq!(t.fire(at(first + 1)), Fired::NotYet, "once a cycle");

        // A tick up to 10 s late still runs, on to the next slot
        assert_eq!(t.fire(at(first + 910)), Fired::Run);
        assert_eq!(t.next_run, first + 1_800);

        // A run whose next slot has passed already — a spread wider than
        // the interval — goes on to the first slot after now (eperd.c:
        // 1328-1333)
        let mut t = task(now, 5, 0, 0);
        let first = t.next_run;
        assert_eq!(t.fire(at(first + 9)), Fired::Run);
        assert_eq!(t.next_run, first + 10);
    }

    /// A wall clock stepped back under a set timer: the timer fires when its
    /// wait runs out on the monotonic clock, early by the wall clock, as
    /// libevent's (eperd.c:776). Within 10 s of its time it runs, and its
    /// end time is asked of now, the moment it fired, as RunJob asks it
    /// (eperd.c:1313-1317).
    #[test]
    fn a_timer_fires_when_its_monotonic_wait_runs_out() {
        let now = 1_791_836_000;
        let slot = 1_791_836_412;
        // Its end time 5 s before its time: run at its time, it has expired
        let mut t = ScheduledTask::new_at(at(now), 1, 900, 312, slot - 5, 0, job());
        assert_eq!(t.next_run, slot);
        let stepped = |wall: i64, mono: i64| Now {
            wall,
            mono: at(mono).mono,
        };
        // the wall clock 8 s back: neither clock is there a second before
        assert_eq!(t.fire(stepped(slot - 9, slot - 1)), Fired::NotYet);
        // the wait runs out with the wall clock at slot - 8, before the end
        // time: it runs
        assert_eq!(t.fire(stepped(slot - 8, slot)), Fired::Run);
        assert_eq!(t.next_run, slot + 900);

        // Its wait runs out first, the line runs early by the wall clock;
        // the wall clock first, it runs on time
        let mut t = task(now, 900, 312, 0);
        assert_eq!(t.fire(stepped(slot, slot - 1)), Fired::Run);
    }

    #[test]
    fn the_spread_centres_on_the_slot() {
        let now = 1_791_836_000;
        for _ in 0..200 {
            let t = task(now, 900, 312, 20);
            assert!((t.next_run - 1_791_836_412).abs() <= 10, "{}", t.next_run);
        }
    }

    /// The twin's reference probe after a host sleep (wire comparison
    /// 2026-10-13, W12), on crons/7's `CRONLINE 60 1 2000000000 UNIFORM 14
    /// condmv -A "RESULT 9907 ongoing" /home/atlas/data/new/7
    /// /home/atlas/data/out/7`: its timer, set at 1791936007 for cycle
    /// 29865601 (slot 1791936061, offset -5), fired at 1791936764.
    #[test]
    fn a_timer_more_than_10_s_late_runs_nothing_and_gives_eperds_record() {
        let generated = 1_791_936_007;
        let mut t = ScheduledTask::new_at(at(generated), 1, 60, 1, 2_000_000_000, 14, job());
        assert_eq!(t.cycle, 29_865_601);
        t.next_run = 1_791_936_061 - 5;
        t.set_timeout(at(generated));

        let fired = t.fire(at(1_791_936_764));
        let Fired::Inconsistent(times) = fired else {
            panic!("{fired:?}");
        };
        assert_eq!(
            times,
            InconsistentTime {
                now: 1_791_936_764,
                nexttime: 1_791_936_056,
                waittime: 48,
                cycle: 29_865_601,
                generated: 1_791_936_007,
            }
        );
        let cmd =
            r#"condmv -A "RESULT 9907 ongoing" /home/atlas/data/new/7 /home/atlas/data/out/7"#;
        assert_eq!(
            format!("RESULT {{ {} }}\n", times.record_body(cmd)),
            "RESULT { \"id\":\"9807\", \"fw\":5130, \"mver\": \"2.6.4\", \"time\":1791936764, \
             \"reason\": \"inconsistent time; now 1791936764; nexttime 1791936056; waittime 48; \
             cycle 29865601; generated 1791936007\", \"cmd\": \"condmv -A \\\"RESULT 9907 \
             ongoing\\\" /home/atlas/data/new/7 /home/atlas/data/out/7\" }\n"
        );

        // set_timeout(line, 1): the first cycle after now, its timer set
        assert_eq!(t.cycle, 29_865_613);
        assert!((1_791_936_781 - 7..=1_791_936_781 + 7).contains(&t.next_run));
        assert_eq!(t.fire(at(t.next_run)), Fired::Run);
    }

    #[test]
    fn the_command_is_escaped_byte_by_byte() {
        let times = InconsistentTime {
            now: 5,
            nexttime: 4,
            waittime: 3,
            cycle: 2,
            generated: 1,
        };
        let body = times.record_body("a\"b\\c\td\u{7f}\u{e9}~ ");
        assert!(
            body.ends_with(r#", "cmd": "a\"b\\c\u0009d\u007f\u00c3\u00a9~ ""#),
            "{body}"
        );
    }

    #[test]
    fn a_timer_that_fires_past_the_end_time_stops_the_line() {
        let now = 1_791_836_000;
        let mut t = ScheduledTask::new_at(at(now), 1, 900, 312, 1_791_836_500, 0, job());
        assert_eq!(t.fire(at(1_791_836_412)), Fired::Run);
        // set for the next slot, past the end time
        assert!(t.is_due(at(1_791_837_312)));
        assert_eq!(t.fire(at(1_791_837_312)), Fired::Expired);
        assert!(!t.is_due(at(1_791_837_312 + 900 * 10)));

        // Late, the timer of an expiring line gives its record all the
        // same, as RunJob checks the time first; the line stays stopped
        let mut t = ScheduledTask::new_at(at(now), 1, 900, 312, 1_791_836_500, 0, job());
        assert_eq!(t.fire(at(1_791_836_412)), Fired::Run);
        assert!(matches!(
            t.fire(at(1_791_837_312 + 11)),
            Fired::Inconsistent(InconsistentTime {
                nexttime: 1_791_837_312,
                ..
            })
        ));
        assert_eq!((t.cycle, t.next_run), (1_990_929 + 1, 1_791_837_312));
        assert!(!t.is_due(at(1_791_837_312 + 900 * 10)));
    }
}
