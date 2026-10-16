//! The `[measurements] honor_ntp_kod` option, off by default: an NTP
//! server's kiss-o'-death codes, honoured as RFC 5905 §7.4 asks.
//!
//! evntp (firmware 5130) reports a KoD as it reports any reply — stratum 0,
//! the code as its "ref-id" — and runs the line again on its next slot,
//! however often the server has said RATE or DENY. With the option on,
//! Starla reports each KoD the same way, then holds every run to that
//! server for a while: RATE slows the runs down (the client "MUST
//! immediately reduce its polling interval to that server"), DENY and RSTR
//! stop them (it "MUST ... stop sending packets to that server"). A run
//! that comes during a hold sends nothing and reports
//! `{ "error":"not sent: KoD RATE" }` (or DENY, RSTR) instead of its
//! entries, in the shape of evntp's own errors that send nothing
//! (create_socket's, ntp.c:1225-1238).
//!
//! The hold is on the server's address and port, whichever line and name
//! led there: the server counts our requests by our source address, every
//! line's together, and a name (a pool's) looks up to another server each
//! run, which owes us nothing.
//!
//! Only a KoD that answers one of the run's own requests counts: its origin
//! timestamp is one of their T1s. Anyone could otherwise silence a probe's
//! NTP measurements with forged KoDs, as ntpd's clients could be silenced
//! until 4.2.8p4 checked the same (NTP bug 2901, CVE-2015-7704). The
//! report is unchanged: evntp reports every reply, its origin unchecked.
//!
//! Holds live in memory; a restart forgets them, at the cost of one run.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A RATE's hold: a minute, doubled by each RATE after it with no answer
/// between, up to an hour.
const RATE_FIRST_HOLD: Duration = Duration::from_secs(60);
const RATE_MAX_HOLD: Duration = Duration::from_secs(60 * 60);

/// DENY's and RSTR's hold: a day, then one run to ask again.
const DENY_HOLD: Duration = Duration::from_secs(24 * 60 * 60);

/// How long a server's RATEs are remembered once its hold is over: a RATE
/// after that is a first one again.
const FORGET_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

static ENABLED: AtomicBool = AtomicBool::new(false);

static HOLDS: Mutex<Holds> = Mutex::new(Holds::new());

/// Whether KoDs hold runs: the option as [`set_enabled`] set it; false
/// until then.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Set the option from the config, once at start-up, before any
/// measurement runs.
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
    if on {
        tracing::info!(
            "honor_ntp_kod on: an NTP server's KoD RATE, DENY or RSTR holds the runs to it, \
             as the reference does not"
        );
    }
}

/// The kiss code that holds runs to `server` now, if any: the run sends
/// nothing. None while the option is off.
pub fn held(server: SocketAddr) -> Option<Kiss> {
    if !enabled() {
        return None;
    }
    let kiss = lock().held(server, Instant::now());
    if let Some(kiss) = kiss {
        tracing::debug!("NTP {}: held after KoD {}, not sent", server, kiss.code());
    }
    kiss
}

/// What a run's server said to its requests, for its next runs. Nothing
/// while the option is off.
pub fn heard(server: SocketAddr, said: Said) {
    if enabled() {
        lock().heard(server, said, Instant::now());
    }
}

fn lock() -> std::sync::MutexGuard<'static, Holds> {
    HOLDS.lock().unwrap_or_else(|e| e.into_inner())
}

/// The kiss codes RFC 5905 §7.4 asks a client to act on; the others in
/// its Figure 13 ask nothing of one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kiss {
    /// Rate exceeded: slow down
    Rate,
    /// Access denied: stop
    Deny,
    /// Access denied by local policy: stop
    Rstr,
}

impl Kiss {
    /// The code a stratum-0 reply's reference id carries, if it is one of
    /// these.
    pub fn from_ref_id(ref_id: u32) -> Option<Kiss> {
        match &ref_id.to_be_bytes() {
            b"RATE" => Some(Kiss::Rate),
            b"DENY" => Some(Kiss::Deny),
            b"RSTR" => Some(Kiss::Rstr),
            _ => None,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Kiss::Rate => "RATE",
            Kiss::Deny => "DENY",
            Kiss::Rstr => "RSTR",
        }
    }

    /// DENY and RSTR stop the runs, RATE slows them.
    fn stops(self) -> bool {
        self != Kiss::Rate
    }
}

/// What a run's server said to the run's own requests: replies whose origin
/// timestamp is the T1 of one of them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Said {
    /// No reply to a request of the run: they all timed out, or none went
    #[default]
    Nothing,
    /// Replies, none of them a kiss code above (another kiss code, INIT
    /// say, is an answer too)
    Answered,
    /// A kiss code: the one that stops, if one did
    Kissed(Kiss),
}

impl Said {
    /// The run's word so far, `reply` heard too: a kiss code over an
    /// answer, one that stops over RATE.
    pub fn and(self, reply: Said) -> Said {
        if reply.weight() > self.weight() {
            reply
        } else {
            self
        }
    }

    fn weight(self) -> u8 {
        match self {
            Said::Nothing => 0,
            Said::Answered => 1,
            Said::Kissed(Kiss::Rate) => 2,
            Said::Kissed(_) => 3,
        }
    }
}

/// A server's hold, and the RATEs that made it
#[derive(Debug)]
struct Hold {
    until: Instant,
    kiss: Kiss,
    /// RATEs in a row, each after the hold before it was over
    rates: u32,
}

/// The servers whose runs are held, or were lately
#[derive(Debug)]
struct Holds(BTreeMap<SocketAddr, Hold>);

impl Holds {
    const fn new() -> Self {
        Holds(BTreeMap::new())
    }

    fn held(&self, server: SocketAddr, now: Instant) -> Option<Kiss> {
        self.0
            .get(&server)
            .filter(|hold| now < hold.until)
            .map(|hold| hold.kiss)
    }

    fn heard(&mut self, server: SocketAddr, said: Said, now: Instant) {
        self.0.retain(|_, hold| now < hold.until + FORGET_AFTER);
        match said {
            Said::Nothing => {}
            Said::Answered => {
                // An answer to a run that started before the hold came
                // does not lift it.
                if self.held(server, now).is_none() && self.0.remove(&server).is_some() {
                    tracing::info!("NTP {}: answered after a KoD, runs no longer held", server);
                }
            }
            Said::Kissed(kiss) => {
                let hold = self.0.entry(server).or_insert(Hold {
                    until: now,
                    kiss,
                    rates: 0,
                });
                if kiss.stops() {
                    hold.until = hold.until.max(now + DENY_HOLD);
                } else if now < hold.until {
                    // A RATE to a run that started before the hold came, or
                    // during a DENY's: the hold already answers it.
                    return;
                } else {
                    hold.rates += 1;
                    hold.until = now + rate_hold(hold.rates);
                }
                hold.kiss = kiss;
                tracing::info!(
                    "NTP {}: KoD {}, runs to it held for {} s",
                    server,
                    kiss.code(),
                    (hold.until - now).as_secs()
                );
            }
        }
    }
}

/// The hold after the `in_a_row`th RATE in a row: a minute, doubled by
/// each RATE after the first, up to an hour.
fn rate_hold(in_a_row: u32) -> Duration {
    let doublings = in_a_row.saturating_sub(1).min(16);
    RATE_FIRST_HOLD
        .saturating_mul(1 << doublings)
        .min(RATE_MAX_HOLD)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(port: u16) -> SocketAddr {
        SocketAddr::new("192.0.2.1".parse().unwrap(), port)
    }

    const MIN: Duration = Duration::from_secs(60);

    #[test]
    fn only_rate_deny_and_rstr_are_kiss_codes_to_act_on() {
        let id = |code: &[u8; 4]| u32::from_be_bytes(*code);
        assert_eq!(Kiss::from_ref_id(id(b"RATE")), Some(Kiss::Rate));
        assert_eq!(Kiss::from_ref_id(id(b"DENY")), Some(Kiss::Deny));
        assert_eq!(Kiss::from_ref_id(id(b"RSTR")), Some(Kiss::Rstr));
        for other in [b"INIT", b"STEP", b"rate", b"GPS\0", b"XRAT"] {
            assert_eq!(Kiss::from_ref_id(id(other)), None);
        }
    }

    /// A run's replies, in any order: a kiss code wins over answers, DENY
    /// and RSTR over RATE, and silence changes nothing.
    #[test]
    fn a_runs_word_is_its_strongest_reply() {
        use Said::*;
        let run = |replies: &[Said]| replies.iter().fold(Nothing, |s, &r| s.and(r));
        assert_eq!(run(&[]), Nothing);
        assert_eq!(run(&[Nothing, Nothing]), Nothing);
        assert_eq!(run(&[Nothing, Answered, Nothing]), Answered);
        assert_eq!(run(&[Answered, Kissed(Kiss::Rate)]), Kissed(Kiss::Rate));
        assert_eq!(run(&[Kissed(Kiss::Rate), Answered]), Kissed(Kiss::Rate));
        assert_eq!(
            run(&[Kissed(Kiss::Rate), Kissed(Kiss::Deny)]),
            Kissed(Kiss::Deny)
        );
        assert_eq!(
            run(&[Kissed(Kiss::Rstr), Kissed(Kiss::Rate), Answered]),
            Kissed(Kiss::Rstr)
        );
    }

    #[test]
    fn rate_holds_double_from_a_minute_to_an_hour() {
        let secs = |n| rate_hold(n).as_secs();
        assert_eq!(
            [1, 2, 3, 4, 5, 6, 7].map(secs),
            [60, 120, 240, 480, 960, 1920, 3600]
        );
        assert_eq!(secs(u32::MAX), 3600);
    }

    /// Each RATE that comes once the hold before it is over doubles the
    /// next; an answer lifts the hold and starts the count again.
    #[test]
    fn rates_in_a_row_hold_longer_until_an_answer() {
        let t0 = Instant::now();
        let mut holds = Holds::new();
        let s = server(123);
        assert_eq!(holds.held(s, t0), None);

        holds.heard(s, Said::Kissed(Kiss::Rate), t0);
        assert_eq!(holds.held(s, t0), Some(Kiss::Rate));
        assert_eq!(
            holds.held(s, t0 + MIN - Duration::from_millis(1)),
            Some(Kiss::Rate)
        );
        assert_eq!(holds.held(s, t0 + MIN), None);

        let t1 = t0 + 3 * MIN;
        holds.heard(s, Said::Kissed(Kiss::Rate), t1);
        assert_eq!(
            holds.held(s, t1 + 2 * MIN - Duration::from_millis(1)),
            Some(Kiss::Rate)
        );
        assert_eq!(holds.held(s, t1 + 2 * MIN), None);

        let t2 = t1 + 10 * MIN;
        holds.heard(s, Said::Answered, t2);
        holds.heard(s, Said::Kissed(Kiss::Rate), t2);
        assert_eq!(
            holds.held(s, t2 + MIN),
            None,
            "a first RATE again: a minute"
        );
    }

    /// Two lines to one server, both started before its first RATE: the
    /// second RATE is the same word, and does not double the hold; nor does
    /// the other's answer lift it.
    #[test]
    fn a_kiss_or_answer_to_a_run_from_before_the_hold_changes_nothing() {
        let t0 = Instant::now();
        let mut holds = Holds::new();
        let s = server(123);
        holds.heard(s, Said::Kissed(Kiss::Rate), t0);
        holds.heard(s, Said::Kissed(Kiss::Rate), t0 + Duration::from_secs(4));
        holds.heard(s, Said::Answered, t0 + Duration::from_secs(8));
        assert_eq!(
            holds.held(s, t0 + MIN - Duration::from_millis(1)),
            Some(Kiss::Rate)
        );
        assert_eq!(holds.held(s, t0 + MIN), None);
    }

    /// DENY and RSTR hold a day, over any RATE hold, and a RATE during
    /// them neither shortens nor relabels them.
    #[test]
    fn deny_and_rstr_hold_a_day() {
        let t0 = Instant::now();
        let day = Duration::from_secs(24 * 60 * 60);
        for kiss in [Kiss::Deny, Kiss::Rstr] {
            let mut holds = Holds::new();
            let s = server(123);
            holds.heard(s, Said::Kissed(Kiss::Rate), t0);
            holds.heard(s, Said::Kissed(kiss), t0 + Duration::from_secs(1));
            holds.heard(s, Said::Kissed(Kiss::Rate), t0 + Duration::from_secs(2));
            let end = t0 + Duration::from_secs(1) + day;
            assert_eq!(holds.held(s, end - Duration::from_millis(1)), Some(kiss));
            assert_eq!(holds.held(s, end), None);
        }
    }

    /// A hold is the server's address and port: another server, or the
    /// same address on another port, is not held.
    #[test]
    fn a_hold_is_one_servers() {
        let t0 = Instant::now();
        let mut holds = Holds::new();
        holds.heard(server(123), Said::Kissed(Kiss::Deny), t0);
        assert_eq!(holds.held(server(123), t0), Some(Kiss::Deny));
        assert_eq!(holds.held(server(1123), t0), None);
        let other = SocketAddr::new("192.0.2.2".parse().unwrap(), 123);
        assert_eq!(holds.held(other, t0), None);
    }

    /// A run that heard nothing — every request timed out — neither holds
    /// nor lifts a hold; and a server's RATEs are forgotten a day after its
    /// hold.
    #[test]
    fn silence_changes_nothing_and_old_rates_are_forgotten() {
        let t0 = Instant::now();
        let mut holds = Holds::new();
        let s = server(123);
        holds.heard(s, Said::Nothing, t0);
        assert!(holds.0.is_empty());

        holds.heard(s, Said::Kissed(Kiss::Rate), t0);
        holds.heard(s, Said::Nothing, t0 + Duration::from_secs(1));
        assert_eq!(holds.held(s, t0 + Duration::from_secs(1)), Some(Kiss::Rate));

        let later = t0 + MIN + FORGET_AFTER;
        holds.heard(server(9), Said::Nothing, later);
        assert!(holds.0.is_empty(), "{:?}", holds.0);
        holds.heard(s, Said::Kissed(Kiss::Rate), later);
        assert_eq!(holds.held(s, later + MIN), None, "a first RATE again");
    }
}
