//! CPU priorities of the probe's threads.
//!
//! The probe's background threads (the controller's SSH session, telnet,
//! uploads, host telemetry, the log writer) run at a lower priority than
//! its measurement threads, which run at the unit's own. Only ever lower:
//! raising a priority needs CAP_SYS_NICE, which the probe does not have,
//! and nothing here tries.

/// How many nice levels below the measurement threads the background
/// threads run.
///
/// Within the probe's cgroup (starla.service) the kernel's fair scheduler
/// shares the CPU between the probe's threads by weight, nice 0 weighing
/// 1024 and nice 10 weighing 110 (sched_prio_to_weight): a measurement
/// thread that wakes for a reply runs ahead of a background thread busy on
/// the same CPU instead of queueing behind it for a slice. Russh's
/// 8192-bit group exchange computes for ~0.3 s at every connect and rekey
/// on the background thread; the measurement threads take their replies
/// meanwhile.
pub const BACKGROUND_NICE_INCREMENT: i32 = 10;

/// The highest nice value Linux has.
#[cfg(target_os = "linux")]
const LOWEST_PRIORITY: i32 = 19;

/// A nice value for threads to lower themselves to: a fixed level, so
/// that a thread which started at it — a thread starts at its creator's —
/// stays there rather than going lower again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nice(i32);

impl Nice {
    /// `increment` levels below the calling thread's priority, at most 19.
    /// None where a thread's priority cannot be set on its own.
    ///
    /// On Linux a nice value belongs to a thread, and
    /// `setpriority(PRIO_PROCESS, 0, …)` sets the calling thread's alone
    /// (setpriority(2): "the nice value is a per-thread attribute").
    /// getpriority and setpriority are allowed under the unit's
    /// `SystemCallFilter=@system-service` (setpriority by its @resources).
    /// Elsewhere there is none: macOS's setpriority sets the whole process,
    /// and its per-thread background state also throttles the thread's
    /// network traffic, which would slow the uploads.
    pub fn below_this_thread(increment: i32) -> std::io::Result<Option<Self>> {
        #[cfg(target_os = "linux")]
        {
            let current = this_thread_nice()?;
            Ok(Some(Self(
                current
                    .saturating_add(increment.max(0))
                    .min(LOWEST_PRIORITY),
            )))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = increment;
            Ok(None)
        }
    }

    /// The nice value
    pub fn get(self) -> i32 {
        self.0
    }

    /// Lower the calling thread's priority to this nice value. A thread
    /// already there, or lower, is left as it is: this never raises a
    /// priority. Returns the nice value the thread runs at now.
    pub fn lower_this_thread(self) -> std::io::Result<i32> {
        #[cfg(target_os = "linux")]
        {
            let current = this_thread_nice()?;
            if current >= self.0 {
                return Ok(current);
            }
            // SAFETY: setpriority takes no pointers.
            if unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, self.0) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(self.0)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(self.0)
        }
    }
}

/// The calling thread's nice value.
#[cfg(target_os = "linux")]
pub fn this_thread_nice() -> std::io::Result<i32> {
    // -1 is a nice value as well as getpriority's error: errno tells them
    // apart.
    // SAFETY: __errno_location returns this thread's errno, and getpriority
    // takes no pointers.
    unsafe {
        *libc::__errno_location() = 0;
        let nice = libc::getpriority(libc::PRIO_PROCESS, 0);
        if nice == -1 && *libc::__errno_location() != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(nice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn a_thread_lowers_its_own_priority_and_no_other() {
        let before = this_thread_nice().unwrap();
        let nice = Nice::below_this_thread(BACKGROUND_NICE_INCREMENT)
            .unwrap()
            .unwrap();
        assert_eq!(nice.get(), (before + BACKGROUND_NICE_INCREMENT).min(19));
        let (lowered, child, again) = std::thread::spawn(move || {
            let lowered = nice.lower_this_thread().unwrap();
            // a thread it starts starts where it is, and lowering that one
            // to the same level leaves it there
            let (child, again) = std::thread::spawn(move || {
                let child = this_thread_nice().unwrap();
                (child, nice.lower_this_thread().unwrap())
            })
            .join()
            .unwrap();
            (lowered, child, again)
        })
        .join()
        .unwrap();
        assert_eq!(
            (lowered, child, again),
            (nice.get(), nice.get(), nice.get())
        );
        assert_eq!(this_thread_nice().unwrap(), before, "only its own thread");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn never_raises() {
        let before = this_thread_nice().unwrap();
        let higher = Nice((before - 1).max(-20));
        std::thread::spawn(move || {
            assert_eq!(higher.lower_this_thread().unwrap(), before);
            assert_eq!(this_thread_nice().unwrap(), before);
            // a negative increment is none
            let same = Nice::below_this_thread(-10).unwrap().unwrap();
            assert_eq!(same.get(), before);
        })
        .join()
        .unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn elsewhere_nothing_is_set() {
        assert_eq!(Nice::below_this_thread(10).unwrap(), None);
    }
}
