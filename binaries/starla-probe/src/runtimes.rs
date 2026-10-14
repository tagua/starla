//! The probe's two runtimes.
//!
//! Measurements take their timestamps in userspace, when a worker polls the
//! socket a reply has arrived on, and a timer's lateness is when the next
//! probe goes out. So nothing else may hold a measurement worker: on one
//! shared runtime a single long poll elsewhere delayed every reply and timer
//! of the runtime. The audit of 2026-10-14 found two such polls on enodia:
//! russh's DH group exchange (two ~0.3 s modpows at every connect and
//! rekey, hourly) and the crontab pushes (6–11 ms of parsing and logging
//! without an await, 2–4 times an hour). Two runtimes:
//!
//! - The **measurement** runtime ([`measurement`]): the multi-thread runtime
//!   `#[tokio::main]` built, one worker per CPU the probe may use
//!   (available_parallelism: two on enodia, CPUAffinity=5 11), at the
//!   unit's priority. It runs the scheduler and the measurements: their
//!   sockets, timers and name lookups, and nothing else. They hand their
//!   results over without waiting (starla_results::ResultSink).
//! - The **background** runtime ([`spawn_background`]): a current-thread
//!   runtime on a thread of its own, `starla-bg`, at
//!   [`BACKGROUND_NICE_INCREMENT`] nice levels lower. It runs everything
//!   that is not time-sensitive: registration and the controller's SSH
//!   sessions (russh spawns its session task on the runtime that connects,
//!   so connecting there puts the modpows there), telnet and the commands it
//!   brings, the result handler and its uploads, host telemetry, the status
//!   socket, the metrics server and the tray's pause file. One thread is
//!   enough for that work, which waits on the network far more than it
//!   computes, and it keeps the background to one CPU's worth at most: the
//!   measurement workers always have the other.
//!
//! The thread priorities are what makes the split hold when both CPUs are
//! busy: the measurement workers get the larger share. Nice does not make a
//! woken worker preempt the background thread computing on its CPU — that
//! can still hold a reply for up to a scheduler slice, ~3 ms
//! ([`BACKGROUND_NICE_INCREMENT`]) — unless the background runs on
//! SCHED_IDLE too, `[measurements] background_sched_idle`, off by default.
//! A thread starts at its creator's nice value and policy, so the
//! background thread lowers its own before it builds its runtime, to a
//! level fixed from the main thread's, and the runtime's blocking threads
//! (a name lookup for an SSH connect) make sure of the same as they start.
//! The measurement runtime is built first, from the main thread, whose
//! priority nothing lowers; its blocking threads are started by its own
//! workers.

use starla_common::priority::{idle_this_thread, Nice, BACKGROUND_NICE_INCREMENT};
use std::future::Future;
use tracing::{debug, warn};

/// The measurement runtime, one worker per CPU the probe may use, as
/// `#[tokio::main]` made it (TOKIO_WORKER_THREADS still sets the count).
pub fn measurement() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("starla-msm")
        .build()
}

/// Run `main` to its end on the background runtime, a current-thread
/// runtime on a thread of its own (`starla-bg`), at
/// [`BACKGROUND_NICE_INCREMENT`] nice levels below the calling thread, and
/// on SCHED_IDLE as well if `sched_idle`.
pub fn spawn_background<F, Fut, T>(
    sched_idle: bool,
    main: F,
) -> std::io::Result<std::thread::JoinHandle<anyhow::Result<T>>>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<T>>,
    T: Send + 'static,
{
    let nice = Nice::below_this_thread(BACKGROUND_NICE_INCREMENT).unwrap_or_else(|e| {
        warn!("Could not read the main thread's priority: {}", e);
        None
    });
    std::thread::Builder::new()
        .name("starla-bg".into())
        .spawn(move || {
            if let Some(nice) = nice {
                match nice.lower_this_thread() {
                    Ok(now) => debug!(nice = now, "Background thread runs at a lower priority"),
                    Err(e) => warn!("Could not lower the background thread's priority: {}", e),
                }
            }
            if sched_idle {
                match idle_this_thread() {
                    Ok(true) => debug!("Background thread runs on SCHED_IDLE"),
                    Ok(false) => debug!("No SCHED_IDLE here: background_sched_idle ignored"),
                    Err(e) => warn!("Could not put the background thread on SCHED_IDLE: {}", e),
                }
            }
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .thread_name("starla-bg-blk")
                .on_thread_start(move || {
                    if let Some(nice) = nice {
                        if let Err(e) = nice.lower_this_thread() {
                            warn!("Could not lower a background thread's priority: {}", e);
                        }
                    }
                    if sched_idle {
                        if let Err(e) = idle_this_thread() {
                            warn!("Could not put a background thread on SCHED_IDLE: {}", e);
                        }
                    }
                })
                .build()?;
            runtime.block_on(main())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// The measurement runtime of the probe on enodia: two workers
    /// (CPUAffinity=5 11). Here as many as the host has would hide a
    /// stalled worker behind the others.
    fn enodias_measurement_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("starla-msm")
            .build()
            .unwrap()
    }

    /// How long russh's session task computes at a connect or rekey: two
    /// 8192-bit modpows of ~0.3 s each, one after the other.
    const STALL: Duration = Duration::from_millis(300);

    /// A task woken by its socket that then computes for [`STALL`] without
    /// returning, as russh's session task does when the server's group
    /// exchange reply arrives. Sets `ended` when it is done.
    async fn stall_when_woken(socket: tokio::net::UdpSocket, ended: Arc<AtomicBool>) {
        let mut buf = [0u8; 16];
        socket.recv_from(&mut buf).await.unwrap();
        let until = Instant::now() + STALL;
        while Instant::now() < until {
            std::hint::spin_loop();
        }
        ended.store(true, SeqCst);
    }

    /// Wake [`stall_when_woken`]'s socket, from outside any runtime.
    fn wake(to: std::net::SocketAddr) {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.send_to(b"kex", to).unwrap();
    }

    /// While a measurement would run, from before the stall at `to` is
    /// woken until it has `ended` (10 s at most) and 100 ms on: how late a
    /// 10 ms timer fired at worst, and the longest a reply waited to be
    /// read. The replies come as from the network, from a thread outside
    /// any runtime every 5 ms, each with the moment it was sent, so the
    /// receive waits on the socket's readiness — on the I/O driver, as a
    /// measurement's does.
    async fn measure_around(
        to: std::net::SocketAddr,
        ended: Arc<AtomicBool>,
    ) -> (Duration, Duration) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let at = socket.local_addr().unwrap();
        let base = Instant::now();
        let measuring = Arc::new(AtomicBool::new(true));
        let sender = std::thread::spawn({
            let measuring = Arc::clone(&measuring);
            move || {
                let from = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                // one more after the measuring, for the receive to take
                let mut last = false;
                while !last {
                    last = !measuring.load(SeqCst);
                    let sent = base.elapsed().as_nanos() as u64;
                    from.send_to(&sent.to_be_bytes(), at).unwrap();
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        });
        let timer = tokio::spawn({
            let measuring = Arc::clone(&measuring);
            async move {
                let mut late = Duration::ZERO;
                while measuring.load(SeqCst) {
                    let t = Instant::now();
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    late = late.max(t.elapsed().saturating_sub(Duration::from_millis(10)));
                }
                late
            }
        });
        let replies = tokio::spawn({
            let measuring = Arc::clone(&measuring);
            async move {
                let mut waited = Duration::ZERO;
                let mut buf = [0u8; 8];
                while measuring.load(SeqCst) {
                    socket.recv_from(&mut buf).await.unwrap();
                    let sent = Duration::from_nanos(u64::from_be_bytes(buf));
                    waited = waited.max(base.elapsed().saturating_sub(sent));
                }
                waited
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        wake(to);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ended.load(SeqCst) {
            assert!(Instant::now() < deadline, "the stall never ended");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        measuring.store(false, SeqCst);
        let measured = (timer.await.unwrap(), replies.await.unwrap());
        sender.join().unwrap();
        measured
    }

    /// Russh's group exchange stalls the runtime it runs on for ~0.3 s at
    /// every connect and rekey. On the background runtime, the
    /// measurements go on meanwhile: a 10 ms timer fires on time and a
    /// reply is read as it arrives. The bound, half the stall, leaves room
    /// for a loaded host, where scheduling alone has held a thread 75 ms;
    /// a measurement held by the stall waits most of it
    /// ([`control_a_stall_on_the_measurement_runtime_holds_its_replies`]).
    ///
    /// On one shared two-worker runtime the same stall, woken by its
    /// socket, held another task's 10 ms timer ~0.29 s, 11 times out of 11
    /// on an idle Mac: the worker that held the I/O and timer driver ran
    /// the woken task from its LIFO slot, which no other worker may steal,
    /// so no other worker was woken to take the driver while it computed.
    /// On a loaded host another worker sometimes held the driver, so that
    /// is not asserted here.
    #[test]
    fn a_background_stall_does_not_delay_a_measurement() {
        let measurement = enodias_measurement_runtime();
        let (bound, socket) = std::sync::mpsc::channel();
        let ended = Arc::new(AtomicBool::new(false));
        let background = spawn_background(false, {
            let ended = Arc::clone(&ended);
            move || async move {
                let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
                bound.send(socket.local_addr()?).unwrap();
                tokio::spawn(stall_when_woken(socket, ended)).await?;
                Ok(())
            }
        })
        .unwrap();
        let to = socket.recv().unwrap();
        let (timer, reply) = measurement.block_on(measure_around(to, ended));
        background.join().unwrap().unwrap();
        eprintln!("split runtimes: timer {timer:?} late, a reply waited {reply:?}");
        assert!(timer < STALL / 2, "a 10 ms timer fired {timer:?} late");
        assert!(reply < STALL / 2, "a reply waited {reply:?} to be read");
    }

    /// The control, run by hand (`--ignored`): the same stall on the
    /// measurement runtime itself holds its replies — the receive half of
    /// the test above measures what it should. Not in the gate: on a
    /// loaded host another worker sometimes holds the driver.
    #[test]
    #[ignore = "a control, run by hand"]
    fn control_a_stall_on_the_measurement_runtime_holds_its_replies() {
        let measurement = enodias_measurement_runtime();
        let ended = Arc::new(AtomicBool::new(false));
        let (timer, reply) = measurement.block_on(async {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let to = socket.local_addr().unwrap();
            let stall = tokio::spawn(stall_when_woken(socket, Arc::clone(&ended)));
            let measured = measure_around(to, ended).await;
            stall.await.unwrap();
            measured
        });
        eprintln!("shared runtime: timer {timer:?} late, a reply waited {reply:?}");
        assert!(reply > STALL / 2, "a reply waited {reply:?}");
    }

    /// The background thread and its runtime's blocking threads run
    /// BACKGROUND_NICE_INCREMENT nice levels below the measurement workers,
    /// whose priority stays the process's.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_background_threads_run_at_a_lower_priority() {
        use starla_common::priority::this_thread_nice;
        let unit = this_thread_nice().unwrap();
        let measurement = measurement().unwrap();
        let (worker, blocking) = measurement.block_on(async {
            let worker = tokio::spawn(async { this_thread_nice().unwrap() });
            let blocking = tokio::task::spawn_blocking(|| this_thread_nice().unwrap());
            (worker.await.unwrap(), blocking.await.unwrap())
        });
        let (bg, bg_blocking) = spawn_background(false, || async {
            let blocking = tokio::task::spawn_blocking(|| this_thread_nice().unwrap()).await?;
            Ok((this_thread_nice()?, blocking))
        })
        .unwrap()
        .join()
        .unwrap()
        .unwrap();

        let lowered = (unit + BACKGROUND_NICE_INCREMENT).min(19);
        assert_eq!((worker, blocking), (unit, unit));
        assert_eq!((bg, bg_blocking), (lowered, lowered));
    }

    /// With `background_sched_idle`, the background thread and its
    /// runtime's blocking threads run on SCHED_IDLE, 10 nice levels lower
    /// still; the measurement workers do not. Without it, none does.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_background_threads_go_idle_when_asked() {
        use starla_common::priority::{this_thread_is_idle, this_thread_nice};
        let lowered = (this_thread_nice().unwrap() + BACKGROUND_NICE_INCREMENT).min(19);
        let measurement = measurement().unwrap();
        let worker = measurement
            .block_on(async { tokio::spawn(async { this_thread_is_idle().unwrap() }).await })
            .unwrap();
        assert!(!worker);
        for sched_idle in [true, false] {
            let (bg, bg_blocking, nice) = spawn_background(sched_idle, || async {
                let blocking =
                    tokio::task::spawn_blocking(|| this_thread_is_idle().unwrap()).await?;
                Ok((this_thread_is_idle()?, blocking, this_thread_nice()?))
            })
            .unwrap()
            .join()
            .unwrap()
            .unwrap();
            assert_eq!((bg, bg_blocking), (sched_idle, sched_idle));
            assert_eq!(nice, lowered);
        }
    }
}
