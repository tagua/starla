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
//! busy: the kernel runs a measurement worker that wakes for a reply ahead
//! of the background thread. A thread starts at its creator's nice value,
//! so the background thread lowers its own before it builds its runtime,
//! to a level fixed from the main thread's, and the runtime's blocking
//! threads (a name lookup for an SSH connect) make sure of the same level
//! as they start. The measurement runtime is built first, from the main
//! thread, whose priority nothing lowers; its blocking threads are started
//! by its own workers.

use starla_common::priority::{Nice, BACKGROUND_NICE_INCREMENT};
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
/// [`BACKGROUND_NICE_INCREMENT`] nice levels below the calling thread.
pub fn spawn_background<F, Fut, T>(
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
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .thread_name("starla-bg-blk")
                .on_thread_start(move || {
                    if let Some(nice) = nice {
                        if let Err(e) = nice.lower_this_thread() {
                            warn!("Could not lower a background thread's priority: {}", e);
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
    /// exchange reply arrives. When it is done, the moment it was.
    async fn stall_when_woken(socket: tokio::net::UdpSocket) -> Instant {
        let mut buf = [0u8; 16];
        socket.recv_from(&mut buf).await.unwrap();
        let until = Instant::now() + STALL;
        while Instant::now() < until {
            std::hint::spin_loop();
        }
        Instant::now()
    }

    /// Wake [`stall_when_woken`]'s socket, from outside any runtime.
    fn wake(to: std::net::SocketAddr) {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.send_to(b"kex", to).unwrap();
    }

    /// For half a second: how late a 10 ms timer fires at worst, and the
    /// slowest loopback datagram, from its send to its receive. The stall
    /// is woken 50 ms in.
    async fn measure_around(to: std::net::SocketAddr) -> (Duration, Duration) {
        let measuring = tokio::spawn(async {
            let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let to = b.local_addr().unwrap();
            let (mut timer, mut echo) = (Duration::ZERO, Duration::ZERO);
            let mut buf = [0u8; 16];
            let began = Instant::now();
            while began.elapsed() < Duration::from_millis(500) {
                let t = Instant::now();
                tokio::time::sleep(Duration::from_millis(10)).await;
                timer = timer.max(t.elapsed().saturating_sub(Duration::from_millis(10)));

                let t = Instant::now();
                a.send_to(b"probe", to).await.unwrap();
                b.recv_from(&mut buf).await.unwrap();
                echo = echo.max(t.elapsed());
            }
            (timer, echo)
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        wake(to);
        measuring.await.unwrap()
    }

    /// Russh's group exchange stalls the runtime it runs on for ~0.3 s at
    /// every connect and rekey. On the background runtime, the
    /// measurements go on meanwhile: a 10 ms timer fires on time and a
    /// loopback datagram is taken as it arrives (~2.4 ms and ~0.2 ms at
    /// worst on an idle Mac; the bound leaves room for a loaded host).
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
        let background = spawn_background(move || async move {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            bound.send(socket.local_addr()?).unwrap();
            Ok(tokio::spawn(stall_when_woken(socket)).await?)
        })
        .unwrap();
        let to = socket.recv().unwrap();
        let (timer, echo) = measurement.block_on(measure_around(to));
        let measured_until = Instant::now();
        let stall_ended = background.join().unwrap().unwrap();
        assert!(
            stall_ended < measured_until,
            "the stall ended after the measurements: proves nothing"
        );
        assert!(
            timer < Duration::from_millis(50),
            "a 10 ms timer fired {timer:?} late"
        );
        assert!(
            echo < Duration::from_millis(50),
            "a loopback datagram took {echo:?}"
        );
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
        let (bg, bg_blocking) = spawn_background(|| async {
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
}
