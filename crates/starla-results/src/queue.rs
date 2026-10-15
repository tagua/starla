//! In-memory result queue with configurable capacity
//!
//! A simple VecDeque-based queue that holds measurement results
//! until they are uploaded. Drops oldest results when at capacity.
//!
//! The main queue is eperd's two spool places at once: the results a post
//! may take, which crons/7's condmv has moved to data/out, at the front,
//! and behind them those still in data/new/7, which wait for its next run
//! ([`ResultQueue::move_out`]).

use starla_common::MeasurementResult;
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

/// A queued measurement result with metadata
#[derive(Debug, Clone)]
pub struct QueuedResult {
    /// The measurement result
    pub result: MeasurementResult,
    /// When this result was queued (unix timestamp)
    pub queued_at: i64,
    /// Number of upload attempts
    pub attempts: u32,
    /// Timestamp of last upload attempt
    pub last_attempt_at: Option<i64>,
    /// `lts` when the result was measured: the reference probe writes
    /// get_timesync() into each result as it is produced, not at upload.
    pub lts: i64,
}

/// Queue statistics
#[derive(Debug, Clone)]
pub struct QueueStats {
    /// Number of items in the queue
    pub count: usize,
    /// Of them, those not yet moved out for a post: still in data/new/7
    pub held: usize,
    /// Maximum capacity
    pub capacity: usize,
}

/// In-memory result queue with a maximum capacity.
/// When full, oldest results are dropped to make room.
pub struct ResultQueue {
    items: VecDeque<QueuedResult>,
    /// How many items, from the front, are moved out: a post may take them
    /// ([`drain_moved`](Self::drain_moved)). The rest were queued since the
    /// last [`move_out`](Self::move_out).
    moved: usize,
    max_capacity: usize,
}

impl ResultQueue {
    /// Create a new queue with the given maximum capacity
    pub fn new(max_capacity: usize) -> Self {
        Self {
            items: VecDeque::with_capacity(max_capacity.min(1024)),
            moved: 0,
            max_capacity,
        }
    }

    /// Add a result to the queue. Drops oldest if at capacity.
    pub fn enqueue(&mut self, result: MeasurementResult) {
        self.enqueue_measured(result, -1);
    }

    /// Add a result with the `lts` it was measured at, behind those moved
    /// out: it waits for the next [`move_out`](Self::move_out).
    pub fn enqueue_measured(&mut self, result: MeasurementResult, lts: i64) {
        if self.items.len() >= self.max_capacity {
            if let Some(d) = self.items.pop_front() {
                self.moved = self.moved.saturating_sub(1);
                warn!(
                    msm_id = d.result.msm_id.0,
                    "Queue full ({}), dropping oldest result", self.max_capacity
                );
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        self.items.push_back(QueuedResult {
            result,
            queued_at: now,
            attempts: 0,
            last_attempt_at: None,
            lts,
        });
    }

    /// Take up to `n` results from the front of the queue, moved out or not
    pub fn drain_batch(&mut self, n: usize) -> Vec<QueuedResult> {
        let count = n.min(self.items.len());
        self.moved = self.moved.saturating_sub(count);
        self.items.drain(..count).collect()
    }

    /// Take all results from the queue, moved out or not
    pub fn drain_all(&mut self) -> Vec<QueuedResult> {
        self.moved = 0;
        self.items.drain(..).collect()
    }

    /// Everything queued so far may go with the next post: crons/7's condmv
    /// renames data/new/7, the results eperd has appended to it and its
    /// marker last, into data/out (condmv_start, eperd/condmv.c:115-136).
    /// Results queued after it wait for its next run.
    pub fn move_out(&mut self) {
        self.moved = self.items.len();
    }

    /// Take the results moved out, in their order: what a post finds in
    /// data/out. Those queued since the last [`move_out`](Self::move_out)
    /// stay.
    pub fn drain_moved(&mut self) -> Vec<QueuedResult> {
        let moved = std::mem::take(&mut self.moved);
        self.items.drain(..moved).collect()
    }

    /// Put results a post did not deliver back at the front, in their order,
    /// one more attempt counted. However many posts fail — a 429, the SSH
    /// session down, any other answer than OK — they wait for the next one,
    /// as httppost's `--delete-file` only deletes the spool's files on an OK
    /// (httppost.c:602): only their age (`cleanup_expired`) and the queue's
    /// size drop them.
    pub fn requeue(&mut self, mut results: Vec<QueuedResult>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        for r in &mut results {
            r.attempts += 1;
            r.last_attempt_at = Some(now);
        }

        self.push_front_moved(results);
    }

    /// Put results a post left out back at the front, in their order, no
    /// attempt counted: they did not fit its `--maxpostsize`, so they were
    /// not posted, as do_dir leaves a file that does not fit for the next
    /// post (httppost.c:1118-1131).
    pub fn put_back(&mut self, results: Vec<QueuedResult>) {
        self.push_front_moved(results);
    }

    /// Results a post took, back at the front in their order: still moved
    /// out, as a spool file httppost did not delete stays in data/out.
    /// Over the capacity, the newest go.
    fn push_front_moved(&mut self, results: Vec<QueuedResult>) {
        self.moved += results.len();
        for r in results.into_iter().rev() {
            self.items.push_front(r);
        }

        while self.items.len() > self.max_capacity {
            self.items.pop_back();
        }
        self.moved = self.moved.min(self.items.len());
    }

    /// Remove results older than `max_age_secs`. Returns number of items
    /// removed.
    pub fn cleanup_expired(&mut self, max_age_secs: i64) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let before = self.items.len();
        let (mut at, mut moved_removed) = (0, 0);
        let moved = self.moved;
        self.items.retain(|r| {
            let keep = now - r.queued_at < max_age_secs;
            if !keep && at < moved {
                moved_removed += 1;
            }
            at += 1;
            keep
        });
        self.moved -= moved_removed;
        let removed = before - self.items.len();
        if removed > 0 {
            debug!("Cleaned up {} expired results", removed);
        }
        removed
    }

    /// Get queue statistics
    pub fn stats(&self) -> QueueStats {
        QueueStats {
            count: self.items.len(),
            held: self.items.len() - self.moved,
            capacity: self.max_capacity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starla_common::{MeasurementData, MeasurementId, MeasurementType, ProbeId, Timestamp};
    use std::net::IpAddr;

    fn make_result(msm_id: u64) -> MeasurementResult {
        MeasurementResult {
            fw: 5120,
            measurement_type: MeasurementType::Ping,
            prb_id: ProbeId(12345),
            msm_id: MeasurementId(msm_id),
            timestamp: Timestamp::now(),
            af: 4,
            dst_addr: "8.8.8.8".parse::<IpAddr>().unwrap(),
            dst_name: None,
            src_addr: None,
            proto: Some("ICMP".to_string()),
            ttl: Some(64),
            size: Some(32),
            data: MeasurementData::Generic(serde_json::json!([{"rtt": 12.5}])),
        }
    }

    #[test]
    fn test_enqueue_and_drain() {
        let mut q = ResultQueue::new(100);
        q.enqueue(make_result(1));
        q.enqueue(make_result(2));
        q.enqueue(make_result(3));

        assert_eq!(q.stats().count, 3);

        let batch = q.drain_batch(2);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].result.msm_id.0, 1);
        assert_eq!(batch[1].result.msm_id.0, 2);
        assert_eq!(q.stats().count, 1);
    }

    #[test]
    fn test_capacity_eviction() {
        let mut q = ResultQueue::new(3);
        q.enqueue(make_result(1));
        q.enqueue(make_result(2));
        q.enqueue(make_result(3));
        q.enqueue(make_result(4));

        assert_eq!(q.stats().count, 3);
        let batch = q.drain_batch(3);
        assert_eq!(batch[0].result.msm_id.0, 2);
    }

    #[test]
    fn test_requeue() {
        let mut q = ResultQueue::new(100);
        q.enqueue(make_result(1));
        q.enqueue(make_result(2));

        let batch = q.drain_batch(2);
        assert_eq!(q.stats().count, 0);

        q.requeue(batch);
        assert_eq!(q.stats().count, 2);

        let batch = q.drain_batch(1);
        assert_eq!(batch[0].attempts, 1);
    }

    /// httppost leaves a file it got no OK for in the spool, however often
    /// that happens: a result is never dropped for its failed posts.
    #[test]
    fn a_result_waits_out_any_number_of_failed_posts() {
        let mut q = ResultQueue::new(10);
        q.enqueue(make_result(1));
        q.enqueue(make_result(2));
        for _ in 0..100 {
            let batch = q.drain_all();
            q.requeue(batch);
        }
        q.enqueue(make_result(3));
        let back = q.drain_all();
        let ids: Vec<u64> = back.iter().map(|r| r.result.msm_id.0).collect();
        assert_eq!(ids, [1, 2, 3], "none dropped, order kept");
        assert!(back[..2]
            .iter()
            .all(|r| r.attempts == 100 && r.last_attempt_at.is_some()));
    }

    fn ids(results: &[QueuedResult]) -> Vec<u64> {
        results.iter().map(|r| r.result.msm_id.0).collect()
    }

    /// A post takes what crons/7's condmv has moved to data/out; what
    /// eperd appended to data/new/7 since waits for its next run.
    #[test]
    fn a_post_takes_only_what_condmv_moved_out() {
        let mut q = ResultQueue::new(100);
        q.enqueue(make_result(1));
        q.enqueue(make_result(2));
        q.move_out();
        q.enqueue(make_result(3));
        assert_eq!((q.stats().count, q.stats().held), (3, 1));

        assert_eq!(ids(&q.drain_moved()), [1, 2]);
        assert!(q.drain_moved().is_empty(), "3 is not moved out");
        q.move_out();
        assert_eq!(ids(&q.drain_moved()), [3]);
        assert_eq!(q.stats().count, 0);
    }

    /// What a post took and did not deliver, or left out for its
    /// --maxpostsize, goes back moved out, ahead of what was moved since:
    /// httppost leaves the spool file in data/out. What is in data/new/7
    /// still waits.
    #[test]
    fn what_a_post_took_goes_back_moved_out() {
        let mut q = ResultQueue::new(100);
        for id in 1..=4 {
            q.enqueue(make_result(id));
        }
        q.move_out();
        q.enqueue(make_result(5));
        let mut taken = q.drain_moved();
        let left_out = taken.split_off(2);
        q.put_back(left_out);
        q.requeue(taken);
        assert_eq!((q.stats().count, q.stats().held), (5, 1));
        let again = q.drain_moved();
        assert_eq!(ids(&again), [1, 2, 3, 4]);
        assert_eq!(again[0].attempts, 1, "posted once");
        assert_eq!(again[2].attempts, 0, "never posted");
        assert_eq!(ids(&q.drain_all()), [5]);
    }

    /// The capacity and the age drop moved-out results and held ones
    /// alike, and what is left keeps its place.
    #[test]
    fn dropped_results_leave_the_rest_where_they_were() {
        let mut q = ResultQueue::new(3);
        q.enqueue(make_result(1));
        q.enqueue(make_result(2));
        q.move_out();
        q.enqueue(make_result(3));
        q.enqueue(make_result(4)); // drops 1, moved out
        assert_eq!((q.stats().count, q.stats().held), (3, 2));

        q.items[0].queued_at -= 7200; // 2, moved out
        q.items[1].queued_at -= 7200; // 3, held
        assert_eq!(q.cleanup_expired(3600), 2);
        assert_eq!((q.stats().count, q.stats().held), (1, 1));
        assert!(q.drain_moved().is_empty());

        // Over the capacity, requeued results push out the newest
        q.requeue(vec![q.items[0].clone(); 3]);
        assert_eq!((q.stats().count, q.stats().held), (3, 0));
    }
}
