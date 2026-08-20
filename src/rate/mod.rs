//! Adaptive rate limiting with exponential backoff and concurrency decay.

use crate::cli::ScanMode;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::time::sleep;

#[derive(Clone)]
pub struct AdaptiveRateLimiter {
    inner: Arc<Inner>,
}

struct Inner {
    semaphore: Arc<Semaphore>,
    initial_permits: usize,
    min_permits: usize,
    /// Current target concurrency (permits we try to keep)
    current_cap: AtomicUsize,
    delay_ms: AtomicU64,
    fixed_delay_ms: u64,
    delay_jitter_ms: u64,
    consecutive_429: AtomicU32,
    retries: AtomicU64,
    max_rps: u32,
    /// Token-bucket style: next allowed instant
    next_slot: Mutex<Instant>,
    mode: ScanMode,
}

impl AdaptiveRateLimiter {
    pub fn new(threads: usize, max_rps: u32, mode: ScanMode) -> Self {
        Self::with_delay(threads, max_rps, mode, 0)
    }

    pub fn with_delay(threads: usize, max_rps: u32, mode: ScanMode, fixed_delay_ms: u64) -> Self {
        Self::with_delay_jitter(threads, max_rps, mode, fixed_delay_ms, 0)
    }

    pub fn with_delay_jitter(
        threads: usize,
        max_rps: u32,
        mode: ScanMode,
        fixed_delay_ms: u64,
        delay_jitter_ms: u64,
    ) -> Self {
        let permits = threads.max(1);
        let min_permits = match mode {
            ScanMode::Fast => (permits / 4).max(1),
            ScanMode::Balanced => (permits / 3).max(1),
            ScanMode::Deep => (permits / 2).max(1),
        };
        let initial_delay = match mode {
            ScanMode::Fast => 0,
            ScanMode::Balanced => 0,
            ScanMode::Deep => 5,
        };

        Self {
            inner: Arc::new(Inner {
                semaphore: Arc::new(Semaphore::new(permits)),
                initial_permits: permits,
                min_permits,
                current_cap: AtomicUsize::new(permits),
                delay_ms: AtomicU64::new(initial_delay.max(fixed_delay_ms)),
                fixed_delay_ms,
                delay_jitter_ms,
                consecutive_429: AtomicU32::new(0),
                retries: AtomicU64::new(0),
                max_rps,
                next_slot: Mutex::new(Instant::now()),
                mode,
            }),
        }
    }

    pub fn semaphore(&self) -> Arc<Semaphore> {
        self.inner.semaphore.clone()
    }

    pub fn current_delay_ms(&self) -> u64 {
        self.inner.delay_ms.load(Ordering::Relaxed)
    }

    pub fn current_cap(&self) -> usize {
        self.inner.current_cap.load(Ordering::Relaxed)
    }

    pub fn retries(&self) -> u64 {
        self.inner.retries.load(Ordering::Relaxed)
    }

    pub fn available_permits(&self) -> usize {
        self.inner.semaphore.available_permits()
    }

    /// Wait for rate-limit slot (RPS + adaptive delay). Serialized for correct RPS.
    pub async fn wait_turn(&self) {
        use rand::Rng;

        let adaptive = self.inner.delay_ms.load(Ordering::Relaxed);
        let fixed = self.inner.fixed_delay_ms;
        let mut delay = adaptive.max(fixed);
        if delay > 0 && self.inner.delay_jitter_ms > 0 {
            delay += rand::thread_rng().gen_range(0..=self.inner.delay_jitter_ms);
        }
        if delay > 0 {
            sleep(Duration::from_millis(delay)).await;
        }

        if self.inner.max_rps > 0 {
            let min_interval = Duration::from_secs_f64(1.0 / self.inner.max_rps as f64);
            let wait_for = {
                let mut next = self.inner.next_slot.lock();
                let now = Instant::now();
                if now < *next {
                    let w = *next - now;
                    *next += min_interval;
                    Some(w)
                } else {
                    *next = now + min_interval;
                    None
                }
            };
            if let Some(w) = wait_for {
                sleep(w).await;
            }
        }
    }

    /// Reduce concurrency by acquiring and leaking permits (hold them out of circulation).
    pub fn on_rate_limited(&self) {
        let n = self.inner.consecutive_429.fetch_add(1, Ordering::Relaxed) + 1;
        let cur = self.inner.delay_ms.load(Ordering::Relaxed);
        let next = if cur == 0 {
            50.max(self.inner.fixed_delay_ms)
        } else {
            (cur.saturating_mul(2)).min(10_000)
        };
        self.inner.delay_ms.store(next, Ordering::Relaxed);

        // Shrink concurrency toward min_permits
        let cap = self.inner.current_cap.load(Ordering::Relaxed);
        if cap > self.inner.min_permits {
            let new_cap = (cap - 1).max(self.inner.min_permits);
            if self
                .inner
                .current_cap
                .compare_exchange(cap, new_cap, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                // Remove one permit from circulation
                if let Ok(permit) = self.inner.semaphore.try_acquire() {
                    std::mem::forget(permit);
                }
            }
        }

        if n > 3 {
            let boosted = self
                .inner
                .delay_ms
                .load(Ordering::Relaxed)
                .saturating_mul(2)
                .min(15_000);
            self.inner.delay_ms.store(boosted, Ordering::Relaxed);
        }
    }

    pub fn on_success(&self) {
        let prev = self.inner.consecutive_429.swap(0, Ordering::Relaxed);
        if prev > 0 {
            let cur = self.inner.delay_ms.load(Ordering::Relaxed);
            let floor = self.inner.fixed_delay_ms;
            self.inner
                .delay_ms
                .store((cur / 2).max(floor), Ordering::Relaxed);
        } else {
            let cur = self.inner.delay_ms.load(Ordering::Relaxed);
            let floor = self.inner.fixed_delay_ms;
            if cur > floor {
                self.inner
                    .delay_ms
                    .store(cur.saturating_sub(5).max(floor), Ordering::Relaxed);
            }
        }

        // Slowly restore concurrency
        let cap = self.inner.current_cap.load(Ordering::Relaxed);
        if cap < self.inner.initial_permits {
            let new_cap = cap + 1;
            if self
                .inner
                .current_cap
                .compare_exchange(cap, new_cap, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                self.inner.semaphore.add_permits(1);
            }
        }
    }

    pub fn record_retry(&self) {
        self.inner.retries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn backoff_for_attempt(&self, attempt: u32) -> Duration {
        let base: u64 = match self.inner.mode {
            ScanMode::Fast => 100,
            ScanMode::Balanced => 200,
            ScanMode::Deep => 400,
        };
        let ms = base.saturating_mul(1u64 << attempt.min(5)).min(8_000);
        Duration::from_millis(ms)
    }

    pub async fn with_retry<F, Fut, T, E>(&self, max_attempts: u32, mut f: F) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        let mut attempt = 0;
        loop {
            match f().await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    attempt += 1;
                    self.record_retry();
                    if attempt >= max_attempts {
                        return Err(e);
                    }
                    sleep(self.backoff_for_attempt(attempt)).await;
                }
            }
        }
    }
}
