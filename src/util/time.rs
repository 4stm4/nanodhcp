//! Unix timestamp helper.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current Unix time in seconds. Returns 0 if the clock is before the epoch
/// (never panics — a broken clock must not take down the daemon).
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
