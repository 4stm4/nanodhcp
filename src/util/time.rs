//! Unix timestamp helpers.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current Unix time in seconds. Returns 0 if the clock is before the epoch
/// (never panics — a broken clock must not take down the daemon).
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format a Unix timestamp (seconds) as ISO-8601 UTC, e.g.
/// `2026-05-29T11:26:51Z`. Leap seconds are ignored; this is for log lines.
pub fn format_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Convert days since 1970-01-01 to a (year, month, day) tuple. From Howard
/// Hinnant's `civil_from_days`, valid across the proleptic Gregorian calendar.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // day of era, [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year, [0, 365]
    let mp = (5 * doy + 2) / 153; // month, [0, 11], starting in March
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = yoe as i64 + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_utc_epoch() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_utc_known_timestamp() {
        // 1_700_000_000 is 2023-11-14T22:13:20Z.
        assert_eq!(format_utc(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn format_utc_leap_year_day() {
        // 2024-02-29T12:00:00Z exercises the leap-day branch.
        assert_eq!(format_utc(1_709_208_000), "2024-02-29T12:00:00Z");
    }
}
