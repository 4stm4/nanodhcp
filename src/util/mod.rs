//! Small shared helpers: MAC addresses, IPv4/CIDR math, time, logging.
//!
//! `ip`, `mac` and `time` are pure (no I/O, no Linux-specific code) so they can
//! be unit-tested in isolation and reused by the DHCP parser/builder. `log` is
//! the exception: it writes timestamped, leveled lines to stdout/stderr.

pub mod ip;
pub mod log;
pub mod mac;
pub mod time;
