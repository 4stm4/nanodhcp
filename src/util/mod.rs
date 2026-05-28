//! Small shared helpers: MAC addresses, IPv4/CIDR math, time.
//!
//! These modules are pure (no I/O, no Linux-specific code) so they can be
//! unit-tested in isolation and reused by the DHCP parser/builder.

pub mod ip;
pub mod mac;
pub mod time;
