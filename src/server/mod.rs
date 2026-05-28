//! UDP server: socket setup and the receive/respond loop. This is the only
//! part that touches the network or Linux-specific syscalls.

pub mod daemon;
pub mod socket;
