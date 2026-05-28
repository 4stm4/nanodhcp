//! Lease data model.

use std::net::Ipv4Addr;

use crate::util::mac::MacAddr;

/// How a lease was produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseKind {
    /// Allocated from the pool; persisted to the lease file.
    Dynamic,
    /// Fixed MAC -> IP binding from config; never written to the lease file.
    Static,
}

impl LeaseKind {
    pub fn label(self) -> &'static str {
        match self {
            LeaseKind::Dynamic => "dynamic",
            LeaseKind::Static => "static",
        }
    }
}

/// A single MAC -> IP assignment.
#[derive(Clone, Debug)]
pub struct Lease {
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
    pub hostname: Option<String>,
    /// Unix timestamp at which a dynamic lease expires. For static leases this
    /// field is unused (set to 0).
    pub expires_at: u64,
    pub kind: LeaseKind,
}

impl Lease {
    pub fn hostname_str(&self) -> &str {
        self.hostname.as_deref().unwrap_or("-")
    }
}
