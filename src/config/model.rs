//! Configuration data model.

use std::net::Ipv4Addr;

use crate::util::ip::Cidr;
use crate::util::mac::MacAddr;

/// A fixed MAC -> IP binding read from the config file.
#[derive(Clone, Debug)]
pub struct StaticLease {
    pub name: String,
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
}

/// Fully parsed and (after `validate`) sane server configuration.
#[derive(Clone, Debug)]
pub struct DhcpConfig {
    pub interface: String,
    pub server_ip: Ipv4Addr,
    pub subnet: Cidr,
    pub subnet_mask: Ipv4Addr,
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
    /// Default gateway (DHCP option 3). Optional.
    pub router: Option<Ipv4Addr>,
    /// DNS servers (DHCP option 6). May be empty.
    pub dns: Vec<Ipv4Addr>,
    /// Lease duration in seconds (DHCP option 51).
    pub lease_time: u32,
    /// Path to the dynamic lease database.
    pub lease_file: String,
    /// When binding the socket to `interface` fails, keep serving on `0.0.0.0`
    /// instead of aborting. Default `false` (fail-fast). Only consulted on
    /// Linux, where interface binding is attempted.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub allow_unbound: bool,
    pub statics: Vec<StaticLease>,
}

impl DhcpConfig {
    /// Static lease matching `mac`, if any.
    pub fn static_for(&self, mac: MacAddr) -> Option<&StaticLease> {
        self.statics.iter().find(|s| s.mac == mac)
    }
}
