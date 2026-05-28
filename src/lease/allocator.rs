//! IP allocation policy.
//!
//! Order of preference:
//!   1. static binding for the MAC,
//!   2. the MAC's existing dynamic lease if that IP is still usable,
//!   3. the first free address in the pool.
//!
//! Never hands out the server IP, the network or broadcast address, any
//! static IP, or an address currently leased to a different MAC.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use crate::config::DhcpConfig;
use crate::util::ip::{from_u32, to_u32};
use crate::util::mac::MacAddr;

use super::store::LeaseStore;

pub fn assign_ip(
    cfg: &DhcpConfig,
    store: &LeaseStore,
    mac: MacAddr,
    now: u64,
) -> Option<Ipv4Addr> {
    // 1. Static binding always wins.
    if let Some(s) = cfg.static_for(mac) {
        return Some(s.ip);
    }

    let network = to_u32(cfg.subnet.network());
    let broadcast = to_u32(cfg.subnet.broadcast());
    let server = to_u32(cfg.server_ip);
    let static_ips: HashSet<u32> = cfg.statics.iter().map(|s| to_u32(s.ip)).collect();
    let start = to_u32(cfg.pool_start);
    let end = to_u32(cfg.pool_end);

    let reserved = |ip: u32| -> bool {
        ip == network || ip == broadcast || ip == server || static_ips.contains(&ip)
    };
    let taken_by_other = |ip: u32| -> bool {
        store
            .iter()
            .any(|l| to_u32(l.ip) == ip && l.mac != mac && l.expires_at > now)
    };

    // 2. Reuse the MAC's previous IP when it is in-pool and not otherwise taken.
    if let Some(lease) = store.get(&mac) {
        let ip = to_u32(lease.ip);
        if ip >= start && ip <= end && !reserved(ip) && !taken_by_other(ip) {
            return Some(from_u32(ip));
        }
    }

    // 3. First free address in the pool.
    for ip in start..=end {
        if !reserved(ip) && !taken_by_other(ip) {
            return Some(from_u32(ip));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parser::parse_config;
    use crate::lease::model::{Lease, LeaseKind};

    fn cfg(extra: &str) -> DhcpConfig {
        let mut text = String::from(
            "\
interface=eth0
server_ip=192.168.10.1
subnet=192.168.10.0/24
subnet_mask=255.255.255.0
pool_start=192.168.10.100
pool_end=192.168.10.102
router=192.168.10.1
lease_time=86400
lease_file=/tmp/nanodhcp-test-leases
",
        );
        text.push_str(extra);
        parse_config(&text).unwrap()
    }

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    fn empty_store() -> LeaseStore {
        LeaseStore::load("/nonexistent/nanodhcp/alloc-test")
    }

    fn lease(m: &str, ip: &str, expires: u64) -> Lease {
        Lease {
            mac: mac(m),
            ip: ip.parse().unwrap(),
            hostname: None,
            expires_at: expires,
            kind: LeaseKind::Dynamic,
        }
    }

    #[test]
    fn static_binding_wins() {
        let c = cfg("static=nas,aa:aa:aa:aa:aa:aa,192.168.10.10\n");
        let store = empty_store();
        let ip = assign_ip(&c, &store, mac("aa:aa:aa:aa:aa:aa"), 1000).unwrap();
        assert_eq!(ip, "192.168.10.10".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn first_free_from_pool() {
        let c = cfg("");
        let store = empty_store();
        let ip = assign_ip(&c, &store, mac("bb:bb:bb:bb:bb:bb"), 1000).unwrap();
        assert_eq!(ip, "192.168.10.100".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn reuse_existing_lease() {
        let c = cfg("");
        let mut store = empty_store();
        store.insert(lease("bb:bb:bb:bb:bb:bb", "192.168.10.101", 2000));
        let ip = assign_ip(&c, &store, mac("bb:bb:bb:bb:bb:bb"), 1000).unwrap();
        assert_eq!(ip, "192.168.10.101".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn skip_ip_taken_by_other_active_lease() {
        let c = cfg("");
        let mut store = empty_store();
        // .100 actively leased to someone else.
        store.insert(lease("cc:cc:cc:cc:cc:cc", "192.168.10.100", 5000));
        let ip = assign_ip(&c, &store, mac("bb:bb:bb:bb:bb:bb"), 1000).unwrap();
        assert_eq!(ip, "192.168.10.101".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn expired_other_lease_is_reclaimable() {
        let c = cfg("");
        let mut store = empty_store();
        // .100 leased to someone else but expired (expires_at <= now).
        store.insert(lease("cc:cc:cc:cc:cc:cc", "192.168.10.100", 500));
        let ip = assign_ip(&c, &store, mac("bb:bb:bb:bb:bb:bb"), 1000).unwrap();
        assert_eq!(ip, "192.168.10.100".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn static_ip_excluded_from_pool() {
        // Static at .100 means the first dynamic IP must be .101.
        let c = cfg("static=nas,dd:dd:dd:dd:dd:dd,192.168.10.100\n");
        let store = empty_store();
        let ip = assign_ip(&c, &store, mac("bb:bb:bb:bb:bb:bb"), 1000).unwrap();
        assert_eq!(ip, "192.168.10.101".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn pool_exhaustion_returns_none() {
        let c = cfg("");
        let mut store = empty_store();
        store.insert(lease("11:11:11:11:11:11", "192.168.10.100", 5000));
        store.insert(lease("22:22:22:22:22:22", "192.168.10.101", 5000));
        store.insert(lease("33:33:33:33:33:33", "192.168.10.102", 5000));
        assert!(assign_ip(&c, &store, mac("bb:bb:bb:bb:bb:bb"), 1000).is_none());
    }
}
