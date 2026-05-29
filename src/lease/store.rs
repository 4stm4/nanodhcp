//! Persistent store of dynamic leases.
//!
//! File format is one lease per line: `MAC IP HOSTNAME EXPIRES_AT`, where
//! `HOSTNAME` is `-` when unknown and `EXPIRES_AT` is a Unix timestamp.
//! Malformed lines are skipped with a warning rather than aborting startup.

use std::collections::HashMap;
use std::fs;
use std::io::{self, ErrorKind, Write};
use std::net::Ipv4Addr;
use std::path::PathBuf;

use crate::util::mac::MacAddr;

use super::model::{Lease, LeaseKind};

pub struct LeaseStore {
    path: PathBuf,
    by_mac: HashMap<MacAddr, Lease>,
}

impl LeaseStore {
    /// Load leases from `path`. A missing file is not an error (fresh start);
    /// unreadable files and malformed lines produce warnings on stderr.
    pub fn load(path: &str) -> LeaseStore {
        let mut by_mac = HashMap::new();
        match fs::read_to_string(path) {
            Ok(text) => {
                for (idx, raw) in text.lines().enumerate() {
                    let line = raw.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    match parse_line(line) {
                        Some(lease) => {
                            by_mac.insert(lease.mac, lease);
                        }
                        None => eprintln!(
                            "nanodhcp: warning: ignoring malformed lease at line {}: '{}'",
                            idx + 1,
                            line
                        ),
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => eprintln!(
                "nanodhcp: warning: cannot read lease file '{}': {}",
                path, e
            ),
        }
        LeaseStore {
            path: PathBuf::from(path),
            by_mac,
        }
    }

    pub fn get(&self, mac: &MacAddr) -> Option<&Lease> {
        self.by_mac.get(mac)
    }

    pub fn insert(&mut self, lease: Lease) {
        self.by_mac.insert(lease.mac, lease);
    }

    pub fn remove(&mut self, mac: &MacAddr) -> Option<Lease> {
        self.by_mac.remove(mac)
    }

    /// Drop dynamic leases that expired at or before `now`, returning how many
    /// were removed. Leases are keyed by MAC, so without this the store (and the
    /// lease file) would grow without bound as distinct clients come and go — an
    /// expired entry is otherwise never reclaimed.
    pub fn purge_expired(&mut self, now: u64) -> usize {
        let before = self.by_mac.len();
        self.by_mac.retain(|_, l| l.expires_at > now);
        before - self.by_mac.len()
    }

    /// All dynamic leases, sorted by IP for stable output.
    pub fn sorted(&self) -> Vec<&Lease> {
        let mut leases: Vec<&Lease> = self.by_mac.values().collect();
        leases.sort_by_key(|l| u32::from(l.ip));
        leases
    }

    /// Iterate all leases (unordered).
    pub fn iter(&self) -> impl Iterator<Item = &Lease> {
        self.by_mac.values()
    }

    /// Write the store to disk atomically (temp file + rename) so a crash
    /// mid-write cannot corrupt the live lease file.
    pub fn save(&self) -> io::Result<()> {
        let mut out = String::new();
        for lease in self.sorted() {
            out.push_str(&format!(
                "{} {} {} {}\n",
                lease.mac,
                lease.ip,
                lease.hostname_str(),
                lease.expires_at
            ));
        }

        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let tmp = self.path.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(out.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)
    }
}

/// Parse one lease line. Returns `None` for any malformed field.
fn parse_line(line: &str) -> Option<Lease> {
    let mut fields = line.split_whitespace();
    let mac = fields.next()?.parse::<MacAddr>().ok()?;
    let ip = fields.next()?.parse::<Ipv4Addr>().ok()?;
    let host = fields.next()?;
    let expires_at = fields.next()?.parse::<u64>().ok()?;
    let hostname = if host == "-" {
        None
    } else {
        Some(host.to_string())
    };
    Some(Lease {
        mac,
        ip,
        hostname,
        expires_at,
        kind: LeaseKind::Dynamic,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_line() {
        let l = parse_line("aa:bb:cc:dd:ee:ff 192.168.10.101 laptop 1780000000").unwrap();
        assert_eq!(l.ip, "192.168.10.101".parse::<Ipv4Addr>().unwrap());
        assert_eq!(l.hostname.as_deref(), Some("laptop"));
        assert_eq!(l.expires_at, 1780000000);
    }

    #[test]
    fn parse_dash_hostname() {
        let l = parse_line("aa:bb:cc:dd:ee:ff 192.168.10.101 - 1780000000").unwrap();
        assert_eq!(l.hostname, None);
    }

    #[test]
    fn reject_malformed() {
        assert!(parse_line("garbage").is_none());
        assert!(parse_line("aa:bb:cc:dd:ee:ff notanip host 123").is_none());
        assert!(parse_line("aa:bb:cc:dd:ee:ff 1.2.3.4 host notanumber").is_none());
    }

    #[test]
    fn missing_file_is_empty() {
        let store = LeaseStore::load("/nonexistent/nanodhcp/leases-test");
        assert_eq!(store.iter().count(), 0);
    }

    #[test]
    fn purge_expired_drops_only_stale() {
        let mut store = LeaseStore::load("/nonexistent/nanodhcp/purge-test");
        let stale: MacAddr = "aa:aa:aa:aa:aa:aa".parse().unwrap();
        let live: MacAddr = "bb:bb:bb:bb:bb:bb".parse().unwrap();
        store.insert(parse_line("aa:aa:aa:aa:aa:aa 192.168.10.10 - 100").unwrap());
        store.insert(parse_line("bb:bb:bb:bb:bb:bb 192.168.10.11 - 5000").unwrap());

        assert_eq!(store.purge_expired(1000), 1);
        assert!(store.get(&stale).is_none());
        assert!(store.get(&live).is_some());
        // An entry exactly at `now` is treated as expired.
        assert_eq!(store.purge_expired(5000), 1);
        assert_eq!(store.iter().count(), 0);
    }
}
