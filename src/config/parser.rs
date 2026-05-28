//! Line-based `key=value` config parser.
//!
//! Rules: blank lines ignored; lines whose first non-space character is `#`
//! are comments; everything else must be `key=value`. The `static` key may
//! repeat. Unknown keys are an error (they are almost always typos).

use std::net::Ipv4Addr;

use crate::util::ip::{self, Cidr};
use crate::util::mac::MacAddr;

use super::model::{DhcpConfig, StaticLease};

pub fn parse_config(text: &str) -> Result<DhcpConfig, String> {
    let mut interface: Option<String> = None;
    let mut server_ip: Option<Ipv4Addr> = None;
    let mut subnet: Option<Cidr> = None;
    let mut subnet_mask: Option<Ipv4Addr> = None;
    let mut pool_start: Option<Ipv4Addr> = None;
    let mut pool_end: Option<Ipv4Addr> = None;
    let mut router: Option<Ipv4Addr> = None;
    let mut dns: Vec<Ipv4Addr> = Vec::new();
    let mut lease_time: Option<u32> = None;
    let mut lease_file: Option<String> = None;
    let mut statics: Vec<StaticLease> = Vec::new();

    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lineno = idx + 1;
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected key=value, got '{}'", lineno, line))?;
        let key = key.trim();
        let value = value.trim();

        match key {
            "interface" => interface = Some(value.to_string()),
            "server_ip" => server_ip = Some(at(lineno, ip::parse_ipv4(value))?),
            "subnet" => subnet = Some(at(lineno, value.parse::<Cidr>())?),
            "subnet_mask" => subnet_mask = Some(at(lineno, ip::parse_ipv4(value))?),
            "pool_start" => pool_start = Some(at(lineno, ip::parse_ipv4(value))?),
            "pool_end" => pool_end = Some(at(lineno, ip::parse_ipv4(value))?),
            "router" => router = Some(at(lineno, ip::parse_ipv4(value))?),
            "dns" => {
                for part in value.split(',') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    dns.push(at(lineno, ip::parse_ipv4(part))?);
                }
            }
            "lease_time" => {
                lease_time = Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| format!("line {}: invalid lease_time '{}'", lineno, value))?,
                )
            }
            "lease_file" => lease_file = Some(value.to_string()),
            "static" => statics.push(at(lineno, parse_static(value))?),
            other => return Err(format!("line {}: unknown key '{}'", lineno, other)),
        }
    }

    Ok(DhcpConfig {
        interface: required(interface, "interface")?,
        server_ip: required(server_ip, "server_ip")?,
        subnet: required(subnet, "subnet")?,
        subnet_mask: required(subnet_mask, "subnet_mask")?,
        pool_start: required(pool_start, "pool_start")?,
        pool_end: required(pool_end, "pool_end")?,
        router,
        dns,
        lease_time: required(lease_time, "lease_time")?,
        lease_file: required(lease_file, "lease_file")?,
        statics,
    })
}

/// Parse `name,mac,ip`.
fn parse_static(value: &str) -> Result<StaticLease, String> {
    let parts: Vec<&str> = value.split(',').map(|p| p.trim()).collect();
    if parts.len() != 3 {
        return Err(format!("static must be 'name,mac,ip', got '{}'", value));
    }
    let mac = parts[1].parse::<MacAddr>()?;
    let ip = ip::parse_ipv4(parts[2])?;
    Ok(StaticLease {
        name: parts[0].to_string(),
        mac,
        ip,
    })
}

/// Attach a line number prefix to a parse error.
fn at<T>(lineno: usize, r: Result<T, String>) -> Result<T, String> {
    r.map_err(|e| format!("line {}: {}", lineno, e))
}

fn required<T>(v: Option<T>, name: &str) -> Result<T, String> {
    v.ok_or_else(|| format!("missing required key '{}'", name))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# nanodhcp config
interface=eth0
server_ip=192.168.10.1
subnet=192.168.10.0/24
subnet_mask=255.255.255.0

pool_start=192.168.10.100
pool_end=192.168.10.200
router=192.168.10.1
dns=192.168.10.1, 1.1.1.1
lease_time=86400
lease_file=/var/lib/nanodhcp/leases
static=nas,aa:bb:cc:dd:ee:ff,192.168.10.10
static=printer,11:22:33:44:55:66,192.168.10.11
";

    #[test]
    fn parses_sample() {
        let cfg = parse_config(SAMPLE).unwrap();
        assert_eq!(cfg.interface, "eth0");
        assert_eq!(cfg.server_ip, "192.168.10.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(cfg.subnet.prefix, 24);
        assert_eq!(
            cfg.pool_start,
            "192.168.10.100".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(cfg.dns.len(), 2);
        assert_eq!(cfg.lease_time, 86400);
        assert_eq!(cfg.statics.len(), 2);
        assert_eq!(cfg.statics[0].name, "nas");
        assert_eq!(
            cfg.router,
            Some("192.168.10.1".parse::<Ipv4Addr>().unwrap())
        );
    }

    #[test]
    fn comments_and_blanks_ignored() {
        let cfg = parse_config(SAMPLE).unwrap();
        assert_eq!(cfg.statics[1].name, "printer");
    }

    #[test]
    fn missing_required_key() {
        let text = "interface=eth0\n";
        let err = parse_config(text).unwrap_err();
        assert!(err.contains("missing required key"));
    }

    #[test]
    fn unknown_key_is_error() {
        let text = "frobnicate=yes\n";
        let err = parse_config(text).unwrap_err();
        assert!(err.contains("unknown key"));
    }

    #[test]
    fn line_without_equals() {
        let text = "interface eth0\n";
        let err = parse_config(text).unwrap_err();
        assert!(err.contains("expected key=value"));
    }

    #[test]
    fn bad_static_shape() {
        let text = "static=onlyname\n";
        let err = parse_config(text).unwrap_err();
        assert!(err.contains("static must be"));
    }
}
