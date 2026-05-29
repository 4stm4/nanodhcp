//! Semantic validation of a parsed [`DhcpConfig`].
//!
//! The parser guarantees syntax and presence; this checks that the values make
//! sense together (subnet membership, pool ordering, mask/prefix agreement,
//! duplicate static bindings).

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::util::ip::to_u32;

use super::model::DhcpConfig;

/// Returns `Ok(())` if the config is usable, otherwise a multi-line error
/// listing every problem found.
pub fn validate(cfg: &DhcpConfig) -> Result<(), String> {
    let mut errors: Vec<String> = Vec::new();

    if cfg.interface.is_empty() {
        errors.push("interface must not be empty".to_string());
    }

    if cfg.lease_file.is_empty() {
        errors.push("lease_file must not be empty".to_string());
    }

    // Option 6 packs 4 bytes per server into a single TLV whose length is one
    // byte, so more than 63 servers would silently truncate on the wire.
    if cfg.dns.len() > 63 {
        errors.push(format!(
            "too many dns servers ({}): at most 63 fit in one DHCP option",
            cfg.dns.len()
        ));
    }

    if cfg.subnet.netmask() != cfg.subnet_mask {
        errors.push(format!(
            "subnet_mask {} does not match subnet prefix /{} (expected {})",
            cfg.subnet_mask,
            cfg.subnet.prefix,
            cfg.subnet.netmask()
        ));
    }

    check_in_subnet(cfg, cfg.server_ip, "server_ip", &mut errors);
    check_in_subnet(cfg, cfg.pool_start, "pool_start", &mut errors);
    check_in_subnet(cfg, cfg.pool_end, "pool_end", &mut errors);
    if let Some(router) = cfg.router {
        check_in_subnet(cfg, router, "router", &mut errors);
    }

    if to_u32(cfg.pool_start) > to_u32(cfg.pool_end) {
        errors.push(format!(
            "pool_start {} is greater than pool_end {}",
            cfg.pool_start, cfg.pool_end
        ));
    }

    if cfg.lease_time == 0 {
        errors.push("lease_time must be greater than 0".to_string());
    }

    let network = cfg.subnet.network();
    let broadcast = cfg.subnet.broadcast();

    // Key addresses must not collide with the network or broadcast address.
    for (ip, label) in [
        (cfg.server_ip, "server_ip"),
        (cfg.pool_start, "pool_start"),
        (cfg.pool_end, "pool_end"),
    ] {
        if ip == network || ip == broadcast {
            errors.push(format!(
                "{} {} must not be the network or broadcast address",
                label, ip
            ));
        }
    }
    if let Some(router) = cfg.router {
        if router == network || router == broadcast {
            errors.push(format!(
                "router {} must not be the network or broadcast address",
                router
            ));
        }
    }

    // The server's own address inside the pool would silently shrink it.
    let server = to_u32(cfg.server_ip);
    if server >= to_u32(cfg.pool_start) && server <= to_u32(cfg.pool_end) {
        errors.push(format!(
            "server_ip {} is inside the dynamic pool {}..={}",
            cfg.server_ip, cfg.pool_start, cfg.pool_end
        ));
    }

    let mut seen_mac: HashMap<String, &str> = HashMap::new();
    let mut seen_ip: HashMap<u32, &str> = HashMap::new();
    for s in &cfg.statics {
        if !cfg.subnet.contains(s.ip) {
            errors.push(format!(
                "static '{}': IP {} is outside subnet {}/{}",
                s.name,
                s.ip,
                cfg.subnet.network(),
                cfg.subnet.prefix
            ));
        }
        if s.ip == network || s.ip == broadcast {
            errors.push(format!(
                "static '{}': IP {} is the network or broadcast address",
                s.name, s.ip
            ));
        }
        let mac = s.mac.to_string();
        if let Some(prev) = seen_mac.insert(mac.clone(), &s.name) {
            errors.push(format!(
                "duplicate static MAC {} (used by '{}' and '{}')",
                mac, prev, s.name
            ));
        }
        if let Some(prev) = seen_ip.insert(to_u32(s.ip), &s.name) {
            errors.push(format!(
                "duplicate static IP {} (used by '{}' and '{}')",
                s.ip, prev, s.name
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

fn check_in_subnet(cfg: &DhcpConfig, ip: Ipv4Addr, label: &str, errors: &mut Vec<String>) {
    if !cfg.subnet.contains(ip) {
        errors.push(format!(
            "{} {} is outside subnet {}/{}",
            label,
            ip,
            cfg.subnet.network(),
            cfg.subnet.prefix
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::super::parser::parse_config;
    use super::*;

    fn base() -> String {
        "\
interface=eth0
server_ip=192.168.10.1
subnet=192.168.10.0/24
subnet_mask=255.255.255.0
pool_start=192.168.10.100
pool_end=192.168.10.200
router=192.168.10.1
dns=1.1.1.1
lease_time=86400
lease_file=/tmp/leases
"
        .to_string()
    }

    #[test]
    fn valid_config_passes() {
        let cfg = parse_config(&base()).unwrap();
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn mask_mismatch_fails() {
        let text = base().replace("subnet_mask=255.255.255.0", "subnet_mask=255.255.0.0");
        let cfg = parse_config(&text).unwrap();
        assert!(validate(&cfg).unwrap_err().contains("subnet_mask"));
    }

    #[test]
    fn pool_outside_subnet_fails() {
        let text = base().replace("pool_end=192.168.10.200", "pool_end=192.168.20.200");
        let cfg = parse_config(&text).unwrap();
        assert!(validate(&cfg).unwrap_err().contains("pool_end"));
    }

    #[test]
    fn reversed_pool_fails() {
        let text = base()
            .replace("pool_start=192.168.10.100", "pool_start=192.168.10.200")
            .replace("pool_end=192.168.10.200\n", "pool_end=192.168.10.100\n");
        let cfg = parse_config(&text).unwrap();
        assert!(validate(&cfg).unwrap_err().contains("greater than"));
    }

    #[test]
    fn duplicate_static_ip_fails() {
        let mut text = base();
        text.push_str("static=a,aa:aa:aa:aa:aa:aa,192.168.10.50\n");
        text.push_str("static=b,bb:bb:bb:bb:bb:bb,192.168.10.50\n");
        let cfg = parse_config(&text).unwrap();
        assert!(validate(&cfg).unwrap_err().contains("duplicate static IP"));
    }

    #[test]
    fn static_outside_subnet_fails() {
        let mut text = base();
        text.push_str("static=a,aa:aa:aa:aa:aa:aa,10.0.0.5\n");
        let cfg = parse_config(&text).unwrap();
        assert!(validate(&cfg).unwrap_err().contains("outside subnet"));
    }

    #[test]
    fn server_ip_in_pool_fails() {
        let text = base().replace("server_ip=192.168.10.1", "server_ip=192.168.10.150");
        let cfg = parse_config(&text).unwrap();
        assert!(validate(&cfg)
            .unwrap_err()
            .contains("inside the dynamic pool"));
    }

    #[test]
    fn too_many_dns_servers_fails() {
        let mut cfg = parse_config(&base()).unwrap();
        cfg.dns = vec!["1.1.1.1".parse().unwrap(); 64];
        assert!(validate(&cfg).unwrap_err().contains("too many dns"));
    }

    #[test]
    fn pool_endpoint_on_broadcast_fails() {
        let text = base().replace("pool_end=192.168.10.200", "pool_end=192.168.10.255");
        let cfg = parse_config(&text).unwrap();
        assert!(validate(&cfg).unwrap_err().contains("broadcast"));
    }
}
