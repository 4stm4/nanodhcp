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

    // subnet_mask must agree with the CIDR prefix.
    if cfg.subnet.netmask() != cfg.subnet_mask {
        errors.push(format!(
            "subnet_mask {} does not match subnet prefix /{} (expected {})",
            cfg.subnet_mask,
            cfg.subnet.prefix,
            cfg.subnet.netmask()
        ));
    }

    // server / router / pool must live in the subnet.
    check_in_subnet(cfg, cfg.server_ip, "server_ip", &mut errors);
    check_in_subnet(cfg, cfg.pool_start, "pool_start", &mut errors);
    check_in_subnet(cfg, cfg.pool_end, "pool_end", &mut errors);
    if let Some(router) = cfg.router {
        check_in_subnet(cfg, router, "router", &mut errors);
    }

    // pool ordering.
    if to_u32(cfg.pool_start) > to_u32(cfg.pool_end) {
        errors.push(format!(
            "pool_start {} is greater than pool_end {}",
            cfg.pool_start, cfg.pool_end
        ));
    }

    if cfg.lease_time == 0 {
        errors.push("lease_time must be greater than 0".to_string());
    }

    // static bindings.
    let network = cfg.subnet.network();
    let broadcast = cfg.subnet.broadcast();
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
}
