//! IPv4 / CIDR helpers built on top of `std::net::Ipv4Addr`.

use std::net::Ipv4Addr;
use std::str::FromStr;

/// IPv4 address as host-order `u32`.
pub fn to_u32(ip: Ipv4Addr) -> u32 {
    u32::from(ip)
}

/// `u32` (host order) back to an IPv4 address.
pub fn from_u32(v: u32) -> Ipv4Addr {
    Ipv4Addr::from(v)
}

/// A subnet in CIDR form, e.g. `192.168.10.0/24`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl Cidr {
    /// Netmask as a `u32`. Prefix 0 yields 0 (avoids an undefined 32-bit shift).
    pub fn mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix as u32)
        }
    }

    /// Network address (host bits cleared).
    pub fn network(&self) -> Ipv4Addr {
        from_u32(to_u32(self.addr) & self.mask())
    }

    /// Broadcast address (host bits set).
    pub fn broadcast(&self) -> Ipv4Addr {
        from_u32(to_u32(self.addr) | !self.mask())
    }

    /// Netmask as an `Ipv4Addr`, e.g. `255.255.255.0`.
    pub fn netmask(&self) -> Ipv4Addr {
        from_u32(self.mask())
    }

    /// Is `ip` inside this subnet?
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (to_u32(ip) & self.mask()) == to_u32(self.network())
    }
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (a, p) = s
            .split_once('/')
            .ok_or_else(|| format!("invalid CIDR '{}': missing /prefix", s))?;
        let addr = Ipv4Addr::from_str(a.trim())
            .map_err(|_| format!("invalid CIDR '{}': bad address '{}'", s, a))?;
        let prefix: u8 = p
            .trim()
            .parse()
            .map_err(|_| format!("invalid CIDR '{}': bad prefix '{}'", s, p))?;
        if prefix > 32 {
            return Err(format!("invalid CIDR '{}': prefix must be 0..=32", s));
        }
        Ok(Cidr { addr, prefix })
    }
}

/// Parse a bare IPv4 address with a friendly error message.
pub fn parse_ipv4(s: &str) -> Result<Ipv4Addr, String> {
    Ipv4Addr::from_str(s.trim()).map_err(|_| format!("invalid IPv4 address '{}'", s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn u32_roundtrip() {
        let a = ip("192.168.10.1");
        assert_eq!(from_u32(to_u32(a)), a);
    }

    #[test]
    fn cidr_parse_and_math() {
        let c: Cidr = "192.168.10.5/24".parse().unwrap();
        assert_eq!(c.network(), ip("192.168.10.0"));
        assert_eq!(c.broadcast(), ip("192.168.10.255"));
        assert_eq!(c.netmask(), ip("255.255.255.0"));
    }

    #[test]
    fn cidr_contains() {
        let c: Cidr = "192.168.10.0/24".parse().unwrap();
        assert!(c.contains(ip("192.168.10.100")));
        assert!(c.contains(ip("192.168.10.0")));
        assert!(c.contains(ip("192.168.10.255")));
        assert!(!c.contains(ip("192.168.11.1")));
        assert!(!c.contains(ip("10.0.0.1")));
    }

    #[test]
    fn cidr_prefix_30() {
        let c: Cidr = "10.0.0.0/30".parse().unwrap();
        assert_eq!(c.broadcast(), ip("10.0.0.3"));
        assert!(c.contains(ip("10.0.0.2")));
        assert!(!c.contains(ip("10.0.0.4")));
    }

    #[test]
    fn cidr_prefix_zero_does_not_panic() {
        let c: Cidr = "0.0.0.0/0".parse().unwrap();
        assert_eq!(c.mask(), 0);
        assert!(c.contains(ip("8.8.8.8")));
    }

    #[test]
    fn cidr_rejects_bad_input() {
        assert!("192.168.10.0".parse::<Cidr>().is_err());
        assert!("192.168.10.0/33".parse::<Cidr>().is_err());
        assert!("nope/24".parse::<Cidr>().is_err());
    }
}
