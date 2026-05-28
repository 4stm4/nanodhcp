//! Ethernet MAC address: parsing, formatting, value semantics.

use std::fmt;
use std::str::FromStr;

/// A 6-byte Ethernet MAC address.
///
/// `Copy`/`Eq`/`Hash` so it can be used directly as a `HashMap` key for lease
/// lookups without allocation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// Build from a byte slice. Returns `None` unless the slice is exactly 6
    /// bytes long — used when reading `chaddr` from an untrusted packet.
    pub fn from_bytes(bytes: &[u8]) -> Option<MacAddr> {
        if bytes.len() != 6 {
            return None;
        }
        let mut a = [0u8; 6];
        a.copy_from_slice(bytes);
        Some(MacAddr(a))
    }

    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl FromStr for MacAddr {
    type Err = String;

    /// Parse `aa:bb:cc:dd:ee:ff` (lower or upper case hex).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut octets = [0u8; 6];
        let mut count = 0;
        for part in s.split(':') {
            if count == 6 {
                return Err(format!("invalid MAC '{}': too many octets", s));
            }
            octets[count] = u8::from_str_radix(part, 16)
                .map_err(|_| format!("invalid MAC '{}': bad octet '{}'", s, part))?;
            count += 1;
        }
        if count != 6 {
            return Err(format!("invalid MAC '{}': expected 6 octets, got {}", s, count));
        }
        Ok(MacAddr(octets))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lowercase() {
        let m: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        assert_eq!(m.0, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn parse_uppercase_and_short_octets() {
        let m: MacAddr = "0A:1:22:33:44:55".parse().unwrap();
        assert_eq!(m.0, [0x0a, 0x01, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn display_roundtrip() {
        let m: MacAddr = "11:22:33:44:55:66".parse().unwrap();
        assert_eq!(m.to_string(), "11:22:33:44:55:66");
    }

    #[test]
    fn reject_wrong_length() {
        assert!("aa:bb:cc:dd:ee".parse::<MacAddr>().is_err());
        assert!("aa:bb:cc:dd:ee:ff:00".parse::<MacAddr>().is_err());
    }

    #[test]
    fn reject_bad_hex() {
        assert!("aa:bb:cc:dd:ee:zz".parse::<MacAddr>().is_err());
    }

    #[test]
    fn from_bytes_checks_length() {
        assert!(MacAddr::from_bytes(&[1, 2, 3, 4, 5, 6]).is_some());
        assert!(MacAddr::from_bytes(&[1, 2, 3]).is_none());
    }
}
