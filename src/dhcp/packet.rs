//! BOOTP/DHCP packet parsing.
//!
//! Layout (RFC 2131): a 236-byte fixed BOOTP header, a 4-byte magic cookie,
//! then variable-length options. All untrusted reads are bounds-checked; the
//! parser returns `Err` for anything malformed and never panics or unwraps.

use std::net::Ipv4Addr;

use crate::util::mac::MacAddr;

use super::options::Options;

pub const BOOTREQUEST: u8 = 1;
pub const BOOTREPLY: u8 = 2;
pub const HTYPE_ETHERNET: u8 = 1;
pub const HLEN_ETHERNET: u8 = 6;
pub const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Offset of the magic cookie / start of the BOOTP+cookie minimum.
pub const COOKIE_OFFSET: usize = 236;
/// Minimum valid packet length: fixed header + cookie.
pub const MIN_LEN: usize = 240;

/// The fields of a client request we use. `op`/`htype`/`hlen` are validated
/// during parsing but not stored (they are constant for a valid request);
/// `yiaddr`/`siaddr` are server-set fields a client request leaves zero.
#[derive(Debug)]
pub struct DhcpPacket {
    pub xid: u32,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: MacAddr,
    pub options: Options,
}

impl DhcpPacket {
    pub fn parse(buf: &[u8]) -> Result<DhcpPacket, &'static str> {
        if buf.len() < MIN_LEN {
            return Err("packet shorter than 240 bytes");
        }
        let op = buf[0];
        let htype = buf[1];
        let hlen = buf[2];
        if op != BOOTREQUEST {
            return Err("op is not BOOTREQUEST");
        }
        if htype != HTYPE_ETHERNET {
            return Err("htype is not Ethernet");
        }
        if hlen != HLEN_ETHERNET {
            return Err("hlen is not 6");
        }
        if buf[COOKIE_OFFSET..MIN_LEN] != MAGIC_COOKIE {
            return Err("invalid magic cookie");
        }

        let xid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let flags = u16::from_be_bytes([buf[10], buf[11]]);
        let ciaddr = read_ipv4(buf, 12);
        let giaddr = read_ipv4(buf, 24);
        // chaddr is 16 bytes at offset 28; for Ethernet only the first 6 matter.
        let chaddr = MacAddr::from_bytes(&buf[28..34]).ok_or("invalid chaddr")?;
        let options = Options::parse(&buf[MIN_LEN..]);

        Ok(DhcpPacket {
            xid,
            flags,
            ciaddr,
            giaddr,
            chaddr,
            options,
        })
    }
}

/// Read 4 bytes at `off` as an IPv4 address. Caller guarantees `off + 4 <= len`
/// (all call sites are within the fixed header, which `parse` length-checked).
fn read_ipv4(buf: &[u8], off: usize) -> Ipv4Addr {
    Ipv4Addr::new(buf[off], buf[off + 1], buf[off + 2], buf[off + 3])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhcp::message::DhcpMessageType;
    use crate::dhcp::options::{OPT_END, OPT_MSG_TYPE};

    /// Build a minimal valid DISCOVER for tests.
    fn discover() -> Vec<u8> {
        let mut p = vec![0u8; MIN_LEN];
        p[0] = BOOTREQUEST;
        p[1] = HTYPE_ETHERNET;
        p[2] = HLEN_ETHERNET;
        p[4..8].copy_from_slice(&0xdead_beefu32.to_be_bytes()); // xid
        p[28..34].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // chaddr
        p[COOKIE_OFFSET..MIN_LEN].copy_from_slice(&MAGIC_COOKIE);
        p.extend_from_slice(&[OPT_MSG_TYPE, 1, 1, OPT_END]);
        p
    }

    #[test]
    fn parses_valid_discover() {
        let pkt = DhcpPacket::parse(&discover()).unwrap();
        assert_eq!(pkt.xid, 0xdead_beef);
        assert_eq!(pkt.chaddr.to_string(), "aa:bb:cc:dd:ee:ff");
        assert_eq!(pkt.options.msg_type(), Some(DhcpMessageType::Discover));
    }

    #[test]
    fn rejects_short_packet() {
        let buf = [0u8; 100];
        assert!(DhcpPacket::parse(&buf).is_err());
    }

    #[test]
    fn rejects_bad_cookie() {
        let mut p = discover();
        p[COOKIE_OFFSET] = 0;
        assert_eq!(DhcpPacket::parse(&p).unwrap_err(), "invalid magic cookie");
    }

    #[test]
    fn rejects_non_bootrequest() {
        let mut p = discover();
        p[0] = BOOTREPLY;
        assert_eq!(DhcpPacket::parse(&p).unwrap_err(), "op is not BOOTREQUEST");
    }

    #[test]
    fn rejects_wrong_htype_hlen() {
        let mut p = discover();
        p[1] = 99;
        assert!(DhcpPacket::parse(&p).is_err());
        let mut p = discover();
        p[2] = 7;
        assert!(DhcpPacket::parse(&p).is_err());
    }

    #[test]
    fn options_truncated_at_240_is_ok() {
        // No options section at all (exactly 240 bytes).
        let mut p = vec![0u8; MIN_LEN];
        p[0] = BOOTREQUEST;
        p[1] = HTYPE_ETHERNET;
        p[2] = HLEN_ETHERNET;
        p[28..34].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        p[COOKIE_OFFSET..MIN_LEN].copy_from_slice(&MAGIC_COOKIE);
        let pkt = DhcpPacket::parse(&p).unwrap();
        assert_eq!(pkt.options.msg_type(), None);
    }
}
