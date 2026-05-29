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

    // ---- Randomized parser fuzzing (std-only, deterministic) ----

    /// SplitMix64: a tiny deterministic PRNG so the fuzz tests are reproducible
    /// and need no external crate.
    struct Rng(u64);

    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn byte(&mut self) -> u8 {
            self.next_u64() as u8
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next_u64() % n as u64) as usize
        }
    }

    /// Touch every accessor on a parsed packet. Under fuzzing the only contract
    /// is that none of these panic or read out of bounds.
    fn exercise(pkt: &DhcpPacket) {
        let _ = pkt.options.msg_type();
        let _ = pkt.options.requested_ip();
        let _ = pkt.options.server_id();
        let _ = pkt.options.param_request_list();
        let _ = pkt.options.hostname();
        let _ = pkt.xid;
        let _ = pkt.flags;
        let _ = pkt.ciaddr;
        let _ = pkt.giaddr;
        let _ = &pkt.chaddr;
    }

    #[test]
    fn fuzz_random_bytes_never_panic() {
        // Arbitrary buffers of arbitrary length must parse to Ok or Err, never
        // panic. Most are rejected by the header checks; any survivor exercises
        // the option parser with whatever bytes followed the cookie.
        let mut rng = Rng(0x1234_5678_9ABC_DEF0);
        for _ in 0..50_000 {
            let n = rng.below(400);
            let mut buf = vec![0u8; n];
            for b in &mut buf {
                *b = rng.byte();
            }
            if let Ok(pkt) = DhcpPacket::parse(&buf) {
                exercise(&pkt);
            }
        }
    }

    #[test]
    fn fuzz_option_area_never_panics() {
        // Pin a valid BOOTP header + cookie and fuzz only the options area so
        // every iteration drives the TLV parser with adversarial length bytes.
        // A valid header always parses, so malformed options must be dropped,
        // never rejected and never over-read.
        let mut rng = Rng(0x0FED_CBA9_8765_4321);
        for _ in 0..50_000 {
            let mut buf = vec![0u8; MIN_LEN];
            buf[0] = BOOTREQUEST;
            buf[1] = HTYPE_ETHERNET;
            buf[2] = HLEN_ETHERNET;
            for b in &mut buf[28..34] {
                *b = rng.byte();
            }
            buf[COOKIE_OFFSET..MIN_LEN].copy_from_slice(&MAGIC_COOKIE);
            let opt_len = rng.below(320);
            for _ in 0..opt_len {
                buf.push(rng.byte());
            }
            let pkt = DhcpPacket::parse(&buf).expect("valid header must always parse");
            exercise(&pkt);
        }
    }
}
