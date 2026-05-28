//! Build DHCP replies (OFFER / ACK / NAK) from a parsed request.

use std::net::Ipv4Addr;

use crate::config::DhcpConfig;

use super::message::DhcpMessageType;
use super::options::{self, OptionsWriter};
use super::packet::{
    DhcpPacket, BOOTREPLY, COOKIE_OFFSET, HLEN_ETHERNET, HTYPE_ETHERNET, MAGIC_COOKIE, MIN_LEN,
};

/// Fill the fixed BOOTP header of a reply, echoing the request's xid, flags,
/// giaddr and chaddr.
fn base_reply(req: &DhcpPacket, cfg: &DhcpConfig, yiaddr: Ipv4Addr) -> Vec<u8> {
    let mut p = vec![0u8; MIN_LEN];
    p[0] = BOOTREPLY;
    p[1] = HTYPE_ETHERNET;
    p[2] = HLEN_ETHERNET;
    p[3] = 0; // hops
    p[4..8].copy_from_slice(&req.xid.to_be_bytes());
    // secs (8..10) left 0
    p[10..12].copy_from_slice(&req.flags.to_be_bytes());
    // ciaddr (12..16) left 0
    p[16..20].copy_from_slice(&yiaddr.octets());
    p[20..24].copy_from_slice(&cfg.server_ip.octets()); // siaddr
    p[24..28].copy_from_slice(&req.giaddr.octets()); // giaddr echoed
    p[28..34].copy_from_slice(req.chaddr.as_bytes()); // chaddr (first 6 of 16)
    p[COOKIE_OFFSET..MIN_LEN].copy_from_slice(&MAGIC_COOKIE);
    p
}

fn build(req: &DhcpPacket, cfg: &DhcpConfig, yiaddr: Ipv4Addr, mt: DhcpMessageType) -> Vec<u8> {
    let mut packet = base_reply(req, cfg, yiaddr);

    let mut w = OptionsWriter::new();
    w.push_u8(options::OPT_MSG_TYPE, mt.to_u8());
    w.push_ipv4(options::OPT_SERVER_ID, cfg.server_ip);

    // NAK carries no configuration parameters.
    if mt != DhcpMessageType::Nak {
        w.push_u32(options::OPT_LEASE_TIME, cfg.lease_time);
        w.push_ipv4(options::OPT_SUBNET_MASK, cfg.subnet_mask);
        if let Some(router) = cfg.router {
            w.push_ipv4(options::OPT_ROUTER, router);
        }
        if !cfg.dns.is_empty() {
            w.push_ipv4_list(options::OPT_DNS, &cfg.dns);
        }
    }

    packet.extend_from_slice(&w.finish());
    packet
}

pub fn build_offer(req: &DhcpPacket, cfg: &DhcpConfig, yiaddr: Ipv4Addr) -> Vec<u8> {
    build(req, cfg, yiaddr, DhcpMessageType::Offer)
}

pub fn build_ack(req: &DhcpPacket, cfg: &DhcpConfig, yiaddr: Ipv4Addr) -> Vec<u8> {
    build(req, cfg, yiaddr, DhcpMessageType::Ack)
}

pub fn build_nak(req: &DhcpPacket, cfg: &DhcpConfig) -> Vec<u8> {
    build(req, cfg, Ipv4Addr::UNSPECIFIED, DhcpMessageType::Nak)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parser::parse_config;
    use crate::dhcp::options::Options;
    use crate::dhcp::packet::{COOKIE_OFFSET, HLEN_ETHERNET, HTYPE_ETHERNET};

    fn cfg() -> DhcpConfig {
        parse_config(
            "\
interface=eth0
server_ip=192.168.10.1
subnet=192.168.10.0/24
subnet_mask=255.255.255.0
pool_start=192.168.10.100
pool_end=192.168.10.200
router=192.168.10.1
dns=1.1.1.1,8.8.8.8
lease_time=86400
lease_file=/tmp/leases
",
        )
        .unwrap()
    }

    fn request() -> DhcpPacket {
        let mut p = vec![0u8; MIN_LEN];
        p[0] = 1;
        p[1] = HTYPE_ETHERNET;
        p[2] = HLEN_ETHERNET;
        p[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        p[28..34].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        p[COOKIE_OFFSET..MIN_LEN].copy_from_slice(&MAGIC_COOKIE);
        p.extend_from_slice(&[options::OPT_MSG_TYPE, 1, 1, options::OPT_END]);
        DhcpPacket::parse(&p).unwrap()
    }

    #[test]
    fn offer_has_expected_header_and_options() {
        let cfg = cfg();
        let req = request();
        let yiaddr = Ipv4Addr::new(192, 168, 10, 100);
        let reply = build_offer(&req, &cfg, yiaddr);

        // BOOTREPLY, echoed xid, yiaddr in place.
        assert_eq!(reply[0], BOOTREPLY);
        assert_eq!(&reply[4..8], &0x1234_5678u32.to_be_bytes());
        assert_eq!(&reply[16..20], &yiaddr.octets());
        assert_eq!(&reply[COOKIE_OFFSET..MIN_LEN], &MAGIC_COOKIE);

        let opts = Options::parse(&reply[MIN_LEN..]);
        assert_eq!(opts.msg_type(), Some(DhcpMessageType::Offer));
        assert_eq!(opts.server_id(), Some(Ipv4Addr::new(192, 168, 10, 1)));
        assert_eq!(
            opts.get(options::OPT_SUBNET_MASK),
            Some(&[255, 255, 255, 0][..])
        );
        assert_eq!(opts.get(options::OPT_DNS).map(|d| d.len()), Some(8));
    }

    #[test]
    fn nak_has_no_lease_params() {
        let cfg = cfg();
        let req = request();
        let reply = build_nak(&req, &cfg);
        assert_eq!(&reply[16..20], &[0, 0, 0, 0]); // yiaddr zeroed
        let opts = Options::parse(&reply[MIN_LEN..]);
        assert_eq!(opts.msg_type(), Some(DhcpMessageType::Nak));
        assert!(opts.get(options::OPT_SUBNET_MASK).is_none());
        assert!(opts.get(options::OPT_LEASE_TIME).is_none());
    }
}
