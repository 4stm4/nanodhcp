//! The receive loop: parse a datagram, decide a response, send it, log it.

use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::config::DhcpConfig;
use crate::dhcp::builder;
use crate::dhcp::message::DhcpMessageType;
use crate::dhcp::packet::DhcpPacket;
use crate::lease::allocator;
use crate::lease::model::{Lease, LeaseKind};
use crate::lease::LeaseStore;
use crate::util::time;

use super::socket::{self, CLIENT_PORT};

/// How long a declined address is held out of the pool. The conflict that
/// prompts a DHCPDECLINE (another host already using the address) is usually
/// transient, so we hold it for an hour rather than forever.
const DECLINE_QUARANTINE_SECS: u64 = 3600;

/// How long `recv_from` blocks before yielding so the loop can notice a
/// shutdown signal and check the purge timer.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// How often expired leases are swept from memory (and the lease file) while
/// running, so a long-lived server does not accumulate stale entries.
const PURGE_INTERVAL_SECS: u64 = 300;

/// Set by the signal handler to ask the receive loop to exit cleanly.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Bind the socket and serve until a shutdown signal arrives.
pub fn run(cfg: DhcpConfig) -> io::Result<()> {
    let sock = socket::bind(&cfg)?;
    // A bounded read timeout turns the blocking receive into a poll so we can
    // act on SIGTERM/SIGINT and run the periodic purge between datagrams.
    sock.set_read_timeout(Some(POLL_INTERVAL))?;
    install_signal_handlers();
    println!("nanodhcp: listening on {} udp/67", cfg.interface);

    let mut store = LeaseStore::load(&cfg.lease_file);
    let purged = store.purge_expired(time::now());
    if purged > 0 {
        println!("nanodhcp: purged {} expired lease(s) at startup", purged);
    }
    let mut next_purge = time::now() + PURGE_INTERVAL_SECS;
    let mut buf = [0u8; 1500];

    while !SHUTDOWN.load(Ordering::Relaxed) {
        match sock.recv_from(&mut buf) {
            Ok((len, _src)) => handle(&sock, &cfg, &mut store, &buf[..len]),
            // A poll timeout (or a signal interrupting the syscall) is normal:
            // fall through to the shutdown and purge checks below.
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) => {}
            Err(e) => eprintln!("nanodhcp: recv error: {}", e),
        }

        let now = time::now();
        if now >= next_purge {
            let removed = store.purge_expired(now);
            if removed > 0 {
                println!("nanodhcp: purged {} expired lease(s)", removed);
                if let Err(e) = store.save() {
                    eprintln!("nanodhcp: warning: cannot save leases: {}", e);
                }
            }
            next_purge = now + PURGE_INTERVAL_SECS;
        }
    }

    println!("nanodhcp: received shutdown signal, exiting");
    Ok(())
}

/// Install handlers for SIGTERM and SIGINT that ask the loop to stop. The
/// handler only sets an atomic flag, which is async-signal-safe.
#[cfg(unix)]
fn install_signal_handlers() {
    use std::os::raw::c_int;

    const SIGINT: c_int = 2;
    const SIGTERM: c_int = 15;

    extern "C" fn on_signal(_sig: c_int) {
        SHUTDOWN.store(true, Ordering::SeqCst);
    }

    extern "C" {
        fn signal(signum: c_int, handler: extern "C" fn(c_int)) -> usize;
    }

    // SAFETY: `on_signal` is a valid function pointer and does nothing but store
    // to an atomic. We discard the previous handler (the returned value may be
    // SIG_DFL/SIG_ERR, hence the `usize` return type rather than a fn pointer).
    unsafe {
        signal(SIGINT, on_signal);
        signal(SIGTERM, on_signal);
    }
}

#[cfg(not(unix))]
fn install_signal_handlers() {}

fn handle(sock: &UdpSocket, cfg: &DhcpConfig, store: &mut LeaseStore, data: &[u8]) {
    let pkt = match DhcpPacket::parse(data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("nanodhcp: ignored malformed packet: {}", e);
            return;
        }
    };

    let decision = decide(cfg, store, &pkt, time::now());
    if decision.persist {
        if let Err(e) = store.save() {
            eprintln!("nanodhcp: warning: cannot save leases: {}", e);
        }
    }
    if let Some((data, dst)) = decision.reply {
        send(sock, &data, dst);
    }
}

/// Where a reply is sent. We serve one directly-attached LAN, so a client that
/// already holds an address (renewing, non-zero `ciaddr`) can be answered by
/// unicast, while one still acquiring an address is answered by broadcast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplyDst {
    Broadcast,
    Unicast(Ipv4Addr),
}

/// Outcome of processing one packet: an optional reply (bytes + destination)
/// and whether the in-memory lease store changed and must be written to disk.
struct Decision {
    reply: Option<(Vec<u8>, ReplyDst)>,
    persist: bool,
}

impl Decision {
    fn silent() -> Decision {
        Decision {
            reply: None,
            persist: false,
        }
    }

    fn reply(data: Vec<u8>, dst: ReplyDst) -> Decision {
        Decision {
            reply: Some((data, dst)),
            persist: false,
        }
    }
}

/// Decide how to answer one parsed packet, applying any lease change to `store`
/// in memory. Performs no socket or disk I/O, so the whole protocol state
/// machine is unit-testable; the caller persists and sends.
fn decide(cfg: &DhcpConfig, store: &mut LeaseStore, pkt: &DhcpPacket, now: u64) -> Decision {
    let mtype = match pkt.options.msg_type() {
        Some(m) => m,
        None => {
            eprintln!("nanodhcp: ignored packet without DHCP message type");
            return Decision::silent();
        }
    };

    let mac = pkt.chaddr;
    let hostname = pkt.options.hostname();
    let host_disp = hostname.as_deref().unwrap_or("-");

    match mtype {
        DhcpMessageType::Discover => {
            println!("nanodhcp: DISCOVER mac={} hostname={}", mac, host_disp);
            match allocator::assign_ip(cfg, store, mac, now) {
                Some(ip) => {
                    println!("nanodhcp: OFFER ip={} mac={}", ip, mac);
                    Decision::reply(builder::build_offer(pkt, cfg, ip), ReplyDst::Broadcast)
                }
                None => {
                    eprintln!("nanodhcp: no free address available for mac={}", mac);
                    Decision::silent()
                }
            }
        }

        DhcpMessageType::Request => {
            let selecting = pkt.options.server_id().is_some();
            // SELECTING: option 54 names the chosen server. If it is not us,
            // stay silent — another DHCP server owns this exchange.
            if let Some(sid) = pkt.options.server_id() {
                if sid != cfg.server_ip {
                    return Decision::silent();
                }
            }
            let requested = pkt.options.requested_ip().unwrap_or(pkt.ciaddr);
            println!("nanodhcp: REQUEST ip={} mac={}", requested, mac);

            // INIT-REBOOT (no option 54): with no record of this client, stay
            // silent so a server that has one can answer (RFC 2131 §4.3.2).
            let known = cfg.static_for(mac).is_some() || store.get(&mac).is_some();
            if !selecting && !known {
                println!(
                    "nanodhcp: REQUEST from unknown mac={} (INIT-REBOOT), ignored",
                    mac
                );
                return Decision::silent();
            }

            match allocator::assign_ip(cfg, store, mac, now) {
                // Honour the request only if the client wants the address we
                // would give it (or expressed no preference).
                Some(ip) if requested.is_unspecified() || requested == ip => {
                    let mut persist = false;
                    if cfg.static_for(mac).is_none() {
                        store.purge_expired(now);
                        store.insert(Lease {
                            mac,
                            ip,
                            hostname: hostname.clone(),
                            expires_at: now + cfg.lease_time as u64,
                            kind: LeaseKind::Dynamic,
                        });
                        persist = true;
                    }
                    println!("nanodhcp: ACK ip={} mac={}", ip, mac);
                    Decision {
                        reply: Some((builder::build_ack(pkt, cfg, ip), ack_dst(pkt))),
                        persist,
                    }
                }
                _ => {
                    println!("nanodhcp: NAK mac={} requested={}", mac, requested);
                    // A NAK is always broadcast: the client's notion of its own
                    // address is wrong, so it may be unreachable by unicast.
                    Decision::reply(builder::build_nak(pkt, cfg), ReplyDst::Broadcast)
                }
            }
        }

        DhcpMessageType::Release => {
            let persist = cfg.static_for(mac).is_none() && store.remove(&mac).is_some();
            println!("nanodhcp: RELEASE mac={}", mac);
            Decision {
                reply: None,
                persist,
            }
        }

        DhcpMessageType::Decline => {
            // RFC 2131 §4.3.3: the client reports the address (option 50) is
            // already in use. Drop our record and quarantine the address so the
            // allocator stops handing it out until the conflict clears.
            let declined = pkt
                .options
                .requested_ip()
                .or_else(|| store.get(&mac).map(|l| l.ip))
                .unwrap_or(pkt.ciaddr);
            let persist = cfg.static_for(mac).is_none() && store.remove(&mac).is_some();
            if !declined.is_unspecified() {
                store.quarantine(declined, now + DECLINE_QUARANTINE_SECS);
            }
            println!("nanodhcp: DECLINE mac={} ip={}", mac, declined);
            Decision {
                reply: None,
                persist,
            }
        }

        DhcpMessageType::Inform => {
            // RFC 2131 §4.3.5: the client already has an address and only wants
            // configuration parameters. Reply with a DHCPACK carrying options
            // but no yiaddr and no lease time, unicast to its ciaddr.
            println!("nanodhcp: INFORM mac={} ciaddr={}", mac, pkt.ciaddr);
            Decision::reply(builder::build_inform_ack(pkt, cfg), ack_dst(pkt))
        }

        other => {
            eprintln!("nanodhcp: ignoring unsupported message type {:?}", other);
            Decision::silent()
        }
    }
}

/// Destination for an ACK. A renewing client (non-zero `ciaddr`) can receive
/// unicast; one still acquiring an address (`ciaddr` zero, from SELECTING or
/// INIT-REBOOT) is answered by broadcast, which it hears before ARP is set up.
fn ack_dst(pkt: &DhcpPacket) -> ReplyDst {
    if pkt.ciaddr.is_unspecified() {
        ReplyDst::Broadcast
    } else {
        ReplyDst::Unicast(pkt.ciaddr)
    }
}

/// Send a reply on the client port, by broadcast or unicast as chosen above.
fn send(sock: &UdpSocket, data: &[u8], dst: ReplyDst) {
    let addr = match dst {
        ReplyDst::Broadcast => SocketAddrV4::new(Ipv4Addr::BROADCAST, CLIENT_PORT),
        ReplyDst::Unicast(ip) => SocketAddrV4::new(ip, CLIENT_PORT),
    };
    if let Err(e) = sock.send_to(data, addr) {
        eprintln!("nanodhcp: send error: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parser::parse_config;
    use crate::dhcp::options::{
        Options, OptionsWriter, OPT_LEASE_TIME, OPT_MSG_TYPE, OPT_REQUESTED_IP, OPT_SERVER_ID,
        OPT_SUBNET_MASK,
    };
    use crate::dhcp::packet::{
        BOOTREQUEST, COOKIE_OFFSET, HLEN_ETHERNET, HTYPE_ETHERNET, MAGIC_COOKIE, MIN_LEN,
    };
    use crate::util::mac::MacAddr;

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
lease_time=3600
lease_file=/tmp/nanodhcp-daemon-test
",
        );
        text.push_str(extra);
        parse_config(&text).unwrap()
    }

    /// Always-empty store backed by a path that never exists; `decide` does no
    /// disk I/O, so this only holds the in-memory map under test.
    fn store() -> LeaseStore {
        LeaseStore::load("/nonexistent/nanodhcp/daemon-test")
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn mac_bytes(s: &str) -> [u8; 6] {
        let m: MacAddr = s.parse().unwrap();
        let b = m.as_bytes();
        [b[0], b[1], b[2], b[3], b[4], b[5]]
    }

    fn lease(mac: &str, addr: &str, expires: u64) -> Lease {
        Lease {
            mac: mac.parse().unwrap(),
            ip: ip(addr),
            hostname: None,
            expires_at: expires,
            kind: LeaseKind::Dynamic,
        }
    }

    /// Build a BOOTREQUEST carrying `mtype`, `ciaddr` and the given options.
    fn packet(
        mtype: DhcpMessageType,
        mac: &str,
        ciaddr: Ipv4Addr,
        opts: &[(u8, Vec<u8>)],
    ) -> DhcpPacket {
        let mut p = vec![0u8; MIN_LEN];
        p[0] = BOOTREQUEST;
        p[1] = HTYPE_ETHERNET;
        p[2] = HLEN_ETHERNET;
        p[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        p[12..16].copy_from_slice(&ciaddr.octets());
        p[28..34].copy_from_slice(&mac_bytes(mac));
        p[COOKIE_OFFSET..MIN_LEN].copy_from_slice(&MAGIC_COOKIE);

        let mut w = OptionsWriter::new();
        w.push_u8(OPT_MSG_TYPE, mtype.to_u8());
        for (code, data) in opts {
            w.push(*code, data);
        }
        p.extend_from_slice(&w.finish());
        DhcpPacket::parse(&p).unwrap()
    }

    /// (message type, yiaddr) of a reply produced by `decide`.
    fn reply_summary(data: &[u8]) -> (DhcpMessageType, Ipv4Addr) {
        let yiaddr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let mt = Options::parse(&data[MIN_LEN..]).msg_type().unwrap();
        (mt, yiaddr)
    }

    fn server_id() -> (u8, Vec<u8>) {
        (OPT_SERVER_ID, ip("192.168.10.1").octets().to_vec())
    }

    fn requested(addr: &str) -> (u8, Vec<u8>) {
        (OPT_REQUESTED_IP, ip(addr).octets().to_vec())
    }

    #[test]
    fn discover_offers_first_free_by_broadcast() {
        let c = cfg("");
        let mut s = store();
        let pkt = packet(
            DhcpMessageType::Discover,
            "aa:aa:aa:aa:aa:aa",
            Ipv4Addr::UNSPECIFIED,
            &[],
        );
        let d = decide(&c, &mut s, &pkt, 1000);
        let (data, dst) = d.reply.expect("offer");
        assert_eq!(dst, ReplyDst::Broadcast);
        assert_eq!(
            reply_summary(&data),
            (DhcpMessageType::Offer, ip("192.168.10.100"))
        );
        assert!(!d.persist);
        // An OFFER reserves nothing.
        assert!(s.get(&"aa:aa:aa:aa:aa:aa".parse().unwrap()).is_none());
    }

    #[test]
    fn selecting_our_server_acks_and_persists() {
        let c = cfg("");
        let mut s = store();
        let pkt = packet(
            DhcpMessageType::Request,
            "bb:bb:bb:bb:bb:bb",
            Ipv4Addr::UNSPECIFIED,
            &[server_id()],
        );
        let d = decide(&c, &mut s, &pkt, 1000);
        let (data, dst) = d.reply.expect("ack");
        assert_eq!(dst, ReplyDst::Broadcast); // ciaddr zero in SELECTING
        assert_eq!(reply_summary(&data).0, DhcpMessageType::Ack);
        assert!(d.persist);
        let stored = s.get(&"bb:bb:bb:bb:bb:bb".parse().unwrap()).unwrap();
        assert_eq!(stored.ip, ip("192.168.10.100"));
        assert_eq!(stored.expires_at, 1000 + 3600);
    }

    #[test]
    fn selecting_other_server_is_silent() {
        let c = cfg("");
        let mut s = store();
        let other = (OPT_SERVER_ID, ip("192.168.10.250").octets().to_vec());
        let pkt = packet(
            DhcpMessageType::Request,
            "bb:bb:bb:bb:bb:bb",
            Ipv4Addr::UNSPECIFIED,
            &[other],
        );
        let d = decide(&c, &mut s, &pkt, 1000);
        assert!(d.reply.is_none());
        assert!(!d.persist);
        assert_eq!(s.iter().count(), 0);
    }

    #[test]
    fn init_reboot_unknown_is_silent() {
        let c = cfg("");
        let mut s = store();
        let pkt = packet(
            DhcpMessageType::Request,
            "cc:cc:cc:cc:cc:cc",
            Ipv4Addr::UNSPECIFIED,
            &[requested("192.168.10.100")],
        );
        let d = decide(&c, &mut s, &pkt, 1000);
        assert!(d.reply.is_none());
        assert!(!d.persist);
    }

    #[test]
    fn init_reboot_known_acks() {
        let c = cfg("");
        let mut s = store();
        s.insert(lease("cc:cc:cc:cc:cc:cc", "192.168.10.101", 9999));
        let pkt = packet(
            DhcpMessageType::Request,
            "cc:cc:cc:cc:cc:cc",
            Ipv4Addr::UNSPECIFIED,
            &[requested("192.168.10.101")],
        );
        let d = decide(&c, &mut s, &pkt, 1000);
        let (data, dst) = d.reply.expect("ack");
        assert_eq!(dst, ReplyDst::Broadcast);
        assert_eq!(
            reply_summary(&data),
            (DhcpMessageType::Ack, ip("192.168.10.101"))
        );
    }

    #[test]
    fn renew_acks_by_unicast_to_ciaddr() {
        let c = cfg("");
        let mut s = store();
        s.insert(lease("dd:dd:dd:dd:dd:dd", "192.168.10.102", 9999));
        // RENEW: no server-id, no requested-ip, client address in ciaddr.
        let pkt = packet(
            DhcpMessageType::Request,
            "dd:dd:dd:dd:dd:dd",
            ip("192.168.10.102"),
            &[],
        );
        let d = decide(&c, &mut s, &pkt, 1000);
        let (data, dst) = d.reply.expect("ack");
        assert_eq!(dst, ReplyDst::Unicast(ip("192.168.10.102")));
        assert_eq!(
            reply_summary(&data),
            (DhcpMessageType::Ack, ip("192.168.10.102"))
        );
        assert!(d.persist);
    }

    #[test]
    fn request_for_wrong_ip_naks() {
        let c = cfg("");
        let mut s = store();
        // SELECTING our server but asking for an address we would not assign.
        let pkt = packet(
            DhcpMessageType::Request,
            "bb:bb:bb:bb:bb:bb",
            Ipv4Addr::UNSPECIFIED,
            &[server_id(), requested("192.168.10.200")],
        );
        let d = decide(&c, &mut s, &pkt, 1000);
        let (data, dst) = d.reply.expect("nak");
        assert_eq!(dst, ReplyDst::Broadcast);
        assert_eq!(reply_summary(&data).0, DhcpMessageType::Nak);
        assert!(!d.persist);
    }

    #[test]
    fn static_request_acks_without_persisting() {
        let c = cfg("static=nas,ee:ee:ee:ee:ee:ee,192.168.10.50\n");
        let mut s = store();
        let pkt = packet(
            DhcpMessageType::Request,
            "ee:ee:ee:ee:ee:ee",
            Ipv4Addr::UNSPECIFIED,
            &[server_id()],
        );
        let d = decide(&c, &mut s, &pkt, 1000);
        let (data, _dst) = d.reply.expect("ack");
        assert_eq!(
            reply_summary(&data),
            (DhcpMessageType::Ack, ip("192.168.10.50"))
        );
        assert!(!d.persist); // static bindings are never written to the store
        assert_eq!(s.iter().count(), 0);
    }

    #[test]
    fn release_removes_lease_and_persists() {
        let c = cfg("");
        let mut s = store();
        s.insert(lease("bb:bb:bb:bb:bb:bb", "192.168.10.100", 9999));
        let pkt = packet(
            DhcpMessageType::Release,
            "bb:bb:bb:bb:bb:bb",
            ip("192.168.10.100"),
            &[],
        );
        let d = decide(&c, &mut s, &pkt, 1000);
        assert!(d.reply.is_none());
        assert!(d.persist);
        assert_eq!(s.iter().count(), 0);
    }

    #[test]
    fn release_unknown_mac_does_not_persist() {
        let c = cfg("");
        let mut s = store();
        let pkt = packet(
            DhcpMessageType::Release,
            "bb:bb:bb:bb:bb:bb",
            Ipv4Addr::UNSPECIFIED,
            &[],
        );
        let d = decide(&c, &mut s, &pkt, 1000);
        assert!(d.reply.is_none());
        assert!(!d.persist);
    }

    #[test]
    fn decline_quarantines_declined_ip_and_persists() {
        let c = cfg("");
        let mut s = store();
        s.insert(lease("bb:bb:bb:bb:bb:bb", "192.168.10.100", 9999));
        let pkt = packet(
            DhcpMessageType::Decline,
            "bb:bb:bb:bb:bb:bb",
            Ipv4Addr::UNSPECIFIED,
            &[requested("192.168.10.100")],
        );
        let d = decide(&c, &mut s, &pkt, 1000);
        assert!(d.reply.is_none());
        assert!(d.persist);
        assert_eq!(s.iter().count(), 0);
        assert!(s.is_quarantined(ip("192.168.10.100"), 1000));

        // A fresh client must not be handed the quarantined address.
        let disc = packet(
            DhcpMessageType::Discover,
            "99:99:99:99:99:99",
            Ipv4Addr::UNSPECIFIED,
            &[],
        );
        let d = decide(&c, &mut s, &disc, 1000);
        let (data, _) = d.reply.expect("offer");
        assert_eq!(reply_summary(&data).1, ip("192.168.10.101"));
    }

    #[test]
    fn inform_acks_config_only_by_unicast() {
        let c = cfg("");
        let mut s = store();
        // The client already holds an address (ciaddr) and only wants options.
        let pkt = packet(
            DhcpMessageType::Inform,
            "bb:bb:bb:bb:bb:bb",
            ip("192.168.10.150"),
            &[],
        );
        let d = decide(&c, &mut s, &pkt, 1000);
        let (data, dst) = d.reply.expect("inform ack");
        assert_eq!(dst, ReplyDst::Unicast(ip("192.168.10.150")));
        let (mt, yiaddr) = reply_summary(&data);
        assert_eq!(mt, DhcpMessageType::Ack);
        assert_eq!(yiaddr, Ipv4Addr::UNSPECIFIED); // no address assigned
        let opts = Options::parse(&data[MIN_LEN..]);
        assert!(opts.get(OPT_LEASE_TIME).is_none()); // no lease for an INFORM
        assert!(opts.get(OPT_SUBNET_MASK).is_some());
        assert!(!d.persist);
        assert_eq!(s.iter().count(), 0);
    }

    #[test]
    fn pool_exhaustion_is_silent() {
        let c = cfg("");
        let mut s = store();
        s.insert(lease("11:11:11:11:11:11", "192.168.10.100", 9999));
        s.insert(lease("22:22:22:22:22:22", "192.168.10.101", 9999));
        s.insert(lease("33:33:33:33:33:33", "192.168.10.102", 9999));
        let pkt = packet(
            DhcpMessageType::Discover,
            "99:99:99:99:99:99",
            Ipv4Addr::UNSPECIFIED,
            &[],
        );
        let d = decide(&c, &mut s, &pkt, 1000);
        assert!(d.reply.is_none());
    }

    #[test]
    fn unsupported_message_type_is_silent() {
        let c = cfg("");
        let mut s = store();
        // An OFFER arriving at the server is not something we answer.
        let pkt = packet(
            DhcpMessageType::Offer,
            "bb:bb:bb:bb:bb:bb",
            Ipv4Addr::UNSPECIFIED,
            &[],
        );
        let d = decide(&c, &mut s, &pkt, 1000);
        assert!(d.reply.is_none());
        assert!(!d.persist);
    }

    #[test]
    fn packet_without_message_type_is_silent() {
        let c = cfg("");
        let mut s = store();
        let mut p = vec![0u8; MIN_LEN];
        p[0] = BOOTREQUEST;
        p[1] = HTYPE_ETHERNET;
        p[2] = HLEN_ETHERNET;
        p[28..34].copy_from_slice(&mac_bytes("bb:bb:bb:bb:bb:bb"));
        p[COOKIE_OFFSET..MIN_LEN].copy_from_slice(&MAGIC_COOKIE);
        let pkt = DhcpPacket::parse(&p).unwrap();
        let d = decide(&c, &mut s, &pkt, 1000);
        assert!(d.reply.is_none());
        assert!(!d.persist);
    }
}
