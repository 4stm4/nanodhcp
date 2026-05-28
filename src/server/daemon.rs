//! The receive loop: parse a datagram, decide a response, send it, log it.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

use crate::config::DhcpConfig;
use crate::dhcp::builder;
use crate::dhcp::message::DhcpMessageType;
use crate::dhcp::packet::DhcpPacket;
use crate::lease::allocator;
use crate::lease::model::{Lease, LeaseKind};
use crate::lease::LeaseStore;
use crate::util::time;

use super::socket::{self, CLIENT_PORT};

/// Bind the socket and serve forever. Only returns on a fatal socket error.
pub fn run(cfg: DhcpConfig) -> io::Result<()> {
    let sock = socket::bind(&cfg)?;
    println!("nanodhcp: listening on {} udp/67", cfg.interface);

    let mut store = LeaseStore::load(&cfg.lease_file);
    let mut buf = [0u8; 1500];

    loop {
        let len = match sock.recv_from(&mut buf) {
            Ok((len, _src)) => len,
            Err(e) => {
                eprintln!("nanodhcp: recv error: {}", e);
                continue;
            }
        };
        handle(&sock, &cfg, &mut store, &buf[..len]);
    }
}

fn handle(sock: &UdpSocket, cfg: &DhcpConfig, store: &mut LeaseStore, data: &[u8]) {
    let pkt = match DhcpPacket::parse(data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("nanodhcp: ignored malformed packet: {}", e);
            return;
        }
    };
    let mtype = match pkt.options.msg_type() {
        Some(m) => m,
        None => {
            eprintln!("nanodhcp: ignored packet without DHCP message type");
            return;
        }
    };

    let mac = pkt.chaddr;
    let hostname = pkt.options.hostname();
    let host_disp = hostname.as_deref().unwrap_or("-");
    let now = time::now();

    match mtype {
        DhcpMessageType::Discover => {
            println!("nanodhcp: DISCOVER mac={} hostname={}", mac, host_disp);
            match allocator::assign_ip(cfg, store, mac, now) {
                Some(ip) => {
                    send(sock, &builder::build_offer(&pkt, cfg, ip));
                    println!("nanodhcp: OFFER ip={} mac={}", ip, mac);
                }
                None => eprintln!("nanodhcp: no free address available for mac={}", mac),
            }
        }

        DhcpMessageType::Request => {
            let selecting = pkt.options.server_id().is_some();
            // SELECTING: option 54 names the chosen server. If it is not us,
            // stay silent — another DHCP server owns this exchange.
            if let Some(sid) = pkt.options.server_id() {
                if sid != cfg.server_ip {
                    return;
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
                return;
            }

            match allocator::assign_ip(cfg, store, mac, now) {
                // Honour the request only if the client wants the address we
                // would give it (or expressed no preference).
                Some(ip) if requested.is_unspecified() || requested == ip => {
                    if cfg.static_for(mac).is_none() {
                        store.insert(Lease {
                            mac,
                            ip,
                            hostname: hostname.clone(),
                            expires_at: now + cfg.lease_time as u64,
                            kind: LeaseKind::Dynamic,
                        });
                        if let Err(e) = store.save() {
                            eprintln!("nanodhcp: warning: cannot save leases: {}", e);
                        }
                    }
                    send(sock, &builder::build_ack(&pkt, cfg, ip));
                    println!("nanodhcp: ACK ip={} mac={}", ip, mac);
                }
                _ => {
                    send(sock, &builder::build_nak(&pkt, cfg));
                    println!("nanodhcp: NAK mac={} requested={}", mac, requested);
                }
            }
        }

        DhcpMessageType::Release => {
            if cfg.static_for(mac).is_none() && store.remove(&mac).is_some() {
                if let Err(e) = store.save() {
                    eprintln!("nanodhcp: warning: cannot save leases: {}", e);
                }
            }
            println!("nanodhcp: RELEASE mac={}", mac);
        }

        DhcpMessageType::Decline => {
            // The client says the address is already in use. Drop our record so
            // we stop offering it; full conflict tracking is out of scope.
            if cfg.static_for(mac).is_none() && store.remove(&mac).is_some() {
                let _ = store.save();
            }
            println!("nanodhcp: DECLINE mac={}", mac);
        }

        other => eprintln!("nanodhcp: ignoring unsupported message type {:?}", other),
    }
}

/// Replies always go to the limited broadcast address on the client port.
/// `nanodhcp` serves a single directly-attached LAN (no relay), so the client
/// — which has no IP yet — receives the answer as a broadcast.
fn send(sock: &UdpSocket, data: &[u8]) {
    let dst = SocketAddrV4::new(Ipv4Addr::BROADCAST, CLIENT_PORT);
    if let Err(e) = sock.send_to(data, dst) {
        eprintln!("nanodhcp: send error: {}", e);
    }
}
