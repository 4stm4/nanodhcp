# DHCP protocol notes

`nanodhcp` implements the minimum of RFC 2131 / RFC 2132 needed to serve a
single directly-attached LAN. This document describes what is on the wire and
what the parser guarantees.

## Message flow

```
client                         nanodhcp
  | --- DHCPDISCOVER (bcast) ----> |   allocate candidate IP
  | <-- DHCPOFFER (bcast) -------- |
  | --- DHCPREQUEST (bcast) -----> |   commit lease (if dynamic)
  | <-- DHCPACK (bcast) ---------- |
```

- **SELECTING** — a `DHCPREQUEST` carrying a server identifier (option 54):
  if it names this server we commit the lease and `DHCPACK`; if it names
  another server we stay silent — that server owns the exchange.
- **INIT-REBOOT** — a `DHCPREQUEST` *without* a server identifier from a client
  we have no dynamic lease or static binding for is ignored, per RFC 2131
  §4.3.2: a server that knows the client should answer instead.
- **RENEWING / REBINDING** — a known client whose address is in `ciaddr` is
  re-ACKed; the reply is **unicast to `ciaddr`** since the client is reachable
  there.
- If the requested address is not the one we would grant, the server replies
  with `DHCPNAK`, which is **always broadcast** (the client's idea of its own
  address is wrong, so it may be unreachable by unicast).
- `DHCPRELEASE` drops the dynamic lease for that MAC.
- `DHCPDECLINE` drops the lease and **quarantines** the declined address for one
  hour (RFC 2131 §4.3.3) so the allocator stops offering it while the conflict
  lasts. The quarantine is in memory only and does not survive a restart.
- `DHCPINFORM` is answered with a `DHCPACK` that carries configuration options
  but **no `yiaddr` and no lease time** (RFC 2131 §4.3.5), unicast to `ciaddr`.
  A `DHCPINFORM` with a zero `ciaddr` is **ignored** — there is no address to
  reply to.
- A reply is **broadcast** to `255.255.255.255:68` while the client is still
  acquiring an address (`ciaddr` zero) or whenever it sets the broadcast flag
  (RFC 2131 §4.1, `flags` bit 15), and **unicast to `ciaddr`** otherwise (renew
  / inform).
- There is no relay support: a packet with a **non-zero `giaddr`** arrived
  through a BOOTP relay and is **ignored**, because the reply would have to
  return via the relay rather than onto the local LAN.

> v0.3 tightens these edge cases (relayed packets, zero-`ciaddr` INFORM, the
> broadcast flag). nanodhcp serves a single directly-attached LAN only: no
> authentication, relay, or server-to-server failover.

## Packet structure

A DHCP packet is a BOOTP message (RFC 951) with a magic cookie and options:

| offset | size | field      | notes                              |
|-------:|-----:|------------|------------------------------------|
| 0      | 1    | `op`       | 1 = BOOTREQUEST, 2 = BOOTREPLY     |
| 1      | 1    | `htype`    | 1 = Ethernet                       |
| 2      | 1    | `hlen`     | 6 for Ethernet                     |
| 3      | 1    | `hops`     |                                    |
| 4      | 4    | `xid`      | transaction id, echoed in replies  |
| 8      | 2    | `secs`     |                                    |
| 10     | 2    | `flags`    | bit 15 = broadcast                 |
| 12     | 4    | `ciaddr`   | client IP (when already bound)     |
| 16     | 4    | `yiaddr`   | "your" IP, set by server in reply  |
| 20     | 4    | `siaddr`   | next-server IP                     |
| 24     | 4    | `giaddr`   | relay agent IP (0 here)            |
| 28     | 16   | `chaddr`   | client hw addr (first 6 = MAC)     |
| 44     | 64   | `sname`    | unused                             |
| 108    | 128  | `file`     | unused                             |
| 236    | 4    | cookie     | `99 130 83 99`                     |
| 240    | ...  | options    | TLV, terminated by option 255      |

So a valid packet is at least **240 bytes**.

## Options

Parsed/emitted options:

| code | name                | direction        |
|-----:|---------------------|------------------|
| 0    | Pad                 | parse            |
| 1    | Subnet Mask         | emit             |
| 3    | Router              | emit             |
| 6    | DNS Servers         | emit             |
| 12   | Hostname            | parse (logging)  |
| 50   | Requested IP        | parse            |
| 51   | IP Address Lease Time | emit           |
| 53   | DHCP Message Type   | parse + emit     |
| 54   | Server Identifier   | parse + emit     |
| 55   | Parameter Request List | parse         |
| 255  | End                 | parse + emit     |

Each option is `code, len, len bytes`, except `Pad` (0) and `End` (255) which
have no length or value. Unknown options are kept verbatim and ignored.

When a client sends a Parameter Request List (option 55), the *optional* emitted
parameters — Router (3) and DNS Servers (6) — are sent only if the client asked
for them. Subnet Mask, Lease Time, Server Identifier and Message Type are always
sent.

## Parser guarantees

The packet parser is defensive against hostile input and never panics:

- packet length must be `>= 240` bytes;
- `op == 1`, `htype == 1`, `hlen == 6`;
- magic cookie must equal `99, 130, 83, 99`;
- the options walker never reads past the buffer: a truncated length byte or an
  option whose length exceeds the remaining bytes simply ends parsing;
- a malformed packet returns `Err(...)` and is logged and dropped — it does not
  affect the daemon;
- no `unwrap` on untrusted packet bytes.

These guarantees are backed by randomized tests (`cargo test`) that feed the
parser hundreds of thousands of arbitrary buffers and arbitrary option streams,
asserting it never panics or over-reads.

The hostname from option 12 is sanitized to hostname-safe characters before it
is logged, so a client cannot inject control characters into the logs.
