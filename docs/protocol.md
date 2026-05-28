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

- A `DHCPREQUEST` carrying a server identifier (option 54) that is **not**
  this server is ignored — another server owns that exchange.
- If the requested address is not the one we would grant, the server replies
  with `DHCPNAK`.
- `DHCPRELEASE` drops the dynamic lease for that MAC. `DHCPDECLINE` is logged
  and the lease dropped (no conflict table in v0.1).
- Replies are sent to the limited broadcast address `255.255.255.255:68`.
  There is no relay support, so `giaddr` is expected to be zero.

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
| 255  | End                 | parse + emit     |

Each option is `code, len, len bytes`, except `Pad` (0) and `End` (255) which
have no length or value. Unknown options are kept verbatim and ignored.

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

The hostname from option 12 is sanitized to hostname-safe characters before it
is logged, so a client cannot inject control characters into the logs.
