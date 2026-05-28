# nanodhcp

A minimal DHCPv4 server in Rust for a single LAN — homelab, embedded Linux, or
an appliance OS. It hands out IPv4 addresses from a pool, remembers leases per
MAC, and supports fixed `MAC -> IP` bindings. That is the whole job.

`nanodhcp` is intentionally **not** a dnsmasq / Kea / ISC DHCP replacement.

## Design constraints

- Rust stable, **std only** — no external crates.
- No async runtime, no Tokio, no serde, no JSON/TOML/YAML.
- No database, no REST API, no DNS, no NAT, no IPv6, no relay, no PXE.
- One static binary, suitable for embedding in a small Linux image.
- The DHCP parser/builder is pure and Linux-independent; only `src/server/`
  touches sockets and Linux syscalls.

## Build

```sh
cargo build --release
# binary at target/release/nanodhcp
```

Requires a working linker/SDK (on macOS: Xcode Command Line Tools,
`xcode-select --install`).

## Usage

```sh
nanodhcp run    -c /etc/nanodhcp.conf   # start the server (needs root for udp/67)
nanodhcp check  -c /etc/nanodhcp.conf   # parse + validate config, then exit
nanodhcp leases -c /etc/nanodhcp.conf   # print static + dynamic leases
nanodhcp help

nanodhcp /etc/nanodhcp.conf             # alias for `run -c ...`
```

Binding UDP port 67 requires root (or `CAP_NET_BIND_SERVICE` +
`CAP_NET_RAW` for `SO_BINDTODEVICE`).

## Configuration

Simple line-based `key=value`. See [`examples/nanodhcp.conf`](examples/nanodhcp.conf).

| key           | meaning                                             |
|---------------|-----------------------------------------------------|
| `interface`   | NIC to serve on (Linux `SO_BINDTODEVICE`)           |
| `server_ip`   | this server's address (option 54)                   |
| `subnet`      | served subnet in CIDR, e.g. `192.168.10.0/24`       |
| `subnet_mask` | netmask (option 1); must match the CIDR prefix      |
| `pool_start`  | first dynamic address (inclusive)                   |
| `pool_end`    | last dynamic address (inclusive)                    |
| `router`      | default gateway (option 3), optional                |
| `dns`         | comma-separated DNS servers (option 6), optional    |
| `lease_time`  | lease duration in seconds (option 51)               |
| `lease_file`  | path to the dynamic lease database                  |
| `allow_unbound` | `true` keeps serving on 0.0.0.0 if interface binding fails; default `false` (fail-fast) |
| `static`      | fixed binding `name,mac,ip` (repeatable)            |

Comments start with `#`; blank lines are ignored; unknown keys are an error.

## How it works

`DISCOVER -> OFFER`, then `REQUEST -> ACK`. A request for an address we cannot
grant gets a `NAK`; `RELEASE` frees a dynamic lease. Allocation prefers, in
order: a static binding, the MAC's previous IP, then the first free pool
address. See [`docs/protocol.md`](docs/protocol.md) and
[`docs/leases.md`](docs/leases.md).

Logs go to stdout/stderr:

```
nanodhcp: listening on eth0 udp/67
nanodhcp: DISCOVER mac=aa:bb:cc:dd:ee:ff hostname=laptop
nanodhcp: OFFER ip=192.168.10.100 mac=aa:bb:cc:dd:ee:ff
nanodhcp: REQUEST ip=192.168.10.100 mac=aa:bb:cc:dd:ee:ff
nanodhcp: ACK ip=192.168.10.100 mac=aa:bb:cc:dd:ee:ff
nanodhcp: ignored malformed packet: invalid magic cookie
```

## Project layout

```
src/
  main.rs        CLI dispatch only
  config/        model, key=value parser, semantic validation
  dhcp/          message types, options TLV, packet parser, reply builder
  lease/         lease model, persistent store, allocation policy
  server/        UDP socket + receive loop (the only Linux-specific code)
  util/          MAC, IPv4/CIDR, time helpers
```

## Tests

Pure logic is unit-tested (MAC, CIDR, options parser, packet parser, config
parser, lease allocator):

```sh
cargo test
```

## Testing against a real client (QEMU)

Bring up an isolated bridge and a VM, then run a client inside it:

```sh
# host: serve on the bridge interface
sudo nanodhcp run -c examples/nanodhcp.conf

# guest:
udhcpc -i eth0        # busybox
# or
dhclient -v eth0
```

The client should receive an address from the configured pool; a host listed
under `static=` always gets its fixed IP; a repeat request returns the same IP.

## License

AGPL-3.0. See [LICENSE](LICENSE).
