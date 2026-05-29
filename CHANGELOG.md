# Changelog

All notable changes to nanodhcp are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-05-29

### Added
- Answer `DHCPINFORM` with a configuration-only `DHCPACK` (no `yiaddr`, no lease
  time), unicast to the client's `ciaddr` (RFC 2131 §4.3.5).
- Honor the Parameter Request List (option 55): optional parameters such as
  Router and DNS Servers are sent only when the client asks for them.
- Quarantine an address reported via `DHCPDECLINE` for one hour so it is not
  re-offered while the conflict persists (RFC 2131 §4.3.3).
- Unicast `DHCPACK` to `ciaddr` for renewing clients; `DHCPNAK` is always
  broadcast.
- Graceful shutdown on `SIGTERM`/`SIGINT`.
- Periodic purge of expired leases while running (every 5 minutes), in addition
  to the existing startup purge.
- Leveled, timestamped logging with `-q`/`--quiet` and `-v`/`--verbose` flags.
- Hardened `packaging/nanodhcp.service` systemd unit and install docs.
- Randomized, std-only fuzz tests for the packet and options parsers.

### Changed
- Log lines now carry a UTC timestamp and a level tag (e.g.
  `2026-05-29T08:41:20Z [INFO] ...`); warnings and errors go to stderr, info and
  debug to stdout.

## [0.1.0]

### Added
- Initial release: a minimal, std-only DHCPv4 server for a single LAN with a
  dynamic pool, static `MAC -> IP` bindings, persistent leases, and Linux
  `SO_BINDTODEVICE` interface binding.
