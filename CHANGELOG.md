# Changelog

All notable changes to nanodhcp are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [0.3.0] - 2026-06-01

### Added
- Honor the client broadcast flag (RFC 2131 §4.1): the `DHCPACK` is broadcast
  whenever `flags` bit 15 is set, not only when `ciaddr` is zero.
- `check` and `leases` accept a bare config path (e.g.
  `nanodhcp check /etc/nanodhcp/nanodhcp.conf`) in addition to `-c`/`--config`.

### Fixed
- Ignore packets with a non-zero `giaddr`: they arrived through a BOOTP relay,
  which a single-LAN server cannot answer correctly.
- Ignore a `DHCPINFORM` whose `ciaddr` is zero — there is no address to unicast
  the reply to (RFC 2131 §4.3.5).
- Reject a `static=` binding with an empty name.
- `OptionsWriter::push` now asserts the payload fits in the one-byte option
  length instead of silently truncating in release builds.

### Changed
- `purge_expired` reports expired leases and quarantines separately; the lease
  file is rewritten only when a lease actually changed, and released quarantines
  are logged on their own.
- Renamed the internal `Decision.persist` flag to `save_leases` to separate
  "rewrite the lease file" from "the in-memory store changed".

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
