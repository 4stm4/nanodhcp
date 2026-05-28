# Leases

## Lease file format

Dynamic leases are stored line-based, one lease per line:

```
aa:bb:cc:dd:ee:ff 192.168.10.101 laptop 1780000000
11:22:33:44:55:66 192.168.10.102 printer 1780000000
```

| field | meaning                          |
|------:|----------------------------------|
| 1     | MAC address                      |
| 2     | leased IPv4 address              |
| 3     | hostname, or `-` if unknown      |
| 4     | expiry as a Unix timestamp       |

Rules:

- Blank lines and `#` comments are ignored on load.
- A malformed line is skipped with a warning; it does not abort startup.
- The file is rewritten **atomically** (write to a temporary file, then
  rename) so a crash mid-write cannot corrupt the live database.
- Static bindings live only in the config and are **never** written here.

## Allocation policy

When a client needs an address (`src/lease/allocator.rs`), the server picks one
in this order:

1. If the MAC has a **static** binding, return that IP.
2. Otherwise, if the MAC has an existing dynamic lease whose IP is still inside
   the pool and not otherwise taken, **reuse the same IP**.
3. Otherwise, return the **first free** address in the pool.

An address is never handed out if it is:

- the server's own IP,
- the subnet network or broadcast address,
- a static binding's IP,
- outside `[pool_start, pool_end]`,
- currently leased to a *different* MAC and not yet expired.

An expired lease belonging to another MAC is reclaimable; a client always keeps
priority on its own previous address while that address remains free.

## Commit timing

A dynamic lease is written to disk only after the server sends a `DHCPACK`
(i.e. on `REQUEST`, not on `DISCOVER`). The expiry is `now + lease_time`.
Static bindings are answered directly and produce no file write.
