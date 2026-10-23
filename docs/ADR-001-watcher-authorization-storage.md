# ADR-001: Watcher authorization storage (Vec scan vs per-address flag)

Status: Accepted — keep the `Vec<Address>` with a hard cap (#232, #233)

## Context
`is_authorized` loads the whole `Vec<Address>` from instance storage and scans it: O(n).
The alternative is `DataKey::WatcherFlag(Address) -> bool` in persistent storage: O(1).

## Estimate
- Vec scan: one instance read (n * ~40 bytes deserialised) plus up to n address
  comparisons. With `MAX_WATCHERS = 100` that is at most ~4 KB read and 100 comparisons —
  small relative to the per-invocation budget; instance storage is already loaded for every call.
- Flag: one persistent-entry read (separate ledger footprint entry, own TTL and rent) and
  O(1) compare. Cheaper at large n, but adds a footprint entry per call.
- These are estimates, not measured benchmarks.

## Decision
Keep the Vec and bound it with `MAX_WATCHERS = 100`. At the cap, the scan cost is bounded
and small. The flag approach would additionally require an index for `get_watchers`,
per-key TTL management, and a migration of existing data, for no practical gain at n <= 100.

## Migration
None required. If the cap is ever raised substantially, revisit: write a flag for each
existing watcher on upgrade, keep the Vec as the enumeration index, and switch
`is_authorized` to the flag lookup.
