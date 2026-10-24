# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en:/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Breaking:** `WatcherRegistry::remove_watcher` now returns `ContractError::WatcherNotFound` when the address is not registered, instead of `Ok(())` (#231).
- `WatcherRegistry::register_watcher` enforces `MAX_WATCHERS` (100) and returns the new `ContractError::WatcherLimitExceeded` (#232). See `docs/watcher-registry.md`.
- `clear_all_watchers` resets the watcher count to 0; covered by a unit test (#230).
- Documented the decision to keep the Vec-based `is_authorized` in `docs/ADR-001-watcher-authorization-storage.md` (#233).
- **Breaking change:** `AlertRegistry::get_per_owner_alert_limit` now returns
` Option<u32>` instead of `u32`. It returns `None` when no limit has been set,
`Some(0)` when the admin explicitly configured an unlimited limit, and
`Some(n)` for `n > 0`. This disambiguates "unset" from "set to zero" and lets
clients determine whether the contract has been configured by an admin. The
storage layer `Get_limit` also returns `Option<u32>`. TypeScript bindings must be
regenerated and any callers must handle the `Option` return value.
- Bumped the pinned Rust toolchain in `rust-toolchain.toml` to a recent stable
  release and declared the `wasm32-unknown-unknown` target so CI and local builds
  get the WASM target automatically (#318).
- Updated the `soroban-sdk` dependency to the latest stable release to pick up
  upstream bug fixes, security patches, new APIs, and compatibility with the
  latest network protocol version (#319).

### Added
- **Multi-admin `AlertRegistry`**: new `add_admin(caller, new_admin)`, `remove_admin(caller, target_admin)`
  and `get_admins()`. `remove_admin` refuses to remove the last admin (`LastAdmin`). Emits
  `("admin", "add")` and `("admin", "remove")`. `transfer_admin` is deprecated: it now replaces the whole set.
  **Migration:** the `ADMIN` instance key now stores `Vec<Address>`. Reads transparently accept the legacy
  single-`Address` format, which is rewritten as a `Vec` on the next admin write; no manual migration is required.
- `get_alerts_updated_since(target_contract, since, offset, limit)` for incremental watcher sync (O(n) scan).
- `transfer_alert_ownership(owner, config_id, new_owner)`; respects the new owner's alert limit; emits `("alert", "transfer")`.
- Optional `tags: Option<Vec<String>>` on `AlertConfig` (max 10 tags, 32 bytes each), a new trailing `tags`
  argument on `register_alert`, and `update_tags`. New errors `TooManyTags`, `TagTooLong`. **Breaking:** the
  `AlertConfig` layout and `register_alert` signature changed; regenerate TypeScript bindings.
- **`AlertRegistry` default TTL is now 120 960 ledgers (~7 days)** (was 17 280, ~24 hours), so alerts are not archived after one day without a write (#249). Storage rent per alert rises accordingly; see `docs/ttl.md`.
- `get_per_owner_alert_limit` unit test covering the three distinct cases: unset (`None`),
  set-to-0 (`Some(0)`), and set-to-n (`Some(n)l`).
- **Feature A — `watcher.remove` event`*: `WatcherRegistry::remove_watcher` now emits
  `(Symbol("watcher"), Symbol("remove"))` with `data = watcher: Address` **only when the
  watcher was actually present** (no-op removals are silent). Dependent systems such as
  `AlertRegistry` watcher-gating must subscribe to this event to revoke trust immediately.
  `clear_all_watchers` emits one event per removed watcher for the same reason.
- **Feature B — configurable TTL via `bump_alert`**: `AlertRegistry` now exposes
  `bump_alert(config_id, ttl)` which extends the TTL of an alert and its associated
  indexes up to `MAX_TTL` (535 680 ledgers ≈ 31 days). Values above the cap are silently
  clamped. No auth is required — any address (e.g. an off-chain keeper) may call it.
  Emits `(Symbol("alert"), Symbol("bump"))` with `data = (id: u64, effective_ttl: u32)`.
- `DEFAULT_TTL` constant (17 280 ledgers ≈ 24 hours) replaces the previous hardcoded
  100-ledger value across all `extend_ttl` calls in `alert-registry`.
- `MAX_TTL` constant (535 680 ledgers ≈ 31 days) as the protocol-enforced ceiling for
  caller-specified TTL values.
- `WatcherRegistry::is_authorized` alias for `is_watcher_authorized` (backwards compat).
- `WatcherRegistry::clear_all_watchers` bulk-deauthorizes all watchers in one admin call,
  emitting a `watcher.remove` event for each removed address.
- `WatcherRegistry::decrement_watcher_count` is now correctly called on `remove_watcher`
  (previously the count only ever incremented — this was a bug fix).
- `alert.bump` event documented in `docs/events.md`.
- `watcher.remove` event marked ✅ implemented in `docs/events.md`.
- `docs/ttl.md` updated to document `DEFAULT_TTL`, `MAX_TTL`, and `bump_alert`.

### Fixed
- `WatcherRegistry::remove_watcher` no longer emits an event when the watcher address
  was not registered (previously always emitted regardless).
- `WatcherRegistry::get_watcher_count` now decrements correctly on removal.
- `AlertRegistry::remove_alert` body was missing in `lib.rs` (structural corruption);
  restored with correct `remove_alert_record` call.
- `AlertRegistry::remove_alert_by_admin` was missing from `lib.rs`; restored.
- `AlertRegistry::register_alert` had duplicated validation calls; deduplicated.
- `AlertRegistry::update_alert` now keeps `DataKey::AlertActive` in sync when `active`
  changes.
- `contract.rs` `[#contract]` / `[#contractimpl]` attributes removed to prevent
  duplicate Soroban client generation conflicting with `lib.rs`.
- All `extend_ttl(_, 100, 100)` calls replaced with `extend_ttl(_, DEFAULT_TTL, DEFAULT_TTL)`.

- `get_watcher_count` function to WatcherRegistry for efficient watcher count queries (#21)
- TypeScript bindings for AlertRegistry published to npm as `@tx-wat/alert-registry-bindings` (#120)
- GitHub Actions workflow for automated npm publishing of TypeScript bindings
- `make bindings` target for local TypeScript binding generation
- Documentation for `get_watcher_count` in `docs/watcher-registry.md`
- Comprehensive README and usage examples for TypeScript bindings package
- `CHANGELOG.md` to track version history (#75)
- `SECURITY.md` with responsible disclosure policy (#76)
- `docs/ttl.md` documenting TT\ values and their implications (#77)
- Inline rustdoc comments on all public and key private functions (#78)
- Expanded `.gitignore` to exclude build artifacts and test snapshots
- `bindings/watcher-registry` — TypeScript bindings package `@tx-wat/watcher-registry` generated via `stellar contract bindings typescript`
- `.github/workflows/publish-bindings.yml` — CI workflow that generates and publishes TypeScript bindings to npm on every GitHub release
- `docs/ecosystem-submission.md` — step-by-step guide for submitting to the Stellar Developer Tools ecosystem listing and the `stellar/soroban-examples` repository
- `contracts/watcher-registry/README.md` and `contracts/alert-registry/README.md` — per-contract READMEs required for the soroban-examples submission

## [0.1.0] - 2025-05-28

### Added
- `AlertRegistry` contract: register, update, remove, and query alert configs on-chain
- `WatcherRegistry` contract: manage authorized watcher node addresses with admin controls
- Persistent storage with TTL extension on every write
- Owner-keyed and contract-keyed index lookups for alert configs
- Stellar CLI, JavaScript SDK, and Rust SEK usage examples in `README.md`
- Deployment addresses tracked in `DEPLOYMENTS.md`
- Function reference docs in `docs/alert-registry.md` and `docs/watcher-registry.md`
- Contribution guidelines in `CONTRIBUTING.md`

#[Unreleased]: https://github.com/Tx-wat/stellar-txwatch-contracts/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Tx-wat/stellar-txwatch-contracts/releases/tag/v0.1.0
