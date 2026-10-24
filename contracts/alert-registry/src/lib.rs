#![no_std]
#![warn(clippy::pedantic)]
use soroban_sdk::{
    contract, contractimpl, contracttype, contracterror, panic_with_error, symbol_short, vec, Address, Env, String, TryFromVal, Val, Vec,
};

// ── Storage keys ────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "nonexistent_skip.rs"]
#[cfg(any())]
mod contract_tests;

#[cfg(test)]
mod error_variant_tests;

#[cfg(test)]
mod batch_pause_tests;

#[cfg(test)]
mod validation_tests;

#[cfg(test)]
mod ttl_expiry_tests;

#[cfg(test)]
mod upgrade_roundtrip_tests;

#[cfg(test)]
mod count_consistency_tests;

#[cfg(test)]
mod owner_isolation_tests;

#[cfg(all(test, feature = "testutils"))]
mod gating_tests;

#[cfg(test)]
mod auth_required_tests;

#[cfg(test)]
mod event_assert_tests;

#[cfg(test)]
mod pagination_boundary_tests;

#[cfg(test)]
mod rule_edge_tests;

// ── TTL constants ─────────────────────────────────────────────────────────────

/// Default TTL applied to persistent storage entries on every write.
///
/// Approximately 7 days at the nominal 5-second ledger close time (#249).
/// See `docs/ttl.md` for the full rationale.
pub const DEFAULT_TTL: u32 = 120_960;

/// Protocol-enforced upper bound on caller-specified TTL values.
///
/// Callers may request any TTL up to this value when calling
/// [`AlertRegistry::bump_alert`].  Requests above this cap are silently
/// clamped to `MAX_TTL`.
///
/// Approximately 31 days at the nominal 5-second ledger close time.
pub const MAX_TTL: u32 = 535_680;

/// Maximum number of IDs accepted by [`AlertRegistry::bulk_renew_ttl`] in a
/// single call, to bound the instruction budget.
pub const MAX_BATCH_SIZE: u32 = 50;

/// Maximum number of tags per alert.
pub const MAX_TAGS: u32 = 10;

/// Maximum length in bytes of a single tag.
pub const MAX_TAG_BYTES: u32 = 32;

/// Storage key variants used to address persistent and instance entries.
#[contracttype]
pub enum DataKey {
    /// Stores an [`AlertConfig`] keyed by its numeric ID.
    Alert(u64),
    /// Stores just the `active` bool separately so it can be read without
    /// deserializing the full [`AlertConfig`].
    AlertActive(u64),
    /// Stores the list of alert IDs owned by a given address.
    OwnerIndex(Address),
    /// Stores the list of alert IDs watching a given contract address.
    ContractIndex(Address),
    /// Monotonic counter used to generate unique alert IDs.
    NextId,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ContractError {
    Unauthorized = 1,
    AlertNotFound = 2,
    AlreadyInitialized = 3,
    NotInitialized = 4,
    /// Returned when a watcher registry is configured and the querying address
    /// is not a registered watcher.
    NotAWatcher = 5,
    /// Returned when `webhook_hash` is not exactly 64 hex characters (#208).
    InvalidWebhookHash = 6,
    LabelTooLong = 7,
    TooManyRules = 8,
    InvalidRuleDescriptor = 9,
    OwnerAlertLimitExceeded = 10,
    DuplicateAlertId = 11,
    /// Returned when `confirm_webhook` is called but no rotation is pending.
    NoPendingWebhook = 12,
    /// A storage write failed, for example because an entry exceeds the protocol size limit.
    /// Returned as a typed error so callers can tell storage saturation from a bug (#251).
    StorageError = 13,
    /// Returned when a mutating function is called while the contract is paused.
    ContractPaused = 14,
    /// Returned when a batch exceeds [`MAX_BATCH_SIZE`] entries.
    BatchTooLarge = 15,
    /// Returned when a non-zero per-owner limit is below the minimum.
    LimitTooLow = 16,
    /// Returned when `rules` is empty.
    EmptyRules = 17,
    /// Returned when `rules` contains a duplicate entry.
    DuplicateRule = 18,
    /// Returned when the alert ID counter would overflow `u64`.
    CounterOverflow = 19,
    /// Returned when removing an admin would leave zero admins.
    LastAdmin = 20,
    /// Returned when an admin is already in the admin set.
    AlreadyAdmin = 21,
    /// Returned when the target is not in the admin set.
    NotAdmin = 22,
    /// Returned when more than `MAX_TAGS` tags are supplied.
    TooManyTags = 23,
    /// Returned when a tag exceeds `MAX_TAG_BYTES` bytes.
    TagTooLong = 24,
}

// ── Data types ───────────────────────────────────────────────────────────────

/// On-chain configuration for a single alert.
///
/// Stored under [`DataKey::Alert`] with a default TTL of [`DEFAULT_TTL`] ledgers
/// (~7 days). Use [`AlertRegistry::bump_alert`] to extend up to [`MAX_TTL`].
/// See `docs/ttl.md` for expiry details.
#[contracttype]
#[derive(Clone)]
pub struct AlertConfig {
    /// Human-readable label for the alert.
    pub label: String,
    /// SHA-256 hash of the webhook URL (the raw URL is never stored on-chain).
    pub webhook_hash: String,
    /// List of rule identifiers that trigger this alert (e.g. `"rule:transfer"`).
    pub rules: Vec<String>,
    /// Address that owns and may mutate this alert.
    pub owner: Address,
    /// Contract address being watched.
    pub target_contract: Address,
    /// Ledger timestamp at the time of registration.
    pub created_at: u64,
    /// Ledger timestamp of the most recent update.
    pub updated_at: u64,
    /// Whether the alert is currently active.
    pub active: bool,
    /// Pending webhook hash proposed via `propose_webhook` but not yet confirmed.
    ///
    /// `None` means no rotation is in progress. Once the owner calls
    /// `confirm_webhook`, this value is promoted to `webhook_hash` and cleared.
    pub pending_webhook_hash: Option<String>,
    /// Optional free-form tags for client-side categorization (max 10 tags,
    /// each max 32 bytes). Opaque to the contract; not indexed on-chain.
    pub tags: Option<Vec<String>>,
}

/// Input payload for a single alert in a `batch_register_alerts` call.
///
/// The owner is taken from the `caller` argument of the batch call.
#[contracttype]
#[derive(Clone)]
pub struct AlertInput {
    /// Contract address to watch.
    pub target_contract: Address,
    /// Human-readable label (max 128 bytes).
    pub label: String,
    /// SHA-256 hex digest of the webhook URL (64 chars).
    pub webhook_hash: String,
    /// Rule identifiers that trigger the alert.
    pub rules: Vec<String>,
}

// ── Contract ─────────────────────────────────────────────────────────────────

/// On-chain registry for alert configurations.
///
/// Each alert is keyed by a monotonically increasing `u64` ID and indexed by
/// both owner address and target contract address for efficient lookups.
///
/// # Watcher-gating (optional)
/// When a `WatcherRegistry` contract address is configured via
/// [`set_watcher_registry`], the read-only query functions
/// (`get_alerts_for_contract`, `get_alerts_by_owner`, and their paginated
/// variants) will perform a cross-contract call to verify that the querying
/// address is a registered watcher before returning data. Callers that are not
/// registered watchers receive [`ContractError::NotAWatcher`].
///
/// If no watcher registry is configured the gating is skipped and the
/// functions behave as before.
///
/// # Storage and TTL
/// All persistent entries are extended by [`DEFAULT_TTL`] ledgers (~7 days) on every
/// write. Callers can extend any alert up to [`MAX_TTL`] ledgers (~31 days) via
/// [`bump_alert`]. See `docs/ttl.md` for full details.
#[contract]
pub struct AlertRegistry;

// ── Cross-contract interface for WatcherRegistry ─────────────────────────────

/// Minimal client interface for calling `WatcherRegistry::is_watcher_authorized`
/// from within `AlertRegistry`.
mod watcher_registry_interface {
    use soroban_sdk::{contractclient, Address, Env};

    #[contractclient(name = "WatcherRegistryClient")]
    pub trait WatcherRegistry {
        fn is_watcher_authorized(env: Env, watcher: Address) -> bool;
    }
}

use watcher_registry_interface::WatcherRegistryClient as ExtWatcherClient;

#[contractimpl]
impl AlertRegistry {
    // ── Admin / configuration ─────────────────────────────────────────────

    /// Initialize the optional admin role for the registry. Can only be called once.
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        if env.storage().instance().has(&symbol_short!("ADMIN")) {
            return Err(ContractError::AlreadyInitialized);
        }
        Self::set_admins(&env, &vec![&env, admin.clone()]);
        // Emit the admin.init event on first initialisation only (#246).
        env.events().publish((symbol_short!("admin"), symbol_short!("init")), admin);
        Ok(())
    }

    /// Replace the entire admin set with a single `new_admin` (admin only).
    ///
    /// # Deprecated
    /// This is a **full set replacement**: every other admin loses privileges.
    /// Prefer [`add_admin`] / [`remove_admin`].
    ///
    /// # Events
    /// Emits `(Symbol("admin"), Symbol("transfer"))` with data
    /// `(old_admin: Address, new_admin: Address)`.
    pub fn transfer_admin(
        env: Env,
        admin: Address,
        new_admin: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;
        Self::set_admins(&env, &vec![&env, new_admin.clone()]);
        env.events().publish((symbol_short!("admin"), symbol_short!("transfer")), (admin, new_admin));
        Ok(())
    }

    /// Add `new_admin` to the admin set (any existing admin).
    ///
    /// # Errors
    /// [`ContractError::AlreadyAdmin`] if `new_admin` is already an admin.
    ///
    /// # Events
    /// Emits `("admin", "add")` with data `(caller, new_admin)`.
    pub fn add_admin(env: Env, caller: Address, new_admin: Address) -> Result<(), ContractError> {
        caller.require_auth();
        Self::assert_admin(&env, &caller)?;
        let mut admins = Self::load_admins(&env).ok_or(ContractError::NotInitialized)?;
        if admins.contains(&new_admin) {
            return Err(ContractError::AlreadyAdmin);
        }
        admins.push_back(new_admin.clone());
        Self::set_admins(&env, &admins);
        env.events()
            .publish((symbol_short!("admin"), symbol_short!("add")), (caller, new_admin));
        Ok(())
    }

    /// Remove `target_admin` from the admin set (any existing admin).
    ///
    /// # Errors
    /// [`ContractError::NotAdmin`] if the target is not an admin;
    /// [`ContractError::LastAdmin`] if it would leave zero admins.
    ///
    /// # Events
    /// Emits `("admin", "remove")` with data `(caller, target_admin)`.
    pub fn remove_admin(
        env: Env,
        caller: Address,
        target_admin: Address,
    ) -> Result<(), ContractError> {
        caller.require_auth();
        Self::assert_admin(&env, &caller)?;
        let admins = Self::load_admins(&env).ok_or(ContractError::NotInitialized)?;
        if !admins.contains(&target_admin) {
            return Err(ContractError::NotAdmin);
        }
        if admins.len() <= 1 {
            return Err(ContractError::LastAdmin);
        }
        let mut updated: Vec<Address> = vec![&env];
        for a in admins.iter() {
            if a != target_admin {
                updated.push_back(a);
            }
        }
        Self::set_admins(&env, &updated);
        env.events()
            .publish((symbol_short!("admin"), symbol_short!("remove")), (caller, target_admin));
        Ok(())
    }

    /// Get the first admin address (kept for backward compatibility).
    pub fn get_admin(env: Env) -> Address {
        Self::load_admins(&env)
            .and_then(|a| a.get(0))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::NotInitialized))
    }

    /// Get the full admin set, or `None` if not initialized.
    #[must_use]
    pub fn get_admins(env: Env) -> Option<Vec<Address>> {
        Self::load_admins(&env)
    }

    /// Set a per-owner active alert limit (admin only).
    ///
    /// # Semantics of `limit = 0`
    ///
    /// Passing `limit = 0` **disables** the per-owner cap entirely.  Once set,
    /// any owner may register an unlimited number of alerts.  This is the
    /// intended way to clear a previously configured limit.
    ///
    /// Note that there is no storage-level way to distinguish "limit was never
    /// configured" from "admin explicitly set limit to 0" — both return `0` from
    /// [`get_per_owner_alert_limit`].  Treat `0` as the canonical "no limit"
    /// sentinel.
    ///
    /// # Minimum limit
    ///
    /// A non-zero `limit` must be **at least 1**.  Values in the range `1..=u32::MAX`
    /// are accepted; the contract enforces a floor of `1` so that a
    /// mistaken call such as `set_per_owner_alert_limit(0)` cannot silently
    /// brick all existing owners when the admin actually intended to keep some
    /// cap in place.  Use `0` explicitly and intentionally to remove the cap.
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `admin`.
    ///
    /// # Errors
    /// Returns [`ContractError::NotInitialized`] if the registry has never been
    /// initialised.  Returns [`ContractError::Unauthorized`] if `admin` is not
    /// the current admin address.
    ///
    /// # Events
    /// Emits `(Symbol("admin"), Symbol("limit"))` with data `(admin: Address, limit: u32)`.
    pub fn set_per_owner_alert_limit(
        env: Env,
        admin: Address,
        limit: u32,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;
        // Reject accidentally-low non-zero limits. `0` is the explicit "no limit" sentinel.
        if limit != 0 && limit < 1 {
            return Err(ContractError::LimitTooLow);
        }
        env.storage().instance().set(&symbol_short!("LIMIT"), &limit);
        // Record every limit change on-chain, so the audit trail shows it (#248).
        env.events().publish((symbol_short!("admin"), symbol_short!("limit")), (admin, limit));
        Ok(())
    }

    /// Pause or unpause all mutating operations (admin only).
    ///
    /// While paused, every mutating entry point returns
    /// [`ContractError::ContractPaused`]. Read-only functions are unaffected.
    pub fn set_paused(env: Env, admin: Address, paused: bool) -> Result<(), ContractError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;
        env.storage().instance().set(&symbol_short!("PAUSED"), &paused);
        let topic = if paused {
            symbol_short!("pause")
        } else {
            symbol_short!("unpause")
        };
        env.events().publish((symbol_short!("admin"), topic), admin);
        Ok(())
    }

    /// Return whether the contract is currently paused.
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&symbol_short!("PAUSED"))
            .unwrap_or(false)
    }

    /// Get the configured per-owner active alert limit, or `0` if none is set.
    pub fn get_per_owner_alert_limit(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&symbol_short!("LIMIT"))
            .unwrap_or(0u32)
    }

    /// Configure the `WatcherRegistry` contract address used for optional
    /// watcher-gating on read queries (admin only).
    ///
    /// Once set, `get_alerts_for_contract`, `get_alerts_by_owner`, and their
    /// paginated variants will cross-call `WatcherRegistry::is_watcher_authorized`
    /// before returning data. Pass the zero address to disable gating.
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `admin`.
    pub fn set_watcher_registry(
        env: Env,
        admin: Address,
        watcher_registry: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;
        env.storage()
            .instance()
            .set(&symbol_short!("WATCHREG"), &watcher_registry);
        Ok(())
    }

    /// Return the configured `WatcherRegistry` contract address, or `None` if
    /// watcher-gating has not been enabled.
    pub fn get_watcher_registry(env: Env) -> Option<Address> {
        env.storage()
            .instance()
            .get(&symbol_short!("WATCHREG"))
    }

    // ── Alert mutations ───────────────────────────────────────────────────

    /// Register a new alert config and return its assigned ID.
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `owner`.
    ///
    /// # Arguments
    /// * `owner` - Address that will own and control this alert.
    /// * `target_contract` - Contract address to watch.
    /// * `label` - Human-readable name for the alert.
    /// * `webhook_hash` - SHA-256 hash of the destination webhook URL.
    /// * `rules` - Rule identifiers that should trigger the alert.
    ///
    /// # Returns
    /// The new alert's numeric ID.
    pub fn register_alert(
        env: Env,
        owner: Address,
        target_contract: Address,
        label: String,
        webhook_hash: String,
        rules: Vec<String>,
        tags: Option<Vec<String>>,
    ) -> Result<u64, ContractError> {
        Self::assert_not_paused(&env)?;
        if webhook_hash.len() != 64 {
            return Err(ContractError::InvalidWebhookHash);
        }
        owner.require_auth();

        Self::validate_label(&label)?;
        Self::validate_rules(&env, &rules)?;
        Self::validate_tags(&tags)?;
        Self::assert_per_owner_limit(&env, &owner)?;

        let id = Self::next_id(&env)?;
        let now = env.ledger().timestamp();

        let config = AlertConfig {
            label,
            webhook_hash,
            rules,
            owner: owner.clone(),
            target_contract: target_contract.clone(),
            created_at: now,
            updated_at: now,
            active: true,
            pending_webhook_hash: None,
            tags,
        };

        env.storage().persistent().set(&DataKey::Alert(id), &config);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Alert(id), DEFAULT_TTL, DEFAULT_TTL);
        env.storage().persistent().set(&DataKey::AlertActive(id), &true);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::AlertActive(id), DEFAULT_TTL, DEFAULT_TTL);
        Self::push_owner_index(&env, &owner, id)?;
        Self::push_contract_index(&env, &target_contract, id)?;

        env.events().publish(
            (symbol_short!("alert"), symbol_short!("register")),
            (id, owner, target_contract),
        );

        Ok(id)
    }

    /// Register many alerts for `caller` in one transaction.
    ///
    /// All inputs are validated (and the per-owner limit checked for the whole
    /// batch) before any write occurs, so the batch is all-or-nothing.
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `caller`.
    ///
    /// # Errors
    /// [`ContractError::BatchTooLarge`] if `inputs.len() > MAX_BATCH_SIZE`, plus any
    /// validation error `register_alert` can return, and
    /// [`ContractError::OwnerAlertLimitExceeded`] if the batch would exceed the cap.
    ///
    /// # Events
    /// Emits one `("alert", "register")` event per alert.
    ///
    /// # Returns
    /// The assigned IDs in insertion order.
    pub fn batch_register_alerts(
        env: Env,
        caller: Address,
        inputs: Vec<AlertInput>,
    ) -> Result<Vec<u64>, ContractError> {
        Self::assert_not_paused(&env)?;
        if inputs.len() > MAX_BATCH_SIZE {
            return Err(ContractError::BatchTooLarge);
        }
        caller.require_auth();

        for i in 0..inputs.len() {
            let input = inputs.get(i).unwrap();
            if input.webhook_hash.len() != 64 {
                return Err(ContractError::InvalidWebhookHash);
            }
            Self::validate_label(&input.label)?;
            Self::validate_rules(&env, &input.rules)?;
        }
        Self::assert_per_owner_limit_for(&env, &caller, inputs.len())?;

        let now = env.ledger().timestamp();
        let mut ids: Vec<u64> = vec![&env];
        for i in 0..inputs.len() {
            let input = inputs.get(i).unwrap();
            let id = Self::next_id(&env)?;
            let config = AlertConfig {
                label: input.label,
                webhook_hash: input.webhook_hash,
                rules: input.rules,
                owner: caller.clone(),
                target_contract: input.target_contract.clone(),
                created_at: now,
                updated_at: now,
                active: true,
                pending_webhook_hash: None,
                tags: None,
            };
            env.storage().persistent().set(&DataKey::Alert(id), &config);
            env.storage()
                .persistent()
                .extend_ttl(&DataKey::Alert(id), DEFAULT_TTL, DEFAULT_TTL);
            env.storage().persistent().set(&DataKey::AlertActive(id), &true);
            env.storage()
                .persistent()
                .extend_ttl(&DataKey::AlertActive(id), DEFAULT_TTL, DEFAULT_TTL);
            Self::push_owner_index(&env, &caller, id)?;
            Self::push_contract_index(&env, &input.target_contract, id)?;
            env.events().publish(
                (symbol_short!("alert"), symbol_short!("register")),
                (id, caller.clone(), input.target_contract),
            );
            ids.push_back(id);
        }
        Ok(ids)
    }

    /// Pause a single alert (admin only). Sets `active = false`.
    ///
    /// # Auth
    /// Requires auth from `admin`; owner auth is not sufficient.
    ///
    /// # Events
    /// Emits `("alert", "update")` with `(id, admin, false)`.
    pub fn pause_alert(env: Env, admin: Address, config_id: u64) -> Result<(), ContractError> {
        Self::set_alert_active_by_admin(&env, &admin, config_id, false)
    }

    /// Unpause a single alert (admin only). Sets `active = true`.
    ///
    /// # Auth
    /// Requires auth from `admin`; owner auth is not sufficient.
    ///
    /// # Events
    /// Emits `("alert", "update")` with `(id, admin, true)`.
    pub fn unpause_alert(env: Env, admin: Address, config_id: u64) -> Result<(), ContractError> {
        Self::set_alert_active_by_admin(&env, &admin, config_id, true)
    }

    fn set_alert_active_by_admin(
        env: &Env,
        admin: &Address,
        config_id: u64,
        active: bool,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        Self::assert_admin(env, admin)?;
        let mut config: AlertConfig = env
            .storage()
            .persistent()
            .get(&DataKey::Alert(config_id))
            .ok_or(ContractError::AlertNotFound)?;
        config.active = active;
        config.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&DataKey::Alert(config_id), &config);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Alert(config_id), DEFAULT_TTL, DEFAULT_TTL);
        env.storage().persistent().set(&DataKey::AlertActive(config_id), &active);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::AlertActive(config_id), DEFAULT_TTL, DEFAULT_TTL);
        env.events().publish(
            (symbol_short!("alert"), symbol_short!("update")),
            (config_id, admin.clone(), active),
        );
        Ok(())
    }

    /// Update the rules and active flag of an existing alert.
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `caller`, who must also be
    /// the original owner of the alert.
    pub fn update_alert(
        env: Env,
        caller: Address,
        config_id: u64,
        rules: Vec<String>,
        active: bool,
    ) -> Result<(), ContractError> {
        Self::assert_not_paused(&env)?;
        caller.require_auth();

        let mut config: AlertConfig = env
            .storage()
            .persistent()
            .get(&DataKey::Alert(config_id))
            .ok_or(ContractError::AlertNotFound)?;

        Self::assert_owner(&config, &caller)?;
        Self::validate_rules(&env, &rules)?;

        config.rules = rules;
        config.active = active;
        config.updated_at = env.ledger().timestamp();

        env.storage()
            .persistent()
            .set(&DataKey::Alert(config_id), &config);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Alert(config_id), DEFAULT_TTL, DEFAULT_TTL);
        // Keep the cheap AlertActive flag in sync with the full config.
        env.storage()
            .persistent()
            .set(&DataKey::AlertActive(config_id), &active);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::AlertActive(config_id), DEFAULT_TTL, DEFAULT_TTL);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::OwnerIndex(config.owner.clone()), DEFAULT_TTL, DEFAULT_TTL);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::ContractIndex(config.target_contract.clone()), DEFAULT_TTL, DEFAULT_TTL);

        env.events().publish(
            (symbol_short!("alert"), symbol_short!("update")),
            (config_id, caller, active),
        );

        Ok(())
    }

    /// Update the webhook hash for an existing alert.
    ///
    /// Emits `(Symbol("alert"), Symbol("webhook"))` with data `(id, caller)`.
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `caller`, who must also be
    /// the original owner of the alert.
    ///
    /// # Errors
    /// Returns [`ContractError::InvalidWebhookHash`] if `webhook_hash` is not
    /// exactly 64 characters (the expected length of a SHA-256 hex digest).
    pub fn update_webhook(
        env: Env,
        caller: Address,
        config_id: u64,
        webhook_hash: String,
    ) -> Result<(), ContractError> {
        Self::assert_not_paused(&env)?;
        caller.require_auth();

        let mut config: AlertConfig = env
            .storage()
            .persistent()
            .get(&DataKey::Alert(config_id))
            .ok_or(ContractError::AlertNotFound)?;

        Self::assert_owner(&config, &caller)?;

        if webhook_hash.len() != 64 {
            return Err(ContractError::InvalidWebhookHash);
        }

        config.webhook_hash = webhook_hash;
        config.updated_at = env.ledger().timestamp();

        env.storage()
            .persistent()
            .set(&DataKey::Alert(config_id), &config);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Alert(config_id), DEFAULT_TTL, DEFAULT_TTL);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::OwnerIndex(config.owner.clone()), DEFAULT_TTL, DEFAULT_TTL);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::ContractIndex(config.target_contract.clone()), DEFAULT_TTL, DEFAULT_TTL);

        env.events().publish(
            (symbol_short!("alert"), symbol_short!("webhook")),
            (config_id, caller),
        );

        Ok(())
    }

    /// Propose a new webhook hash for an existing alert (step 1 of 2).
    ///
    /// The new hash is stored in `pending_webhook_hash` and does **not** replace
    /// the live `webhook_hash` yet. The owner must call [`confirm_webhook`] to
    /// complete the rotation. This two-step flow prevents a window where the old
    /// webhook is deactivated before the new one is confirmed by the off-chain
    /// watcher.
    ///
    /// Calling `propose_webhook` again before confirming overwrites the previous
    /// pending hash, allowing the owner to correct a mistake.
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `caller`, who must also be
    /// the original owner of the alert.
    ///
    /// # Errors
    /// Returns [`ContractError::AlertNotFound`] if `config_id` does not exist.
    /// Returns [`ContractError::Unauthorized`] if `caller` is not the alert owner.
    ///
    /// # Events
    /// Emits `(Symbol("alert"), Symbol("wh_prop"))` with data `(id: u64, caller: Address)`.
    pub fn propose_webhook(
        env: Env,
        caller: Address,
        config_id: u64,
        new_webhook_hash: String,
    ) -> Result<(), ContractError> {
        caller.require_auth();

        let mut config: AlertConfig = env
            .storage()
            .persistent()
            .get(&DataKey::Alert(config_id))
            .ok_or(ContractError::AlertNotFound)?;

        Self::assert_owner(&config, &caller)?;

        config.pending_webhook_hash = Some(new_webhook_hash);
        config.updated_at = env.ledger().timestamp();

        env.storage()
            .persistent()
            .set(&DataKey::Alert(config_id), &config);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Alert(config_id), DEFAULT_TTL, DEFAULT_TTL);

        env.events().publish(
            (symbol_short!("alert"), symbol_short!("wh_prop")),
            (config_id, caller),
        );

        Ok(())
    }

    /// Confirm a pending webhook hash rotation (step 2 of 2).
    ///
    /// Promotes `pending_webhook_hash` to `webhook_hash` and clears the pending
    /// field. The caller must have previously called [`propose_webhook`] for this
    /// alert. Returns [`ContractError::NoPendingWebhook`] if no rotation is in
    /// progress.
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `caller`, who must also be
    /// the original owner of the alert.
    ///
    /// # Errors
    /// Returns [`ContractError::AlertNotFound`] if `config_id` does not exist.
    /// Returns [`ContractError::Unauthorized`] if `caller` is not the alert owner.
    /// Returns [`ContractError::NoPendingWebhook`] if no pending hash exists.
    ///
    /// # Events
    /// Emits `(Symbol("alert"), Symbol("webhook"))` with data `(id: u64, caller: Address)`.
    pub fn confirm_webhook(
        env: Env,
        caller: Address,
        config_id: u64,
    ) -> Result<(), ContractError> {
        caller.require_auth();

        let mut config: AlertConfig = env
            .storage()
            .persistent()
            .get(&DataKey::Alert(config_id))
            .ok_or(ContractError::AlertNotFound)?;

        Self::assert_owner(&config, &caller)?;

        let pending = config
            .pending_webhook_hash
            .take()
            .ok_or(ContractError::NoPendingWebhook)?;

        config.webhook_hash = pending;
        config.updated_at = env.ledger().timestamp();

        env.storage()
            .persistent()
            .set(&DataKey::Alert(config_id), &config);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Alert(config_id), DEFAULT_TTL, DEFAULT_TTL);

        // #204: emit the canonical alert.webhook event (not the non-standard wh_conf).
        env.events().publish(
            (symbol_short!("alert"), symbol_short!("webhook")),
            (config_id, caller),
        );

        Ok(())
    }

    /// Update only the label of an existing alert, leaving rules and webhook hash unchanged.
    ///
    /// Use this when you want to rename an alert without touching its rules or
    /// rotating its webhook URL.
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `caller`, who must also be
    /// the original owner of the alert.
    ///
    /// # Errors
    /// Returns [`ContractError::AlertNotFound`] if `config_id` does not exist.
    /// Returns [`ContractError::Unauthorized`] if `caller` is not the alert owner.
    /// Returns [`ContractError::LabelTooLong`] if `label` exceeds 128 bytes.
    ///
    /// # Events
    /// Emits `(Symbol("alert"), Symbol("update"))` with `(id, caller, active)`.
    pub fn update_label(
        env: Env,
        caller: Address,
        config_id: u64,
        label: String,
    ) -> Result<(), ContractError> {
        Self::assert_not_paused(&env)?;
        caller.require_auth();

        Self::validate_label(&label)?;

        let mut config: AlertConfig = env
            .storage()
            .persistent()
            .get(&DataKey::Alert(config_id))
            .ok_or(ContractError::AlertNotFound)?;

        Self::assert_owner(&config, &caller)?;

        config.label = label;
        config.updated_at = env.ledger().timestamp();

        env.storage()
            .persistent()
            .set(&DataKey::Alert(config_id), &config);
        env.storage().persistent().extend_ttl(&DataKey::Alert(config_id), DEFAULT_TTL, DEFAULT_TTL);
        env.storage().persistent().extend_ttl(&DataKey::OwnerIndex(config.owner.clone()), DEFAULT_TTL, DEFAULT_TTL);
        env.storage().persistent().extend_ttl(&DataKey::ContractIndex(config.target_contract.clone()), DEFAULT_TTL, DEFAULT_TTL);
        env.events().publish(
            (symbol_short!("alert"), symbol_short!("update")),
            (config_id, caller, config.active),
        );
        Ok(())
    }

    /// Remove an alert config from storage.
    ///
    /// Also removes the alert ID from the owner and contract indexes.
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `caller`, who must also be
    /// the original owner of the alert.
    pub fn remove_alert(
        env: Env,
        caller: Address,
        config_id: u64,
    ) -> Result<(), ContractError> {
        Self::assert_not_paused(&env)?;
        caller.require_auth();

        let config: AlertConfig = env
            .storage()
            .persistent()
            .get(&DataKey::Alert(config_id))
            .ok_or(ContractError::AlertNotFound)?;

        Self::assert_owner(&config, &caller)?;
        Self::remove_alert_record(&env, &config, config_id, &caller);
        Ok(())
    }

    /// Remove any alert config from storage (admin only).
    ///
    /// Unlike [`remove_alert`], the caller does not need to be the alert owner.
    /// The emitted `alert.remove` event includes both the admin address and the
    /// original alert owner so that off-chain indexers can distinguish
    /// admin-initiated removals from owner-initiated ones (fixes #213).
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `admin`.
    pub fn remove_alert_by_admin(
        env: Env,
        admin: Address,
        config_id: u64,
    ) -> Result<(), ContractError> {
        Self::assert_not_paused(&env)?;
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;

        let config: AlertConfig = env
            .storage()
            .persistent()
            .get(&DataKey::Alert(config_id))
            .ok_or(ContractError::AlertNotFound)?;

        let owner = config.owner.clone();
        Self::remove_alert_record_by_admin(&env, &config, config_id, &admin, &owner);
        Ok(())
    }

    /// Extend the TTL of an alert and its associated indexes.
    ///
    /// Callers may request any TTL up to [`MAX_TTL`] ledgers.  Values above
    /// the cap are silently clamped to `MAX_TTL`, so callers can safely pass
    /// `u32::MAX` to request the longest possible lifetime.
    ///
    /// This is the primary mechanism for keeping long-lived alerts alive
    /// without modifying their content.  Unlike `update_alert`, this function
    /// does **not** require the caller to be the alert owner — any address may
    /// bump an alert's TTL (e.g. an off-chain keeper service).
    ///
    /// # Arguments
    /// * `config_id` - ID of the alert to extend.
    /// * `ttl`       - Desired TTL in ledgers (clamped to [`MAX_TTL`]).
    ///
    /// # Errors
    /// Returns [`ContractError::AlertNotFound`] if `config_id` does not exist.
    ///
    /// # Events
    /// Emits `(Symbol("alert"), Symbol("bump"))` with data
    /// `(id: u64, ttl: u32)` so off-chain indexers can track renewal activity.
    pub fn bump_alert(
        env: Env,
        config_id: u64,
        ttl: u32,
    ) -> Result<(), ContractError> {
        Self::assert_not_paused(&env)?;
        // Extends all four related entries, so the owner index cannot expire while the alert
        // is still live and make it disappear from `get_alerts_by_owner` (#254).
        // Clamp the requested TTL to the protocol maximum.
        let effective_ttl = ttl.min(MAX_TTL);

        let config: AlertConfig = env
            .storage()
            .persistent()
            .get(&DataKey::Alert(config_id))
            .ok_or(ContractError::AlertNotFound)?;

        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Alert(config_id), effective_ttl, effective_ttl);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::AlertActive(config_id), effective_ttl, effective_ttl);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::OwnerIndex(config.owner.clone()), effective_ttl, effective_ttl);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::ContractIndex(config.target_contract), effective_ttl, effective_ttl);
        // Also extend the global ID counter (issue #212).  NextId must not
        // expire independently of the alert entries it produced — if it did,
        // the next registration would restart from 0 and collide with live IDs.
        if env.storage().persistent().has(&DataKey::NextId) {
            env.storage()
                .persistent()
                .extend_ttl(&DataKey::NextId, effective_ttl, effective_ttl);
        }

        // Fix #212: also extend the NextId counter so it cannot expire independently
        // of alert data when a contract only receives TTL renewals and no new
        // registrations.  Without this, the counter could drop from storage and the
        // next register_alert would restart from 0, causing ID collisions.
        env.storage()
            .instance()
            .extend_ttl(effective_ttl, effective_ttl);

        env.events().publish(
            (symbol_short!("alert"), symbol_short!("bump")),
            (config_id, effective_ttl),
        );

        Ok(())
    }

    /// Extend the TTL of many alerts in a single transaction.
    ///
    /// Intended for off-chain keeper services: no auth is required (consistent
    /// with [`bump_alert`]).  Each live ID has its `Alert`, `AlertActive`,
    /// `OwnerIndex`, and `ContractIndex` entries extended by [`DEFAULT_TTL`].
    /// IDs that no longer exist (expired or removed) are silently skipped.
    ///
    /// # Arguments
    /// * `config_ids` - IDs of the alerts to renew.  Must not exceed
    ///   [`MAX_BATCH_SIZE`].
    ///
    /// # Returns
    /// The number of alerts that were successfully renewed.
    ///
    /// # Errors
    /// Returns [`ContractError::TooManyRules`] if `config_ids` exceeds
    /// [`MAX_BATCH_SIZE`].
    ///
    /// # Events
    /// Emits `(Symbol("alert"), Symbol("bump"))` with data `(id: u64, ttl: u32)`
    /// for each renewed alert.
    pub fn bulk_renew_ttl(env: Env, config_ids: Vec<u64>) -> Result<u32, ContractError> {
        if config_ids.len() > MAX_BATCH_SIZE {
            return Err(ContractError::TooManyRules);
        }

        let mut renewed: u32 = 0;
        for i in 0..config_ids.len() {
            let id = config_ids.get(i).unwrap();
            let config: Option<AlertConfig> = env
                .storage()
                .persistent()
                .get(&DataKey::Alert(id));
            if let Some(config) = config {
                env.storage()
                    .persistent()
                    .extend_ttl(&DataKey::Alert(id), DEFAULT_TTL, DEFAULT_TTL);
                env.storage()
                    .persistent()
                    .extend_ttl(&DataKey::AlertActive(id), DEFAULT_TTL, DEFAULT_TTL);
                env.storage()
                    .persistent()
                    .extend_ttl(&DataKey::OwnerIndex(config.owner.clone()), DEFAULT_TTL, DEFAULT_TTL);
                env.storage()
                    .persistent()
                    .extend_ttl(&DataKey::ContractIndex(config.target_contract), DEFAULT_TTL, DEFAULT_TTL);

                env.events().publish(
                    (symbol_short!("alert"), symbol_short!("bump")),
                    (id, DEFAULT_TTL),
                );
                renewed += 1;
            }
        }
        Ok(renewed)
    }

    /// Retrieve all alert configs that watch a given contract address.
    ///
    /// If a `WatcherRegistry` is configured, `querier` must be a registered
    /// watcher or the call returns [`ContractError::NotAWatcher`].
    ///
    /// Returns an empty vec if no alerts exist for `target_contract`.
    pub fn get_alerts_for_contract(
        env: Env,
        querier: Address,
        target_contract: Address,
    ) -> Result<Vec<AlertConfig>, ContractError> {
        Self::assert_watcher_if_configured(&env, &querier)?;
        let ids = Self::contract_index(&env, &target_contract);
        Ok(Self::configs_for_ids(&env, &ids))
    }

    /// Return the IDs of live alerts watching `target_contract` without
    /// deserializing the configs. IDs whose storage entry is gone are skipped.
    #[must_use]
    pub fn get_alert_ids_for_contract(env: Env, target_contract: Address) -> Vec<u64> {
        let ids = Self::contract_index(&env, &target_contract);
        Self::live_ids(&env, &ids)
    }

    /// Return the IDs of live alerts owned by `owner` without deserializing
    /// the configs. IDs whose storage entry is gone are skipped.
    #[must_use]
    pub fn get_alert_ids_by_owner(env: Env, owner: Address) -> Vec<u64> {
        let ids = Self::owner_index(&env, &owner);
        Self::live_ids(&env, &ids)
    }

    /// Retrieve only the active alert configs that watch a given contract address.
    ///
    /// Equivalent to [`get_alerts_for_contract`] but filters out any entries
    /// where `active == false`. Returns an empty vec if no active alerts exist
    /// for `target_contract`.
    pub fn get_active_alerts_for_contract(env: Env, target_contract: Address) -> Vec<AlertConfig> {
        let ids = Self::contract_index(&env, &target_contract);
        Self::active_configs_for_ids(&env, &ids)
    }

    /// Paginated variant of [`get_active_alerts_for_contract`].
    ///
    /// `offset` and `limit` apply to the *active* alerts (after filtering);
    /// `limit` is clamped to [`MAX_BATCH_SIZE`].
    pub fn get_active_alerts_paginated(
        env: Env,
        target_contract: Address,
        offset: u32,
        limit: u32,
    ) -> Vec<AlertConfig> {
        let ids = Self::contract_index(&env, &target_contract);
        let active = Self::active_configs_for_ids(&env, &ids);
        let effective_limit = limit.min(MAX_BATCH_SIZE);
        let start = offset.min(active.len());
        let end = offset.saturating_add(effective_limit).min(active.len());
        let mut out: Vec<AlertConfig> = vec![&env];
        for i in start..end {
            out.push_back(active.get(i).unwrap());
        }
        out
    }

    /// Retrieve all alert configs owned by a given address.
    ///
    /// If a `WatcherRegistry` is configured, `querier` must be a registered
    /// watcher or the call returns [`ContractError::NotAWatcher`].
    ///
    /// Returns an empty vec if `owner` has no registered alerts.
    pub fn get_alerts_by_owner(
        env: Env,
        querier: Address,
        owner: Address,
    ) -> Result<Vec<AlertConfig>, ContractError> {
        Self::assert_watcher_if_configured(&env, &querier)?;
        let ids = Self::owner_index(&env, &owner);
        Ok(Self::configs_for_ids(&env, &ids))
    }

    /// Get a page of alert configs for a target contract (offset + limit).
    ///
    /// If a `WatcherRegistry` is configured, `querier` must be a registered
    /// watcher or the call returns [`ContractError::NotAWatcher`].
    pub fn get_contract_alerts_paginated(
        env: Env,
        querier: Address,
        target_contract: Address,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<AlertConfig>, ContractError> {
        Self::assert_watcher_if_configured(&env, &querier)?;
        let ids = Self::contract_index(&env, &target_contract);
        Ok(Self::configs_paginated(&env, &ids, offset, limit))
    }

    /// Get a page of alert configs owned by an address (offset + limit).
    ///
    /// If a `WatcherRegistry` is configured, `querier` must be a registered
    /// watcher or the call returns [`ContractError::NotAWatcher`].
    pub fn get_alerts_by_owner_paginated(
        env: Env,
        querier: Address,
        owner: Address,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<AlertConfig>, ContractError> {
        Self::assert_watcher_if_configured(&env, &querier)?;
        let ids = Self::owner_index(&env, &owner);
        Ok(Self::configs_paginated(&env, &ids, offset, limit))
    }

    /// Retrieve a single alert config by its ID.
    ///
    /// Returns `None` if the alert does not exist or has expired.
    pub fn get_alert(env: Env, config_id: u64) -> Option<AlertConfig> {
        let key = DataKey::Alert(config_id);
        let cfg: Option<AlertConfig> = env.storage().persistent().get(&key);
        if cfg.is_some() {
            // A read keeps an alert that is only ever read from archiving (#250).
            env.storage().persistent().extend_ttl(&key, DEFAULT_TTL, DEFAULT_TTL);
        }
        cfg
    }

    /// Read the `active` flag of an alert without deserializing the full config.
    ///
    /// Returns `None` if the alert does not exist or has expired.
    pub fn get_alert_active(env: Env, config_id: u64) -> Option<bool> {
        env.storage()
            .persistent()
            .get(&DataKey::AlertActive(config_id))
    }

    /// Deactivate all alerts owned by `caller` in a single call.
    ///
    /// Iterates the owner's index and sets `active = false` on every live
    /// alert.  Expired or already-removed entries are silently skipped.
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `caller`.
    ///
    /// # Returns
    /// The number of alerts that were deactivated.
    pub fn deactivate_all_alerts(env: Env, caller: Address) -> u32 {
        Self::assert_not_paused(&env).unwrap_or_else(|e| panic_with_error!(&env, e));
        caller.require_auth();
        let ids = Self::owner_index(&env, &caller);
        let mut count: u32 = 0;
        for i in 0..ids.len() {
            let id = ids.get(i).unwrap();
            if let Some(mut cfg) = env
                .storage()
                .persistent()
                .get::<DataKey, AlertConfig>(&DataKey::Alert(id))
            {
                if cfg.active {
                    cfg.active = false;
                    cfg.updated_at = env.ledger().timestamp();
                    env.storage().persistent().set(&DataKey::Alert(id), &cfg);
                    env.storage()
                        .persistent()
                        .extend_ttl(&DataKey::Alert(id), DEFAULT_TTL, DEFAULT_TTL);
                    env.storage()
                        .persistent()
                        .set(&DataKey::AlertActive(id), &false);
                    env.storage()
                        .persistent()
                        .extend_ttl(&DataKey::AlertActive(id), DEFAULT_TTL, DEFAULT_TTL);
                    count += 1;
                }
            }
        }
        count
    }

    /// Move an alert to watch a different target contract.
    ///
    /// Updates the `target_contract` field of the alert config and migrates
    /// the alert ID from the old contract index to the new one.
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `caller`, who must also be
    /// the original owner of the alert.
    ///
    /// # Errors
    /// Returns [`ContractError::AlertNotFound`] if `config_id` does not exist.
    /// Returns [`ContractError::Unauthorized`] if `caller` is not the alert owner.
    pub fn update_target_contract(
        env: Env,
        caller: Address,
        config_id: u64,
        new_target: Address,
    ) -> Result<(), ContractError> {
        Self::assert_not_paused(&env)?;
        caller.require_auth();

        let mut config: AlertConfig = env
            .storage()
            .persistent()
            .get(&DataKey::Alert(config_id))
            .ok_or(ContractError::AlertNotFound)?;

        Self::assert_owner(&config, &caller)?;

        let old_target = config.target_contract.clone();
        config.target_contract = new_target.clone();
        config.updated_at = env.ledger().timestamp();

        env.storage()
            .persistent()
            .set(&DataKey::Alert(config_id), &config);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Alert(config_id), DEFAULT_TTL, DEFAULT_TTL);

        // Migrate the contract index
        Self::remove_from_contract_index(&env, &old_target, config_id);
        Self::push_contract_index(&env, &new_target, config_id)?;

        Ok(())
    }

    /// Return all alert configs whose `updated_at` timestamp is greater than or
    /// equal to `since`.
    ///
    /// This enables efficient **incremental sync** for watcher nodes: on each
    /// polling cycle a watcher passes the ledger timestamp of its last sync and
    /// receives only the alerts that have been created or modified since then,
    /// rather than fetching the entire registry.
    ///
    /// # Arguments
    /// * `since` - Ledger timestamp (inclusive lower bound). Pass `0` to
    ///   retrieve every alert that is currently stored.
    ///
    /// # Returns
    /// A `Vec<AlertConfig>` containing every live alert with
    /// `updated_at >= since`. Alerts that have been removed (and whose storage
    /// entry has therefore expired) are silently omitted.
    ///
    /// # Note
    /// The function scans all IDs from `0` up to the current `NEXT_ID`
    /// counter. This is acceptable for the expected registry sizes on Soroban
    /// and avoids the need for a separate timestamp index. For very large
    /// registries consider combining this with the paginated variants.
    #[must_use]
    pub fn get_alerts_modified_since(env: Env, since: u64) -> Vec<AlertConfig> {
        let total: u64 = env
            .storage()
            .instance()
            .get(&symbol_short!("NEXT_ID"))
            .unwrap_or(0u64);

        let mut out: Vec<AlertConfig> = vec![&env];
        for id in 0..total {
            if let Some(cfg) = env
                .storage()
                .persistent()
                .get::<DataKey, AlertConfig>(&DataKey::Alert(id))
            {
                if cfg.updated_at >= since {
                    out.push_back(cfg);
                }
            }
        }
        out
    }

    /// Replace the tags of an alert (owner only). Pass `None` to clear.
    ///
    /// Validates at most `MAX_TAGS` tags of at most `MAX_TAG_BYTES` bytes each.
    /// Emits `("alert", "tags")` with data `(config_id, caller)`.
    pub fn update_tags(
        env: Env,
        caller: Address,
        config_id: u64,
        tags: Option<Vec<String>>,
    ) -> Result<(), ContractError> {
        Self::assert_not_paused(&env)?;
        caller.require_auth();
        let mut config: AlertConfig = env
            .storage()
            .persistent()
            .get(&DataKey::Alert(config_id))
            .ok_or(ContractError::AlertNotFound)?;
        Self::assert_owner(&config, &caller)?;
        Self::validate_tags(&tags)?;
        config.tags = tags;
        config.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&DataKey::Alert(config_id), &config);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Alert(config_id), DEFAULT_TTL, DEFAULT_TTL);
        env.events().publish(
            (symbol_short!("alert"), symbol_short!("tags")),
            (config_id, caller),
        );
        Ok(())
    }

    /// Transfer ownership of an alert to `new_owner`.
    ///
    /// Requires auth from `owner`, who must be the current owner. The new
    /// owner's per-owner alert limit is checked first. Updates both owner
    /// indexes and sets `updated_at`.
    ///
    /// Emits `("alert", "transfer")` with data `(config_id, owner, new_owner)`.
    pub fn transfer_alert_ownership(
        env: Env,
        owner: Address,
        config_id: u64,
        new_owner: Address,
    ) -> Result<(), ContractError> {
        Self::assert_not_paused(&env)?;
        owner.require_auth();
        let mut config: AlertConfig = env
            .storage()
            .persistent()
            .get(&DataKey::Alert(config_id))
            .ok_or(ContractError::AlertNotFound)?;
        Self::assert_owner(&config, &owner)?;
        if new_owner == owner {
            return Ok(());
        }
        Self::assert_per_owner_limit(&env, &new_owner)?;

        Self::remove_from_owner_index(&env, &owner, config_id);
        Self::push_owner_index(&env, &new_owner, config_id)?;

        config.owner = new_owner.clone();
        config.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&DataKey::Alert(config_id), &config);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Alert(config_id), DEFAULT_TTL, DEFAULT_TTL);
        env.events().publish(
            (symbol_short!("alert"), symbol_short!("transfer")),
            (config_id, owner, new_owner),
        );
        Ok(())
    }

    /// Incremental sync: alerts watching `target_contract` with
    /// `updated_at >= since`, paginated by `offset`/`limit`.
    ///
    /// # Complexity
    /// **O(n)** in the size of the contract's index per call: it scans the
    /// whole `ContractIndex` and filters. A timestamp-sorted secondary index
    /// would be faster but costs more storage; profile before adding one.
    #[must_use]
    pub fn get_alerts_updated_since(
        env: Env,
        target_contract: Address,
        since: u64,
        offset: u32,
        limit: u32,
    ) -> Vec<AlertConfig> {
        let ids = Self::contract_index(&env, &target_contract);
        let mut out: Vec<AlertConfig> = vec![&env];
        let mut skipped = 0u32;
        for id in ids.iter() {
            if out.len() >= limit {
                break;
            }
            if let Some(cfg) = env
                .storage()
                .persistent()
                .get::<DataKey, AlertConfig>(&DataKey::Alert(id))
            {
                if cfg.updated_at >= since {
                    if skipped < offset {
                        skipped += 1;
                    } else {
                        out.push_back(cfg);
                    }
                }
            }
        }
        out
    }

    /// Get the total number of alerts ever registered.
    ///
    /// This is a **monotonic counter** — it only increases and is never
    /// decremented when alerts are removed. Use [`get_active_alert_count`]
    /// if you need the number of currently live alerts for a given owner.
    #[must_use]
    pub fn get_alert_count(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&symbol_short!("NEXT_ID"))
            .unwrap_or(0u64)
    }

    /// Get the number of currently active (non-removed) alerts owned by `owner`.
    ///
    /// Unlike [`get_alert_count`], this reflects removals and only counts
    /// alerts whose storage entries are still live.
    pub fn get_active_alert_count(env: Env, owner: Address) -> u32 {
        let ids = Self::owner_index(&env, &owner);
        let mut count: u32 = 0;
        for i in 0..ids.len() {
            let id = ids.get(i).unwrap();
            if env.storage().persistent().has(&DataKey::Alert(id)) {
                count += 1;
            }
        }
        count
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// Reject mutating calls while the contract is paused.
    fn assert_not_paused(env: &Env) -> Result<(), ContractError> {
        if Self::is_paused(env.clone()) {
            return Err(ContractError::ContractPaused);
        }
        Ok(())
    }

    /// If a `WatcherRegistry` contract address is stored in instance storage,
    /// perform a cross-contract call to verify that `querier` is a registered
    /// watcher. Returns `Ok(())` when no registry is configured (gating is
    /// disabled) or when the querier passes the check.
    fn assert_watcher_if_configured(env: &Env, querier: &Address) -> Result<(), ContractError> {
        let maybe_registry: Option<Address> = env
            .storage()
            .instance()
            .get(&symbol_short!("WATCHREG"));

        if let Some(registry_addr) = maybe_registry {
            let client = ExtWatcherClient::new(env, &registry_addr);
            if !client.is_watcher_authorized(querier) {
                return Err(ContractError::NotAWatcher);
            }
        }
        Ok(())
    }

    fn live_ids(env: &Env, ids: &Vec<u64>) -> Vec<u64> {
        let mut out: Vec<u64> = vec![env];
        for i in 0..ids.len() {
            let id = ids.get(i).unwrap();
            if env.storage().persistent().has(&DataKey::Alert(id)) {
                out.push_back(id);
            }
        }
        out
    }

    fn assert_owner(config: &AlertConfig, caller: &Address) -> Result<(), ContractError> {
        if config.owner == *caller {
            Ok(())
        } else {
            Err(ContractError::Unauthorized)
        }
    }

    /// Load the admin set, transparently migrating the legacy single-`Address` format.
    fn load_admins(env: &Env) -> Option<Vec<Address>> {
        let raw: Val = env.storage().instance().get(&symbol_short!("ADMIN"))?;
        if let Ok(v) = Vec::<Address>::try_from_val(env, &raw) {
            return Some(v);
        }
        Address::try_from_val(env, &raw).ok().map(|a| vec![env, a])
    }

    fn set_admins(env: &Env, admins: &Vec<Address>) {
        env.storage().instance().set(&symbol_short!("ADMIN"), admins);
    }

    fn assert_admin(env: &Env, caller: &Address) -> Result<(), ContractError> {
        let admins = Self::load_admins(env).ok_or(ContractError::NotInitialized)?;
        if admins.contains(caller) {
            Ok(())
        } else {
            Err(ContractError::Unauthorized)
        }
    }

    fn validate_tags(tags: &Option<Vec<String>>) -> Result<(), ContractError> {
        if let Some(t) = tags {
            if t.len() > MAX_TAGS {
                return Err(ContractError::TooManyTags);
            }
            for tag in t.iter() {
                if tag.len() > MAX_TAG_BYTES {
                    return Err(ContractError::TagTooLong);
                }
            }
        }
        Ok(())
    }

    /// Check that `owner` has not reached the per-owner active alert cap.
    ///
    /// A limit of `0` means **no cap is enforced** — this is the default when
    /// no admin has called [`set_per_owner_alert_limit`].  A non-zero limit is
    /// the maximum number of *active* alerts any single owner may hold
    /// simultaneously; attempts to register beyond that count are rejected with
    /// [`ContractError::OwnerAlertLimitExceeded`].
    fn assert_per_owner_limit(env: &Env, owner: &Address) -> Result<(), ContractError> {
        Self::assert_per_owner_limit_for(env, owner, 1)
    }

    /// Like [`assert_per_owner_limit`], but checks that `additional` new alerts
    /// would still fit under the cap.
    fn assert_per_owner_limit_for(
        env: &Env,
        owner: &Address,
        additional: u32,
    ) -> Result<(), ContractError> {
        let limit = Self::get_per_owner_alert_limit(env.clone());
        if limit > 0 {
            let ids = Self::owner_index(env, owner);
            let mut live_ids: Vec<u64> = vec![env];
            for i in 0..ids.len() {
                let id = ids.get(i).unwrap();
                if env.storage().persistent().has(&DataKey::Alert(id)) {
                    live_ids.push_back(id);
                }
            }
            // #205: prune stale/expired IDs from the index lazily.
            if live_ids.len() != ids.len() {
                if live_ids.is_empty() {
                    env.storage()
                        .persistent()
                        .remove(&DataKey::OwnerIndex(owner.clone()));
                } else {
                    env.storage()
                        .persistent()
                        .set(&DataKey::OwnerIndex(owner.clone()), &live_ids);
                    env.storage()
                        .persistent()
                        .extend_ttl(&DataKey::OwnerIndex(owner.clone()), DEFAULT_TTL, DEFAULT_TTL);
                }
            }
            if live_ids.len().saturating_add(additional) > limit {
                return Err(ContractError::OwnerAlertLimitExceeded);
            }
        }
        Ok(())
    }

    /// Validate that a label does not exceed the 128-byte limit.
    fn validate_label(label: &String) -> Result<(), ContractError> {
        if label.len() > 128 {
            return Err(ContractError::LabelTooLong);
        }
        Ok(())
    }

    fn validate_rules(env: &Env, rules: &Vec<String>) -> Result<(), ContractError> {
        if rules.is_empty() {
            return Err(ContractError::EmptyRules);
        }
        if rules.len() > 50 {
            return Err(ContractError::TooManyRules);
        }
        // Validate each rule descriptor and check for duplicates in a single pass.
        // No std HashMap available in no_std Soroban — use a linear scan instead.
        let mut seen: Vec<String> = Vec::new(env);
        for i in 0..rules.len() {
            let rule = rules.get(i).unwrap();
            Self::validate_rule(env, &rule)?;
            for j in 0..seen.len() {
                if seen.get(j).unwrap() == rule {
                    return Err(ContractError::DuplicateRule);
                }
            }
            seen.push_back(rule);
        }
        Ok(())
    }

    fn validate_rule(env: &Env, rule: &String) -> Result<(), ContractError> {
        let transfer = String::from_str(env, "rule:transfer");
        let mint = String::from_str(env, "rule:mint");
        let invoke = String::from_str(env, "rule:invoke");
        let all = String::from_str(env, "rule:all");
        if *rule != transfer && *rule != mint && *rule != invoke && *rule != all {
            return Err(ContractError::InvalidRuleDescriptor);
        }
        Ok(())
    }

    fn remove_alert_record(env: &Env, config: &AlertConfig, config_id: u64, caller: &Address) {
        env.storage()
            .persistent()
            .remove(&DataKey::Alert(config_id));
        env.storage()
            .persistent()
            .remove(&DataKey::AlertActive(config_id));

        Self::remove_from_owner_index(env, &config.owner, config_id);
        Self::remove_from_contract_index(env, &config.target_contract, config_id);

        env.events().publish(
            (symbol_short!("alert"), symbol_short!("remove")),
            (config_id, caller.clone()),
        );
    }

    /// Like [`remove_alert_record`] but used for admin-initiated removals.
    ///
    /// Emits `(alert, remove)` with data `(id, admin, owner)` so off-chain
    /// indexers can tell admin-initiated removals from owner-initiated ones
    /// and include both parties in the audit trail (fixes #213).
    fn remove_alert_record_by_admin(
        env: &Env,
        config: &AlertConfig,
        config_id: u64,
        admin: &Address,
        owner: &Address,
    ) {
        env.storage()
            .persistent()
            .remove(&DataKey::Alert(config_id));
        env.storage()
            .persistent()
            .remove(&DataKey::AlertActive(config_id));

        Self::remove_from_owner_index(env, &config.owner, config_id);
        Self::remove_from_contract_index(env, &config.target_contract, config_id);

        // Include both admin and original owner so indexers can attribute the
        // removal correctly without having to look up the alert after deletion.
        env.events().publish(
            (symbol_short!("alert"), symbol_short!("remove")),
            (config_id, admin.clone(), owner.clone()),
        );
    }

    /// Atomically read and increment the global alert ID counter.
    ///
    /// Returns the current value before incrementing, so the first ID is `0`.
    /// The counter is stored in instance storage and its TTL is extended on
    /// every call, so it survives as long as the instance is alive.
    fn next_id(env: &Env) -> Result<u64, ContractError> {
        let id: u64 = env
            .storage()
            .instance()
            .get(&symbol_short!("NEXT_ID"))
            .unwrap_or(0u64);
        let next = id.checked_add(1).ok_or(ContractError::CounterOverflow)?;
        env.storage()
            .instance()
            .set(&symbol_short!("NEXT_ID"), &next);
        // Extend instance TTL so the counter stays alive even when only
        // bump_alert calls come in and no new registrations are happening (#212).
        env.storage()
            .instance()
            .extend_ttl(DEFAULT_TTL, DEFAULT_TTL);
        Ok(id)
    }

    /// Load the list of alert IDs owned by `owner`, or an empty vec.
    fn owner_index(env: &Env, owner: &Address) -> Vec<u64> {
        env.storage()
            .persistent()
            .get(&DataKey::OwnerIndex(owner.clone()))
            .unwrap_or_else(|| vec![env])
    }

    /// Load the list of alert IDs watching `target`, or an empty vec.
    fn contract_index(env: &Env, target: &Address) -> Vec<u64> {
        env.storage()
            .persistent()
            .get(&DataKey::ContractIndex(target.clone()))
            .unwrap_or_else(|| vec![env])
    }

    /// Append `id` to the owner's index and persist it with a refreshed TTL.
    fn push_owner_index(env: &Env, owner: &Address, id: u64) -> Result<(), ContractError> {
        let mut ids = Self::owner_index(env, owner);
        for i in 0..ids.len() {
            if ids.get(i).unwrap() == id {
                return Err(ContractError::DuplicateAlertId);
            }
        }
        ids.push_back(id);
        env.storage()
            .persistent()
            .set(&DataKey::OwnerIndex(owner.clone()), &ids);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::OwnerIndex(owner.clone()), DEFAULT_TTL, DEFAULT_TTL);
        Ok(())
    }

    /// Append `id` to the contract's index and persist it with a refreshed TTL.
    fn push_contract_index(env: &Env, target: &Address, id: u64) -> Result<(), ContractError> {
        let mut ids = Self::contract_index(env, target);
        for i in 0..ids.len() {
            if ids.get(i).unwrap() == id {
                return Err(ContractError::DuplicateAlertId);
            }
        }
        ids.push_back(id);
        env.storage()
            .persistent()
            .set(&DataKey::ContractIndex(target.clone()), &ids);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::ContractIndex(target.clone()), DEFAULT_TTL, DEFAULT_TTL);
        Ok(())
    }

    /// Remove `id` from the owner's index and persist the updated list.
    fn remove_from_owner_index(env: &Env, owner: &Address, id: u64) {
        let ids = Self::owner_index(env, owner);
        let mut updated: Vec<u64> = vec![env];
        for i in 0..ids.len() {
            let v = ids.get(i).unwrap();
            if v != id {
                updated.push_back(v);
            }
        }
        // #203: delete the key instead of writing an empty vec to avoid storage leaks.
        if updated.is_empty() {
            env.storage()
                .persistent()
                .remove(&DataKey::OwnerIndex(owner.clone()));
        } else {
            env.storage()
                .persistent()
                .set(&DataKey::OwnerIndex(owner.clone()), &updated);
            env.storage()
                .persistent()
                .extend_ttl(&DataKey::OwnerIndex(owner.clone()), DEFAULT_TTL, DEFAULT_TTL);
        }
    }

    /// Remove `id` from the contract's index and persist the updated list.
    fn remove_from_contract_index(env: &Env, target: &Address, id: u64) {
        let ids = Self::contract_index(env, target);
        let mut updated: Vec<u64> = vec![env];
        for i in 0..ids.len() {
            let v = ids.get(i).unwrap();
            if v != id {
                updated.push_back(v);
            }
        }
        // #203: delete the key instead of writing an empty vec to avoid storage leaks.
        if updated.is_empty() {
            env.storage()
                .persistent()
                .remove(&DataKey::ContractIndex(target.clone()));
        } else {
            env.storage()
                .persistent()
                .set(&DataKey::ContractIndex(target.clone()), &updated);
            env.storage()
                .persistent()
                .extend_ttl(&DataKey::ContractIndex(target.clone()), DEFAULT_TTL, DEFAULT_TTL);
        }
    }

    /// Resolve a list of alert IDs to their stored [`AlertConfig`] values.
    ///
    /// IDs that no longer exist in storage (expired or removed) are silently
    /// skipped.
    fn configs_for_ids(env: &Env, ids: &Vec<u64>) -> Vec<AlertConfig> {
        let mut out: Vec<AlertConfig> = vec![env];
        for i in 0..ids.len() {
            let id = ids.get(i).unwrap();
            if let Some(cfg) = env.storage().persistent().get(&DataKey::Alert(id)) {
                out.push_back(cfg);
            }
        }
        out
    }

    /// Like [`configs_for_ids`] but only includes entries where `active == true`.
    ///
    /// IDs that no longer exist in storage are silently skipped, as are configs
    /// whose `active` field is `false`.
    fn active_configs_for_ids(env: &Env, ids: &Vec<u64>) -> Vec<AlertConfig> {
        let mut out: Vec<AlertConfig> = vec![env];
        for i in 0..ids.len() {
            let id = ids.get(i).unwrap();
            if let Some(cfg) = env.storage().persistent().get::<DataKey, AlertConfig>(&DataKey::Alert(id)) {
                if cfg.active {
                    out.push_back(cfg);
                }
            }
        }
        out
    }

    /// Returns a page of alert configs from `ids` starting at `offset` with at most `limit`
    /// entries. The `limit` argument is silently clamped to [`MAX_BATCH_SIZE`] to prevent a
    /// single call from scanning the entire index and exhausting the Soroban instruction
    /// budget (#209). IDs that no longer exist in storage are silently skipped.
    fn configs_paginated(
        env: &Env,
        ids: &Vec<u64>,
        offset: u32,
        limit: u32,
    ) -> Vec<AlertConfig> {
        // Clamp to the protocol maximum to prevent unbounded reads (#209).
        let effective_limit = limit.min(MAX_BATCH_SIZE);
        let mut out: Vec<AlertConfig> = vec![env];
        let len = ids.len();
        let start = offset.min(len);
        // saturating_add: a huge offset must not overflow the end bound (#265).
        let end = offset.saturating_add(effective_limit).min(len);
        for i in start..end {
            let id = ids.get(i).unwrap();
            if let Some(cfg) = env.storage().persistent().get(&DataKey::Alert(id)) {
                out.push_back(cfg);
            }
        }
        out
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Ledger as _}, vec, Env, String};

    fn setup() -> (Env, AlertRegistryClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(AlertRegistry, ());
        let client = AlertRegistryClient::new(&env, &contract_id);
        (env, client)
    }

    fn str(env: &Env, s: &str) -> String {
        String::from_str(env, s)
    }

    /// Return a valid 64-character hex webhook hash for use in tests.
    ///
    /// The value is a deterministic all-`a` string that satisfies the
    /// `webhook_hash.len() == 64` validation added by #208.
    fn hash64(env: &Env) -> String {
        String::from_str(env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    }

    // ── Helpers shared by watcher-gating tests ────────────────────────────

    #[cfg(feature = "testutils")]
    fn setup_with_watcher_registry() -> (
        Env,
        AlertRegistryClient<'static>,
        watcher_registry::WatcherRegistryClient<'static>,
    ) {
        use watcher_registry::WatcherRegistry;
        let env = Env::default();
        env.mock_all_auths();

        let alert_id = env.register(AlertRegistry, ());
        let watcher_id = env.register(WatcherRegistry, ());

        let alert_client = AlertRegistryClient::new(&env, &alert_id);
        let watcher_client = watcher_registry::WatcherRegistryClient::new(&env, &watcher_id);

        (env, alert_client, watcher_client)
    }

    // 1. Happy path — register and retrieve
    #[test]
    fn test_register_and_get_alert() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "My Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        let cfg = client.get_alert(&id).unwrap();
        assert_eq!(cfg.label, str(&env, "My Alert"));
        assert_eq!(cfg.owner, owner);
        assert!(cfg.active);
    }

    // 2. Happy path — update alert
    #[test]
    fn test_update_alert() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        assert_eq!(
            client
                .try_update_alert(&owner, &id, &vec![&env, str(&env, "rule:mint")], &false)
                .unwrap(),
            Ok(())
        );

        let cfg = client.get_alert(&id).unwrap();
        assert!(!cfg.active);
        assert_eq!(cfg.rules.get(0).unwrap(), str(&env, "rule:mint"));

        // Verify alert.update event was emitted
        assert!(env.events().all().len() >= 2);
    }

    #[test]
    fn test_update_alert_emits_event() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        let count_before = env.events().all().len();
        client.update_alert(&owner, &id, &vec![&env, str(&env, "rule:mint")], &false);
        let count_after = env.events().all().len();
        assert_eq!(count_after, count_before + 1);
    }

    // 3. Happy path — remove alert
    #[test]
    fn test_remove_alert() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        assert_eq!(client.try_remove_alert(&owner, &id).unwrap(), Ok(()));
        assert!(client.get_alert(&id).is_none());
    }

    // 4. Unauthorized update rejected
    #[test]
    fn test_update_unauthorized() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let attacker = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        assert_eq!(
            client
                .try_update_alert(&attacker, &id, &vec![&env, str(&env, "rule:transfer")], &false)
                .unwrap_err()
                .unwrap(),
            ContractError::Unauthorized
        );
    }

    #[test]
    #[should_panic(expected = "invalid rule descriptor")]
    fn test_register_alert_rejects_invalid_rules() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:unknown")],
            &None,
        );
    }

    #[test]
    #[should_panic(expected = "invalid rule descriptor")]
    fn test_update_alert_rejects_invalid_rules() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        client.update_alert(&owner, &id, &vec![&env, str(&env, "rule:bogus")], &true);
    }

    #[test]
    fn test_admin_remove_any_alert() {
        let (env, client) = setup();
        let admin = Address::generate(&env);
        client.initialize(&admin);

        let owner = Address::generate(&env);
        let target = Address::generate(&env);
        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:mint")],
            &None,
        );

        client.remove_alert_by_admin(&admin, &id);
        assert!(client.get_alert(&id).is_none());
    }

    #[test]
    #[should_panic(expected = "owner alert limit exceeded")]
    fn test_admin_set_per_owner_alert_limit() {
        let (env, client) = setup();
        let admin = Address::generate(&env);
        client.initialize(&admin);
        client.set_per_owner_alert_limit(&admin, &1u32);

        let owner = Address::generate(&env);
        let target = Address::generate(&env);
        client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert1"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert2"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:mint")],
            &None,
        );
    }

    #[test]
    fn test_admin_transfer_admin() {
        let (env, client) = setup();
        let admin = Address::generate(&env);
        client.initialize(&admin);
        let new_admin = Address::generate(&env);

        client.transfer_admin(&admin, &new_admin);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);
        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        client.remove_alert_by_admin(&new_admin, &id);
    }

    #[test]
    fn test_old_admin_rejected_after_transfer() {
        let (env, client) = setup();
        let admin = Address::generate(&env);
        client.initialize(&admin).unwrap();
        let new_admin = Address::generate(&env);

        // first transfer succeeds
        assert_eq!(
            client.try_transfer_admin(&admin, &new_admin).unwrap(),
            Ok(())
        );

        // old admin cannot call transfer_admin again
        assert_eq!(
            client
                .try_transfer_admin(&admin, &new_admin)
                .unwrap_err()
                .unwrap(),
            ContractError::Unauthorized
        );
    }

    // 5. Unauthorized remove rejected
    #[test]
    fn test_remove_unauthorized() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let attacker = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        assert_eq!(
            client
                .try_remove_alert(&attacker, &id)
                .unwrap_err()
                .unwrap(),
            ContractError::Unauthorized
        );
    }

    // Issue #49 — get_alert_count is monotonically increasing after multiple register/remove cycles
    #[test]
    fn test_get_alert_count_after_multiple_cycles() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        // Start at 0
        assert_eq!(client.get_alert_count(), 0);

        // Cycle 1: register -> count goes to 1
        let id1 = client.register_alert(&owner, &target, &str(&env, "A"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
        assert_eq!(client.get_alert_count(), 1);
        // remove -> count stays at 1 (monotonic)
        client.remove_alert(&owner, &id1);
        assert_eq!(client.get_alert_count(), 1);

        // Cycle 2: register -> count goes to 2
        let id2 = client.register_alert(&owner, &target, &str(&env, "B"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
        assert_eq!(client.get_alert_count(), 2);
        // remove -> count stays at 2
        client.remove_alert(&owner, &id2);
        assert_eq!(client.get_alert_count(), 2);

        // Cycle 3: register -> count goes to 3
        let id3 = client.register_alert(&owner, &target, &str(&env, "C"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
        assert_eq!(client.get_alert_count(), 3);
        // remove -> count stays at 3
        client.remove_alert(&owner, &id3);
        assert_eq!(client.get_alert_count(), 3);

        // Final verification: after 3 cycles the counter is 3, never reset to 0
        assert_eq!(client.get_alert_count(), 3);
        // No active alerts remain
        assert_eq!(client.get_active_alert_count(&owner), 0);
    }

    // 6. Edge case — get nonexistent alert returns None
    #[test]
    fn test_get_nonexistent_alert() {
        let (_env, client) = setup();
        assert!(client.get_alert(&999u64).is_none());
    }

    // 7. Edge case — get alerts for contract with no alerts returns empty vec
    #[test]
    fn test_get_alerts_for_contract_empty() {
        let (env, client) = setup();
        let querier = Address::generate(&env);
        let target = Address::generate(&env);
        let result = client.get_alerts_for_contract(&querier, &target).unwrap();
        assert_eq!(result.len(), 0);
    }

    // Issue #68 — get_alerts_by_owner returns empty vec for address with no alerts
    #[test]
    fn test_get_alerts_by_owner_empty() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let querier = Address::generate(&env);
        assert_eq!(client.get_alerts_by_owner(&querier, &owner).unwrap().len(), 0);
    }

    // 8. Index queries — get_alerts_for_contract and get_alerts_by_owner
    #[test]
    fn test_index_queries() {
        let (env, client) = setup();
        let querier = Address::generate(&env);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        client.register_alert(&owner, &target, &str(&env, "A1"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
        client.register_alert(&owner, &target, &str(&env, "A2"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);

        assert_eq!(
            client.get_alerts_for_contract(&querier, &target).unwrap().len(),
            2
        );
        assert_eq!(
            client.get_alerts_by_owner(&querier, &owner).unwrap().len(),
            2
        );
    }

    // 9. get_alert_count reflects registered alerts (monotonic — does not decrease)
    #[test]
    fn test_get_alert_count() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        assert_eq!(client.get_alert_count(), 0u64);

        client.register_alert(
            &owner,
            &target,
            &str(&env, "A"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );
        assert_eq!(client.get_alert_count(), 1u64);
    }

    // 10. Paginated queries work without watcher gating
    #[test]
    fn test_paginated_queries_no_gating() {
        let (env, client) = setup();
        let querier = Address::generate(&env);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        for i in 0..5u32 {
            let label = String::from_str(&env, "alert");
            let _ = i; // suppress unused warning
            client.register_alert(
                &owner,
                &target,
                &label,
                &hash64(&env),
                &vec![&env, str(&env, "rule:transfer")],
                &None,
            );
        }

        let page = client
            .get_contract_alerts_paginated(&querier, &target, &0u32, &3u32)
            .unwrap();
        assert_eq!(page.len(), 3);

        let page2 = client
            .get_alerts_by_owner_paginated(&querier, &owner, &3u32, &10u32)
            .unwrap();
        assert_eq!(page2.len(), 2);
    }

    // ── Watcher-gating tests ──────────────────────────────────────────────

    // 11. No watcher registry configured — any querier can read
    #[test]
    fn test_no_watcher_registry_any_querier_can_read() {
        let (env, client) = setup();
        let stranger = Address::generate(&env);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        // No registry set — stranger can still query
        assert_eq!(
            client.get_alerts_for_contract(&stranger, &target).unwrap().len(),
            1
        );
    }

    // 12. Watcher registry configured — registered watcher can read
    #[test]
    #[cfg(feature = "testutils")]
    fn test_watcher_registry_registered_watcher_can_read() {
        use watcher_registry::WatcherRegistry;
        let (env, alert_client, watcher_client) = setup_with_watcher_registry();

        let admin = Address::generate(&env);
        let watcher = Address::generate(&env);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        watcher_client.initialize(&admin);
        watcher_client.register_watcher(&admin, &watcher, &None);

        // Point alert registry at the watcher registry
        alert_client.initialize(&admin).unwrap();
        let watcher_contract_id = watcher_client.address.clone();
        alert_client
            .set_watcher_registry(&admin, &watcher_contract_id)
            .unwrap();

        alert_client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        // Registered watcher can query
        let results = alert_client
            .get_alerts_for_contract(&watcher, &target)
            .unwrap();
        assert_eq!(results.len(), 1);
    }

    // 13. Watcher registry configured — unregistered address is rejected
    #[test]
    #[cfg(feature = "testutils")]
    fn test_watcher_registry_unregistered_address_rejected() {
        use watcher_registry::WatcherRegistry;
        let (env, alert_client, watcher_client) = setup_with_watcher_registry();

        let admin = Address::generate(&env);
        let stranger = Address::generate(&env);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        watcher_client.initialize(&admin);

        alert_client.initialize(&admin).unwrap();
        let watcher_contract_id = watcher_client.address.clone();
        alert_client
            .set_watcher_registry(&admin, &watcher_contract_id)
            .unwrap();

        alert_client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        // Stranger (not a watcher) is rejected
        assert_eq!(
            alert_client
                .try_get_alerts_for_contract(&stranger, &target)
                .unwrap_err()
                .unwrap(),
            ContractError::NotAWatcher
        );
    }

    // 14. Watcher registry configured — removed watcher loses access
    #[test]
    #[cfg(feature = "testutils")]
    fn test_watcher_registry_removed_watcher_loses_access() {
        use watcher_registry::WatcherRegistry;
        let (env, alert_client, watcher_client) = setup_with_watcher_registry();

        let admin = Address::generate(&env);
        let watcher = Address::generate(&env);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        watcher_client.initialize(&admin);
        watcher_client.register_watcher(&admin, &watcher, &None);

        alert_client.initialize(&admin).unwrap();
        let watcher_contract_id = watcher_client.address.clone();
        alert_client
            .set_watcher_registry(&admin, &watcher_contract_id)
            .unwrap();

        alert_client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        // Watcher can read before removal
        assert_eq!(
            alert_client
                .get_alerts_for_contract(&watcher, &target)
                .unwrap()
                .len(),
            1
        );

        // Remove the watcher
        watcher_client.remove_watcher(&admin, &watcher);

        // Now rejected
        assert_eq!(
            alert_client
                .try_get_alerts_for_contract(&watcher, &target)
                .unwrap_err()
                .unwrap(),
            ContractError::NotAWatcher
        );
    }

    // 15. get_watcher_registry returns None before configuration
    #[test]
    fn test_get_watcher_registry_none_before_set() {
        let (_env, client) = setup();
        assert!(client.get_watcher_registry().is_none());
    }

    // 16. set_watcher_registry persists and get_watcher_registry returns it
    #[test]
    #[cfg(feature = "testutils")]
    fn test_set_and_get_watcher_registry() {
        use watcher_registry::WatcherRegistry;
        let (env, alert_client, watcher_client) = setup_with_watcher_registry();

        let admin = Address::generate(&env);
        alert_client.initialize(&admin).unwrap();

        let watcher_contract_id = watcher_client.address.clone();
        alert_client
            .set_watcher_registry(&admin, &watcher_contract_id)
            .unwrap();

        assert_eq!(
            alert_client.get_watcher_registry().unwrap(),
            watcher_contract_id
        );
    }

    // 17. Only admin can set watcher registry
    #[test]
    fn test_set_watcher_registry_non_admin_rejected() {
        let (env, client) = setup();
        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);
        let fake_registry = Address::generate(&env);

        client.initialize(&admin).unwrap();

        assert_eq!(
            client
                .try_set_watcher_registry(&attacker, &fake_registry)
                .unwrap_err()
                .unwrap(),
            ContractError::Unauthorized
        );
    }

    // 18. updated_at is strictly greater than created_at after update_alert
    //
    // The Soroban test environment starts with timestamp 0 and does not
    // advance automatically. We manually bump the ledger timestamp by 1
    // second between registration and update so that the contract's
    // `env.ledger().timestamp()` call inside `update_alert` returns a
    // value that is strictly greater than the one captured at registration.
    #[test]
    fn test_updated_at_strictly_greater_than_created_at() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        // Register at timestamp T (default = 0).
        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Timestamp Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        let before = client.get_alert(&id).unwrap();
        assert_eq!(
            before.created_at, before.updated_at,
            "created_at and updated_at should be equal right after registration"
        );

        // Advance the ledger clock by 1 second so the update lands at T+1.
        env.ledger().with_mut(|li| {
            li.timestamp += 1;
        });

        client
            .update_alert(&owner, &id, &vec![&env, str(&env, "rule:mint")], &true)
            .unwrap();

        let after = client.get_alert(&id).unwrap();
        assert!(
            after.updated_at > after.created_at,
            "updated_at ({}) must be strictly greater than created_at ({})",
            after.updated_at,
            after.created_at
        );
    }

    // 19. Register an alert with all valid rule descriptors (no duplicates).
    //
    // Since only two valid descriptors exist ("rule:transfer" and "rule:mint"),
    // the maximum without duplicates is 2. This verifies both are accepted
    // together and stored correctly.
    #[test]
    fn test_register_alert_with_all_valid_rules() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let rules = vec![
            &env,
            str(&env, "rule:transfer"),
            str(&env, "rule:mint"),
        ];

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Bulk Rules Alert"),
            &hash64(&env),
            &rules,
            &None,
        );

        let cfg = client.get_alert(&id).unwrap();
        assert_eq!(cfg.rules.len(), 2, "both rules should be persisted");
        assert_eq!(cfg.rules.get(0).unwrap(), str(&env, "rule:transfer"));
        assert_eq!(cfg.rules.get(1).unwrap(), str(&env, "rule:mint"));
    }

    // ── Feature A: update_label ───────────────────────────────────────────────

    // 18. Happy path — update_label changes only the label
    #[test]
    fn test_update_label_changes_label() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Original"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        assert_eq!(
            client.try_update_label(&owner, &id, &str(&env, "Renamed")).unwrap(),
            Ok(())
        );

        let cfg = client.get_alert(&id).unwrap();
        assert_eq!(cfg.label, str(&env, "Renamed"));
        // rules and webhook_hash must be untouched
        assert_eq!(cfg.rules.get(0).unwrap(), str(&env, "rule:transfer"));
        assert_eq!(cfg.webhook_hash, hash64(&env));
        assert!(cfg.active);
    }

    // 19. update_label — unauthorized caller is rejected
    #[test]
    fn test_update_label_unauthorized() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let attacker = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        assert_eq!(
            client
                .try_update_label(&attacker, &id, &str(&env, "Hacked"))
                .unwrap_err()
                .unwrap(),
            ContractError::Unauthorized
        );
    }

    // 20. update_label — nonexistent alert returns AlertNotFound
    #[test]
    fn test_update_label_not_found() {
        let (env, client) = setup();
        let caller = Address::generate(&env);

        assert_eq!(
            client
                .try_update_label(&caller, &999u64, &str(&env, "X"))
                .unwrap_err()
                .unwrap(),
            ContractError::AlertNotFound
        );
    }

    // 21. update_label — label exceeding 128 bytes is rejected
    #[test]
    #[should_panic(expected = "label exceeds 128 bytes")]
    fn test_update_label_too_long() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        client.update_label(&owner, &id, &str(&env, &"a".repeat(129)));
    }

    // 22. update_label — exactly 128 bytes is accepted
    #[test]
    fn test_update_label_max_length_accepted() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        assert_eq!(
            client
                .try_update_label(&owner, &id, &str(&env, &"a".repeat(128)))
                .unwrap(),
            Ok(())
        );
    }


    // ── Feature B: get_active_alerts_for_contract ─────────────────────────────

    // 23. Happy path — only active alerts are returned
    #[test]
    fn test_get_active_alerts_for_contract_filters_inactive() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id1 = client.register_alert(
            &owner,
            &target,
            &str(&env, "Active"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );
        let _id2 = client.register_alert(
            &owner,
            &target,
            &str(&env, "Inactive"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:mint")],
            &None,
        );

        // Deactivate the second alert
        client.update_alert(&owner, &_id2, &vec![&env, str(&env, "rule:mint")], &false);

        let all = client.get_alerts_for_contract(&owner, &target).unwrap();
        assert_eq!(all.len(), 2);

        let active = client.get_active_alerts_for_contract(&target);
        assert_eq!(active.len(), 1);
        assert_eq!(active.get(0).unwrap().label, str(&env, "Active"));
        let _ = id1;
    }

    // 24. get_active_alerts_for_contract — returns empty when all are inactive
    #[test]
    fn test_get_active_alerts_for_contract_all_inactive() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        client.update_alert(&owner, &id, &vec![&env, str(&env, "rule:transfer")], &false);

        let active = client.get_active_alerts_for_contract(&target);
        assert_eq!(active.len(), 0);
    }

    // 25. get_active_alerts_for_contract — returns empty for unknown contract
    #[test]
    fn test_get_active_alerts_for_contract_empty() {
        let (env, client) = setup();
        let target = Address::generate(&env);
        assert_eq!(client.get_active_alerts_for_contract(&target).len(), 0);
    }

    // 26. get_active_alerts_for_contract — all active alerts are returned
    #[test]
    fn test_get_active_alerts_for_contract_all_active() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        client.register_alert(
            &owner,
            &target,
            &str(&env, "A1"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );
        client.register_alert(
            &owner,
            &target,
            &str(&env, "A2"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:mint")],
            &None,
        );

        let active = client.get_active_alerts_for_contract(&target);
        assert_eq!(active.len(), 2);
    }

    // 18. transfer_admin emits an ("admin", "transfer") event
    #[test]
    fn test_transfer_admin_emits_event() {
        let (env, client) = setup();
        let admin = Address::generate(&env);
        client.initialize(&admin).unwrap();
        let new_admin = Address::generate(&env);

        client.transfer_admin(&admin, &new_admin).unwrap();

        // Verify at least one event was published during the transfer
        assert!(!env.events().all().is_empty());
    }

    // 19. old admin cannot act after transfer_admin
    #[test]
    fn test_old_admin_rejected_after_transfer() {
        let (env, client) = setup();
        let admin = Address::generate(&env);
        client.initialize(&admin).unwrap();
        let new_admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        client.transfer_admin(&admin, &new_admin).unwrap();

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        // old admin can no longer perform admin actions
        assert_eq!(
            client
                .try_remove_alert_by_admin(&admin, &id)
                .unwrap_err()
                .unwrap(),
            ContractError::Unauthorized
        );
    }

    // ── get_alerts_modified_since ─────────────────────────────────────────────

    // 18. Returns all alerts when since == 0
    #[test]
    fn test_get_alerts_modified_since_zero_returns_all() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        client.register_alert(&owner, &target, &str(&env, "A"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
        client.register_alert(&owner, &target, &str(&env, "B"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);

        let results = client.get_alerts_modified_since(&0u64);
        assert_eq!(results.len(), 2);
    }

    // 19. Returns empty vec when no alerts exist
    #[test]
    fn test_get_alerts_modified_since_empty_registry() {
        let (_env, client) = setup();
        let results = client.get_alerts_modified_since(&0u64);
        assert_eq!(results.len(), 0);
    }

    // 20. Filters out alerts whose updated_at is before `since`
    #[test]
    fn test_get_alerts_modified_since_filters_old_alerts() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        // Register at ledger timestamp 0 (default in tests)
        let _id1 = client.register_alert(&owner, &target, &str(&env, "Old"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);

        // Advance the ledger timestamp so the next alert has a higher updated_at
        env.ledger().with_mut(|li| li.timestamp = 1000);

        let _id2 = client.register_alert(&owner, &target, &str(&env, "New"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);

        // Query with since = 1000 — should only return the second alert
        let results = client.get_alerts_modified_since(&1000u64);
        assert_eq!(results.len(), 1);
        assert_eq!(results.get(0).unwrap().label, str(&env, "New"));
    }

    // 21. An updated alert appears in a subsequent incremental sync
    #[test]
    fn test_get_alerts_modified_since_includes_updated_alert() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        // Register both alerts at timestamp 0
        let id1 = client.register_alert(&owner, &target, &str(&env, "A"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
        let _id2 = client.register_alert(&owner, &target, &str(&env, "B"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);

        // Advance time and update the first alert
        env.ledger().with_mut(|li| li.timestamp = 500);
        client.update_alert(&owner, &id1, &vec![&env, str(&env, "rule:transfer")], &false);

        // Incremental sync from timestamp 500 should return only the updated alert
        let results = client.get_alerts_modified_since(&500u64);
        assert_eq!(results.len(), 1);
        assert_eq!(results.get(0).unwrap().label, str(&env, "A"));
    }

    // 22. Removed alerts are not returned
    #[test]
    fn test_get_alerts_modified_since_excludes_removed_alerts() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id1 = client.register_alert(&owner, &target, &str(&env, "A"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
        client.register_alert(&owner, &target, &str(&env, "B"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);

        client.remove_alert(&owner, &id1);

        // Only the surviving alert should be returned
        let results = client.get_alerts_modified_since(&0u64);
        assert_eq!(results.len(), 1);
        assert_eq!(results.get(0).unwrap().label, str(&env, "B"));
    }

    // 23. since is exclusive of nothing — boundary value exactly equal is included
    #[test]
    fn test_get_alerts_modified_since_boundary_inclusive() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        env.ledger().with_mut(|li| li.timestamp = 42);
        client.register_alert(&owner, &target, &str(&env, "Boundary"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);

        // since == updated_at should be inclusive
        let results = client.get_alerts_modified_since(&42u64);
        assert_eq!(results.len(), 1);

        // since == updated_at + 1 should exclude it
        let results_after = client.get_alerts_modified_since(&43u64);
        assert_eq!(results_after.len(), 0);
    }

    // ── Auth-failure tests (no mock_all_auths) ────────────────────────────────

    #[test]
    #[should_panic]
    fn test_register_alert_requires_auth() {
        let env = Env::default();
        let contract_id = env.register(AlertRegistry, ());
        let client = AlertRegistryClient::new(&env, &contract_id);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);
        client.register_alert(
            &owner,
            &target,
            &str(&env, "A"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );
    }

    #[test]
    #[should_panic]
    fn test_update_alert_requires_auth() {
        let env = Env::default();
        let contract_id = env.register(AlertRegistry, ());
        let client = AlertRegistryClient::new(&env, &contract_id);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);
        // register with mocked auth first, then call update without auth
        env.mock_all_auths();
        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "A"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );
        env.set_auths(&[]);
        client.update_alert(&owner, &id, &vec![&env, str(&env, "rule:transfer")], &false);
    }

    #[test]
    #[should_panic]
    fn test_update_webhook_requires_auth() {
        let env = Env::default();
        let contract_id = env.register(AlertRegistry, ());
        let client = AlertRegistryClient::new(&env, &contract_id);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);
        env.mock_all_auths();
        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "A"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );
        env.set_auths(&[]);
        client.update_webhook(&owner, &id, &hash64(&env));
    }

    #[test]
    #[should_panic]
    fn test_remove_alert_requires_auth() {
        let env = Env::default();
        let contract_id = env.register(AlertRegistry, ());
        let client = AlertRegistryClient::new(&env, &contract_id);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);
        env.mock_all_auths();
        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "A"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );
        env.set_auths(&[]);
        client.remove_alert(&owner, &id);
    }

    #[test]
    #[should_panic]
    fn test_transfer_admin_requires_auth() {
        let env = Env::default();
        let contract_id = env.register(AlertRegistry, ());
        let client = AlertRegistryClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin).unwrap();
        let new_admin = Address::generate(&env);
        env.set_auths(&[]);
        client.transfer_admin(&admin, &new_admin);
    }

    #[test]
    #[should_panic]
    fn test_set_per_owner_alert_limit_requires_auth() {
        let env = Env::default();
        let contract_id = env.register(AlertRegistry, ());
        let client = AlertRegistryClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin).unwrap();
        env.set_auths(&[]);
        client.set_per_owner_alert_limit(&admin, &5u32);
    }

    #[test]
    #[should_panic]
    fn test_remove_alert_by_admin_requires_auth() {
        let env = Env::default();
        let contract_id = env.register(AlertRegistry, ());
        let client = AlertRegistryClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin).unwrap();
        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "A"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );
        env.set_auths(&[]);
        client.remove_alert_by_admin(&admin, &id);
    }

    // #63 — ID monotonicity: each successive register_alert returns prev+1
    #[test]
    fn test_id_monotonicity() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        const N: u64 = 10;
        let mut prev_id: Option<u64> = None;
        for i in 0..N {
            let id = client.register_alert(
                &owner,
                &target,
                &str(&env, "alert"),
                &hash64(&env),
                &vec![&env, str(&env, "rule:transfer")],
                &None,
            );
            if let Some(p) = prev_id {
                assert_eq!(id, p + 1, "expected id {} but got {} at iteration {}", p + 1, id, i);
            }
            prev_id = Some(id);
        }
    }

    #[test]
    fn test_alert_ids_live_only_and_new_rules() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);
        let mut ids = vec![&env];
        for _ in 0..3 {
            ids.push_back(client.register_alert(
                &owner,
                &target,
                &str(&env, "A"),
                &hash64(&env),
                &vec![&env, str(&env, "rule:invoke"), str(&env, "rule:all")],
            ));
        }
        client.remove_alert(&owner, &ids.get(1).unwrap());
        assert_eq!(client.get_alert_ids_by_owner(&owner).len(), 2);
        assert_eq!(client.get_alert_ids_for_contract(&target).len(), 2);
    }

    // #33 — update_target_contract moves the alert to a new contract index
    #[test]
    fn test_update_target_contract() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let old_target = Address::generate(&env);
        let new_target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &old_target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        client.update_target_contract(&owner, &id, &new_target);

        // alert config reflects new target
        let cfg = client.get_alert(&id).unwrap();
        assert_eq!(cfg.target_contract, new_target);

        // indexes updated correctly
        assert_eq!(client.get_alerts_for_contract(&owner, &old_target).unwrap().len(), 0);
        assert_eq!(client.get_alerts_for_contract(&owner, &new_target).unwrap().len(), 1);
    }

    // #33 — update_target_contract unauthorized
    #[test]
    fn test_update_target_contract_unauthorized() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let attacker = Address::generate(&env);
        let target = Address::generate(&env);
        let new_target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        assert_eq!(
            client
                .try_update_target_contract(&attacker, &id, &new_target)
                .unwrap_err()
                .unwrap(),
            ContractError::Unauthorized
        );
    }

    // 18. update_alert after remove_alert returns AlertNotFound
    #[test]
    fn test_update_alert_after_remove_returns_not_found() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        assert_eq!(client.try_remove_alert(&owner, &id).unwrap(), Ok(()));

        assert_eq!(
            client
                .try_update_alert(&owner, &id, &vec![&env, str(&env, "rule:transfer")], &false)
                .unwrap_err()
                .unwrap(),
            ContractError::AlertNotFound
        );
    }

    // 19. update_webhook after remove_alert returns AlertNotFound
    #[test]
    fn test_update_webhook_after_remove_returns_not_found() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        assert_eq!(client.try_remove_alert(&owner, &id).unwrap(), Ok(()));

        assert_eq!(
            client
                .try_update_webhook(&owner, &id, &hash64(&env))
                .unwrap_err()
                .unwrap(),
            ContractError::AlertNotFound
        );
    }

    // 18. get_alert_active returns None for nonexistent ID
    #[test]
    fn test_get_alert_active_nonexistent() {
        let (_env, client) = setup();
        assert!(client.get_alert_active(&999u64).is_none());
    }

    // 19. get_alert_active returns true after registration
    #[test]
    fn test_get_alert_active_after_register() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        assert_eq!(client.get_alert_active(&id), Some(true));
    }

    // 20. get_alert_active reflects update_alert changes
    #[test]
    fn test_get_alert_active_after_update() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        assert_eq!(client.get_alert_active(&id), Some(true));

        client.update_alert(&owner, &id, &vec![&env, str(&env, "rule:transfer")], &false);
        assert_eq!(client.get_alert_active(&id), Some(false));

        client.update_alert(&owner, &id, &vec![&env, str(&env, "rule:transfer")], &true);
        assert_eq!(client.get_alert_active(&id), Some(true));
    }

    // 21. get_alert_active returns None after removal
    #[test]
    fn test_get_alert_active_after_remove() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        assert_eq!(client.get_alert_active(&id), Some(true));
        client.remove_alert(&owner, &id);
        assert!(client.get_alert_active(&id).is_none());
    }

    // 22. deactivate_all_alerts returns 0 when owner has no alerts
    #[test]
    fn test_deactivate_all_alerts_empty() {
        let (env, client) = setup();
        let owner = Address::generate(&env);

        assert_eq!(client.deactivate_all_alerts(&owner), 0);
    }

    // 23. deactivate_all_alerts deactivates all alerts for the owner
    #[test]
    fn test_deactivate_all_alerts_multiple() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id1 = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert 1"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );
        let id2 = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert 2"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:mint")],
            &None,
        );
        let id3 = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert 3"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        assert_eq!(client.get_alert_active(&id1), Some(true));
        assert_eq!(client.get_alert_active(&id2), Some(true));
        assert_eq!(client.get_alert_active(&id3), Some(true));

        let count = client.deactivate_all_alerts(&owner);
        assert_eq!(count, 3);

        assert_eq!(client.get_alert_active(&id1), Some(false));
        assert_eq!(client.get_alert_active(&id2), Some(false));
        assert_eq!(client.get_alert_active(&id3), Some(false));
    }

    // 24. deactivate_all_alerts only affects the calling owner's alerts
    #[test]
    fn test_deactivate_all_alerts_other_owner_unaffected() {
        let (env, client) = setup();
        let owner1 = Address::generate(&env);
        let owner2 = Address::generate(&env);
        let target = Address::generate(&env);

        let id1 = client.register_alert(
            &owner1,
            &target,
            &str(&env, "Owner1 Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );
        let id2 = client.register_alert(
            &owner2,
            &target,
            &str(&env, "Owner2 Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:mint")],
            &None,
        );

        let count = client.deactivate_all_alerts(&owner1);
        assert_eq!(count, 1);

        assert_eq!(client.get_alert_active(&id1), Some(false));
        assert_eq!(client.get_alert_active(&id2), Some(true));
    }

    // 25. deactivate_all_alerts skips removed alerts and deactivates remaining
    #[test]
    fn test_deactivate_all_alerts_after_removal() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id1 = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert 1"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );
        let id2 = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert 2"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:mint")],
            &None,
        );

        client.remove_alert(&owner, &id1);

        let count = client.deactivate_all_alerts(&owner);
        assert_eq!(count, 1);

        // id1 is gone
        assert!(client.get_alert(&id1).is_none());
        // id2 is now inactive
        assert_eq!(client.get_alert_active(&id2), Some(false));
    }

    // 18. get_alerts_by_owner_paginated — basic pagination
    #[test]
    fn test_get_alerts_by_owner_paginated() {
        let (env, client) = setup();
        let querier = Address::generate(&env);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        for label in ["A", "B", "C", "D", "E"] {
            client.register_alert(&owner, &target, &str(&env, label), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
        }

        // first page
        let page1 = client.get_alerts_by_owner_paginated(&querier, &owner, &0u32, &3u32).unwrap();
        assert_eq!(page1.len(), 3);

        // second page
        let page2 = client.get_alerts_by_owner_paginated(&querier, &owner, &3u32, &3u32).unwrap();
        assert_eq!(page2.len(), 2);

        // offset beyond length returns empty
        let empty = client.get_alerts_by_owner_paginated(&querier, &owner, &10u32, &3u32).unwrap();
        assert_eq!(empty.len(), 0);
    }

    // 19. get_contract_alerts_paginated — basic pagination
    #[test]
    fn test_get_contract_alerts_paginated() {
        let (env, client) = setup();
        let querier = Address::generate(&env);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        for label in ["A", "B", "C", "D"] {
            client.register_alert(&owner, &target, &str(&env, label), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
        }

        let page = client.get_contract_alerts_paginated(&querier, &target, &1u32, &2u32).unwrap();
        assert_eq!(page.len(), 2);
    }

    // 18. get_admin panics with NotInitialized when contract is not initialized
    #[test]
    #[should_panic]
    fn test_get_admin_not_initialized() {
        let env = Env::default();
        let contract_id = env.register(AlertRegistry, ());
        let client = AlertRegistryClient::new(&env, &contract_id);
        client.get_admin();
    }

    // 19. Alert can be deactivated and reactivated via update_alert
    #[test]
    fn test_alert_deactivate_reactivate() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:mint")],
            &None,
        );

        // deactivate
        assert_eq!(
            client
                .try_update_alert(&owner, &id, &vec![&env, str(&env, "rule:mint")], &false)
                .unwrap(),
            Ok(())
        );
        let cfg = client.get_alert(&id).unwrap();
        assert!(!cfg.active);

        // reactivate
        assert_eq!(
            client
                .try_update_alert(&owner, &id, &vec![&env, str(&env, "rule:mint")], &true)
                .unwrap(),
            Ok(())
        );
        let cfg = client.get_alert(&id).unwrap();
        assert!(cfg.active);
    }

    // 18. update_webhook advances updated_at beyond its value at registration
    #[test]
    fn test_update_webhook_updates_timestamp() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "A"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        let original_updated_at = client.get_alert(&id).unwrap().updated_at;
        env.ledger().set_timestamp(original_updated_at + 100);

        client.try_update_webhook(&owner, &id, &hash64(&env)).unwrap().unwrap();

        let cfg = client.get_alert(&id).unwrap();
        assert!(cfg.updated_at > original_updated_at);
    }

    // update_webhook emits alert.webhook with (id, caller)
    #[test]
    fn test_update_webhook_emits_event() {
        use soroban_sdk::{symbol_short, testutils::Events as _, IntoVal};
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "A"),
            &str(&env, "hash"),
            &vec![&env],
            &None,
        );
        client.update_webhook(&owner, &id, &str(&env, "new-hash"));

        let (_, topics, data) = env.events().all().last().unwrap();
        assert_eq!(
            topics,
            (symbol_short!("alert"), symbol_short!("webhook")).into_val(&env)
        );
        let data: (u64, Address) = data.into_val(&env);
        assert_eq!(data, (id, owner));
    }

    // 19. Multiple owners watching the same contract — indexes are isolated per owner
    #[test]
    fn test_multiple_owners_overlapping_target_contract() {
        let (env, client) = setup();
        let owner_a = Address::generate(&env);
        let owner_b = Address::generate(&env);
        let target = Address::generate(&env);

        client.register_alert(
            &owner_a,
            &target,
            &str(&env, "Alert-A"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );
        client.register_alert(
            &owner_b,
            &target,
            &str(&env, "Alert-B"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        assert_eq!(client.get_alerts_for_contract(&owner_a, &target).unwrap().len(), 2);

        let alerts_a = client.get_alerts_by_owner(&owner_a, &owner_a).unwrap();
        assert_eq!(alerts_a.len(), 1);
        assert_eq!(alerts_a.get(0).unwrap().owner, owner_a);

        let alerts_b = client.get_alerts_by_owner(&owner_b, &owner_b).unwrap();
        assert_eq!(alerts_b.len(), 1);
        assert_eq!(alerts_b.get(0).unwrap().owner, owner_b);
    }

    // ── Feature B: configurable TTL via bump_alert ────────────────────────────

    // B-1. bump_alert succeeds for an existing alert
    #[test]
    fn test_bump_alert_succeeds() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        assert_eq!(client.try_bump_alert(&id, &17_280u32).unwrap(), Ok(()));
    }

    // B-2. bump_alert returns AlertNotFound for a non-existent ID
    #[test]
    fn test_bump_alert_not_found() {
        let (_env, client) = setup();
        assert_eq!(
            client.try_bump_alert(&999u64, &17_280u32).unwrap_err().unwrap(),
            ContractError::AlertNotFound
        );
    }

    // B-3. bump_alert clamps TTL above MAX_TTL to MAX_TTL
    #[test]
    fn test_bump_alert_clamps_to_max_ttl() {
        use soroban_sdk::testutils::Events as _;

        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        // Request a TTL above the protocol maximum
        client.bump_alert(&id, &u32::MAX).unwrap();

        // The emitted event should carry the clamped effective TTL
        let events = env.events().all();
        let bump_event = events.iter().find(|(_, topics, _)| {
            topics.len() == 2
                && topics.get(0).unwrap() == soroban_sdk::symbol_short!("alert").into()
                && topics.get(1).unwrap() == soroban_sdk::symbol_short!("bump").into()
        });
        assert!(bump_event.is_some(), "expected an alert.bump event");

        let (_, _, data) = bump_event.unwrap();
        let (emitted_id, emitted_ttl): (u64, u32) =
            soroban_sdk::FromVal::from_val(&env, &data);
        assert_eq!(emitted_id, id);
        assert_eq!(emitted_ttl, MAX_TTL, "TTL must be clamped to MAX_TTL");
    }

    // B-4. bump_alert with TTL below MAX_TTL uses the requested value exactly
    #[test]
    fn test_bump_alert_uses_requested_ttl_when_below_max() {
        use soroban_sdk::testutils::Events as _;

        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        let requested_ttl: u32 = 120_960; // ~7 days, well below MAX_TTL
        client.bump_alert(&id, &requested_ttl).unwrap();

        let events = env.events().all();
        let bump_event = events.iter().find(|(_, topics, _)| {
            topics.len() == 2
                && topics.get(0).unwrap() == soroban_sdk::symbol_short!("alert").into()
                && topics.get(1).unwrap() == soroban_sdk::symbol_short!("bump").into()
        });
        assert!(bump_event.is_some());

        let (_, _, data) = bump_event.unwrap();
        let (_, emitted_ttl): (u64, u32) = soroban_sdk::FromVal::from_val(&env, &data);
        assert_eq!(emitted_ttl, requested_ttl);
    }

    // B-5. bump_alert emits the correct event shape (topic + data)
    #[test]
    fn test_bump_alert_event_shape() {
        use soroban_sdk::{symbol_short, testutils::Events as _};

        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Alert"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        let ttl: u32 = 17_280;
        client.bump_alert(&id, &ttl).unwrap();

        let events = env.events().all();
        let bump_event = events
            .iter()
            .find(|(_, topics, _)| {
                topics.len() == 2
                    && topics.get(0).unwrap() == symbol_short!("alert").into()
                    && topics.get(1).unwrap() == symbol_short!("bump").into()
            })
            .expect("alert.bump event must be emitted");

        // Verify data shape: (id: u64, ttl: u32)
        let (_, _, data) = bump_event;
        let (emitted_id, emitted_ttl): (u64, u32) =
            soroban_sdk::FromVal::from_val(&env, &data);
        assert_eq!(emitted_id, id);
        assert_eq!(emitted_ttl, ttl);
    }

    // B-6. bump_alert does not modify the alert's content
    #[test]
    fn test_bump_alert_does_not_modify_content() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner,
            &target,
            &str(&env, "Immutable"),
            &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        let before = client.get_alert(&id).unwrap();
        client.bump_alert(&id, &17_280u32).unwrap();
        let after = client.get_alert(&id).unwrap();

        // All fields must be identical after a bump
        assert_eq!(after.label, before.label);
        assert_eq!(after.webhook_hash, before.webhook_hash);
        assert_eq!(after.rules.len(), before.rules.len());
        assert_eq!(after.owner, before.owner);
        assert_eq!(after.target_contract, before.target_contract);
        assert_eq!(after.created_at, before.created_at);
        assert_eq!(after.updated_at, before.updated_at);
        assert_eq!(after.active, before.active);
    }

    // B-7. DEFAULT_TTL and MAX_TTL constants have the expected values
    #[test]
    fn test_ttl_constants() {
        // DEFAULT_TTL ≈ 7 days at 5 s/ledger (120_960 × 5 = 604_800 s)
        assert_eq!(DEFAULT_TTL, 120_960);
        // MAX_TTL ≈ 31 days at 5 s/ledger
        assert_eq!(MAX_TTL, 535_680);
        // MAX_TTL must be strictly greater than DEFAULT_TTL
        assert!(MAX_TTL > DEFAULT_TTL);
    }

    // Counter overflow guard test
    #[test]
    fn test_counter_overflow_guard() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        env.storage().instance().set(&symbol_short!("NEXT_ID"), &u64::MAX);

        let res = client.try_register_alert(
            &owner,
            &target,
            &str(&env, "alert"),
            &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );

        assert_eq!(res.unwrap_err().unwrap(), ContractError::CounterOverflow);
    }

    // ── Issue #210: limit=0 semantics and minimum-limit validation ────────────

    /// A limit of 0 means "no cap" — owners should be able to register freely.
    #[test]
    fn test_issue_210_limit_zero_means_no_cap() {
        let (env, client) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        client.initialize(&admin).unwrap();
        // Explicitly set limit to 0 (no cap).
        client.set_per_owner_alert_limit(&admin, &0u32).unwrap();

        // Should be able to register multiple alerts without hitting any cap.
        for _ in 0..5 {
            client.register_alert(
                &owner,
                &target,
                &str(&env, "Alert"),
                &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                &vec![&env],
                &None,
            ).unwrap();
        }
        assert_eq!(client.get_active_alert_count(&owner), 5u32);
    }

    /// A non-zero limit of 1 should enforce the cap correctly.
    #[test]
    fn test_issue_210_nonzero_limit_enforced() {
        let (env, client) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        client.initialize(&admin).unwrap();
        client.set_per_owner_alert_limit(&admin, &2u32).unwrap();

        // First two should succeed.
        client.register_alert(
            &owner, &target, &str(&env, "A"),
            &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            &vec![&env],
            &None,
        ).unwrap();
        client.register_alert(
            &owner, &target, &str(&env, "B"),
            &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            &vec![&env],
            &None,
        ).unwrap();

        // Third should be rejected.
        let res = client.try_register_alert(
            &owner, &target, &str(&env, "C"),
            &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            &vec![&env],
            &None,
        );
        assert_eq!(res.unwrap_err().unwrap(), ContractError::OwnerAlertLimitExceeded);
    }

    /// After clearing the limit back to 0, registrations should succeed again.
    #[test]
    fn test_issue_210_clearing_limit_re_enables_registration() {
        let (env, client) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        client.initialize(&admin).unwrap();
        client.set_per_owner_alert_limit(&admin, &1u32).unwrap();

        // First succeeds, second fails.
        client.register_alert(
            &owner, &target, &str(&env, "A"),
            &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            &vec![&env],
            &None,
        ).unwrap();
        assert!(client.try_register_alert(
            &owner, &target, &str(&env, "B"),
            &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            &vec![&env],
            &None,
        ).unwrap_err().is_ok());

        // Clear the limit — registrations resume.
        client.set_per_owner_alert_limit(&admin, &0u32).unwrap();
        client.register_alert(
            &owner, &target, &str(&env, "C"),
            &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            &vec![&env],
            &None,
        ).unwrap();
    }

    // ── Issue #212: bump_alert extends the NextId counter TTL ────────────────

    /// Calling bump_alert should not lose the NEXT_ID counter value.
    /// In the real network instance storage TTL is separate; here we verify
    /// the counter survives repeated bumps without re-registration.
    #[test]
    fn test_issue_212_next_id_survives_repeated_bumps() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        // Register one alert so NEXT_ID becomes 1.
        let id = client.register_alert(
            &owner, &target, &str(&env, "Alert"),
            &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            &vec![&env],
            &None,
        ).unwrap();

        // Counter should be 1 after first registration.
        let count_before: u64 = env
            .storage()
            .instance()
            .get(&symbol_short!("NEXT_ID"))
            .unwrap_or(0u64);
        assert_eq!(count_before, 1u64);

        // Bump several times without new registrations.
        for _ in 0..5 {
            client.bump_alert(&id, &DEFAULT_TTL).unwrap();
        }

        // Counter value must be unchanged — bumping must not reset or corrupt it.
        let count_after: u64 = env
            .storage()
            .instance()
            .get(&symbol_short!("NEXT_ID"))
            .unwrap_or(0u64);
        assert_eq!(count_after, count_before, "NEXT_ID must not change after bump_alert calls");

        // A new registration should get the correct next ID (1, not 0).
        let id2 = client.register_alert(
            &owner, &target, &str(&env, "Alert2"),
            &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            &vec![&env],
            &None,
        ).unwrap();
        assert_eq!(id2, 1u64, "Second registration must receive ID 1, not 0");
    }

    // ── Issue #213: remove_alert_by_admin event includes both admin and owner ─

    /// Owner-initiated remove emits (id, caller) — two-element data.
    #[test]
    fn test_issue_213_owner_remove_event_shape() {
        use soroban_sdk::testutils::Events as _;

        let (env, client) = setup();
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        let id = client.register_alert(
            &owner, &target, &str(&env, "Alert"),
            &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            &vec![&env],
            &None,
        ).unwrap();

        let events_before = env.events().all().len();
        client.remove_alert(&owner, &id).unwrap();

        let events = env.events().all();
        let remove_event = events.iter().skip(events_before).find(|(_, topics, _)| {
            topics.len() == 2
                && topics.get(0).unwrap() == symbol_short!("alert").into()
                && topics.get(1).unwrap() == symbol_short!("remove").into()
        }).expect("alert.remove event must be emitted");

        // Owner-initiated: data is (id: u64, caller: Address)
        let (_, _, data) = remove_event;
        let (emitted_id, emitted_caller): (u64, Address) =
            soroban_sdk::FromVal::from_val(&env, &data);
        assert_eq!(emitted_id, id);
        assert_eq!(emitted_caller, owner);
    }

    /// Admin-initiated remove emits (id, admin, owner) — three-element data.
    #[test]
    fn test_issue_213_admin_remove_event_includes_owner() {
        use soroban_sdk::testutils::Events as _;

        let (env, client) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);

        client.initialize(&admin).unwrap();
        let id = client.register_alert(
            &owner, &target, &str(&env, "Alert"),
            &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            &vec![&env],
            &None,
        ).unwrap();

        let events_before = env.events().all().len();
        client.remove_alert_by_admin(&admin, &id).unwrap();

        let events = env.events().all();
        let remove_event = events.iter().skip(events_before).find(|(_, topics, _)| {
            topics.len() == 2
                && topics.get(0).unwrap() == symbol_short!("alert").into()
                && topics.get(1).unwrap() == symbol_short!("remove").into()
        }).expect("alert.remove event must be emitted for admin removal");

        // Admin-initiated: data is (id: u64, admin: Address, owner: Address)
        let (_, _, data) = remove_event;
        let (emitted_id, emitted_admin, emitted_owner): (u64, Address, Address) =
            soroban_sdk::FromVal::from_val(&env, &data);
        assert_eq!(emitted_id, id);
        assert_eq!(emitted_admin, admin, "event must contain the admin address");
        assert_eq!(emitted_owner, owner, "event must contain the original alert owner");
    }

    // ── Multi-admin / tags / transfer / incremental sync ─────────────────

    fn reg(env: &Env, c: &AlertRegistryClient<'static>, o: &Address, t: &Address, tags: Option<Vec<String>>) -> u64 {
        c.register_alert(o, t, &str(env, "l"), &hash64(env), &vec![env, str(env, "rule:transfer")], &tags)
    }

    #[test]
    fn test_multi_admin_add_remove_and_last_admin_guard() {
        let (env, c) = setup();
        let (a, b, x) = (Address::generate(&env), Address::generate(&env), Address::generate(&env));
        c.initialize(&a);
        c.add_admin(&a, &b);
        assert_eq!(c.get_admins().unwrap().len(), 2);
        assert_eq!(c.try_add_admin(&b, &a), Err(Ok(ContractError::AlreadyAdmin)));
        assert_eq!(c.try_add_admin(&x, &x), Err(Ok(ContractError::Unauthorized)));
        // new admin can use admin-only ops
        c.set_paused(&b, &false);
        assert_eq!(c.try_remove_admin(&a, &x), Err(Ok(ContractError::NotAdmin)));
        c.remove_admin(&b, &a);
        assert_eq!(c.try_remove_admin(&b, &b), Err(Ok(ContractError::LastAdmin)));
        assert_eq!(c.try_set_paused(&a, &true), Err(Ok(ContractError::Unauthorized)));
        assert_eq!(c.get_admin(), b);
    }

    #[test]
    fn test_legacy_single_admin_is_migrated_on_read() {
        let (env, c) = setup();
        let a = Address::generate(&env);
        let b = Address::generate(&env);
        env.as_contract(&c.address, || {
            env.storage().instance().set(&symbol_short!("ADMIN"), &a);
        });
        assert_eq!(c.get_admin(), a);
        c.add_admin(&a, &b);
        assert_eq!(c.get_admins().unwrap().len(), 2);
    }

    #[test]
    fn test_transfer_admin_replaces_set() {
        let (env, c) = setup();
        let (a, b, n) = (Address::generate(&env), Address::generate(&env), Address::generate(&env));
        c.initialize(&a);
        c.add_admin(&a, &b);
        c.transfer_admin(&a, &n);
        assert_eq!(c.get_admins().unwrap(), vec![&env, n]);
    }

    #[test]
    fn test_tags_valid_and_invalid() {
        let (env, c) = setup();
        let (o, t) = (Address::generate(&env), Address::generate(&env));
        let id = reg(&env, &c, &o, &t, Some(vec![&env, str(&env, "prod")]));
        assert_eq!(c.get_alert(&id).unwrap().tags, Some(vec![&env, str(&env, "prod")]));
        let mut ten: Vec<String> = vec![&env];
        for _ in 0..10 { ten.push_back(str(&env, "x")); }
        c.update_tags(&o, &id, &Some(ten.clone()));
        ten.push_back(str(&env, "x"));
        assert_eq!(c.try_update_tags(&o, &id, &Some(ten.clone())), Err(Ok(ContractError::TooManyTags)));
        let long = str(&env, "0123456789012345678901234567890123");
        assert_eq!(c.try_update_tags(&o, &id, &Some(vec![&env, long.clone()])), Err(Ok(ContractError::TagTooLong)));
        assert_eq!(
            c.try_register_alert(&o, &t, &str(&env, "l"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &Some(vec![&env, long])),
            Err(Ok(ContractError::TagTooLong))
        );
        let other = Address::generate(&env);
        assert_eq!(c.try_update_tags(&other, &id, &None), Err(Ok(ContractError::Unauthorized)));
        c.update_tags(&o, &id, &None);
        assert_eq!(c.get_alert(&id).unwrap().tags, None);
    }

    #[test]
    fn test_transfer_alert_ownership_and_limit_guard() {
        let (env, c) = setup();
        let admin = Address::generate(&env);
        let (o, n, t) = (Address::generate(&env), Address::generate(&env), Address::generate(&env));
        c.initialize(&admin);
        let id = reg(&env, &c, &o, &t, None);
        c.transfer_alert_ownership(&o, &id, &n);
        assert_eq!(c.get_alert(&id).unwrap().owner, n);
        assert_eq!(c.get_alerts_by_owner(&o, &o).len(), 0);
        assert_eq!(c.get_alerts_by_owner(&n, &n).len(), 1);
        assert_eq!(c.try_transfer_alert_ownership(&o, &id, &o), Err(Ok(ContractError::Unauthorized)));
        // limit guard: new owner already at limit
        c.set_per_owner_alert_limit(&admin, &1u32);
        assert_eq!(
            c.try_transfer_alert_ownership(&n, &id, &o).map(|_| ()),
            Ok(())
        );
        let id2 = reg(&env, &c, &n, &t, None);
        assert_eq!(c.try_transfer_alert_ownership(&n, &id2, &o), Err(Ok(ContractError::OwnerAlertLimitExceeded)));
    }

    #[test]
    fn test_get_alerts_updated_since() {
        let (env, c) = setup();
        let (o, t) = (Address::generate(&env), Address::generate(&env));
        env.ledger().set_timestamp(100);
        let a = reg(&env, &c, &o, &t, None);
        let _b = reg(&env, &c, &o, &t, None);
        let d = reg(&env, &c, &o, &t, None);
        env.ledger().set_timestamp(200);
        c.update_alert(&o, &a, &vec![&env, str(&env, "rule:transfer")], &false);
        c.update_alert(&o, &d, &vec![&env, str(&env, "rule:transfer")], &true);
        let r = c.get_alerts_updated_since(&t, &200, &0, &10);
        assert_eq!(r.len(), 2);
        assert_eq!(c.get_alerts_updated_since(&t, &100, &0, &10).len(), 3);
        assert_eq!(c.get_alerts_updated_since(&t, &200, &1, &10).len(), 1);
        assert_eq!(c.get_alerts_updated_since(&t, &200, &0, &1).len(), 1);
        assert_eq!(c.get_alerts_updated_since(&t, &201, &0, &10).len(), 0);
    }
}

