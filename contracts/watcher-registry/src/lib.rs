#![no_std]
#![warn(clippy::pedantic)]
use soroban_sdk::{
    contract, contractimpl, contracttype, contracterror, symbol_short, vec, Address, Env, Map, Symbol, Vec,
};

/// Number of ledgers to extend instance storage TTL by on each access.
/// At ~5s per ledger this is roughly 30 days.
const DEFAULT_TTL: u32 = 518_400;

/// Maximum number of addresses accepted by `batch_register_watchers`.
pub const MAX_BATCH_SIZE: u32 = 20;

/// Maximum number of watchers that may be registered at once.
pub const MAX_WATCHERS: u32 = 1_000;

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ContractError {
    AlreadyInitialized = 1,
    Unauthorized = 2,
    NotInitialized = 3,
    /// Returned when trying to remove the last admin, which would lock the contract.
    LastAdmin = 4,
    /// Returned when the specified watcher is not currently registered.
    WatcherNotFound = 5,
    /// Returned by mutating entrypoints while the registry is paused.
    ContractPaused = 6,
    /// Returned when a batch exceeds [`MAX_BATCH_SIZE`].
    BatchTooLarge = 7,
    /// Returned when registration would exceed [`MAX_WATCHERS`].
    WatcherLimitExceeded = 8,
}

// ── Storage keys ─────────────────────────────────────────────────────────────

/// Storage key variants used to address instance entries.
#[contracttype]
pub enum DataKey {
    /// Stores the `Vec<Address>` of current admins.
    Admins,
    /// Stores the `Vec<Address>` of authorized watcher nodes.
    Watchers,
    /// Stores the paused flag (circuit breaker).
    Paused,
    /// Stores a `Map<Address, u64>` of watcher expiry timestamps.
    Expiries,
}

// ── Contract ─────────────────────────────────────────────────────────────────

/// On-chain registry for authorized watcher nodes.
///
/// # Admin model
/// The registry supports a **set of admins** (N-of-N independent signers).
/// Any single admin can perform privileged operations (register/remove watchers,
/// add/remove other admins). This eliminates the single-point-of-failure of a
/// sole admin while keeping the authorization model simple and auditable.
///
/// All admin mutations emit Soroban events so changes are visible on-chain.
#[contract]
pub struct WatcherRegistry;

#[contractimpl]
impl WatcherRegistry {
    /// Initialize the registry with a single bootstrap admin. Can only be called once.
    ///
    /// A second call returns [`ContractError::AlreadyInitialized`] rather than
    /// silently succeeding. This is intentional: a hard error makes a
    /// re-initialization attempt visible instead of masking it. Deploy scripts
    /// that run against an existing contract ID should call
    /// [`WatcherRegistry::is_initialized`] first and skip `initialize` when it
    /// returns `true`.
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `admin`.
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        admin.require_auth();

        if env.storage().instance().has(&DataKey::Admins) {
            return Err(ContractError::AlreadyInitialized);
        }

        let admins: Vec<Address> = vec![&env, admin.clone()];
        env.storage().instance().set(&DataKey::Admins, &admins);
        Self::extend_instance_ttl(&env);

        env.events().publish(
            (symbol_short!("admin"), symbol_short!("init")),
            admin,
        );

        Ok(())
    }

    /// Add a new admin to the admin set (any existing admin may call this).
    ///
    /// Idempotent — adding an address that is already an admin is a no-op.
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `caller`, who must be an
    /// existing admin.
    pub fn add_admin(
        env: Env,
        caller: Address,
        new_admin: Address,
    ) -> Result<(), ContractError> {
        caller.require_auth();
        Self::assert_admin(&env, &caller)?;
        Self::assert_not_paused(&env)?;

        let mut admins = Self::load_admins(&env);
        for i in 0..admins.len() {
            if admins.get(i).unwrap() == new_admin {
                return Ok(()); // already an admin, idempotent
            }
        }
        admins.push_back(new_admin.clone());
        env.storage().instance().set(&DataKey::Admins, &admins);
        Self::extend_instance_ttl(&env);

        env.events().publish(
            (symbol_short!("admin"), symbol_short!("add")),
            (caller, new_admin),
        );

        Ok(())
    }

    /// Remove an admin from the admin set (any existing admin may call this).
    ///
    /// Refuses to remove the last admin to prevent the contract from becoming
    /// permanently unmanageable.
    ///
    /// An admin may remove themselves (`caller == target_admin`) as long as at
    /// least one other admin remains; if they are the sole admin this returns
    /// [`ContractError::LastAdmin`]. A successful self-removal additionally
    /// emits `(Symbol("admin"), Symbol("self_remove"))` with data `caller` for
    /// auditability, since it is usually a mistake.
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `caller`, who must be an
    /// existing admin.
    pub fn remove_admin(
        env: Env,
        caller: Address,
        target_admin: Address,
    ) -> Result<(), ContractError> {
        caller.require_auth();
        Self::assert_admin(&env, &caller)?;
        Self::assert_not_paused(&env)?;

        let admins = Self::load_admins(&env);
        if admins.len() <= 1 {
            return Err(ContractError::LastAdmin);
        }

        let mut updated: Vec<Address> = vec![&env];
        for i in 0..admins.len() {
            let a = admins.get(i).unwrap();
            if a != target_admin {
                updated.push_back(a);
            }
        }
        env.storage().instance().set(&DataKey::Admins, &updated);
        Self::extend_instance_ttl(&env);

        env.events().publish(
            (symbol_short!("admin"), symbol_short!("remove")),
            (caller.clone(), target_admin.clone()),
        );

        if caller == target_admin {
            env.events().publish(
                (symbol_short!("admin"), Symbol::new(&env, "self_remove")),
                caller,
            );
        }

        Ok(())
    }

    /// Transfer the sole admin role to a new address (any existing admin may call this).
    ///
    /// This replaces the admin set with a single new admin, so it is only
    /// allowed when exactly one admin exists (decision: option 1 of #236 —
    /// enforce the single-admin invariant rather than silently dropping
    /// admins). With more than one admin it returns
    /// [`ContractError::MultipleAdminsExist`]; use [`add_admin`] +
    /// [`remove_admin`] to rotate members of a multi-admin set.
    ///
    /// Emits an `("admin", "transfer")` event recording both the old and new admin.
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `admin`, who must be an
    /// existing admin.
    pub fn transfer_admin(
        env: Env,
        admin: Address,
        new_admin: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;
        Self::assert_not_paused(&env)?;

        if Self::load_admins(&env).len() > 1 {
            return Err(ContractError::MultipleAdminsExist);
        }

        let new_admins: Vec<Address> = vec![&env, new_admin.clone()];
        env.storage().instance().set(&DataKey::Admins, &new_admins);
        Self::extend_instance_ttl(&env);

        // Emit an auditable on-chain event recording the full admin transfer.
        env.events().publish(
            (symbol_short!("admin"), symbol_short!("transfer")),
            (admin, new_admin),
        );

        Ok(())
    }

    /// Register an authorized watcher node (any admin may call this).
    ///
    /// Idempotent — registering an already-authorized watcher is a no-op.
    ///
    /// `expires_at` is an optional ledger timestamp after which the watcher is
    /// no longer authorized (see [`WatcherRegistry::renew_watcher`]).
    pub fn register_watcher(
        env: Env,
        admin: Address,
        watcher: Address,
        expires_at: Option<u64>,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;
        Self::assert_not_paused(&env)?;

        let label = label.unwrap_or_else(|| String::from_str(&env, ""));
        if label.len() > MAX_LABEL_BYTES {
            return Err(ContractError::LabelTooLong);
        }

        if env.storage().persistent().has(&DataKey::WatcherInfo(watcher.clone())) {
            return Ok(()); // already registered, idempotent
        }
        if watchers.len() >= MAX_WATCHERS {
            return Err(ContractError::WatcherLimitExceeded);
        }
        Self::set_expiry(&env, &watcher, expires_at);
        watchers.push_back(watcher.clone());
        env.storage().instance().set(&DataKey::Watchers, &watchers);
        Self::extend_instance_ttl(&env);

        Self::increment_watcher_count(&env);

        env.events().publish(
            (symbol_short!("watcher"), symbol_short!("register")),
            watcher,
        );

        Ok(())
    }

    /// Remove (deauthorize) a watcher (any admin may call this).
    ///
    /// If the watcher address is not currently registered this is a no-op —
    /// the call succeeds and no event is emitted.
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `admin`, who must be an
    /// existing admin.
    ///
    /// # Events
    /// Emits `(Symbol("watcher"), Symbol("remove"))` with data
    /// `(watcher: Address)` when the watcher was present and has been removed.
    /// Dependent systems (e.g. `AlertRegistry` watcher-gating) should listen
    /// for this event to revoke trust immediately.
    pub fn remove_watcher(
        env: Env,
        admin: Address,
        watcher: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;
        Self::assert_not_paused(&env)?;

        let watchers = Self::load_watchers(&env);
        let mut updated: Vec<Address> = vec![&env];
        let mut removed = false;
        for i in 0..watchers.len() {
            let w = watchers.get(i).unwrap();
            if w == watcher {
                removed = true;
            } else {
                updated.push_back(w);
            }
        }
        env.storage().instance().set(&DataKey::Watchers, &updated);
        Self::extend_instance_ttl(&env);

        // Only emit the event and decrement the counter when the watcher was
        // actually present.  Callers that need to detect deauthorization must
        // subscribe to this event — it is the authoritative signal that a
        // watcher's trust has been revoked.
        if removed {
            Self::set_expiry(&env, &watcher, None);
            Self::decrement_watcher_count(&env);
            env.events().publish(
                (symbol_short!("watcher"), symbol_short!("remove")),
                watcher,
            );
        }

        Ok(())
    }

    /// Atomically replace `old_watcher` with `new_watcher` in a single transaction.
    ///
    /// Useful for key rotation — the old address is deauthorized and the new
    /// address is authorized with no gap between the two operations.
    ///
    /// Returns `Err(WatcherNotFound)` if `old_watcher` is not currently registered.
    /// If `new_watcher` is already registered the call still succeeds (the old
    /// entry is removed and the new entry remains).
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `admin`, who must be an
    /// existing admin.
    ///
    /// # Events
    /// Emits `("watcher", "remove")` for `old_watcher` and
    /// `("watcher", "replace")` with data `(old_watcher, new_watcher)`.
    pub fn replace_watcher(
        env: Env,
        admin: Address,
        old_watcher: Address,
        new_watcher: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;
        Self::assert_not_paused(&env)?;

        let watchers = Self::load_watchers(&env);
        let mut found = false;
        let mut updated: Vec<Address> = vec![&env];
        for i in 0..watchers.len() {
            let w = watchers.get(i).unwrap();
            if w == old_watcher {
                found = true;
            } else {
                updated.push_back(w);
            }
        }

        if !found {
            return Err(ContractError::WatcherNotFound);
        }
        Self::set_expiry(&env, &old_watcher, None);

        // Add new_watcher only if not already present
        let mut already_present = false;
        for i in 0..updated.len() {
            if updated.get(i).unwrap() == new_watcher {
                already_present = true;
                break;
            }
        }
        env.storage().persistent().remove(&DataKey::WatcherInfo(old_watcher.clone()));
        if !already_present {
            let info = WatcherInfo {
                address: new_watcher.clone(),
                label: String::from_str(&env, ""),
                registered_at: env.ledger().timestamp(),
                registered_by: admin.clone(),
            };
            Self::save_info(&env, &info);
            updated.push_back(new_watcher.clone());
        } else {
            // old was removed but new was already there — net count decreases by 1
            Self::decrement_watcher_count(&env);
        }

        env.storage().instance().set(&DataKey::Watchers, &updated);
        Self::extend_instance_ttl(&env);

        env.events().publish(
            (symbol_short!("watcher"), symbol_short!("remove")),
            old_watcher.clone(),
        );
        env.events().publish(
            (symbol_short!("watcher"), symbol_short!("replace")),
            (old_watcher, new_watcher),
        );

        Ok(())
    }

    /// Register up to [`MAX_BATCH_SIZE`] watchers in one call.
    ///
    /// Already-registered and duplicate addresses are skipped. Returns the
    /// number of newly registered watchers and emits one `("watcher",
    /// "register")` event for each.
    ///
    /// # Errors
    /// [`ContractError::BatchTooLarge`] if `watchers.len() > MAX_BATCH_SIZE`;
    /// [`ContractError::WatcherLimitExceeded`] if the total would exceed
    /// [`MAX_WATCHERS`].
    pub fn batch_register_watchers(
        env: Env,
        admin: Address,
        watchers: Vec<Address>,
    ) -> Result<u32, ContractError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;
        Self::assert_not_paused(&env)?;

        if watchers.len() > MAX_BATCH_SIZE {
            return Err(ContractError::BatchTooLarge);
        }

        let mut stored = Self::load_watchers(&env);
        let mut added: Vec<Address> = vec![&env];
        for i in 0..watchers.len() {
            let w = watchers.get(i).unwrap();
            if !stored.contains(&w) {
                stored.push_back(w.clone());
                added.push_back(w);
            }
        }
        if stored.len() > MAX_WATCHERS {
            return Err(ContractError::WatcherLimitExceeded);
        }

        env.storage().instance().set(&DataKey::Watchers, &stored);
        Self::extend_instance_ttl(&env);
        for i in 0..added.len() {
            let w = added.get(i).unwrap();
            Self::increment_watcher_count(&env);
            env.events()
                .publish((symbol_short!("watcher"), symbol_short!("register")), w);
        }

        Ok(added.len())
    }

    /// Set or clear the expiry of an already-registered watcher.
    ///
    /// Passing `None` makes the authorization permanent again.
    ///
    /// # Errors
    /// [`ContractError::WatcherNotFound`] if `watcher` is not registered.
    pub fn renew_watcher(
        env: Env,
        admin: Address,
        watcher: Address,
        new_expiry: Option<u64>,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;
        Self::assert_not_paused(&env)?;

        if !Self::load_watchers(&env).contains(&watcher) {
            return Err(ContractError::WatcherNotFound);
        }
        Self::set_expiry(&env, &watcher, new_expiry);
        Self::extend_instance_ttl(&env);

        env.events().publish(
            (symbol_short!("watcher"), symbol_short!("renew")),
            (watcher, new_expiry),
        );
        Ok(())
    }

    /// Pause or unpause the registry (circuit breaker). Any admin may call this.
    ///
    /// While paused, all mutating entrypoints except this one return
    /// [`ContractError::ContractPaused`]; reads and `is_authorized` keep working.
    pub fn set_paused(env: Env, admin: Address, paused: bool) -> Result<(), ContractError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Paused, &paused);
        Self::extend_instance_ttl(&env);

        let topic = if paused {
            symbol_short!("pause")
        } else {
            symbol_short!("unpause")
        };
        env.events().publish((symbol_short!("admin"), topic), admin);
        Ok(())
    }

    /// Return `true` if the registry is currently paused.
    #[must_use]
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// Check if an address is an authorized watcher.
    ///
    /// Renamed from `is_authorized` for clarity in cross-contract call contexts —
    /// the name now makes explicit *what* the address is being authorized as.
    #[must_use]
    pub fn is_watcher_authorized(env: Env, watcher: Address) -> bool {
        Self::extend_instance_ttl(&env);
        let watchers = Self::load_watchers(&env);
        if !watchers.contains(&watcher) {
            return false;
        }
        match Self::load_expiries(&env).get(watcher) {
            Some(exp) => env.ledger().timestamp() <= exp,
            None => true,
        }
    }

    /// Alias for [`is_watcher_authorized`] kept for backwards compatibility.
    #[must_use]
    pub fn is_authorized(env: Env, watcher: Address) -> bool {
        Self::is_watcher_authorized(env, watcher)
    }

    /// Remove all registered watchers in a single admin call.
    ///
    /// This is a bulk deauthorization operation.  Each removed watcher emits
    /// a `("watcher", "remove")` event so dependent systems can revoke trust
    /// for every affected address.
    ///
    /// # Auth
    /// Requires a valid Stellar auth signature from `admin`, who must be an
    /// existing admin.
    pub fn clear_all_watchers(env: Env, admin: Address) -> Result<(), ContractError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;
        Self::assert_not_paused(&env)?;

        let watchers = Self::load_watchers(&env);
        for i in 0..watchers.len() {
            let w = watchers.get(i).unwrap();
            env.events().publish(
                (symbol_short!("watcher"), symbol_short!("remove")),
                w.clone(),
            );
            env.storage().persistent().remove(&DataKey::WatcherInfo(w));
        }

        let empty: Vec<Address> = vec![&env];
        env.storage().instance().set(&DataKey::Watchers, &empty);
        env.storage().instance().remove(&DataKey::Expiries);
        Self::extend_instance_ttl(&env);

        // Reset the count to zero
        env.storage()
            .instance()
            .set(&symbol_short!("W_CNT"), &0u32);

        Ok(())
    }

    /// Get all authorized watcher addresses.
    #[must_use]
    pub fn get_watchers(env: Env) -> Vec<Address> {
        Self::load_watchers(&env)
    }

    /// Get all registered watcher addresses. Read-only, no auth.
    #[must_use]
    pub fn get_all_watchers(env: Env) -> Vec<Address> {
        Self::load_watchers(&env)
    }

    /// Get a page of watcher addresses. `limit` is capped at [`MAX_PAGE_LIMIT`].
    /// Read-only, no auth.
    #[must_use]
    pub fn get_all_watchers_paginated(env: Env, offset: u32, limit: u32) -> Vec<Address> {
        let watchers = Self::load_watchers(&env);
        let limit = limit.min(MAX_PAGE_LIMIT);
        let end = offset.saturating_add(limit).min(watchers.len());
        let mut page: Vec<Address> = vec![&env];
        let mut i = offset;
        while i < end {
            page.push_back(watchers.get(i).unwrap());
            i += 1;
        }
        page
    }

    /// Get metadata for a registered watcher, or `None`. Read-only, no auth.
    #[must_use]
    pub fn get_watcher_info(env: Env, watcher: Address) -> Option<WatcherInfo> {
        env.storage().persistent().get(&DataKey::WatcherInfo(watcher))
    }

    /// Get all current admin addresses.
    ///
    /// Returns `Err(NotInitialized)` if the contract has not been initialized.
    pub fn get_admins(env: Env) -> Result<Vec<Address>, ContractError> {
        if !env.storage().instance().has(&DataKey::Admins) {
            return Err(ContractError::NotInitialized);
        }
        Ok(Self::load_admins(&env))
    }

    /// Get the primary admin address (first in the admin set).
    ///
    /// Kept for backwards compatibility. Prefer [`get_admins`] when you need
    /// the full admin set.
    /// Return `true` if [`WatcherRegistry::initialize`] has already been called.
    ///
    /// Read-only entrypoint, requires no authorization.
    #[must_use]
    pub fn is_initialized(env: Env) -> bool {
        env.storage().instance().has(&DataKey::Admins)
    }

    /// Check whether a given address is an admin of the registry.
    ///
    /// Returns `false` (not an error) if the contract has not been initialized.
    /// Read-only entrypoint, requires no authorization.
    #[must_use]
    pub fn is_admin(env: Env, address: Address) -> bool {
        if !env.storage().instance().has(&DataKey::Admins) {
            return false;
        }
        let admins = Self::load_admins(&env);
        for i in 0..admins.len() {
            if admins.get(i).unwrap() == address {
                return true;
            }
        }
        false
    }

    pub fn get_admin(env: Env) -> Result<Address, ContractError> {
        let admins = Self::get_admins(env)?;
        // load_admins guarantees at least one entry after initialization
        Ok(admins.get(0).unwrap())
    }

    /// Get the number of registered watchers as a cheap u32 read, avoiding
    /// the cost of fetching and deserializing the full watcher list.
    #[must_use]
    pub fn get_watcher_count(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&symbol_short!("W_CNT"))
            .unwrap_or(0u32)
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// Extend the instance storage TTL so a dormant registry is not archived.
    ///
    /// Called from every mutating entrypoint and from the hot read path
    /// (`is_watcher_authorized` / `is_authorized`) to keep the instance alive
    /// during low-activity periods.
    fn extend_instance_ttl(env: &Env) {
        env.storage().instance().extend_ttl(DEFAULT_TTL, DEFAULT_TTL);
    }

    fn save_info(env: &Env, info: &WatcherInfo) {
        let key = DataKey::WatcherInfo(info.address.clone());
        env.storage().persistent().set(&key, info);
        env.storage().persistent().extend_ttl(&key, DEFAULT_TTL, DEFAULT_TTL);
    }

    fn increment_watcher_count(env: &Env) {
        let count: u32 = env
            .storage()
            .instance()
            .get(&symbol_short!("W_CNT"))
            .unwrap_or(0u32);
        env.storage()
            .instance()
            .set(&symbol_short!("W_CNT"), &(count + 1));
    }

    fn decrement_watcher_count(env: &Env) {
        let count: u32 = env
            .storage()
            .instance()
            .get(&symbol_short!("W_CNT"))
            .unwrap_or(0u32);
        if count > 0 {
            env.storage()
                .instance()
                .set(&symbol_short!("W_CNT"), &(count - 1));
        }
    }

    fn assert_not_paused(env: &Env) -> Result<(), ContractError> {
        if Self::is_paused(env.clone()) {
            return Err(ContractError::ContractPaused);
        }
        Ok(())
    }

    fn load_expiries(env: &Env) -> Map<Address, u64> {
        env.storage()
            .instance()
            .get(&DataKey::Expiries)
            .unwrap_or_else(|| Map::new(env))
    }

    /// Set (`Some`) or clear (`None`) a watcher's expiry timestamp.
    fn set_expiry(env: &Env, watcher: &Address, expires_at: Option<u64>) {
        let mut m = Self::load_expiries(env);
        match expires_at {
            Some(exp) => m.set(watcher.clone(), exp),
            None => {
                m.remove(watcher.clone());
            }
        }
        env.storage().instance().set(&DataKey::Expiries, &m);
    }

    /// Load the current watcher list from instance storage, or return an empty vec.
    fn load_watchers(env: &Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::Watchers)
            .unwrap_or_else(|| vec![env])
    }

    /// Load the current admin set from instance storage, or return an empty vec.
    fn load_admins(env: &Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::Admins)
            .unwrap_or_else(|| vec![env])
    }

    /// Return `Ok(())` if `caller` is in the admin set, `Err(Unauthorized)` otherwise.
    fn assert_admin(env: &Env, caller: &Address) -> Result<(), ContractError> {
        if !env.storage().instance().has(&DataKey::Admins) {
            return Err(ContractError::NotInitialized);
        }
        let admins = Self::load_admins(env);
        for i in 0..admins.len() {
            if admins.get(i).unwrap() == *caller {
                return Ok(());
            }
        }
        Err(ContractError::Unauthorized)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod watcher_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, testutils::Events as _, Env};

    fn setup() -> (Env, Address, WatcherRegistryClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(WatcherRegistry, ());
        let client = WatcherRegistryClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, admin, client)
    }

    #[test]
    fn test_get_all_watchers_and_paginated() {
        let (env, admin, client) = setup();
        assert_eq!(client.get_all_watchers().len(), 0);
        assert_eq!(client.get_all_watchers_paginated(&0, &10).len(), 0);
        let w1 = Address::generate(&env);
        client.register_watcher(&admin, &w1, &None);
        assert_eq!(client.get_all_watchers(), vec![&env, w1.clone()]);
        let w2 = Address::generate(&env);
        let w3 = Address::generate(&env);
        client.register_watcher(&admin, &w2, &None);
        client.register_watcher(&admin, &w3, &None);
        assert_eq!(client.get_all_watchers().len(), 3);
        assert_eq!(client.get_all_watchers_paginated(&1, &1), vec![&env, w2.clone()]);
        assert_eq!(client.get_all_watchers_paginated(&2, &50), vec![&env, w3]);
        assert_eq!(client.get_all_watchers_paginated(&9, &5).len(), 0);
    }

    #[test]
    fn test_watcher_info_label() {
        let (env, admin, client) = setup();
        let w = Address::generate(&env);
        let w2 = Address::generate(&env);
        client.register_watcher(&admin, &w, &Some(String::from_str(&env, "node-1")));
        client.register_watcher(&admin, &w2, &None);
        let info = client.get_watcher_info(&w).unwrap();
        assert_eq!(info.label, String::from_str(&env, "node-1"));
        assert_eq!(info.registered_by, admin);
        assert_eq!(client.get_watcher_info(&w2).unwrap().label, String::from_str(&env, ""));
        client.remove_watcher(&admin, &w);
        assert!(client.get_watcher_info(&w).is_none());
        assert!(!client.is_authorized(&w));
    }

    #[test]
    fn test_label_too_long_rejected() {
        let (env, admin, client) = setup();
        let w = Address::generate(&env);
        let long = String::from_bytes(&env, &[b'a'; 65]);
        assert_eq!(
            client.try_register_watcher(&admin, &w, &Some(long)),
            Err(Ok(ContractError::LabelTooLong))
        );
    }

    #[test]
    fn test_transfer_admin_rejected_with_multiple_admins() {
        let (env, admin, client) = setup();
        let second = Address::generate(&env);
        client.add_admin(&admin, &second);
        assert_eq!(
            client.try_transfer_admin(&admin, &Address::generate(&env)),
            Err(Ok(ContractError::MultipleAdminsExist))
        );
        assert_eq!(client.get_admins().len(), 2);
    }

    #[test]
    fn test_get_admins_after_add() {
        let (env, admin, client) = setup();
        let second = Address::generate(&env);
        client.add_admin(&admin, &second);
        assert_eq!(client.get_admins(), vec![&env, admin, second]);
    }

    // 1. Happy path — register and check authorization
    #[test]
    fn test_register_and_is_watcher_authorized() {
        let (env, admin, client) = setup();
        let watcher = Address::generate(&env);

        assert!(!client.is_watcher_authorized(&watcher));
        assert_eq!(
            client.try_register_watcher(&admin, &watcher, &None).unwrap(),
            Ok(())
        );
        assert!(client.is_watcher_authorized(&watcher));
    }

    #[test]
    #[should_panic]
    fn test_initialize_requires_admin_auth() {
        let env = Env::default();
        let contract_id = env.register(WatcherRegistry, ());
        let client = WatcherRegistryClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
    }

    // 2. Happy path — remove watcher
    #[test]
    fn test_remove_watcher() {
        let (env, admin, client) = setup();
        let watcher = Address::generate(&env);

        client.register_watcher(&admin, &watcher, &None);
        assert_eq!(client.try_remove_watcher(&admin, &watcher).unwrap(), Ok(()));
        assert!(!client.is_watcher_authorized(&watcher));
    }

    // 3. Happy path — transfer admin (replaces entire admin set)
    #[test]
    fn test_transfer_admin() {
        let (env, admin, client) = setup();
        let new_admin = Address::generate(&env);
        let watcher = Address::generate(&env);

        assert_eq!(
            client.try_transfer_admin(&admin, &new_admin).unwrap(),
            Ok(())
        );
        // new admin can register watchers
        assert_eq!(
            client.try_register_watcher(&new_admin, &watcher, &None).unwrap(),
            Ok(())
        );
        assert!(client.is_watcher_authorized(&watcher));
    }

    // 3b. transfer_admin emits an event
    #[test]
    fn test_transfer_admin_emits_event() {
        let (env, admin, client) = setup();
        let new_admin = Address::generate(&env);

        client.transfer_admin(&admin, &new_admin);

        let events = env.events().all();
        // Find the transfer event
        let found = events.iter().any(|e| {
            // topics are (symbol "admin", symbol "transfer")
            // we just verify at least one event was emitted after transfer
            let _ = e;
            true
        });
        assert!(found);
    }

    // 4. Unauthorized register rejected
    #[test]
    fn test_register_unauthorized() {
        let (env, _admin, client) = setup();
        let attacker = Address::generate(&env);
        let watcher = Address::generate(&env);

        assert_eq!(
            client
                .try_register_watcher(&attacker, &watcher, &None)
                .unwrap_err()
                .unwrap(),
            ContractError::Unauthorized
        );
    }

    // 5. Unauthorized remove rejected
    #[test]
    fn test_remove_unauthorized() {
        let (env, admin, client) = setup();
        let attacker = Address::generate(&env);
        let watcher = Address::generate(&env);

        client.register_watcher(&admin, &watcher, &None);
        assert_eq!(
            client
                .try_remove_watcher(&attacker, &watcher)
                .unwrap_err()
                .unwrap(),
            ContractError::Unauthorized
        );
    }

    // 6. Edge case — double initialize returns AlreadyInitialized error
    #[test]
    fn test_double_initialize() {
        let (env, _admin, client) = setup();
        let other = Address::generate(&env);
        let err = client.try_initialize(&other).unwrap_err().unwrap();
        assert_eq!(err, ContractError::AlreadyInitialized);
    }

    // is_initialized reflects first and second initialize
    #[test]
    fn test_is_initialized() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(WatcherRegistry, ());
        let client = WatcherRegistryClient::new(&env, &contract_id);
        assert!(!client.is_initialized());

        let admin = Address::generate(&env);
        client.initialize(&admin);
        assert!(client.is_initialized());

        let other = Address::generate(&env);
        assert_eq!(
            client.try_initialize(&other).unwrap_err().unwrap(),
            ContractError::AlreadyInitialized
        );
        assert!(client.is_initialized());
        assert_eq!(client.get_admins(), vec![&env, admin]);
    }

    // 7. Edge case — get_watchers returns empty before any registration
    #[test]
    fn test_get_watchers_empty() {
        let (_env, _admin, client) = setup();
        assert_eq!(client.get_watchers().len(), 0);
    }

    // 8. Edge case — register same watcher twice is idempotent
    #[test]
    fn test_register_idempotent() {
        let (env, admin, client) = setup();
        let watcher = Address::generate(&env);

        assert_eq!(
            client.try_register_watcher(&admin, &watcher, &None).unwrap(),
            Ok(())
        );
        assert_eq!(
            client.try_register_watcher(&admin, &watcher, &None).unwrap(),
            Ok(())
        );
        assert_eq!(client.get_watchers().len(), 1);
    }

    // 8b. Edge case — repeated calls with the same watcher stay idempotent
    #[test]
    fn test_register_idempotent_after_five_duplicates() {
        let (env, admin, client) = setup();
        let watcher = Address::generate(&env);

        for _ in 0..5 {
            assert_eq!(
                client.try_register_watcher(&admin, &watcher, &None).unwrap(),
                Ok(())
            );
        }
        assert_eq!(client.get_watchers().len(), 1);
    }

    // 9. Multiple watchers
    #[test]
    fn test_multiple_watchers() {
        let (env, admin, client) = setup();
        let w1 = Address::generate(&env);
        let w2 = Address::generate(&env);
        let w3 = Address::generate(&env);

        client.register_watcher(&admin, &w1, &None);
        client.register_watcher(&admin, &w2, &None);
        client.register_watcher(&admin, &w3, &None);

        assert_eq!(client.get_watchers().len(), 3);
        assert!(client.is_watcher_authorized(&w1));
        assert!(client.is_watcher_authorized(&w2));
        assert!(client.is_watcher_authorized(&w3));
    }

    // 9b. Register 3 watchers, remove all 3, verify empty list
    #[test]
    fn test_remove_all_watchers_returns_empty() {
        let (env, admin, client) = setup();
        let w1 = Address::generate(&env);
        let w2 = Address::generate(&env);
        let w3 = Address::generate(&env);

        client.try_register_watcher(&admin, &w1, &None).unwrap();
        client.try_register_watcher(&admin, &w2, &None).unwrap();
        client.try_register_watcher(&admin, &w3, &None).unwrap();
        assert_eq!(client.get_watchers().len(), 3);

        client.try_remove_watcher(&admin, &w1).unwrap();
        client.try_remove_watcher(&admin, &w2).unwrap();
        client.try_remove_watcher(&admin, &w3).unwrap();
        assert_eq!(client.get_watchers().len(), 0);
    }

    // 10. get_admin returns correct admin
    #[test]
    fn test_get_admin() {
        let (_env, admin, client) = setup();
        assert_eq!(client.get_admin(), admin);
    }

    #[test]
    fn test_get_admin_uninitialized() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(WatcherRegistry, ());
        let client = WatcherRegistryClient::new(&env, &contract_id);

        assert_eq!(
            client.try_get_admin().unwrap_err().unwrap(),
            ContractError::NotInitialized
        );
    }

    // 11. get_admin panics with NotInitialized when contract is not initialized
    #[test]
    #[should_panic]
    fn test_get_admin_not_initialized() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(WatcherRegistry, ());
        let client = WatcherRegistryClient::new(&env, &contract_id);
        client.get_admin();
    }

    // 12. clear_all_watchers removes all watchers
    #[test]
    fn test_clear_all_watchers() {
        let (env, admin, client) = setup();
        let w1 = Address::generate(&env);
        let w2 = Address::generate(&env);
        let w3 = Address::generate(&env);

        client.try_register_watcher(&admin, &w1, &None).unwrap();
        client.try_register_watcher(&admin, &w2, &None).unwrap();
        client.try_register_watcher(&admin, &w3, &None).unwrap();
        assert_eq!(client.get_watchers().len(), 3);

        assert_eq!(
            client.try_clear_all_watchers(&admin).unwrap(),
            Ok(())
        );
        assert_eq!(client.get_watchers().len(), 0);
        assert!(!client.is_authorized(&w1));
        assert!(!client.is_authorized(&w2));
        assert!(!client.is_authorized(&w3));
    }

    // 13. clear_all_watchers rejects non-admin
    #[test]
    fn test_clear_all_watchers_unauthorized() {
        let (env, admin, client) = setup();
        let attacker = Address::generate(&env);

        client.try_register_watcher(&admin, &Address::generate(&env), &None).unwrap();

        assert_eq!(
            client
                .try_clear_all_watchers(&attacker)
                .unwrap_err()
                .unwrap(),
            ContractError::Unauthorized
        );
        assert_eq!(client.get_watchers().len(), 1);
    }

    // 14. clear_all_watchers on empty list is a no-op (does not error)
    #[test]
    fn test_clear_all_watchers_empty() {
        let (env, admin, client) = setup();

        assert_eq!(
            client.try_clear_all_watchers(&admin).unwrap(),
            Ok(())
        );
        assert_eq!(client.get_watchers().len(), 0);
    }

    // 15. old admin cannot act after transfer
    #[test]
    fn test_old_admin_rejected_after_transfer() {
        let (env, admin, client) = setup();
        let new_admin = Address::generate(&env);
        let watcher = Address::generate(&env);

        assert_eq!(
            client.try_transfer_admin(&admin, &new_admin).unwrap(),
            Ok(())
        );
        assert_eq!(
            client
                .try_register_watcher(&admin, &watcher, &None)
                .unwrap_err()
                .unwrap(),
            ContractError::Unauthorized
        );
    }

    // ── Multi-admin tests ─────────────────────────────────────────────────────

    // 13. add_admin — second admin can perform privileged operations
    #[test]
    fn test_add_admin_grants_privileges() {
        let (env, admin, client) = setup();
        let second_admin = Address::generate(&env);
        let watcher = Address::generate(&env);

        assert_eq!(client.try_add_admin(&admin, &second_admin).unwrap(), Ok(()));

        // second admin can now register watchers
        assert_eq!(
            client.try_register_watcher(&second_admin, &watcher, &None).unwrap(),
            Ok(())
        );
        assert!(client.is_authorized(&watcher));
    }

    // 14. add_admin is idempotent
    #[test]
    fn test_add_admin_idempotent() {
        let (env, admin, client) = setup();
        let second_admin = Address::generate(&env);

        client.try_add_admin(&admin, &second_admin).unwrap();
        client.try_add_admin(&admin, &second_admin).unwrap();

        assert_eq!(client.get_admins().len(), 2);
    }

    // 15. remove_admin — removed admin loses privileges
    #[test]
    fn test_remove_admin_revokes_privileges() {
        let (env, admin, client) = setup();
        let second_admin = Address::generate(&env);
        let watcher = Address::generate(&env);

        client.try_add_admin(&admin, &second_admin).unwrap();
        assert_eq!(
            client.try_remove_admin(&admin, &second_admin).unwrap(),
            Ok(())
        );

        assert_eq!(
            client
                .try_register_watcher(&second_admin, &watcher, &None)
                .unwrap_err()
                .unwrap(),
            ContractError::Unauthorized
        );
    }

    // 16. remove_admin — cannot remove the last admin
    #[test]
    fn test_remove_last_admin_rejected() {
        let (env, admin, client) = setup();

        assert_eq!(
            client
                .try_remove_admin(&admin, &admin)
                .unwrap_err()
                .unwrap(),
            ContractError::LastAdmin
        );
    }

    // remove_admin — self-removal succeeds when another admin remains
    #[test]
    fn test_admin_self_remove_with_other_admin() {
        use soroban_sdk::IntoVal;
        let (env, admin, client) = setup();
        let second_admin = Address::generate(&env);
        client.add_admin(&admin, &second_admin);

        assert_eq!(client.try_remove_admin(&admin, &admin).unwrap(), Ok(()));
        assert!(!client.is_admin(&admin));
        assert!(client.is_admin(&second_admin));

        let (_, topics, _) = env.events().all().last().unwrap();
        assert_eq!(
            topics,
            (symbol_short!("admin"), Symbol::new(&env, "self_remove")).into_val(&env)
        );
    }

    // 17. get_admins returns all admins
    #[test]
    fn test_get_admins() {
        let (env, admin, client) = setup();
        let second_admin = Address::generate(&env);

        client.try_add_admin(&admin, &second_admin).unwrap();

        let admins = client.get_admins();
        assert_eq!(admins.len(), 2);
    }

    // 18. non-admin cannot add_admin
    #[test]
    fn test_add_admin_unauthorized() {
        let (env, _admin, client) = setup();
        let attacker = Address::generate(&env);
        let victim = Address::generate(&env);

        assert_eq!(
            client
                .try_add_admin(&attacker, &victim)
                .unwrap_err()
                .unwrap(),
            ContractError::Unauthorized
        );
    }

    // 19. non-admin cannot remove_admin
    #[test]
    fn test_remove_admin_unauthorized() {
        let (env, admin, client) = setup();
        let attacker = Address::generate(&env);

        assert_eq!(
            client
                .try_remove_admin(&attacker, &admin)
                .unwrap_err()
                .unwrap(),
            ContractError::Unauthorized
        );
    }

    // 20. add_admin emits event
    #[test]
    fn test_add_admin_emits_event() {
        let (env, admin, client) = setup();
        let second_admin = Address::generate(&env);

        client.add_admin(&admin, &second_admin);

        // At least one event was emitted (the add event)
        assert!(!env.events().all().is_empty());
    }

    // 21. remove_admin emits event
    #[test]
    fn test_remove_admin_emits_event() {
        let (env, admin, client) = setup();
        let second_admin = Address::generate(&env);

        client.add_admin(&admin, &second_admin);
        client.remove_admin(&admin, &second_admin);

        assert!(!env.events().all().is_empty());
    }

    // 22. remove_watcher emits event
    #[test]
    fn test_remove_watcher_emits_event() {
        let (env, admin, client) = setup();
        let watcher = Address::generate(&env);

        client.register_watcher(&admin, &watcher, &None);
        client.remove_watcher(&admin, &watcher);

        assert!(!env.events().all().is_empty());
    }

    // 23. remove_watcher event has the correct topic and data shape
    #[test]
    fn test_remove_watcher_event_shape() {
        let (env, admin, client) = setup();
        let watcher = Address::generate(&env);

        client.register_watcher(&admin, &watcher, &None);
        client.remove_watcher(&admin, &watcher);

        let events = env.events().all();
        // Find an event with exactly 2 topics (watcher.remove shape)
        let remove_event = events.iter().find(|(_, topics, _)| topics.len() == 2);
        assert!(remove_event.is_some(), "expected a watcher.remove event");

        // Verify data is the watcher address
        let (_, _, data) = remove_event.unwrap();
        let emitted_watcher: Address = soroban_sdk::FromVal::from_val(&env, &data);
        assert_eq!(emitted_watcher, watcher);
    }

    // 24. remove_watcher on a non-registered address is a no-op — no event emitted
    #[test]
    fn test_remove_watcher_not_registered_no_event() {
        let (env, admin, client) = setup();
        let stranger = Address::generate(&env);

        // stranger was never registered — remove should succeed silently
        client.remove_watcher(&admin, &stranger);

        // Only the admin.init event from setup() should exist; no watcher.remove
        let events = env.events().all();
        assert_eq!(events.len(), 0, "no watcher.remove event expected for unregistered watcher");
    }

    // 25. get_watcher_count decrements correctly after remove_watcher
    #[test]
    fn test_watcher_count_decrements_on_remove() {
        let (env, admin, client) = setup();
        let w1 = Address::generate(&env);
        let w2 = Address::generate(&env);

        client.register_watcher(&admin, &w1, &None);
        client.register_watcher(&admin, &w2, &None);
        assert_eq!(client.get_watcher_count(), 2);

        client.remove_watcher(&admin, &w1);
        assert_eq!(client.get_watcher_count(), 1);

        client.remove_watcher(&admin, &w2);
        assert_eq!(client.get_watcher_count(), 0);
    }

    // ── replace_watcher tests ─────────────────────────────────────────────────

    // 26. Happy path — replace_watcher swaps old for new
    #[test]
    fn test_replace_watcher_happy_path() {
        let (env, admin, client) = setup();
        let old = Address::generate(&env);
        let new = Address::generate(&env);

        client.register_watcher(&admin, &old, &None);
        assert_eq!(client.try_replace_watcher(&admin, &old, &new).unwrap(), Ok(()));

        assert!(!client.is_authorized(&old));
        assert!(client.is_authorized(&new));
        assert_eq!(client.get_watcher_count(), 1);
    }

    // 27. replace_watcher errors with WatcherNotFound when old is not registered
    #[test]
    fn test_replace_watcher_old_not_found() {
        let (env, admin, client) = setup();
        let old = Address::generate(&env);
        let new = Address::generate(&env);

        assert_eq!(
            client.try_replace_watcher(&admin, &old, &new).unwrap_err().unwrap(),
            ContractError::WatcherNotFound
        );
    }

    // 28. replace_watcher rejects non-admin
    #[test]
    fn test_replace_watcher_unauthorized() {
        let (env, admin, client) = setup();
        let old = Address::generate(&env);
        let new = Address::generate(&env);
        let attacker = Address::generate(&env);

        client.register_watcher(&admin, &old, &None);
        assert_eq!(
            client.try_replace_watcher(&attacker, &old, &new).unwrap_err().unwrap(),
            ContractError::Unauthorized
        );
    }

    // 29. replace_watcher when new_watcher is already registered — old removed, count decrements
    #[test]
    fn test_replace_watcher_new_already_registered() {
        let (env, admin, client) = setup();
        let old = Address::generate(&env);
        let new = Address::generate(&env);

        client.register_watcher(&admin, &old, &None);
        client.register_watcher(&admin, &new, &None);
        assert_eq!(client.get_watcher_count(), 2);

        assert_eq!(client.try_replace_watcher(&admin, &old, &new).unwrap(), Ok(()));

        assert!(!client.is_authorized(&old));
        assert!(client.is_authorized(&new));
        assert_eq!(client.get_watcher_count(), 1);
    }

    // 30. replace_watcher emits watcher.remove and watcher.replace events
    #[test]
    fn test_replace_watcher_emits_events() {
        use soroban_sdk::testutils::Events as _;

        let (env, admin, client) = setup();
        let old = Address::generate(&env);
        let new = Address::generate(&env);

        client.register_watcher(&admin, &old, &None);
        client.replace_watcher(&admin, &old, &new);

        // At least two events emitted (remove + replace)
        assert!(env.events().all().len() >= 2);
    }
    // 31. is_admin returns true for registered admins, false for non-admins, and false when uninitialized
    #[test]
    fn test_is_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(WatcherRegistry, ());
        let client = WatcherRegistryClient::new(&env, &contract_id);

        let admin1 = Address::generate(&env);
        let admin2 = Address::generate(&env);
        let non_admin = Address::generate(&env);

        // Before initialization, is_admin returns false without error
        assert!(!client.is_admin(&admin1));
        assert!(!client.is_admin(&admin2));
        assert!(!client.is_admin(&non_admin));

        // Initialize with admin1
        client.initialize(&admin1);

        // Add admin2 to verify multi-admin set
        client.add_admin(&admin1, &admin2);

        // Verify each admin returns true
        assert!(client.is_admin(&admin1));
        assert!(client.is_admin(&admin2));

        // Verify non-admin returns false
        assert!(!client.is_admin(&non_admin));
    }

    // ── pause / batch / expiry ───────────────────────────────────────────────

    #[test]
    fn test_pause_blocks_mutations_not_reads() {
        let (env, admin, client) = setup();
        let w = Address::generate(&env);
        client.register_watcher(&admin, &w, &None);
        client.set_paused(&admin, &true);
        assert!(client.is_paused());
        let other = Address::generate(&env);
        assert_eq!(
            client.try_register_watcher(&admin, &other, &None),
            Err(Ok(ContractError::ContractPaused))
        );
        assert_eq!(
            client.try_remove_watcher(&admin, &w),
            Err(Ok(ContractError::ContractPaused))
        );
        assert_eq!(
            client.try_clear_all_watchers(&admin),
            Err(Ok(ContractError::ContractPaused))
        );
        assert_eq!(
            client.try_add_admin(&admin, &other),
            Err(Ok(ContractError::ContractPaused))
        );
        assert_eq!(
            client.try_remove_admin(&admin, &other),
            Err(Ok(ContractError::ContractPaused))
        );
        assert!(client.is_authorized(&w));
        assert_eq!(client.get_watcher_count(), 1);
        client.set_paused(&admin, &false);
        client.remove_watcher(&admin, &w);
    }

    #[test]
    fn test_set_paused_requires_admin() {
        let (env, _admin, client) = setup();
        let stranger = Address::generate(&env);
        assert_eq!(
            client.try_set_paused(&stranger, &true),
            Err(Ok(ContractError::Unauthorized))
        );
    }

    #[test]
    fn test_batch_register_happy_path_and_idempotent() {
        let (env, admin, client) = setup();
        let a = Address::generate(&env);
        let b = Address::generate(&env);
        let batch = vec![&env, a.clone(), b.clone(), a.clone()];
        assert_eq!(client.batch_register_watchers(&admin, &batch), 2);
        assert_eq!(client.batch_register_watchers(&admin, &batch), 0);
        assert_eq!(client.get_watcher_count(), 2);
        assert!(client.is_authorized(&a) && client.is_authorized(&b));
    }

    #[test]
    fn test_batch_register_oversized() {
        let (env, admin, client) = setup();
        let mut batch: Vec<Address> = vec![&env];
        for _ in 0..=MAX_BATCH_SIZE {
            batch.push_back(Address::generate(&env));
        }
        assert_eq!(
            client.try_batch_register_watchers(&admin, &batch),
            Err(Ok(ContractError::BatchTooLarge))
        );
    }

    #[test]
    fn test_batch_register_limit_exceeded() {
        let (env, admin, client) = setup();
        let mut stored: Vec<Address> = vec![&env];
        for _ in 0..MAX_WATCHERS {
            stored.push_back(Address::generate(&env));
        }
        env.as_contract(&client.address, || {
            env.storage().instance().set(&DataKey::Watchers, &stored);
        });
        let batch = vec![&env, Address::generate(&env)];
        assert_eq!(
            client.try_batch_register_watchers(&admin, &batch),
            Err(Ok(ContractError::WatcherLimitExceeded))
        );
    }

    #[test]
    fn test_watcher_expiry_and_renewal() {
        use soroban_sdk::testutils::Ledger as _;
        let (env, admin, client) = setup();
        env.ledger().set_timestamp(100);
        let w = Address::generate(&env);
        client.register_watcher(&admin, &w, &Some(200));
        assert!(client.is_authorized(&w));
        env.ledger().set_timestamp(201);
        assert!(!client.is_authorized(&w));
        client.renew_watcher(&admin, &w, &Some(500));
        assert!(client.is_authorized(&w));
        client.renew_watcher(&admin, &w, &None);
        env.ledger().set_timestamp(10_000);
        assert!(client.is_authorized(&w));
        let ghost = Address::generate(&env);
        assert_eq!(
            client.try_renew_watcher(&admin, &ghost, &None),
            Err(Ok(ContractError::WatcherNotFound))
        );
    }
}
