//! Tests for issue #212 — renew_alert_ttl / bump_alert must extend NextId TTL
//!
//! The fix ensures that calling `renew_alert_ttl` (or `bump_alert`) on a live
//! alert also extends the `NextId` counter's TTL so the counter cannot expire
//! independently of the alert data it produced.
//!
//! Failure scenario (pre-fix):
//!   1. Register one alert → NextId = 1.
//!   2. Advance ledgers to DEFAULT_TTL+1 without any new registrations.
//!   3. Call renew_alert_ttl — extends Alert/OwnerIndex/ContractIndex but
//!      leaves NextId with TTL ≈ 0.
//!   4. Advance ledgers past DEFAULT_TTL again.
//!   5. NextId expires.  The next register_alert call reads 0 (unwrap_or default)
//!      and issues ID 0, colliding with the first alert.
//!
//! After the fix step 3 also bumps NextId so the counter stays alive.

#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    vec, Address, Env, String,
};

use crate::{AlertRegistry, AlertRegistryClient, DEFAULT_TTL};

// ── helpers ───────────────────────────────────────────────────────────────────

fn setup() -> (Env, AlertRegistryClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let cid = env.register(AlertRegistry, ());
    (env.clone(), AlertRegistryClient::new(&env, &cid))
}

fn advance(env: &Env, by: u32) {
    env.ledger().with_mut(|l| l.sequence_number += by);
}

fn register_one(
    client: &AlertRegistryClient,
    env: &Env,
    owner: &Address,
    target: &Address,
) -> u64 {
    client.register_alert(
        owner,
        target,
        &String::from_str(env, "alert"),
        &String::from_str(env, "hash"),
        &vec![env, String::from_str(env, "rule:transfer")],
        &None,
    )
}

// ── Test 1: NextId counter survives repeated renew calls without re-registration ──

/// Core acceptance criterion from issue #212.
///
/// After several `renew_alert_ttl` calls — with ledger advances in between —
/// the NextId counter must remain alive (not expire) and subsequent
/// registrations must continue from the correct next value, never producing
/// a collision with an existing alert.
#[test]
fn next_id_survives_repeated_renew_calls_without_re_registration() {
    let (env, client) = setup();

    let owner  = Address::generate(&env);
    let target = Address::generate(&env);

    // Register one alert.  NextId is now 1 (counter == 1, returned id == 0).
    let first_id = register_one(&client, &env, &owner, &target);
    assert_eq!(first_id, 0u64, "first registered alert must have id 0");

    // Simulate a long-running alert that only receives TTL renewals.
    // Advance ledgers and renew several times — each cycle would previously
    // leave NextId with a shrinking TTL.
    for _ in 0..3 {
        advance(&env, DEFAULT_TTL / 2);
        client.renew_alert_ttl(&owner, &first_id);
    }

    // After the loop, the alert data is still alive (TTL was kept up).
    assert!(
        client.get_alert(&first_id).is_some(),
        "alert must still be readable after renew cycles"
    );

    // Now register a second alert.  If NextId had expired and been allowed to
    // reset to its default (0), this would also return id 0 and collide.
    let second_id = register_one(&client, &env, &owner, &target);
    assert_ne!(
        second_id, first_id,
        "second alert must not collide with first — NextId must have survived"
    );
    assert_eq!(second_id, 1u64, "second alert id must be 1 (monotonic counter)");
}

// ── Test 2: bump_alert also extends NextId ─────────────────────────────────────

/// `bump_alert` is the `lib.rs` entry-point that off-chain keepers call.
/// It must also keep NextId alive (issue #212 fix applied to lib.rs).
#[test]
fn bump_alert_extends_next_id_ttl() {
    let (env, client) = setup();

    let owner  = Address::generate(&env);
    let target = Address::generate(&env);

    let id = register_one(&client, &env, &owner, &target);

    // Advance just under DEFAULT_TTL then bump.
    advance(&env, DEFAULT_TTL - 10);
    client.bump_alert(&id, &DEFAULT_TTL);

    // Advance another chunk that would expire an un-bumped NextId.
    advance(&env, DEFAULT_TTL / 2);

    // The second registration must not restart from 0.
    let id2 = register_one(&client, &env, &owner, &target);
    assert_ne!(id2, id, "second id must not collide after bump_alert");
    assert_eq!(id2, 1u64);
}

// ── Test 3: extend_next_id_ttl is a no-op when NextId absent ─────────────────

/// `storage::extend_next_id_ttl` guards against the case where NextId has
/// never been written (first-ever registration hasn't happened yet).  This
/// should be a clean no-op rather than a trap/panic.
#[test]
fn extend_next_id_ttl_is_noop_when_not_yet_written() {
    let (env, _client) = setup();
    // Never register anything — NextId is absent.  Calling the helper must
    // not panic.
    crate::storage::extend_next_id_ttl(&env);
}

// ── Test 4: first registration after renew still issues unique id ─────────────

/// Variant of test 1 using a larger advance to stress-test the TTL.
#[test]
fn first_registration_after_many_renewals_gets_unique_id() {
    let (env, client) = setup();

    let owner  = Address::generate(&env);
    let target = Address::generate(&env);

    // Register two alerts up front.
    let id0 = register_one(&client, &env, &owner, &target);
    let id1 = register_one(&client, &env, &owner, &target);
    assert_eq!(id0, 0u64);
    assert_eq!(id1, 1u64);

    // Renew both alerts many times.
    for _ in 0..5 {
        advance(&env, DEFAULT_TTL / 3);
        client.renew_alert_ttl(&owner, &id0);
        client.renew_alert_ttl(&owner, &id1);
    }

    // A third registration must get id 2, not 0 or 1.
    let id2 = register_one(&client, &env, &owner, &target);
    assert_eq!(id2, 2u64, "third registration must continue from counter = 2");
}
