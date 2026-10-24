use alert_registry::{AlertRegistry, AlertRegistryClient, ContractError as AlertError};
use soroban_sdk::{testutils::Address as _, vec, Address, Env, String};
use watcher_registry::{WatcherRegistry, WatcherRegistryClient};

// Re-export setup_both as setup so all tests below compile unchanged.
use test_utils::setup_both as setup;
use test_utils::str;

// `setup_both` returns (env, alert_client, watcher_client) — same shape as the
// old local `setup()` function, so all tests below compile unchanged.

/// An authorized watcher can query AlertRegistry and see registered alerts
/// when no watcher-gating is configured (open access mode).
#[test]
fn test_authorized_watcher_can_query_alert_registry_open_mode() {
    let (env, alert_client, watcher_client) = setup();

    let admin = Address::generate(&env);
    let watcher = Address::generate(&env);
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    // Initialize watcher registry and authorize the watcher
    watcher_client.initialize(&admin);
    watcher_client.register_watcher(&admin, &watcher, &None);

    // Register an alert in the alert registry
    let id = alert_client.register_alert(
        &owner,
        &target,
        &str(&env, "Cross-contract alert"),
        &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &vec![&env, str(&env, "rule:transfer")], &None,
    );

    // Verify the watcher is authorized in the watcher registry
    assert!(watcher_client.is_watcher_authorized(&watcher));

    // No gating configured — watcher queries the alert registry freely
    let alerts = alert_client
        .get_alerts_for_contract(&watcher, &target)
        .unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(
        alerts.get(0).unwrap().label,
        str(&env, "Cross-contract alert")
    );

    let cfg = alert_client.get_alert(&id).unwrap();
    assert_eq!(cfg.owner, owner);
    assert_eq!(cfg.target_contract, target);
    assert!(cfg.active);
}

/// An unauthorized address is not a watcher and cannot be confused with one.
#[test]
fn test_unauthorized_address_not_a_watcher() {
    let (env, _alert_client, watcher_client) = setup();

    let admin = Address::generate(&env);
    let stranger = Address::generate(&env);

    watcher_client.initialize(&admin);

    assert!(!watcher_client.is_watcher_authorized(&stranger));
}

/// Removing a watcher revokes their authorization while alert data is unaffected.
#[test]
fn test_removed_watcher_loses_authorization_alert_data_intact() {
    let (env, alert_client, watcher_client) = setup();

    let admin = Address::generate(&env);
    let watcher = Address::generate(&env);
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    watcher_client.initialize(&admin);
    watcher_client.register_watcher(&admin, &watcher, &None);

    alert_client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &vec![&env, String::from_str(&env, "rule:transfer")], &None,
    );

    // Remove the watcher
    watcher_client.remove_watcher(&admin, &watcher);
    assert!(!watcher_client.is_watcher_authorized(&watcher));

    // Alert data is still intact (no gating configured)
    assert_eq!(
        alert_client
            .get_alerts_for_contract(&watcher, &target)
            .unwrap()
            .len(),
        1
    );
}

/// When watcher-gating is enabled, a registered watcher can read alert data.
#[test]
fn test_watcher_gating_registered_watcher_can_read() {
    let (env, alert_client, watcher_client) = setup();

    let admin = Address::generate(&env);
    let watcher = Address::generate(&env);
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    // Set up watcher registry
    watcher_client.initialize(&admin);
    watcher_client.register_watcher(&admin, &watcher, &None);

    // Initialize alert registry and point it at the watcher registry
    alert_client.initialize(&admin).unwrap();
    let watcher_contract_id = watcher_client.address.clone();
    alert_client
        .set_watcher_registry(&admin, &watcher_contract_id)
        .unwrap();

    alert_client.register_alert(
        &owner,
        &target,
        &String::from_str(&env, "Gated Alert"),
        &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &vec![&env, String::from_str(&env, "rule:transfer")], &None,
    );

    // Registered watcher can read
    let results = alert_client
        .get_alerts_for_contract(&watcher, &target)
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(
        results.get(0).unwrap().label,
        String::from_str(&env, "Gated Alert")
    );
}

/// When watcher-gating is enabled, an unregistered address is rejected.
#[test]
fn test_watcher_gating_unregistered_address_rejected() {
    let (env, alert_client, watcher_client) = setup();

    let admin = Address::generate(&env);
    let stranger = Address::generate(&env);
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    watcher_client.initialize(&admin);
    // stranger is NOT registered as a watcher

    alert_client.initialize(&admin).unwrap();
    let watcher_contract_id = watcher_client.address.clone();
    alert_client
        .set_watcher_registry(&admin, &watcher_contract_id)
        .unwrap();

    alert_client.register_alert(
        &owner,
        &target,
        &String::from_str(&env, "Alert"),
        &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &vec![&env, String::from_str(&env, "rule:transfer")], &None,
    );

    assert_eq!(
        alert_client
            .try_get_alerts_for_contract(&stranger, &target)
            .unwrap_err()
            .unwrap(),
        AlertError::NotAWatcher
    );
}

/// When watcher-gating is enabled, a removed watcher loses read access.
#[test]
fn test_watcher_gating_removed_watcher_loses_access() {
    let (env, alert_client, watcher_client) = setup();

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
        &String::from_str(&env, "Alert"),
        &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &vec![&env, String::from_str(&env, "rule:transfer")], &None,
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
        AlertError::NotAWatcher
    );
}

/// Watcher-gating also applies to get_alerts_by_owner.
#[test]
fn test_watcher_gating_get_alerts_by_owner() {
    let (env, alert_client, watcher_client) = setup();

    let admin = Address::generate(&env);
    let watcher = Address::generate(&env);
    let stranger = Address::generate(&env);
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
        &String::from_str(&env, "Alert"),
        &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &vec![&env, String::from_str(&env, "rule:transfer")], &None,
    );

    // Registered watcher can query by owner
    assert_eq!(
        alert_client
            .get_alerts_by_owner(&watcher, &owner)
            .unwrap()
            .len(),
        1
    );

    // Stranger is rejected
    assert_eq!(
        alert_client
            .try_get_alerts_by_owner(&stranger, &owner)
            .unwrap_err()
            .unwrap(),
        AlertError::NotAWatcher
    );
}

// ── Feature A: watcher.remove event ──────────────────────────────────────────

/// Removing a watcher emits a `("watcher", "remove")` event with the correct
/// address as data.  Dependent systems must subscribe to this event to revoke
/// trust immediately.
#[test]
fn test_remove_watcher_emits_event_with_correct_address() {
    use soroban_sdk::{symbol_short, testutils::Events as _};

    let (env, _alert_client, watcher_client) = setup();

    let admin = Address::generate(&env);
    let watcher = Address::generate(&env);

    watcher_client.initialize(&admin);
    watcher_client.register_watcher(&admin, &watcher, &None).unwrap();
    watcher_client.remove_watcher(&admin, &watcher).unwrap();

    let events = env.events().all();
    let remove_event = events
        .iter()
        .find(|(_, topics, _)| {
            topics.len() == 2
                && topics.get(0).unwrap() == symbol_short!("watcher").into()
                && topics.get(1).unwrap() == symbol_short!("remove").into()
        })
        .expect("watcher.remove event must be emitted");

    let (_, _, data) = remove_event;
    let emitted: Address = soroban_sdk::FromVal::from_val(&env, &data);
    assert_eq!(emitted, watcher, "event data must carry the deauthorized watcher address");
}

/// After a watcher is removed, the `watcher.remove` event is emitted AND the
/// watcher immediately loses access to gated alert queries.
#[test]
fn test_remove_watcher_event_and_immediate_access_revocation() {
    use soroban_sdk::{symbol_short, testutils::Events as _};

    let (env, alert_client, watcher_client) = setup();

    let admin = Address::generate(&env);
    let watcher = Address::generate(&env);
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    watcher_client.initialize(&admin);
    watcher_client.register_watcher(&admin, &watcher, &None).unwrap();

    alert_client.initialize(&admin).unwrap();
    let watcher_contract_id = watcher_client.address.clone();
    alert_client
        .set_watcher_registry(&admin, &watcher_contract_id)
        .unwrap();

    alert_client.register_alert(
        &owner,
        &target,
        &String::from_str(&env, "Alert"),
        &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &vec![&env, String::from_str(&env, "rule:transfer")], &None,
    );

    // Watcher can read before removal
    assert_eq!(
        alert_client
            .get_alerts_for_contract(&watcher, &target)
            .unwrap()
            .len(),
        1
    );

    // Remove the watcher — this must emit the event
    watcher_client.remove_watcher(&admin, &watcher).unwrap();

    // Verify the event was emitted
    let events = env.events().all();
    let has_remove_event = events.iter().any(|(_, topics, _)| {
        topics.len() == 2
            && topics.get(0).unwrap() == symbol_short!("watcher").into()
            && topics.get(1).unwrap() == symbol_short!("remove").into()
    });
    assert!(has_remove_event, "watcher.remove event must be emitted on deauthorization");

    // Access is revoked immediately — no delay, no cache
    assert_eq!(
        alert_client
            .try_get_alerts_for_contract(&watcher, &target)
            .unwrap_err()
            .unwrap(),
        AlertError::NotAWatcher
    );
}

// ── Feature B: bump_alert cross-contract ─────────────────────────────────────

/// bump_alert can be called by any address (no auth required) and keeps the
/// alert alive without modifying its content.
#[test]
fn test_bump_alert_by_third_party() {
    let (env, alert_client, _watcher_client) = setup();

    let owner = Address::generate(&env);
    let keeper = Address::generate(&env); // third-party keeper service
    let target = Address::generate(&env);

    let id = alert_client.register_alert(
        &owner,
        &target,
        &String::from_str(&env, "Long-lived Alert"),
        &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &vec![&env, String::from_str(&env, "rule:transfer")], &None,
    );

    let before = alert_client.get_alert(&id).unwrap();

    // A third-party keeper bumps the TTL — no auth needed
    let _ = keeper; // keeper address not used for auth, just illustrative
    alert_client.bump_alert(&id, &535_680u32).unwrap();

    let after = alert_client.get_alert(&id).unwrap();

    // Content must be unchanged
    assert_eq!(after.label, before.label);
    assert_eq!(after.webhook_hash, before.webhook_hash);
    assert_eq!(after.updated_at, before.updated_at);
}
