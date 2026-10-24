//! Cross-contract watcher gating between `AlertRegistry` and `WatcherRegistry` (#262).
//!
//! Mirrors the gating path in `assert_watcher_if_configured`. The issue names the error
//! `WatcherNotAuthorized`, but the compiled contract returns `NotAWatcher`, so that name is used.

#![cfg(all(test, feature = "testutils"))]

use soroban_sdk::{testutils::Address as _, vec, Address, Env, String};
use watcher_registry::WatcherRegistry;

use crate::{AlertRegistry, AlertRegistryClient, ContractError};

fn hash64(env: &Env) -> String {
    String::from_str(env, "a3f1b2c4d5e6f7089abcdef01234567890abcdef01234567890abcdef012345")
}

fn setup() -> (Env, AlertRegistryClient<'static>, watcher_registry::WatcherRegistryClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let alert_id = env.register(AlertRegistry, ());
    let watcher_id = env.register(WatcherRegistry, ());
    let alert = AlertRegistryClient::new(&env, &alert_id);
    let watcher = watcher_registry::WatcherRegistryClient::new(&env, &watcher_id);

    let admin = Address::generate(&env);
    alert.initialize(&admin);
    watcher.initialize(&admin);

    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    alert.register_alert(
        &owner,
        &target,
        &String::from_str(&env, "alert"),
        &String::from_str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &vec![&env, String::from_str(&env, "rule:transfer")],
        &None,
    );
    (env, alert, watcher, admin)
}

#[test]
fn gate_not_set_lets_any_address_read() {
    let (env, alert, _watcher, _admin) = setup();
    let stranger = Address::generate(&env);
    let target = Address::generate(&env);
    let result = alert.try_get_alerts_for_contract(&stranger, &target);
    assert!(result.is_ok());
}

#[test]
fn gate_set_and_registered_watcher_can_read() {
    let (env, alert, watcher, admin) = setup();
    let watcher_addr = Address::generate(&env);
    watcher.register_watcher(&admin, &watcher_addr, &None);
    alert.set_watcher_registry(&admin, &watcher.address);

    let target = Address::generate(&env);
    let result = alert.try_get_alerts_for_contract(&watcher_addr, &target);
    assert!(result.is_ok());
}

#[test]
fn gate_set_and_unregistered_caller_is_refused() {
    let (env, alert, watcher, admin) = setup();
    alert.set_watcher_registry(&admin, &watcher.address);

    let stranger = Address::generate(&env);
    let target = Address::generate(&env);
    let result = alert.try_get_alerts_for_contract(&stranger, &target);
    assert_eq!(result, Err(Ok(ContractError::NotAWatcher)));
}

#[test]
fn removing_a_watcher_mid_test_revokes_read_access() {
    let (env, alert, watcher, admin) = setup();
    let watcher_addr = Address::generate(&env);
    watcher.register_watcher(&admin, &watcher_addr, &None);
    alert.set_watcher_registry(&admin, &watcher.address);

    let target = Address::generate(&env);
    assert!(alert.try_get_alerts_for_contract(&watcher_addr, &target).is_ok());

    watcher.remove_watcher(&admin, &watcher_addr);
    let result = alert.try_get_alerts_for_contract(&watcher_addr, &target);
    assert_eq!(result, Err(Ok(ContractError::NotAWatcher)));
}
