//! Unit tests for `WatcherRegistry` admin and watcher operations (#260).

#![cfg(test)]

use soroban_sdk::{testutils::Address as _, Address, Env};

use crate::{ContractError, WatcherRegistry, WatcherRegistryClient};

fn setup() -> (Env, WatcherRegistryClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(WatcherRegistry, ());
    let client = WatcherRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    (env, client, admin)
}

#[test]
fn initialize_sets_the_admin() {
    let (_env, client, admin) = setup();
    assert_eq!(client.get_admins().len(), 1);
    assert_eq!(client.get_admin(), admin);
}

#[test]
fn double_initialize_is_rejected() {
    let (env, client, _admin) = setup();
    let other = Address::generate(&env);
    assert_eq!(client.try_initialize(&other), Err(Ok(ContractError::AlreadyInitialized)));
}

#[test]
fn non_admin_cannot_add_an_admin() {
    let (env, client, _admin) = setup();
    let stranger = Address::generate(&env);
    let new_admin = Address::generate(&env);
    assert_eq!(client.try_add_admin(&stranger, &new_admin), Err(Ok(ContractError::Unauthorized)));
}

#[test]
fn duplicate_add_admin_is_idempotent() {
    let (env, client, admin) = setup();
    let second = Address::generate(&env);
    client.add_admin(&admin, &second);
    client.add_admin(&admin, &second);
    assert_eq!(client.get_admins().len(), 2);
}

#[test]
fn removing_the_last_admin_is_refused() {
    let (_env, client, admin) = setup();
    assert_eq!(client.try_remove_admin(&admin, &admin), Err(Ok(ContractError::LastAdmin)));
}

#[test]
fn transfer_admin_replaces_the_admin_set() {
    let (env, client, admin) = setup();
    let new_admin = Address::generate(&env);
    client.transfer_admin(&admin, &new_admin);
    let admins = client.get_admins();
    assert_eq!(admins.len(), 1);
    assert_eq!(admins.get(0).unwrap(), new_admin);
}

#[test]
fn register_watcher_is_idempotent_and_admin_only() {
    let (env, client, admin) = setup();
    let watcher = Address::generate(&env);
    client.register_watcher(&admin, &watcher, &None);
    client.register_watcher(&admin, &watcher, &None);
    assert_eq!(client.get_watcher_count(), 1);

    let stranger = Address::generate(&env);
    assert_eq!(client.try_register_watcher(&stranger, &watcher, &None), Err(Ok(ContractError::Unauthorized)));
}

#[test]
fn remove_unknown_watcher_returns_not_found() {
    let (env, client, admin) = setup();
    let watcher = Address::generate(&env);
    assert_eq!(client.try_remove_watcher(&admin, &watcher), Err(Ok(ContractError::WatcherNotFound)));
}

#[test]
fn clear_all_watchers_empties_the_list() {
    let (env, client, admin) = setup();
    client.register_watcher(&admin, &Address::generate(&env), &None);
    client.register_watcher(&admin, &Address::generate(&env), &None);
    client.clear_all_watchers(&admin);
    assert_eq!(client.get_watcher_count(), 0);
}

#[test]
fn is_authorized_is_true_only_for_registered_watchers() {
    let (env, client, admin) = setup();
    let watcher = Address::generate(&env);
    let other = Address::generate(&env);
    client.register_watcher(&admin, &watcher, &None);
    assert!(client.is_authorized(&watcher));
    assert!(!client.is_authorized(&other));
}
