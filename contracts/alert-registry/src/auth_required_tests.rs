//! Mutating functions reject calls without auth (#266).
//!
//! These tests do not call `mock_all_auths`, so every `require_auth` is real. If one of those
//! checks were removed, the matching call below would succeed and the test would fail.

#![cfg(test)]

use soroban_sdk::{testutils::Address as _, vec, Address, Env, String};

use crate::{AlertRegistry, AlertRegistryClient};

fn unauthed() -> (Env, AlertRegistryClient<'static>) {
    let env = Env::default();
    let contract_id = env.register(AlertRegistry, ());
    (env.clone(), AlertRegistryClient::new(&env, &contract_id))
}

fn hash64(env: &Env) -> String {
    String::from_str(env, "a3f1b2c4d5e6f7089abcdef01234567890abcdef01234567890abcdef012345")
}

#[test]
fn register_alert_requires_owner_auth() {
    let (env, client) = unauthed();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let result = client.try_register_alert(
        &owner,
        &target,
        &String::from_str(&env, "alert"),
        &String::from_str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &vec![&env, String::from_str(&env, "rule:transfer")],
        &None,
    );
    assert!(result.is_err());
}

#[test]
fn remove_alert_requires_caller_auth() {
    let (env, client) = unauthed();
    let caller = Address::generate(&env);
    let result = client.try_remove_alert(&caller, &1);
    assert!(result.is_err());
}

#[test]
fn update_alert_requires_caller_auth() {
    let (env, client) = unauthed();
    let caller = Address::generate(&env);
    let result = client.try_update_alert(
        &caller,
        &1,
        &vec![&env, String::from_str(&env, "rule:mint")],
        &true,
    );
    assert!(result.is_err());
}

#[test]
fn set_per_owner_alert_limit_requires_admin_auth() {
    let (env, client) = unauthed();
    let admin = Address::generate(&env);
    client.initialize(&admin);
    let result = client.try_set_per_owner_alert_limit(&admin, &5);
    assert!(result.is_err());
}
