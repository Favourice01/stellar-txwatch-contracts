//! Tests for `batch_register_alerts`, `pause_alert` / `unpause_alert` and
//! `get_active_alerts_paginated` (#215, #216, #217).

use crate::{
    AlertInput, AlertRegistry, AlertRegistryClient, ContractError, MAX_BATCH_SIZE,
};
use soroban_sdk::{testutils::Address as _, vec, Address, Env, String};

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

fn hash64(env: &Env) -> String {
    String::from_str(env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
}

fn input(env: &Env, target: &Address, label: &str) -> AlertInput {
    AlertInput {
        target_contract: target.clone(),
        label: str(env, label),
        webhook_hash: hash64(env),
        rules: vec![env, str(env, "rule:transfer")],
    }
}

#[test]
fn test_batch_register_alerts_happy_path() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let inputs = vec![&env, input(&env, &target, "a"), input(&env, &target, "b")];
    let ids = client.batch_register_alerts(&owner, &inputs);
    assert_eq!(ids.len(), 2);
    assert_eq!(client.get_alert(&ids.get(1).unwrap()).unwrap().label, str(&env, "b"));
    assert_eq!(client.get_active_alerts_for_contract(&target).len(), 2);
}

#[test]
fn test_batch_register_alerts_oversized() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let mut inputs = vec![&env];
    for _ in 0..=MAX_BATCH_SIZE {
        inputs.push_back(input(&env, &target, "x"));
    }
    assert_eq!(
        client.try_batch_register_alerts(&owner, &inputs).unwrap_err().unwrap(),
        ContractError::BatchTooLarge
    );
}

#[test]
fn test_batch_register_alerts_limit_exceeded_is_atomic() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    client.initialize(&admin);
    client.set_per_owner_alert_limit(&admin, &2);
    let inputs = vec![
        &env,
        input(&env, &target, "a"),
        input(&env, &target, "b"),
        input(&env, &target, "c"),
    ];
    assert_eq!(
        client.try_batch_register_alerts(&owner, &inputs).unwrap_err().unwrap(),
        ContractError::OwnerAlertLimitExceeded
    );
    assert_eq!(client.get_active_alerts_for_contract(&target).len(), 0);
}

#[test]
fn test_pause_unpause_alert_admin() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    client.initialize(&admin);
    let id = client.register_alert(
        &owner, &target, &str(&env, "a"), &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")], &None,
    );
    client.pause_alert(&admin, &id);
    assert!(!client.get_alert(&id).unwrap().active);
    client.unpause_alert(&admin, &id);
    assert!(client.get_alert(&id).unwrap().active);
}

#[test]
fn test_pause_alert_non_admin_rejected() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    client.initialize(&admin);
    let id = client.register_alert(
        &owner, &target, &str(&env, "a"), &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")], &None,
    );
    assert_eq!(
        client.try_pause_alert(&owner, &id).unwrap_err().unwrap(),
        ContractError::Unauthorized
    );
}

#[test]
fn test_get_active_alerts_paginated() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let mut ids = vec![&env];
    for _ in 0..3 {
        ids.push_back(client.register_alert(
            &owner, &target, &str(&env, "a"), &hash64(&env),
            &vec![&env, str(&env, "rule:transfer")], &None,
        ));
    }
    client.update_alert(&owner, &ids.get(0).unwrap(), &vec![&env, str(&env, "rule:transfer")], &false);
    assert_eq!(client.get_active_alerts_paginated(&target, &0, &10).len(), 2);
    assert_eq!(client.get_active_alerts_paginated(&target, &1, &10).len(), 1);
}

