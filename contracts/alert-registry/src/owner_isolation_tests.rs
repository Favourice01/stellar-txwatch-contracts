//! Owners cannot see or change each other's alerts (#269).

#![cfg(test)]

use soroban_sdk::{testutils::Address as _, vec, Address, Env, String};

use crate::{AlertRegistry, AlertRegistryClient, ContractError};

fn setup() -> (Env, AlertRegistryClient<'static>, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AlertRegistry, ());
    let client = AlertRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    let owner_a = Address::generate(&env);
    let owner_b = Address::generate(&env);
    (env, client, admin, owner_a, owner_b)
}

fn register(env: &Env, client: &AlertRegistryClient<'static>, owner: &Address) -> u64 {
    let target = Address::generate(env);
    client.register_alert(
        owner,
        &target,
        &String::from_str(env, "alert"),
        &String::from_str(env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &vec![env, String::from_str(env, "rule:transfer")],
        &None,
    )
}

#[test]
fn cross_owner_remove_is_refused() {
    let (env, client, _admin, owner_a, owner_b) = setup();
    let id = register(&env, &client, &owner_a);
    assert_eq!(client.try_remove_alert(&owner_b, &id), Err(Ok(ContractError::Unauthorized)));
}

#[test]
fn cross_owner_update_is_refused() {
    let (env, client, _admin, owner_a, owner_b) = setup();
    let id = register(&env, &client, &owner_a);
    let result = client.try_update_alert(&owner_b, &id, &vec![&env, String::from_str(&env, "rule:mint")], &true);
    assert_eq!(result, Err(Ok(ContractError::Unauthorized)));
}

#[test]
fn cross_owner_target_change_is_refused() {
    let (env, client, _admin, owner_a, owner_b) = setup();
    let id = register(&env, &client, &owner_a);
    let new_target = Address::generate(&env);
    let result = client.try_update_target_contract(&owner_b, &id, &new_target);
    assert_eq!(result, Err(Ok(ContractError::Unauthorized)));
}

#[test]
fn owner_index_lists_only_that_owners_alerts() {
    let (env, client, _admin, owner_a, owner_b) = setup();
    register(&env, &client, &owner_a);
    register(&env, &client, &owner_b);

    let a_alerts = client.try_get_alerts_by_owner(&owner_a, &owner_a).unwrap().unwrap();
    assert_eq!(a_alerts.len(), 1);
    assert_eq!(a_alerts.get(0).unwrap().owner, owner_a);
}

#[test]
fn admin_can_remove_any_owners_alert() {
    let (env, client, admin, owner_a, _owner_b) = setup();
    let id = register(&env, &client, &owner_a);
    client.remove_alert_by_admin(&admin, &id);
    assert!(client.get_alert(&id).is_none());
}
