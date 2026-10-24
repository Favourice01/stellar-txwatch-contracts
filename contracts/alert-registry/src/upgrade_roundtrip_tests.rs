//! Stored alerts round-trip through the storage keys, as a stand-in for an upgrade check (#271).
//!
//! A real upgrade test needs two deployed WASM versions, and this repo has one. Instead this checks
//! that what is written under each key reads back identically, through the same lookups an upgraded
//! contract would use. It does not test a WASM upgrade.

#![cfg(test)]

use soroban_sdk::{testutils::Address as _, vec, Address, Env, String};

use crate::{AlertRegistry, AlertRegistryClient};

#[test]
fn alerts_read_back_identically_through_every_index() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AlertRegistry, ());
    let client = AlertRegistryClient::new(&env, &contract_id);

    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let id = client.register_alert(
        &owner,
        &target,
        &String::from_str(&env, "persist"),
        &String::from_str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &vec![&env, String::from_str(&env, "rule:transfer")],
        &None,
    );

    let by_id = client.get_alert(&id).unwrap();
    let by_owner = client.try_get_alerts_by_owner(&owner, &owner).unwrap().unwrap();
    let by_target = client.try_get_alerts_for_contract(&target, &target).unwrap().unwrap();

    assert_eq!(by_owner.get(0).unwrap(), by_id);
    assert_eq!(by_target.get(0).unwrap(), by_id);
    assert_eq!(by_id.label, String::from_str(&env, "persist"));
}
