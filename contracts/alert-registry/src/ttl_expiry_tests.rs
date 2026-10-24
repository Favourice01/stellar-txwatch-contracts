//! Expiry behaviour once an alert's TTL has run out (#264).
//!
//! The test advances the ledger past `DEFAULT_TTL` without any write or bump. An alert whose
//! entry is archived must read as absent, and must not count as live.

#![cfg(test)]

use soroban_sdk::{testutils::{Address as _, Ledger as _}, vec, Address, Env, String};

use crate::{AlertRegistry, AlertRegistryClient, DEFAULT_TTL};

fn setup() -> (Env, AlertRegistryClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AlertRegistry, ());
    (env.clone(), AlertRegistryClient::new(&env, &contract_id))
}

fn advance_ledgers(env: &Env, by: u32) {
    env.ledger().with_mut(|l| l.sequence_number += by);
}

#[test]
fn expired_alert_reads_as_none() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let id = client.register_alert(
        &owner,
        &target,
        &String::from_str(&env, "alert"),
        &String::from_str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &vec![&env, String::from_str(&env, "rule:transfer")],
        &None,
    );
    assert!(client.get_alert(&id).is_some());

    advance_ledgers(&env, DEFAULT_TTL + 1);

    assert!(client.get_alert(&id).is_none());
}

#[test]
fn expired_alert_is_not_counted_as_active() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    client.register_alert(
        &owner,
        &target,
        &String::from_str(&env, "alert"),
        &String::from_str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &vec![&env, String::from_str(&env, "rule:transfer")],
        &None,
    );

    advance_ledgers(&env, DEFAULT_TTL + 1);

    assert_eq!(client.get_active_alert_count(&owner), 0);
}
