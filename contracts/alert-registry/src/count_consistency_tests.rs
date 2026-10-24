//! `get_alert_count` and `get_active_alert_count` stay consistent across removals (#272).

#![cfg(test)]

use soroban_sdk::{testutils::Address as _, vec, Address, Env, String};

use crate::{AlertRegistry, AlertRegistryClient};

fn setup() -> (Env, AlertRegistryClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AlertRegistry, ());
    (env.clone(), AlertRegistryClient::new(&env, &contract_id))
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
fn counts_follow_registrations_and_removals() {
    let (env, client) = setup();
    let owner = Address::generate(&env);

    let a = register(&env, &client, &owner);
    register(&env, &client, &owner);
    register(&env, &client, &owner);
    assert_eq!(client.get_alert_count(), 3);
    assert_eq!(client.get_active_alert_count(&owner), 3);

    client.remove_alert(&owner, &a);
    assert_eq!(client.get_alert_count(), 3, "the total never goes down");
    assert_eq!(client.get_active_alert_count(&owner), 2);

    register(&env, &client, &owner);
    assert_eq!(client.get_alert_count(), 4);
    assert_eq!(client.get_active_alert_count(&owner), 3);
}

#[test]
fn active_counts_across_two_owners_never_exceed_the_total() {
    let (env, client) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    register(&env, &client, &alice);
    register(&env, &client, &alice);
    register(&env, &client, &bob);

    let total = client.get_alert_count();
    let sum = client.get_active_alert_count(&alice) + client.get_active_alert_count(&bob);
    assert_eq!(total, 3);
    assert!(u64::from(sum) <= total);
}
