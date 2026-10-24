//! Asserts the topics of the events the compiled `AlertRegistry` emits (#267).
//!
//! If a topic is renamed, these tests fail, so off-chain indexers see the break in CI rather than
//! in production. Only events present in the compiled `lib.rs` are covered.

#![cfg(test)]

use soroban_sdk::{testutils::{Address as _, Events as _}, vec, Address, Env, String, Symbol, TryFromVal};

use crate::{AlertRegistry, AlertRegistryClient};

/// True when some emitted event has exactly the two topics `(a, b)`.
fn emitted(env: &Env, a: &str, b: &str) -> bool {
    let want_a = Symbol::new(env, a);
    let want_b = Symbol::new(env, b);
    env.events().all().iter().any(|(_contract, topics, _data)| {
        topics.len() == 2
            && Symbol::try_from_val(env, &topics.get(0).unwrap()).ok() == Some(want_a.clone())
            && Symbol::try_from_val(env, &topics.get(1).unwrap()).ok() == Some(want_b.clone())
    })
}

fn setup() -> (Env, AlertRegistryClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AlertRegistry, ());
    let client = AlertRegistryClient::new(&env, &contract_id);
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    (env, client, owner, target)
}

fn hash64(env: &Env) -> String {
    String::from_str(env, "a3f1b2c4d5e6f7089abcdef01234567890abcdef01234567890abcdef012345")
}

#[test]
fn register_emits_alert_register() {
    let (env, client, owner, target) = setup();
    client.register_alert(
        &owner,
        &target,
        &String::from_str(&env, "alert"),
        &String::from_str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &vec![&env, String::from_str(&env, "rule:transfer")],
        &None,
    );
    assert!(emitted(&env, "alert", "register"));
}

#[test]
fn remove_emits_alert_remove() {
    let (env, client, owner, target) = setup();
    let id = client.register_alert(
        &owner,
        &target,
        &String::from_str(&env, "alert"),
        &String::from_str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &vec![&env, String::from_str(&env, "rule:transfer")],
        &None,
    );
    client.remove_alert(&owner, &id);
    assert!(emitted(&env, "alert", "remove"));
}

#[test]
fn bump_emits_alert_bump() {
    let (env, client, owner, target) = setup();
    let id = client.register_alert(
        &owner,
        &target,
        &String::from_str(&env, "alert"),
        &String::from_str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &vec![&env, String::from_str(&env, "rule:transfer")],
        &None,
    );
    client.bump_alert(&id, &1_000);
    assert!(emitted(&env, "alert", "bump"));
}

#[test]
fn propose_webhook_emits_alert_wh_prop() {
    let (env, client, owner, target) = setup();
    let id = client.register_alert(
        &owner,
        &target,
        &String::from_str(&env, "alert"),
        &String::from_str(&env, "hash"),
        &vec![&env, String::from_str(&env, "rule:transfer")],
        &None,
    );
    client.propose_webhook(&owner, &id, &String::from_str(&env, "new-hash")).unwrap();
    assert!(emitted(&env, "alert", "wh_prop"), "propose_webhook must emit (alert, wh_prop)");
}

// #204 — confirm_webhook must emit ("alert", "webhook"), not ("alert", "wh_conf").
#[test]
fn confirm_webhook_emits_alert_webhook() {
    let (env, client, owner, target) = setup();
    let id = client.register_alert(
        &owner,
        &target,
        &String::from_str(&env, "alert"),
        &String::from_str(&env, "hash"),
        &vec![&env, String::from_str(&env, "rule:transfer")],
        &None,
    );
    client.propose_webhook(&owner, &id, &String::from_str(&env, "new-hash")).unwrap();
    client.confirm_webhook(&owner, &id).unwrap();
    assert!(emitted(&env, "alert", "webhook"), "#204: confirm_webhook must emit (alert, webhook)");
    // Confirm the old non-standard event is NOT emitted.
    assert!(!emitted(&env, "alert", "wh_conf"), "#204: wh_conf must NOT be emitted by confirm_webhook");
}
