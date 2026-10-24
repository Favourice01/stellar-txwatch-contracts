//! One test per `ContractError` variant that the compiled `AlertRegistry` can return (#259).
//!
//! `DuplicateAlertId` is not covered: duplicate IDs cannot be produced through the public API.

#![cfg(test)]

use soroban_sdk::{testutils::Address as _, vec, Address, Env, String};

use crate::{AlertRegistry, AlertRegistryClient, ContractError};

fn setup() -> (Env, AlertRegistryClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AlertRegistry, ());
    let client = AlertRegistryClient::new(&env, &contract_id);
    (env, client)
}

fn s(env: &Env, text: &str) -> String {
    String::from_str(env, text)
}

fn hash64(env: &Env) -> String {
    String::from_str(env, "a3f1b2c4d5e6f7089abcdef01234567890abcdef01234567890abcdef012345")
}

#[test]
fn already_initialized_on_second_initialize() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    client.initialize(&admin);
    let again = client.try_initialize(&admin);
    assert_eq!(again, Err(Ok(ContractError::AlreadyInitialized)));
}

#[test]
fn not_initialized_before_initialize() {
    let (_env, client) = setup();
    let result = client.try_get_admin();
    assert_eq!(result, Err(Ok(ContractError::NotInitialized)));
}

#[test]
fn unauthorized_when_a_stranger_removes_an_alert() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let stranger = Address::generate(&env);
    let target = Address::generate(&env);
    let id = client.register_alert(
        &owner,
        &target,
        &s(&env, "alert"),
        &hash64(&env),
        &vec![&env, s(&env, "rule:transfer")],
        &None,
    );
    let result = client.try_remove_alert(&stranger, &id);
    assert_eq!(result, Err(Ok(ContractError::Unauthorized)));
}

#[test]
fn alert_not_found_when_bumping_a_missing_id() {
    let (_env, client) = setup();
    let result = client.try_bump_alert(&999, &1_000);
    assert_eq!(result, Err(Ok(ContractError::AlertNotFound)));
}

#[test]
fn invalid_rule_descriptor_for_an_unknown_rule() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let result = client.try_register_alert(
        &owner,
        &target,
        &s(&env, "alert"),
        &hash64(&env),
        &vec![&env, s(&env, "rule:bogus")],
        &None,
    );
    assert_eq!(result, Err(Ok(ContractError::InvalidRuleDescriptor)));
}

#[test]
fn owner_alert_limit_exceeded_on_the_second_registration() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    client.initialize(&admin);
    client.set_per_owner_alert_limit(&admin, &1);

    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let rules = vec![&env, s(&env, "rule:transfer")];
    client.register_alert(&owner, &target, &s(&env, "first"), &hash64(&env), &rules, &None);

    let result = client.try_register_alert(&owner, &target, &s(&env, "second"), &hash64(&env), &rules, &None);
    assert_eq!(result, Err(Ok(ContractError::OwnerAlertLimitExceeded)));
}

/// #206 — empty rules vec is rejected.
#[test]
fn empty_rules_returns_empty_rules_error() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let result = client.try_register_alert(
        &owner,
        &target,
        &s(&env, "alert"),
        &hash64(&env),
        &vec![&env],
        &None,
    );
    assert_eq!(result, Err(Ok(ContractError::EmptyRules)));
}

/// #207 — duplicate rule descriptors are rejected.
#[test]
fn duplicate_rule_returns_duplicate_rule_error() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let result = client.try_register_alert(
        &owner,
        &target,
        &s(&env, "alert"),
        &hash64(&env),
        &vec![&env, s(&env, "rule:transfer"), s(&env, "rule:transfer")],
        &None,
    );
    assert_eq!(result, Err(Ok(ContractError::DuplicateRule)));
}

/// #208 — webhook_hash shorter than 64 chars is rejected.
#[test]
fn invalid_webhook_hash_too_short() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let result = client.try_register_alert(
        &owner,
        &target,
        &s(&env, "alert"),
        &s(&env, "tooshort"),
        &vec![&env, s(&env, "rule:transfer")],
        &None,
    );
    assert_eq!(result, Err(Ok(ContractError::InvalidWebhookHash)));
}

/// #208 — webhook_hash longer than 64 chars is rejected.
#[test]
fn invalid_webhook_hash_too_long() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    // 65 chars
    let long_hash = s(&env, "a3f1b2c4d5e6f7089abcdef01234567890abcdef01234567890abcdef0123456");
    let result = client.try_register_alert(
        &owner,
        &target,
        &s(&env, "alert"),
        &long_hash,
        &vec![&env, s(&env, "rule:transfer")],
        &None,
    );
    assert_eq!(result, Err(Ok(ContractError::InvalidWebhookHash)));
}

/// #208 — update_webhook with short hash is rejected.
#[test]
fn update_webhook_rejects_invalid_hash() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let id = client.register_alert(
        &owner,
        &target,
        &s(&env, "alert"),
        &hash64(&env),
        &vec![&env, s(&env, "rule:transfer")],
        &None,
    );
    let result = client.try_update_webhook(&owner, &id, &s(&env, "not-64-chars"));
    assert_eq!(result, Err(Ok(ContractError::InvalidWebhookHash)));
}
