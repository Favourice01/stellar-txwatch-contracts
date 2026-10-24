//! Edge-case inputs for `validate_rules` (#263).
//!
//! This is a fixed table of hostile strings, not a randomized fuzz run. It checks that each one is
//! refused with `InvalidRuleDescriptor` and that none of them panics. A property-based fuzzer
//! would extend the table, but would need a new dev-dependency.

#![cfg(test)]

use soroban_sdk::{testutils::Address as _, vec, Address, Env, String};

use crate::{AlertRegistry, AlertRegistryClient, ContractError};

fn setup() -> (Env, AlertRegistryClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AlertRegistry, ());
    (env.clone(), AlertRegistryClient::new(&env, &contract_id))
}

fn hash64(env: &Env) -> String {
    String::from_str(env, "a3f1b2c4d5e6f7089abcdef01234567890abcdef01234567890abcdef012345")
}

#[test]
fn hostile_rule_strings_are_refused_without_panicking() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let long = "rule:".repeat(400);
    let hostile = [
        "",
        "rule:",
        "rule:transfer ",
        " rule:transfer",
        "RULE:TRANSFER",
        "rule:transfer\0",
        "rule:мint",
        "rule:transfer\u{200b}",
        long.as_str(),
    ];

    for raw in hostile {
        let rules = vec![&env, String::from_str(&env, raw)];
        let result = client.try_register_alert(
            &owner,
            &target,
            &String::from_str(&env, "alert"),
            &String::from_str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            &rules,
            &None,
        );
        assert_eq!(result, Err(Ok(ContractError::InvalidRuleDescriptor)), "input {raw:?}");
    }
}

#[test]
fn the_two_valid_rules_are_accepted() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let rules = vec![
        &env,
        String::from_str(&env, "rule:transfer"),
        String::from_str(&env, "rule:mint"),
    ];
    let result = client.try_register_alert(
        &owner,
        &target,
        &String::from_str(&env, "alert"),
        &String::from_str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &rules,
        &None,
    );
    assert!(result.is_ok());
}
