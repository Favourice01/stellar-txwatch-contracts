use crate::AlertRegistry;
use crate::ContractError;
use crate::AlertRegistryClient;
use soroban_sdk::{testutils::Address as _, vec, Address, Env, String, Vec};

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

/// Return a valid 64-character hex webhook hash for use in tests (#208).
fn hash64(env: &Env) -> String {
    String::from_str(env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
}

/// Build a Soroban String of `n` repetitions of ASCII char `ch`.
fn str_repeat(env: &Env, ch: char, n: usize) -> String {
    assert!(n <= 8192, "str_repeat: n exceeds Soroban String max");
    let byte = ch as u8;
    let mut buf = [0u8; 8192];
    for b in buf.iter_mut().take(n) {
        *b = byte;
    }
    let s = core::str::from_utf8(&buf[..n]).unwrap();
    String::from_str(env, s)
}

// 1. Happy path — register and retrieve
#[test]
fn test_register_and_get_alert() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "My Alert"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );

    let cfg = client.get_alert(&id).unwrap();
    assert_eq!(cfg.label, str(&env, "My Alert"));
    assert_eq!(cfg.owner, owner);
    assert!(cfg.active);
}

// 2. Happy path — update alert
#[test]
fn test_update_alert() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );

    assert_eq!(
        client
            .try_update_alert(&owner, &id, &vec![&env, str(&env, "rule:mint")], &false)
            .unwrap(),
        Ok(())
    );

    let cfg = client.get_alert(&id).unwrap();
    assert!(!cfg.active);
    assert_eq!(cfg.rules.get(0).unwrap(), str(&env, "rule:mint"));
}

// 3. Happy path — remove alert
#[test]
fn test_remove_alert() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );

    assert_eq!(client.try_remove_alert(&owner, &id).unwrap(), Ok(()));
    assert!(client.get_alert(&id).is_none());
}

// 4. Unauthorized update rejected
#[test]
fn test_update_unauthorized() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let attacker = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );

    assert_eq!(
        client
            .try_update_alert(&attacker, &id, &vec![&env, str(&env, "rule:transfer")], &false)
            .unwrap_err()
            .unwrap(),
        ContractError::Unauthorized
    );
}

#[test]
#[should_panic(expected = "invalid rule descriptor")]
fn test_register_alert_rejects_invalid_rules() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:unknown")],
        &None,
    );
}

#[test]
#[should_panic(expected = "invalid rule descriptor")]
fn test_update_alert_rejects_invalid_rules() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );

    client.update_alert(&owner, &id, &vec![&env, str(&env, "rule:bogus")], &true);
}

#[test]
fn test_admin_remove_any_alert() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:mint")],
        &None,
    );

    assert_eq!(client.remove_alert_by_admin(&admin, &id), ());
    assert!(client.get_alert(&id).is_none());
}

#[test]
#[should_panic(expected = "owner alert limit exceeded")]
fn test_admin_set_per_owner_alert_limit() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    client.initialize(&admin);
    client.set_per_owner_alert_limit(&admin, &1u32);

    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert1"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );
    client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert2"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:mint")],
        &None,
    );
}

#[test]
fn test_admin_transfer_admin() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    client.initialize(&admin);
    let new_admin = Address::generate(&env);

    assert_eq!(client.transfer_admin(&admin, &new_admin), ());
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );
    assert_eq!(client.remove_alert_by_admin(&new_admin, &id), ());
}

// 5. Unauthorized remove rejected
#[test]
fn test_remove_unauthorized() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let attacker = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );

    assert_eq!(
        client
            .try_remove_alert(&attacker, &id)
            .unwrap_err()
            .unwrap(),
        ContractError::Unauthorized
    );
}

// 6. Edge case — get nonexistent alert returns None
#[test]
fn test_get_nonexistent_alert() {
    let (_env, client) = setup();
    assert!(client.get_alert(&999u64).is_none());
}

// 7. Edge case — get alerts for contract with no alerts returns empty vec
#[test]
fn test_get_alerts_for_contract_empty() {
    let (env, client) = setup();
    let querier = Address::generate(&env);
    let target = Address::generate(&env);
    assert_eq!(client.get_alerts_for_contract(&querier, &target).unwrap().len(), 0);
}

// 8. Index queries
#[test]
fn test_index_queries() {
    let (env, client) = setup();
    let querier = Address::generate(&env);
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    client.register_alert(&owner, &target, &str(&env, "A1"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
    client.register_alert(&owner, &target, &str(&env, "A2"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);

    assert_eq!(client.get_alerts_for_contract(&querier, &target).unwrap().len(), 2);
    assert_eq!(client.get_alerts_by_owner(&querier, &owner).unwrap().len(), 2);
}

// 9. get_alert_count is monotonic
#[test]
fn test_get_alert_count() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    assert_eq!(client.get_alert_count(), 0);
    let id = client.register_alert(&owner, &target, &str(&env, "A"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
    assert_eq!(client.get_alert_count(), 1);
    client.register_alert(&owner, &target, &str(&env, "B"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
    assert_eq!(client.get_alert_count(), 2);
    client.remove_alert(&owner, &id);
    assert_eq!(client.get_alert_count(), 2);
}

// get_active_alert_count decreases after remove
#[test]
fn test_get_active_alert_count() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    assert_eq!(client.get_active_alert_count(&owner), 0);
    let id1 = client.register_alert(&owner, &target, &str(&env, "A"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
    let _id2 = client.register_alert(&owner, &target, &str(&env, "B"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
    assert_eq!(client.get_active_alert_count(&owner), 2);
    client.remove_alert(&owner, &id1);
    assert_eq!(client.get_active_alert_count(&owner), 1);
}

// 10. update_webhook changes the hash
#[test]
fn test_update_webhook() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(&owner, &target, &str(&env, "A"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
    assert_eq!(
        client.try_update_webhook(&owner, &id, &hash64(&env)).unwrap(),
        Ok(())
    );
    assert_eq!(client.get_alert(&id).unwrap().webhook_hash, hash64(&env));
}

// 11. update_webhook unauthorized
#[test]
fn test_update_webhook_unauthorized() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let attacker = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(&owner, &target, &str(&env, "A"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
    assert_eq!(
        client
            .try_update_webhook(&attacker, &id, &hash64b(&env))
            .unwrap_err()
            .unwrap(),
        ContractError::Unauthorized
    );
}

// 11a. update_webhook rejects a hash shorter than 64 chars
#[test]
fn test_update_webhook_short_hash_rejected() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(&owner, &target, &str(&env, "A"), &str(&env, "hash"), &vec![&env], &None);
    let short_hash = str(&env, "tooshort");
    assert_eq!(
        client
            .try_update_webhook(&owner, &id, &short_hash)
            .unwrap_err()
            .unwrap(),
        ContractError::InvalidWebhookHash
    );
    // Ensure original hash is unchanged
    assert_eq!(client.get_alert(&id).unwrap().webhook_hash, str(&env, "hash"));
}

// 11b. update_webhook rejects a hash longer than 64 chars
#[test]
fn test_update_webhook_long_hash_rejected() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(&owner, &target, &str(&env, "A"), &str(&env, "hash"), &vec![&env], &None);
    // 65 hex chars — one too many
    let long_hash = str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(
        client
            .try_update_webhook(&owner, &id, &long_hash)
            .unwrap_err()
            .unwrap(),
        ContractError::InvalidWebhookHash
    );
    // Ensure original hash is unchanged
    assert_eq!(client.get_alert(&id).unwrap().webhook_hash, str(&env, "hash"));
}

// 11c. update_webhook accepts exactly 64 chars (valid SHA-256 hex digest)
#[test]
fn test_update_webhook_valid_64_char_hash_accepted() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(&owner, &target, &str(&env, "A"), &str(&env, "hash"), &vec![&env], &None);
    // Exactly 64 hex chars
    let valid_hash = str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(
        client.try_update_webhook(&owner, &id, &valid_hash).unwrap(),
        Ok(())
    );
    assert_eq!(client.get_alert(&id).unwrap().webhook_hash, valid_hash);
}

// 11d. update_webhook on a nonexistent alert returns AlertNotFound
#[test]
fn test_update_webhook_not_found() {
    let (env, client) = setup();
    let caller = Address::generate(&env);

    // valid 64-char hash so the length check passes before the existence check
    let valid_hash = str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(
        client
            .try_update_webhook(&caller, &999u64, &valid_hash)
            .unwrap_err()
            .unwrap(),
        ContractError::AlertNotFound
    );
}

#[test]
fn test_update_alert_missing_returns_not_found() {
    let (env, client) = setup();
    let attacker = Address::generate(&env);

    assert_eq!(
        client
            .try_update_alert(&attacker, &999u64, &vec![&env, str(&env, "rule:transfer")], &false)
            .unwrap_err()
            .unwrap(),
        ContractError::AlertNotFound
    );
}

#[test]
fn test_remove_alert_nonexistent_returns_not_found() {
    let (env, client) = setup();
    let owner = Address::generate(&env);

    assert_eq!(
        client
            .try_remove_alert(&owner, &999u64)
            .unwrap_err()
            .unwrap(),
        ContractError::AlertNotFound
    );
}

// 12. active defaults to true on registration
#[test]
fn test_active_defaults_to_true() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(&owner, &target, &str(&env, "Alert"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
    assert!(client.get_alert(&id).unwrap().active);
}

// 13. register_alert rejects more than 50 rules
#[test]
#[should_panic(expected = "too many rules")]
fn test_register_alert_too_many_rules() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let mut rules: Vec<String> = vec![&env];
    for _ in 0..51u32 {
        rules.push_back(str(&env, "rule"));
    }
    client.register_alert(&owner, &target, &str(&env, "A"), &hash64(&env), &rules, &None);
}

// 14. update_alert rejects more than 50 rules
#[test]
#[should_panic(expected = "too many rules: maximum is 50")]
fn test_update_alert_too_many_rules() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(&owner, &target, &str(&env, "A"), &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);

    let mut rules: Vec<String> = vec![&env];
    for _ in 0..51u32 {
        rules.push_back(str(&env, "rule"));
    }
    client.update_alert(&owner, &id, &rules, &true);
}

// 15. exactly 50 rules is accepted
#[test]
fn test_register_alert_exactly_50_rules() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let mut rules: Vec<String> = vec![&env];
    for i in 0..50u32 {
        rules.push_back(str(&env, if i % 2 == 0 { "rule:transfer" } else { "rule:mint" }));
    }
    let id = client.register_alert(&owner, &target, &str(&env, "A"), &hash64(&env), &rules, &None);
    assert_eq!(client.get_alert(&id).unwrap().rules.len(), 50);
}

// 14. Label exceeding 128 bytes is rejected
#[test]
#[should_panic(expected = "label exceeds 128 bytes")]
fn test_label_too_long() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let long_label = str(&env, &"a".repeat(129));
    client.register_alert(&owner, &target, &long_label, &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
}

// 15. Label at exactly 128 bytes is accepted
#[test]
fn test_label_max_length_accepted() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let max_label = str(&env, &"a".repeat(128));
    client.register_alert(&owner, &target, &max_label, &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
}

// ── Soroban string-length boundary tests ─────────────────────────────────────

#[test]
#[should_panic(expected = "label exceeds 128 bytes")]
fn test_label_at_soroban_max_rejected_by_app_guard() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let label = str_repeat(&env, 'a', 8192);
    client.register_alert(&owner, &target, &label, &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
}

// 19. Label of 8 191 bytes (one below Soroban max) is also rejected by the app guard.
#[test]
#[should_panic(expected = "label exceeds 128 bytes")]
fn test_label_one_below_soroban_max_rejected_by_app_guard() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let label = str_repeat(&env, 'b', 8191);
    client.register_alert(&owner, &target, &label, &hash64(&env), &vec![&env, str(&env, "rule:transfer")], &None);
}

#[test]
fn test_soroban_string_8192_bytes_is_constructible() {
    let (env, _client) = setup();
    let s = str_repeat(&env, 'x', 8192);
    assert_eq!(s.len(), 8192);
}

// ── Feature: renew_alert_ttl ──────────────────────────────────────────────────

// renew_alert_ttl — happy path: owner can renew without changing data
#[test]
fn test_renew_alert_ttl_happy_path() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );

    let before = client.get_alert(&id).unwrap();

    // Advance time — renew should NOT change updated_at
    env.ledger().with_mut(|li| li.timestamp += 100);

    assert_eq!(client.try_renew_alert_ttl(&owner, &id).unwrap(), Ok(()));

    let after = client.get_alert(&id).unwrap();

/// register_alert with empty rules returns EmptyRules (#206).
#[test]
fn test_register_alert_empty_rules_rejected() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );

    assert_eq!(
        client
            .try_renew_alert_ttl(&attacker, &id)
            .unwrap_err()
            .unwrap(),
        ContractError::Unauthorized
    );
}

// renew_alert_ttl — nonexistent alert returns AlertNotFound
#[test]
fn test_renew_alert_ttl_not_found() {
    let (env, client) = setup();
    let caller = Address::generate(&env);

    assert_eq!(
        client
            .try_register_alert(&owner, &target, &str(&env, "Alert"), &hash64(&env), &vec![&env], &None)
            .unwrap_err()
            .unwrap(),
        ContractError::EmptyRules
    );
}

/// update_alert with empty rules returns EmptyRules (#206).
#[test]
fn test_update_alert_empty_rules_rejected() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );

    assert_eq!(
        client
            .try_propose_webhook(&owner, &id, &hash64(&env))
            .unwrap(),
        ContractError::EmptyRules
    );

    let cfg = client.get_alert(&id).unwrap();
    // Live hash must still be the original
    assert_eq!(cfg.webhook_hash, hash64(&env));
    // Pending hash must be set
    assert_eq!(cfg.pending_webhook_hash, Some(hash64(&env)));
}

// confirm_webhook — happy path: pending hash is promoted to live hash
#[test]
fn test_confirm_webhook_promotes_pending_hash() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );

    client.propose_webhook(&owner, &id, &hash64(&env)).unwrap();

    assert_eq!(client.try_confirm_webhook(&owner, &id).unwrap(), Ok(()));

    let cfg = client.get_alert(&id).unwrap();
    // Live hash must now be the new one
    assert_eq!(cfg.webhook_hash, hash64(&env));
    // Pending hash must be cleared
    assert!(cfg.pending_webhook_hash.is_none());
}

/// register_alert with duplicate rule descriptors returns DuplicateRule (#207).
#[test]
fn test_register_alert_duplicate_rules_rejected() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );

    assert_eq!(
        client
            .try_register_alert(
                &owner,
                &target,
                &str(&env, "Alert"),
                &hash64(&env),
                &vec![&env, str(&env, "rule:transfer"), str(&env, "rule:transfer")],
                &None,
            )
            .unwrap_err()
            .unwrap(),
        ContractError::DuplicateRule
    );
}

/// update_alert with duplicate rule descriptors returns DuplicateRule (#207).
#[test]
fn test_update_alert_duplicate_rules_rejected() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );

    assert_eq!(
        client
            .try_update_alert(
                &owner,
                &id,
                &vec![&env, str(&env, "rule:mint"), str(&env, "rule:mint")],
                &true,
            )
            .unwrap_err()
            .unwrap(),
        ContractError::DuplicateRule
    );
}

/// Two distinct valid rule descriptors are accepted (no duplicate) (#207).
#[test]
fn test_two_unique_rules_accepted() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );

    client.propose_webhook(&owner, &id, &hash64(&env)).unwrap();

    assert_eq!(
        client
            .try_confirm_webhook(&attacker, &id)
            .unwrap_err()
            .unwrap(),
        ContractError::Unauthorized
    );
}

// ── #208 — webhook_hash format validation ────────────────────────────────────

/// register_alert rejects hashes shorter than 64 characters (#208).
#[test]
fn test_register_alert_short_webhook_hash_rejected() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    assert_eq!(
        client
            .try_propose_webhook(&caller, &999u64, &hash64(&env))
            .unwrap_err()
            .unwrap(),
        ContractError::InvalidWebhookHash
    );
}

/// register_alert rejects hashes longer than 64 characters (#208).
#[test]
fn test_register_alert_long_webhook_hash_rejected() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    // 65 chars
    let long_hash = str(&env, "a3f1b2c4d5e6f7089abcdef01234567890abcdef01234567890abcdef0123456");

    assert_eq!(
        client
            .try_register_alert(
                &owner,
                &target,
                &str(&env, "Alert"),
                &long_hash,
                &vec![&env, str(&env, "rule:transfer")],
                &None,
            )
            .unwrap_err()
            .unwrap(),
        ContractError::InvalidWebhookHash
    );
}

/// A valid 64-character hash is accepted by register_alert (#208).
#[test]
fn test_register_alert_valid_webhook_hash_accepted() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &str(&env, "original"),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );

    assert_eq!(client.get_alert(&id).unwrap().webhook_hash, hash64(&env));
}

// Full rotation flow: propose → confirm → propose again → confirm again
#[test]
fn test_webhook_rotation_full_cycle() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &str(&env, "v1"),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );

    // First rotation
    client.propose_webhook(&owner, &id, &str(&env, "v2")).unwrap();
    client.confirm_webhook(&owner, &id).unwrap();
    let cfg = client.get_alert(&id).unwrap();
    assert_eq!(cfg.webhook_hash, str(&env, "v2"));
    assert!(cfg.pending_webhook_hash.is_none());

    // Second rotation
    client.propose_webhook(&owner, &id, &str(&env, "v3")).unwrap();
    client.confirm_webhook(&owner, &id).unwrap();
    let cfg = client.get_alert(&id).unwrap();
    assert_eq!(cfg.webhook_hash, str(&env, "v3"));
    assert!(cfg.pending_webhook_hash.is_none());
}

/// A limit > MAX_BATCH_SIZE is silently clamped — response has at most MAX_BATCH_SIZE entries (#209).
#[test]
fn test_paginated_clamps_large_limit() {
    use crate::MAX_BATCH_SIZE;
    let (env, client) = setup();
    let querier = Address::generate(&env);
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );

    client.propose_webhook(&owner, &id, &hash64(&env)).unwrap();

    assert!(!env.events().all().is_empty());
}

// confirm_webhook emits a wh_conf event
#[test]
fn test_confirm_webhook_emits_event() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );

    client.propose_webhook(&owner, &id, &hash64(&env)).unwrap();
    client.confirm_webhook(&owner, &id).unwrap();

    assert!(!env.events().all().is_empty());
}

// pending_webhook_hash is None on fresh registration
#[test]
fn test_pending_webhook_hash_none_on_registration() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &hash64(&env),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );

    let cfg = client.get_alert(&id).unwrap();
    assert!(cfg.pending_webhook_hash.is_none());
}

/// 10 alerts from the same owner watching the same contract (#64).
#[test]
fn test_ten_alerts_same_owner_same_contract() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    let labels = [
        "Alert 0", "Alert 1", "Alert 2", "Alert 3", "Alert 4",
        "Alert 5", "Alert 6", "Alert 7", "Alert 8", "Alert 9",
    ];

    for label in labels {
        client.register_alert(
            &owner,
            &target,
            &str(&env, label),
            &webhook_hash,
            &vec![&env, str(&env, "rule:transfer")],
            &None,
        );
    }

    assert_eq!(
        client.get_alerts_by_owner(&owner, &owner).unwrap().len(),
        10
    );
    assert_eq!(
        client.get_alerts_for_contract(&owner, &target).unwrap().len(),
        10
    );
}

// Counter overflow guard
#[test]
fn test_counter_overflow_guard() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    env.storage().instance().set(&soroban_sdk::symbol_short!("NEXT_ID"), &u64::MAX);

    let res = client.try_register_alert(
        &owner,
        &target,
        &str(&env, "alert-overflow"),
        &str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &vec![&env, str(&env, "rule:transfer")],
        &None,
    );

    assert_eq!(res.unwrap_err().unwrap(), ContractError::CounterOverflow);
}

// ── Feature: contract-level pause / unpause (circuit breaker) ────────────────

// is_paused defaults to false before any admin action
#[test]
fn test_is_paused_defaults_to_false() {
    let (_env, client) = setup();
    assert!(!client.is_paused());
}

// Admin can pause and unpause; is_paused reflects the state
#[test]
fn test_admin_can_pause_and_unpause() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    client.initialize(&admin);

    assert_eq!(client.try_set_paused(&admin, &true).unwrap(), Ok(()));
    assert!(client.is_paused());

    assert_eq!(client.try_set_paused(&admin, &false).unwrap(), Ok(()));
    assert!(!client.is_paused());
}

// Non-admin cannot pause
#[test]
fn test_set_paused_unauthorized() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let attacker = Address::generate(&env);
    client.initialize(&admin);

    assert_eq!(
        client
            .try_set_paused(&attacker, &true)
            .unwrap_err()
            .unwrap(),
        ContractError::Unauthorized
    );
    assert!(!client.is_paused());
}

// Non-admin cannot unpause after admin paused
#[test]
fn test_set_unpaused_unauthorized() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let attacker = Address::generate(&env);
    client.initialize(&admin);
    client.set_paused(&admin, &true);

    assert_eq!(
        client
            .try_set_paused(&attacker, &false)
            .unwrap_err()
            .unwrap(),
        ContractError::Unauthorized
    );
    assert!(client.is_paused());
}

// register_alert is rejected while paused
#[test]
fn test_register_alert_rejected_when_paused() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    client.initialize(&admin);
    client.set_paused(&admin, &true);

    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    assert_eq!(
        client
            .try_register_alert(
                &owner,
                &target,
                &str(&env, "Alert"),
                &str(&env, "hash"),
                &vec![&env],
                &None,
            )
            .unwrap_err()
            .unwrap(),
        ContractError::ContractPaused
    );
}

// update_alert is rejected while paused
#[test]
fn test_update_alert_rejected_when_paused() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &str(&env, "hash"),
        &vec![&env],
        &None,
    );

    client.set_paused(&admin, &true);

    assert_eq!(
        client
            .try_update_alert(&owner, &id, &vec![&env], &false)
            .unwrap_err()
            .unwrap(),
        ContractError::ContractPaused
    );
}

// remove_alert is rejected while paused
#[test]
fn test_remove_alert_rejected_when_paused() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &str(&env, "hash"),
        &vec![&env],
        &None,
    );

    client.set_paused(&admin, &true);

    assert_eq!(
        client
            .try_remove_alert(&owner, &id)
            .unwrap_err()
            .unwrap(),
        ContractError::ContractPaused
    );
}

// Read-only functions remain available while paused
#[test]
fn test_reads_work_while_paused() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &str(&env, "hash"),
        &vec![&env],
        &None,
    );

    client.set_paused(&admin, &true);

    assert!(client.get_alert(&id).is_some());
    assert_eq!(
        client.get_alerts_for_contract(&owner, &target).unwrap().len(),
        1
    );
}

// Mutations resume after unpause
#[test]
fn test_mutations_resume_after_unpause() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    client.initialize(&admin);
    client.set_paused(&admin, &true);
    client.set_paused(&admin, &false);

    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let id = client.register_alert(
        &owner,
        &target,
        &str(&env, "Alert"),
        &str(&env, "hash"),
        &vec![&env],
        &None,
    );
    assert!(client.get_alert(&id).is_some());
}

// set_paused emits an event
#[test]
fn test_set_paused_emits_event() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    client.initialize(&admin);

    client.set_paused(&admin, &true);
    assert!(!env.events().all().is_empty());
}
