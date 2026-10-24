//! Stress test for `WatcherRegistry` with a large admin set and many watchers (#270).
//!
//! The compiled registry defines no maximum sizes, so this test uses fixed counts (50 admins,
//! 200 watchers) and checks they behave correctly. It does not measure instruction budgets.

#![cfg(test)]

use soroban_sdk::{testutils::Address as _, Address, Env, Vec};

use crate::{WatcherRegistry, WatcherRegistryClient};

const ADMINS: u32 = 50;
const WATCHERS: u32 = 200;

#[test]
fn many_admins_and_watchers_stay_consistent() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(WatcherRegistry, ());
    let client = WatcherRegistryClient::new(&env, &contract_id);

    let first_admin = Address::generate(&env);
    client.initialize(&first_admin);

    let mut admins: Vec<Address> = Vec::new(&env);
    admins.push_back(first_admin.clone());
    for _ in 1..ADMINS {
        let next = Address::generate(&env);
        client.add_admin(&first_admin, &next);
        admins.push_back(next);
    }
    assert_eq!(client.get_admins().unwrap().len(), ADMINS);

    let mut watchers: Vec<Address> = Vec::new(&env);
    for _ in 0..WATCHERS {
        let w = Address::generate(&env);
        client.register_watcher(&first_admin, &w, &None);
        watchers.push_back(w);
    }
    assert_eq!(client.get_watcher_count(), WATCHERS);

    let last = watchers.get(WATCHERS - 1).unwrap();
    assert!(client.is_authorized(&last));

    client.clear_all_watchers(&first_admin);
    assert_eq!(client.get_watcher_count(), 0);
    assert!(!client.is_authorized(&last));
}
