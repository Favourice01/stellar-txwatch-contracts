// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Tx-wat Contributors

import { Address, Contract, NativeToScenMap, Scval, XdriValue } from '@stellar/stellar-sdk';

export type AlertLevel = {
  tag: 'Info';
  values: void;
} | {
  tag: 'Warn';
  values: void;
} | {
  tag: 'Critical';
  values: void;
};

export type OwnerAlertConfig = {
  alert_level: AlertLevel;
  enabled: boolean;
};

export type WatcherInfo = {
  address: string;
  label: string;
  registered_at: bigint;
  registered_by: string;
};

export interface Client {
  register_watcher({ admin, watcher, label }: { admin: string; watcher: string; label?: string }): Promise<void>;
  get_watcher_info({ watcher }: { watcher: string }): Promise<WatcherInfo | undefined>;
  get_all_watchers(): Promise<string[]>;
  get_all_watchers_paginated({ offset, limit }: { offset: number; limit: number }): Promise<string[]>;
  get_admins(): Promise<string[]>;
  get_per_owner_alert_limit(): Promise<number | undefined>;
  get_owner_alert_config({ owner }: { owner: string }): Promise<OwnerAlertConfig | undefined>;
  set_per_owner_alert_limit({ limit }: { limit: number }): Promise<void>;
  register_watcher({ admin, watcher, expires_at }: { admin: string; watcher: string; expires_at?: bigint }): Promise<void>;
  batch_register_watchers({ admin, watchers }: { admin: string; watchers: string[] }): Promise<number>;
  renew_watcher({ admin, watcher, new_expiry }: { admin: string; watcher: string; new_expiry?: bigint }): Promise<void>;
  set_paused({ admin, paused }: { admin: string; paused: boolean }): Promise<void>;
  is_paused(): Promise<boolean>;
}

export class WatcherRegistry implements Client {
  readonly contract: Contract;

  constructor(contract: Contract) {
    this.contract = contract;
  }

  async get_per_owner_alert_limit(): Promise<number | undefined> {
    const result = await this.contract.call('get_per_owner_alert_limit');
    const value = result.result;
    return value === undefined || value === null ? undefined : Number(value);
  }

  async get_owner_alert_config({ owner }: { owner: string }): Promise<OwnerAlertConfig | undefined> {
    const result = await this.contract.call('get_owner_alert_config', { owner });
    const value = result.result;
    if (value === undefined || value === null) {
      return undefined;
    }
    return value as OwnerAlertConfig;
  }

  async set_per_owner_alert_limit({ limit }: { limit: number }): Promise<void> {
    await this.contract.call('set_per_owner_alert_limit', { limit });
  }

  async register_watcher({ admin, watcher, expires_at }: { admin: string; watcher: string; expires_at?: bigint }): Promise<void> {
    await this.contract.call('register_watcher', { admin, watcher, expires_at });
  }

  async batch_register_watchers({ admin, watchers }: { admin: string; watchers: string[] }): Promise<number> {
    const result = await this.contract.call('batch_register_watchers', { admin, watchers });
    return Number(result.result);
  }

  async renew_watcher({ admin, watcher, new_expiry }: { admin: string; watcher: string; new_expiry?: bigint }): Promise<void> {
    await this.contract.call('renew_watcher', { admin, watcher, new_expiry });
  }

  async set_paused({ admin, paused }: { admin: string; paused: boolean }): Promise<void> {
    await this.contract.call('set_paused', { admin, paused });
  }

  async is_paused(): Promise<boolean> {
    const result = await this.contract.call('is_paused');
    return Boolean(result.result);
  }
}
