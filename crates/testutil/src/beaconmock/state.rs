//! Shared state, validator types, and helpers for `BeaconMock`.

use std::{
    collections::BTreeMap,
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use pluto_eth2api::{
    ValidatorResponseValidator, ValidatorStatus,
    spec::phase0::{BLSPubKey, ValidatorIndex},
};
use serde_json::Value;

use super::attestation::AttestationStore;

pub(crate) const DEFAULT_WITHDRAWAL_CREDENTIALS: &str =
    "0x3132333435363738393031323334353637383930313233343536373839303132";

/// Minimal validator representation used by the beacon mock.
#[derive(Debug, Clone, PartialEq)]
pub struct Validator {
    /// Validator index in the beacon registry.
    pub index: ValidatorIndex,
    /// Current balance in gwei.
    pub balance: u64,
    /// Current validator status.
    pub status: ValidatorStatus,
    /// Validator details returned by the beacon API.
    pub validator: ValidatorResponseValidator,
}

impl Validator {
    /// Creates an active validator with the provided index and public key.
    ///
    /// Mirrors Charon's `ValidatorSetA`: `exit_epoch` and `withdrawable_epoch`
    /// are the Go zero value (`"0"`), not `FAR_FUTURE_EPOCH`.
    #[must_use]
    pub fn active(index: ValidatorIndex, pubkey: BLSPubKey) -> Self {
        let pubkey = hex_0x(pubkey);

        Self {
            index,
            balance: index,
            status: ValidatorStatus::ActiveOngoing,
            validator: ValidatorResponseValidator {
                activation_eligibility_epoch: index.to_string(),
                activation_epoch: index.checked_add(1).unwrap_or(index).to_string(),
                effective_balance: index.to_string(),
                exit_epoch: "0".to_string(),
                pubkey,
                slashed: false,
                withdrawable_epoch: "0".to_string(),
                withdrawal_credentials: DEFAULT_WITHDRAWAL_CREDENTIALS.to_string(),
            },
        }
    }
}

/// Validator set used to seed validator and duty endpoints.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ValidatorSet(BTreeMap<ValidatorIndex, Validator>);

impl ValidatorSet {
    /// Returns the small deterministic validator set from Charon's Go
    /// beaconmock.
    #[must_use]
    pub fn validator_set_a() -> Self {
        [
            (
                1,
                "0x914cff835a769156ba43ad50b931083c2dadd94e8359ce394bc7a3e06424d0214922ddf15f81640530b9c25c0bc0d490",
            ),
            (
                2,
                "0x8dae41352b69f2b3a1c0b05330c1bf65f03730c520273028864b11fcb94d8ce8f26d64f979a0ee3025467f45fd2241ea",
            ),
            (
                3,
                "0x8ee91545183c8c2db86633626f5074fd8ef93c4c9b7a2879ad1768f600c5b5906c3af20d47de42c3b032956fa8db1a76",
            ),
        ]
        .into_iter()
        .filter_map(|(index, pubkey)| {
            parse_pubkey(pubkey).map(|pubkey| (index, Validator::active(index, pubkey)))
        })
        .collect()
    }

    /// Inserts or replaces a validator.
    pub fn insert(&mut self, validator: Validator) {
        self.0.insert(validator.index, validator);
    }

    /// Returns all validators in index order.
    #[must_use]
    pub fn validators(&self) -> Vec<Validator> {
        self.0.values().cloned().collect()
    }

    /// Returns the validator for an index.
    #[must_use]
    pub fn by_index(&self, index: ValidatorIndex) -> Option<Validator> {
        self.0.get(&index).cloned()
    }

    /// Returns the first validator matching the given BLS public key.
    ///
    /// Mirrors `ValidatorSet.ByPublicKey` from Charon's Go beaconmock: a linear
    /// scan over the set returning a clone of the matching validator.
    #[must_use]
    pub fn by_public_key(&self, pubkey: &BLSPubKey) -> Option<Validator> {
        let needle = hex_0x(pubkey);
        self.0
            .values()
            .find(|validator| validator.validator.pubkey == needle)
            .cloned()
    }

    /// Returns the BLS public keys of all validators in index order.
    ///
    /// Validators whose stored hex pubkey fails to parse back into a
    /// `BLSPubKey` are silently skipped; all validators inserted via
    /// `Validator::active` round-trip cleanly.
    #[must_use]
    pub fn public_keys(&self) -> Vec<BLSPubKey> {
        self.0
            .values()
            .filter_map(|validator| parse_pubkey(&validator.validator.pubkey))
            .collect()
    }

    /// Returns true if the set contains no validators.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromIterator<(ValidatorIndex, Validator)> for ValidatorSet {
    fn from_iter<T: IntoIterator<Item = (ValidatorIndex, Validator)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

/// Shared mock state used by mounted HTTP handlers.
#[derive(Debug)]
pub struct MockState {
    pub(crate) spec: RwLock<Value>,
    pub(crate) genesis: RwLock<Value>,
    pub(crate) validator_set: RwLock<ValidatorSet>,
    pub(crate) deterministic_attester_duties: RwLock<Option<u64>>,
    pub(crate) deterministic_proposer_duties: RwLock<Option<u64>>,
    pub(crate) deterministic_sync_comm_duties: RwLock<Option<(u64, u64)>>,
    pub(crate) attestation_store: AttestationStore,
}

impl MockState {
    pub(crate) fn new(spec: Value, genesis: Value, validator_set: ValidatorSet) -> Self {
        Self {
            spec: RwLock::new(spec),
            genesis: RwLock::new(genesis),
            validator_set: RwLock::new(validator_set),
            deterministic_attester_duties: RwLock::new(None),
            deterministic_proposer_duties: RwLock::new(None),
            deterministic_sync_comm_duties: RwLock::new(None),
            attestation_store: AttestationStore::default(),
        }
    }

    /// Returns a clone of the spec map served by `/eth/v1/config/spec`.
    #[must_use]
    pub fn spec(&self) -> Value {
        read_lock(&self.spec).clone()
    }

    /// Replaces one spec key.
    pub fn set_spec_field(&self, key: impl Into<String>, value: impl Into<Value>) {
        let key = key.into();
        let value = value.into();
        if let Some(spec) = write_lock(&self.spec).as_object_mut() {
            spec.insert(key, value);
        }
    }

    /// Returns a clone of the genesis data served by `/eth/v1/beacon/genesis`.
    #[must_use]
    pub fn genesis(&self) -> Value {
        read_lock(&self.genesis).clone()
    }

    /// Replaces one genesis field.
    pub fn set_genesis_field(&self, key: impl Into<String>, value: impl Into<Value>) {
        let key = key.into();
        let value = value.into();
        if let Some(genesis) = write_lock(&self.genesis).as_object_mut() {
            genesis.insert(key, value);
        }
    }

    /// Replaces the validator set served by validator-related endpoints.
    pub fn set_validator_set(&self, validator_set: ValidatorSet) {
        *write_lock(&self.validator_set) = validator_set;
    }
}

pub(crate) fn hex_0x(bytes: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(bytes.as_ref()))
}

/// Parses the trailing `/{u64}` segment of a request path (e.g. the `epoch`
/// in `/eth/v1/validator/duties/attester/3` or the `slot` in
/// `/eth/v2/beacon/blocks/5`), returning `0` on missing or non-numeric input.
pub(crate) fn last_path_segment_u64(path: &str) -> u64 {
    path.rsplit('/')
        .next()
        .and_then(|seg| seg.parse::<u64>().ok())
        .unwrap_or_default()
}

pub(crate) fn parse_pubkey(pubkey: &str) -> Option<BLSPubKey> {
    let pubkey = pubkey.strip_prefix("0x").unwrap_or(pubkey);
    let bytes = hex::decode(pubkey).ok()?;
    bytes.try_into().ok()
}

pub(crate) fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub(crate) fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub(crate) fn set_object_field(target: &mut Value, key: &'static str, value: impl Into<Value>) {
    if let Some(target) = target.as_object_mut() {
        target.insert(key.to_string(), value.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_set_a_has_three_validators() {
        let set = ValidatorSet::validator_set_a();
        assert_eq!(set.validators().len(), 3);
    }

    #[test]
    fn by_public_key_hit_returns_validator() {
        let set = ValidatorSet::validator_set_a();
        let pubkey = parse_pubkey(
            "0x914cff835a769156ba43ad50b931083c2dadd94e8359ce394bc7a3e06424d0214922ddf15f81640530b9c25c0bc0d490",
        )
        .expect("static pubkey parses");

        let validator = set.by_public_key(&pubkey).expect("validator by pubkey");
        assert_eq!(validator.index, 1);
    }

    #[test]
    fn by_public_key_miss_returns_none() {
        let set = ValidatorSet::validator_set_a();
        let unknown: BLSPubKey = [0u8; 48];
        assert!(set.by_public_key(&unknown).is_none());
    }

    #[test]
    fn public_keys_returns_all_validator_pubkeys() {
        let set = ValidatorSet::validator_set_a();
        let pubkeys = set.public_keys();
        assert_eq!(pubkeys.len(), 3);
        // Every emitted pubkey must round-trip back to a validator in the set.
        for pubkey in pubkeys {
            assert!(set.by_public_key(&pubkey).is_some());
        }
    }
}
