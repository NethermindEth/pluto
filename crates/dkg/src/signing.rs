//! Post-DKG signing and aggregation.
//!
//! Primitive signing functions for lock hash, deposit messages, and validator
//! registrations. Async orchestration wrappers coordinate exchange with peers
//! and aggregate the collected partial signatures.

use std::collections::HashMap;

use pluto_cluster::{
    definition::{Creator, Definition, DefinitionError, NodeIdx},
    lock::Lock,
    operator::Operator,
};
use pluto_core::{
    signeddata::VersionedSignedValidatorRegistration,
    types::{ParSignedData, ParSignedDataSet, PubKey},
};
use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls, tblsconv::pubkey_to_eth2};
use pluto_eth2api::{spec::phase0, v1, versioned};
use pluto_eth2util::{deposit, network, registration};
use tracing::{info, warn};

use crate::{
    aggregate::{agg_deposit_data, agg_lock_hash_sig, agg_validator_registrations},
    dkg::AppendConfig,
    exchanger::{Exchanger, SIG_DEPOSIT_DATA, SIG_LOCK, SIG_VALIDATOR_REG},
    share::Share,
    validators::create_dist_validators,
};

/// Result type for DKG signing helpers.
pub type Result<T> = std::result::Result<T, SigningError>;

/// Error type for DKG signing helpers.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// Failed to build a core public key from bytes.
    #[error("invalid public key length while {error_context}")]
    InvalidPublicKeyLength {
        /// Signing helper that encountered the invalid key.
        error_context: &'static str,
    },

    /// Failed to sign or verify with threshold BLS.
    #[error(transparent)]
    Crypto(#[from] pluto_crypto::types::Error),

    /// Failed to build or hash deposit data.
    #[error(transparent)]
    Deposit(#[from] deposit::DepositError),

    /// Failed to normalize the withdrawal address.
    #[error(transparent)]
    Helper(#[from] pluto_eth2util::helpers::HelperError),

    /// Failed to build or hash validator registrations.
    #[error(transparent)]
    Registration(#[from] registration::RegistrationError),

    /// Failed to resolve network metadata from the fork version.
    #[error(transparent)]
    Network(#[from] network::NetworkError),

    /// Fork version is not 4 bytes.
    #[error("invalid fork version length")]
    InvalidForkVersionLength,

    /// Failed to build a versioned validator registration wrapper.
    #[error(transparent)]
    SignedData(#[from] pluto_core::signeddata::SignedDataError),

    /// Failed to convert a timestamp to seconds.
    #[error(transparent)]
    Timestamp(#[from] std::num::TryFromIntError),

    /// Withdrawal addresses do not cover all shares.
    #[error("insufficient withdrawal addresses")]
    InsufficientWithdrawalAddresses,

    /// Fee recipients do not cover all shares.
    #[error("insufficient fee recipients")]
    InsufficientFeeRecipients,

    /// Partial-signature exchange failed.
    #[error(transparent)]
    Exchanger(#[from] crate::exchanger::ExchangerError),

    /// Partial-signature aggregation failed.
    #[error(transparent)]
    Aggregate(#[from] crate::aggregate::AggregateError),

    /// Distributed-validator assembly failed.
    #[error(transparent)]
    Validators(#[from] crate::validators::ValidatorsError),

    /// Lock hash computation failed.
    #[error(transparent)]
    Lock(#[from] pluto_cluster::lock::LockError),

    /// Cluster definition update failed.
    #[error(transparent)]
    Definition(#[from] DefinitionError),

    /// Integer overflow in deposit-amount slot calculation.
    #[error("overflow in deposit amount slot index")]
    Overflow,
}

/// Returns partially signed signatures of the lock hash.
pub fn sign_lock_hash(share_idx: u64, shares: &[Share], hash: &[u8]) -> Result<ParSignedDataSet> {
    let mut set = ParSignedDataSet::new();

    for share in shares {
        let pub_key = share_pubkey(share, "signing lock hash")?;
        let sig = BlstImpl.sign(&share.secret_share, hash)?;

        set.insert(
            pub_key,
            ParSignedData::new(pluto_core::types::Signature::new(sig), share_idx),
        );
    }

    Ok(set)
}

/// Returns partially signed deposit-message signatures keyed by validator
/// pubkey.
pub fn sign_deposit_msgs(
    shares: &[Share],
    share_idx: u64,
    withdrawal_addresses: &[String],
    network_name: &str,
    amount: phase0::Gwei,
    compounding: bool,
) -> Result<(ParSignedDataSet, HashMap<PubKey, phase0::DepositMessage>)> {
    if shares.len() != withdrawal_addresses.len() {
        return Err(SigningError::InsufficientWithdrawalAddresses);
    }

    let mut msgs = HashMap::with_capacity(shares.len());
    let mut set = ParSignedDataSet::new();

    for (share, withdrawal_address) in shares.iter().zip(withdrawal_addresses.iter()) {
        let eth2_pubkey = pubkey_to_eth2(share.pub_key);
        let pub_key = share_pubkey(share, "signing deposit message")?;
        let withdrawal_address = pluto_eth2util::helpers::checksum_address(withdrawal_address)?;

        let msg = deposit::new_message(eth2_pubkey, &withdrawal_address, amount, compounding)?;
        let sig_root = deposit::get_message_signing_root(&msg, network_name)?;
        let sig = BlstImpl.sign(&share.secret_share, &sig_root)?;

        set.insert(
            pub_key,
            ParSignedData::new(pluto_core::types::Signature::new(sig), share_idx),
        );
        msgs.insert(pub_key, msg);
    }

    Ok((set, msgs))
}

/// Returns partially signed validator registrations keyed by validator pubkey.
pub fn sign_validator_registrations(
    shares: &[Share],
    share_idx: u64,
    fee_recipients: &[String],
    gas_limit: u64,
    fork_version: &[u8],
) -> Result<(
    ParSignedDataSet,
    HashMap<PubKey, VersionedSignedValidatorRegistration>,
)> {
    if shares.len() != fee_recipients.len() {
        return Err(SigningError::InsufficientFeeRecipients);
    }

    let timestamp = network::fork_version_to_genesis_time(fork_version)?;
    let fork_version_arr: phase0::Version = fork_version
        .try_into()
        .map_err(|_| SigningError::InvalidForkVersionLength)?;

    let mut msgs = HashMap::with_capacity(shares.len());
    let mut set = ParSignedDataSet::new();

    for (share, fee_recipient) in shares.iter().zip(fee_recipients.iter()) {
        let eth2_pubkey = pubkey_to_eth2(share.pub_key);
        let pub_key = share_pubkey(share, "signing validator registration")?;

        let reg_msg = registration::new_message(
            eth2_pubkey,
            fee_recipient,
            gas_limit,
            u64::try_from(timestamp.timestamp())?,
        )?;
        let sig_root = registration::get_message_signing_root(&reg_msg, fork_version_arr);
        let sig = BlstImpl.sign(&share.secret_share, &sig_root)?;

        let signed_reg = VersionedSignedValidatorRegistration::new(
            versioned::VersionedSignedValidatorRegistration {
                version: versioned::BuilderVersion::V1,
                v1: Some(v1::SignedValidatorRegistration {
                    message: reg_msg,
                    signature: sig,
                }),
            },
        )?;

        set.insert(
            pub_key,
            ParSignedData::new(pluto_core::types::Signature::new(sig), share_idx),
        );
        msgs.insert(pub_key, signed_reg);
    }

    Ok((set, msgs))
}

/// Signs, exchanges, and aggregates deposit data for each deposit amount.
#[allow(dead_code, reason = "will be used in dkg later ")]
pub(crate) async fn sign_and_agg_deposit_data(
    exchanger: &Exchanger,
    shares: &[Share],
    withdrawal_addresses: &[String],
    network: &str,
    node_idx: &NodeIdx,
    deposit_amounts: &[phase0::Gwei],
    compounding: bool,
) -> Result<Vec<Vec<phase0::DepositData>>> {
    let share_idx = u64::try_from(node_idx.share_idx)?;
    let mut result = Vec::with_capacity(deposit_amounts.len());

    for (i, &amount) in deposit_amounts.iter().enumerate() {
        let (set, msgs) = sign_deposit_msgs(
            shares,
            share_idx,
            withdrawal_addresses,
            network,
            amount,
            compounding,
        )?;

        let sig_type = SIG_DEPOSIT_DATA
            .checked_add(u64::try_from(i)?)
            .ok_or(SigningError::Overflow)?;
        let peer_sigs = exchanger.exchange(sig_type, set).await?;
        let deposit_data = agg_deposit_data(&peer_sigs, shares, &msgs, network)?;
        result.push(deposit_data);
    }

    Ok(result)
}

/// Signs, exchanges, and aggregates validator registrations.
#[allow(dead_code, reason = "will be used in dkg later ")]
pub(crate) async fn sign_and_agg_validator_registrations(
    exchanger: &Exchanger,
    shares: &[Share],
    fee_recipients: &[String],
    gas_limit: u64,
    node_idx: &NodeIdx,
    fork_version: &[u8],
) -> Result<Vec<VersionedSignedValidatorRegistration>> {
    let effective_gas_limit = if gas_limit == 0 {
        warn!(
            default = registration::DEFAULT_GAS_LIMIT,
            "gas_limit not set, using default"
        );
        registration::DEFAULT_GAS_LIMIT
    } else {
        gas_limit
    };

    let share_idx = u64::try_from(node_idx.share_idx)?;
    let (set, msgs) = sign_validator_registrations(
        shares,
        share_idx,
        fee_recipients,
        effective_gas_limit,
        fork_version,
    )?;

    let peer_sigs = exchanger.exchange(SIG_VALIDATOR_REG, set).await?;
    Ok(agg_validator_registrations(
        &peer_sigs,
        shares,
        &msgs,
        fork_version,
    )?)
}

/// Signs, exchanges, and aggregates lock-hash partial signatures; builds the
/// cluster lock. When `append_config` is `Some`, the new validators are merged
/// into the existing lock and the definition is re-hashed; signing happens over
/// the union of `existing_shares` and `new_shares` unless the append is
/// unverified, in which case signing is skipped.
#[allow(dead_code, reason = "will be used in dkg later ")]
#[allow(clippy::too_many_arguments, reason = "mirrors Go signAndAggLockHash")]
pub(crate) async fn sign_and_aggregate_lock_hash(
    existing_shares: &[Share],
    new_shares: &[Share],
    mut definition: Definition,
    node_idx: &NodeIdx,
    exchanger: &Exchanger,
    deposit_datas: Vec<Vec<phase0::DepositData>>,
    val_regs: Vec<VersionedSignedValidatorRegistration>,
    append_config: Option<&AppendConfig>,
) -> Result<Lock> {
    let mut validators = create_dist_validators(new_shares, &deposit_datas, &val_regs)?;

    if let Some(append) = append_config {
        let mut merged = append.cluster_lock.distributed_validators.clone();
        merged.append(&mut validators);
        validators = merged;

        definition
            .validator_addresses
            .extend(append.validator_addresses.iter().cloned());
        definition.num_validators = u64::try_from(validators.len())?;

        // Creator and operator signatures no longer cover the updated
        // definition; reset them so the lock can be re-signed downstream.
        if !append.unverified {
            definition.creator = Creator::default();
            for operator in &mut definition.operators {
                *operator = Operator {
                    enr: std::mem::take(&mut operator.enr),
                    ..Operator::default()
                };
            }
        }

        definition.set_definition_hashes()?;
    }

    if !pluto_cluster::version::support_pregen_registrations(&definition.version) {
        for dv in &mut validators {
            dv.builder_registration = pluto_cluster::registration::BuilderRegistration::default();
        }
    }

    let mut lock = Lock {
        definition,
        distributed_validators: validators,
        lock_hash: Vec::new(),
        signature_aggregate: Vec::new(),
        node_signatures: Vec::new(),
    };
    lock.set_lock_hash()?;

    if append_config.is_some_and(|a| a.unverified) {
        info!("The new cluster-lock file will not be signed due to --unverified flag");
        return Ok(lock);
    }

    let all_shares: Vec<Share> = existing_shares
        .iter()
        .chain(new_shares.iter())
        .cloned()
        .collect();

    let share_idx = u64::try_from(node_idx.share_idx)?;
    let lock_hash_sig_set = sign_lock_hash(share_idx, &all_shares, &lock.lock_hash)?;
    let peer_sigs = exchanger.exchange(SIG_LOCK, lock_hash_sig_set).await?;

    let shares_map: HashMap<PubKey, Share> = all_shares
        .iter()
        .map(|s| {
            PubKey::try_from(s.pub_key.as_slice())
                .map(|pk| (pk, s.clone()))
                .map_err(|_| SigningError::InvalidPublicKeyLength {
                    error_context: "building lock hash shares map",
                })
        })
        .collect::<Result<_>>()?;

    let (agg_sig, all_pubshares) = agg_lock_hash_sig(&peer_sigs, &shares_map, &lock.lock_hash)?;

    BlstImpl.verify_aggregate(&all_pubshares, agg_sig, &lock.lock_hash)?;
    lock.signature_aggregate = agg_sig.to_vec();

    Ok(lock)
}

fn share_pubkey(share: &Share, error_context: &'static str) -> Result<PubKey> {
    PubKey::try_from(share.pub_key.as_slice())
        .map_err(|_| SigningError::InvalidPublicKeyLength { error_context })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn build_shares(num_validators: usize, total: u8, threshold: u8, share_idx: u8) -> Vec<Share> {
        let mut res = Vec::with_capacity(num_validators);

        for seed in 0..num_validators {
            let secret = BlstImpl
                .generate_insecure_secret(rand::rngs::StdRng::seed_from_u64(
                    u64::try_from(seed)
                        .expect("seed should fit")
                        .checked_add(1)
                        .expect("seed increment should not overflow"),
                ))
                .expect("secret generation should succeed");
            let pub_key = BlstImpl
                .secret_to_public_key(&secret)
                .expect("public key derivation should succeed");
            let shares = BlstImpl
                .threshold_split(&secret, total, threshold)
                .expect("threshold split should succeed");

            res.push(Share {
                pub_key,
                secret_share: *shares
                    .get(&share_idx)
                    .expect("requested share index should exist"),
                public_shares: shares
                    .into_iter()
                    .map(|(idx, secret_share)| {
                        (
                            u64::from(idx),
                            BlstImpl
                                .secret_to_public_key(&secret_share)
                                .expect("public share derivation should succeed"),
                        )
                    })
                    .collect(),
            });
        }

        res
    }

    #[test]
    fn sign_deposit_msgs_returns_one_message_per_share() {
        let shares = build_shares(2, 4, 3, 1);
        let withdrawal_addresses = vec![
            "0x000000000000000000000000000000000000dEaD".to_string(),
            "0x000000000000000000000000000000000000bEEF".to_string(),
        ];

        let (set, msgs) = sign_deposit_msgs(
            &shares,
            1,
            &withdrawal_addresses,
            "goerli",
            deposit::DEFAULT_DEPOSIT_AMOUNT,
            true,
        )
        .expect("deposit signing should succeed");

        assert_eq!(set.inner().len(), 2);
        assert_eq!(msgs.len(), 2);
        for (share, withdrawal_address) in shares.iter().zip(withdrawal_addresses.iter()) {
            let pub_key = PubKey::try_from(share.pub_key.as_slice()).expect("pubkey should fit");
            let msg = msgs.get(&pub_key).expect("message should exist");
            let expected = deposit::new_message(
                share.pub_key,
                withdrawal_address,
                deposit::DEFAULT_DEPOSIT_AMOUNT,
                true,
            )
            .expect("message should build");
            assert_eq!(*msg, expected);
            assert_eq!(
                set.get(&pub_key).expect("signature should exist").share_idx,
                1
            );
        }
    }

    #[test]
    fn sign_lock_hash_returns_one_partial_signature_per_share() {
        let shares = build_shares(2, 4, 3, 2);
        let hash = [0x42; 32];

        let set = sign_lock_hash(2, &shares, &hash).expect("lock hash signing should succeed");

        assert_eq!(set.inner().len(), shares.len());
        for share in &shares {
            let pub_key = PubKey::try_from(share.pub_key.as_slice()).expect("pubkey should fit");
            let partial = set.get(&pub_key).expect("partial signature should exist");

            assert_eq!(partial.share_idx, 2);
            let sig = partial
                .signed_data
                .signature()
                .expect("signature should exist");
            BlstImpl
                .verify(&share.public_shares[&2], &hash, sig.as_ref())
                .expect("partial signature should verify against share public key");
        }
    }

    #[test]
    fn sign_validator_registrations_uses_fork_version_timestamp() {
        let shares = build_shares(1, 4, 3, 1);
        let fork_version =
            network::network_to_fork_version_bytes("goerli").expect("network should exist");
        let (set, msgs) = sign_validator_registrations(
            &shares,
            1,
            &["0x000000000000000000000000000000000000dEaD".to_string()],
            registration::DEFAULT_GAS_LIMIT,
            &fork_version,
        )
        .expect("registration signing should succeed");

        let pub_key = PubKey::try_from(shares[0].pub_key.as_slice()).expect("pubkey should fit");
        let msg = msgs.get(&pub_key).expect("message should exist");
        let expected_timestamp = network::fork_version_to_genesis_time(&fork_version)
            .expect("fork version should be valid")
            .timestamp();

        let v1 = msg.0.v1.as_ref().expect("v1 payload should exist");
        assert_eq!(
            i64::try_from(v1.message.timestamp).expect("timestamp should fit"),
            expected_timestamp
        );
        assert_eq!(
            set.get(&pub_key).expect("signature should exist").share_idx,
            1
        );
    }
}
