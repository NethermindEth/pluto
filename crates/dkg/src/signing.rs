//! Post-DKG signing and aggregation.
//!
//! Ports Charon's `signLockHash`, `signDepositMsgs`,
//! `signValidatorRegistrations`, `aggLockHashSig`, `aggDepositData`,
//! `aggValidatorRegistrations`, `createDistValidators`, and the `signAndAgg*`
//! driver functions (charon/dkg/dkg.go:600-1146).

use std::collections::HashMap;

use chrono::DateTime;
use pluto_cluster::{
    definition::{Definition, NodeIdx},
    distvalidator::DistValidator,
    lock::Lock,
    registration::{BuilderRegistration, Registration},
};
use pluto_core::types::{ParSignedData, ParSignedDataSet, PubKey, Signature};
use pluto_crypto::{
    blst_impl::BlstImpl,
    tbls::Tbls,
    types::{PublicKey, Signature as CryptoSignature},
};
use pluto_eth2api::{
    spec::{phase0::Version, version::BuilderVersion},
    v1::SignedValidatorRegistration,
    versioned::VersionedSignedValidatorRegistration,
};
use pluto_eth2util::{
    deposit as deposit_util, network::fork_version_to_genesis_time, registration as reg_util,
};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::{
    exchanger::{Exchanger, SIG_DEPOSIT_DATA, SIG_LOCK, SIG_VALIDATOR_REG},
    share::Share,
};

// Type aliases for clarity.
type Eth2DepositData = pluto_eth2api::spec::phase0::DepositData;
type ClusterDepositData = pluto_cluster::deposit::DepositData;

/// Error from signing/aggregation operations.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// BLS sign, verify, or aggregate operation failed.
    #[error("BLS sign/verify/aggregate: {0:?}")]
    Bls(pluto_crypto::types::Error),
    /// Deposit message construction or signing-root computation failed.
    #[error("deposit: {0}")]
    Deposit(#[from] pluto_eth2util::deposit::DepositError),
    /// Validator registration construction failed.
    #[error("registration: {0}")]
    Registration(#[from] pluto_eth2util::registration::RegistrationError),
    /// Network/fork-version mapping failed.
    #[error("network: {0}")]
    Network(#[from] pluto_eth2util::network::NetworkError),
    /// Partial-signature exchange failed.
    #[error("exchanger: {0}")]
    Exchanger(#[from] crate::exchanger::ExchangerError),
    /// Lock hash computation failed.
    #[error("lock hash: {0}")]
    LockHash(#[from] pluto_cluster::lock::LockError),
    /// A public key had the wrong byte length.
    #[error("invalid public key bytes")]
    InvalidPubKey,
    /// No partial signatures were found for a given DV public key.
    #[error("no partial signatures for pubkey {0}")]
    MissingPartialSig(String),
    /// No deposit message was produced for a DV's public key.
    #[error("deposit message not found for pubkey")]
    MissingDepositMsg,
    /// A partial deposit signature failed verification against its public share.
    #[error("invalid deposit data partial signature from share {share_idx} for pubkey {pubkey}")]
    InvalidDepositPartialSignature {
        /// 1-indexed share index carried on the partial signature.
        share_idx: u64,
        /// DV public key the partial signature belongs to.
        pubkey: String,
    },
    /// A threshold-aggregated deposit signature failed final verification.
    #[error("invalid deposit data aggregated signature for pubkey {pubkey}")]
    InvalidDepositAggregateSignature {
        /// DV public key the aggregate signature belongs to.
        pubkey: String,
    },
    /// Pluto's own freshly generated partial deposit signature failed local verification.
    #[error("locally generated deposit data partial signature failed verification for share {share_idx} pubkey {pubkey}")]
    InvalidLocalDepositPartialSignature {
        /// 1-indexed share index for this Pluto node.
        share_idx: u64,
        /// DV public key the partial signature belongs to.
        pubkey: String,
    },
    /// No validator registration was produced for a DV's public key.
    #[error("registration not found for pubkey")]
    MissingRegistration,
    /// A share or peer index exceeded its allowed range.
    #[error("share index overflow")]
    Overflow,
    /// Fork version to genesis time mapping failed.
    #[error("fork version genesis time: {0}")]
    GenesisTime(String),
    /// Fork version bytes had the wrong length.
    #[error("fork version: {0}")]
    ForkVersion(String),
}

impl From<pluto_crypto::types::Error> for SigningError {
    fn from(e: pluto_crypto::types::Error) -> Self {
        SigningError::Bls(e)
    }
}

// ── Helpers for private-field access ────────────────────────────────────────

/// Extract raw bytes from a pluto_core::types::Signature (field is pub(crate)).
fn sig_bytes(sig: &pluto_core::types::Signature) -> CryptoSignature {
    *sig.as_ref()
}

/// Extract raw bytes from a pluto_core::types::PubKey (field is pub(crate)).
fn pk_bytes(pk: &PubKey) -> [u8; 48] {
    pk.as_ref().try_into().expect("PubKey always 48 bytes")
}

// ── Lock hash ───────────────────────────────────────────────────────────────

/// Signs the lock hash with each share's secret key and returns a
/// `ParSignedDataSet` containing one partial signature per DV.
/// Reference: charon/dkg/dkg.go:793 `signLockHash`.
fn sign_lock_hash(
    share_idx: usize,
    shares: &[Share],
    hash: &[u8],
) -> Result<ParSignedDataSet, SigningError> {
    let mut set = ParSignedDataSet::new();
    for share in shares {
        let sig_bytes = BlstImpl.sign(&share.secret_share, hash)?;
        let pk = PubKey::new(share.pub_key);
        set.insert(
            pk,
            ParSignedData::new(Signature::new(sig_bytes), share_idx as u64),
        );
    }
    Ok(set)
}

/// Aggregates (non-threshold) partial lock-hash signatures from all peers.
/// Returns the aggregate signature and the list of contributing public shares.
/// Reference: charon/dkg/dkg.go:747 `aggLockHashSig`.
fn agg_lock_hash_sig(
    data: &HashMap<PubKey, Vec<ParSignedData>>,
    shares_by_pk: &HashMap<PubKey, &Share>,
    hash: &[u8],
) -> Result<(CryptoSignature, Vec<PublicKey>), SigningError> {
    let mut all_sigs: Vec<CryptoSignature> = Vec::new();
    let mut all_pubshares: Vec<PublicKey> = Vec::new();

    for (pk, psigs) in data {
        let share = shares_by_pk
            .get(pk)
            .ok_or_else(|| SigningError::MissingPartialSig(pk.to_string()))?;

        for psig in psigs {
            let raw_sig: CryptoSignature = sig_bytes(
                &psig
                    .signed_data
                    .signature()
                    .map_err(|_| SigningError::InvalidPubKey)?,
            );
            let pubshare = share
                .public_shares
                .get(&psig.share_idx)
                .ok_or_else(|| SigningError::MissingPartialSig(pk.to_string()))?;

            BlstImpl.verify(pubshare, hash, &raw_sig)?;
            all_sigs.push(raw_sig);
            all_pubshares.push(*pubshare);
        }
    }

    Ok((BlstImpl.aggregate(&all_sigs)?, all_pubshares))
}

/// Signs, exchanges, and aggregates lock-hash partial signatures; builds the
/// cluster lock.
/// Reference: charon/dkg/dkg.go:599 `signAndAggLockHash`.
pub async fn sign_and_agg_lock_hash(
    _ct: CancellationToken,
    shares: &[Share],
    definition: Definition,
    node_idx: &NodeIdx,
    exchanger: &Exchanger,
    deposit_datas: Vec<Vec<Eth2DepositData>>,
    val_regs: Vec<VersionedSignedValidatorRegistration>,
) -> Result<Lock, SigningError> {
    let validators = create_dist_validators(shares, &deposit_datas, &val_regs)?;

    let mut lock = Lock {
        definition,
        distributed_validators: validators,
        lock_hash: Vec::new(),
        signature_aggregate: Vec::new(),
        node_signatures: Vec::new(),
    };
    lock.set_lock_hash()?;

    let lock_hash_sig_set = sign_lock_hash(node_idx.share_idx, shares, &lock.lock_hash)?;
    let peer_sigs = exchanger.exchange(SIG_LOCK, lock_hash_sig_set).await?;

    let shares_by_pk: HashMap<PubKey, &Share> =
        shares.iter().map(|s| (PubKey::new(s.pub_key), s)).collect();

    let (agg_sig, all_pubshares) = agg_lock_hash_sig(&peer_sigs, &shares_by_pk, &lock.lock_hash)?;

    BlstImpl.verify_aggregate(&all_pubshares, agg_sig, &lock.lock_hash)?;

    lock.signature_aggregate = agg_sig.to_vec();
    Ok(lock)
}

// ── Deposit data ────────────────────────────────────────────────────────────

// DepositMessage is the unsigned portion; DepositData adds the signature.
type Eth2DepositMessage = pluto_eth2api::spec::phase0::DepositMessage;

/// Signs deposit messages for each DV share and returns a
/// `(ParSignedDataSet, msgs_map)` for the given deposit amount.
/// Reference: charon/dkg/dkg.go:812 `signDepositMsgs`.
fn sign_deposit_msgs(
    shares: &[Share],
    share_idx: usize,
    withdrawal_addresses: &[String],
    network: &str,
    amount: u64,
    compounding: bool,
) -> Result<(ParSignedDataSet, HashMap<PubKey, Eth2DepositMessage>), SigningError> {
    let mut msgs: HashMap<PubKey, Eth2DepositMessage> = HashMap::new();
    let mut set = ParSignedDataSet::new();

    for (i, share) in shares.iter().enumerate() {
        let withdrawal_addr = withdrawal_addresses
            .get(i)
            .map(String::as_str)
            .unwrap_or_default();

        let msg = deposit_util::new_message(share.pub_key, withdrawal_addr, amount, compounding)?;
        let signing_root = deposit_util::get_message_signing_root(&msg, network)?;

        let raw_sig = BlstImpl.sign(&share.secret_share, signing_root.as_ref())?;
        let pk = PubKey::new(share.pub_key);
        let local_pubshare = share.public_shares.get(&(share_idx as u64)).ok_or_else(|| {
            SigningError::InvalidLocalDepositPartialSignature {
                share_idx: share_idx as u64,
                pubkey: pk.to_string(),
            }
        })?;
        BlstImpl
            .verify(local_pubshare, signing_root.as_ref(), &raw_sig)
            .map_err(|_| SigningError::InvalidLocalDepositPartialSignature {
                share_idx: share_idx as u64,
                pubkey: pk.to_string(),
            })?;
        set.insert(
            pk,
            ParSignedData::new(Signature::new(raw_sig), share_idx as u64),
        );
        msgs.insert(pk, msg);
    }

    Ok((set, msgs))
}

/// Threshold-aggregates partial deposit signatures into complete deposit data.
/// Reference: charon/dkg/dkg.go:910 `aggDepositData`.
fn agg_deposit_data(
    data: &HashMap<PubKey, Vec<ParSignedData>>,
    shares: &[Share],
    msgs: &HashMap<PubKey, Eth2DepositMessage>,
    network: &str,
) -> Result<Vec<Eth2DepositData>, SigningError> {
    let pubshares_by_pk: HashMap<PubKey, &HashMap<u64, PublicKey>> = shares
        .iter()
        .map(|s| (PubKey::new(s.pub_key), &s.public_shares))
        .collect();

    let mut result = Vec::new();

    for (pk, psigs) in data {
        let msg = msgs.get(pk).ok_or(SigningError::MissingDepositMsg)?;
        let signing_root = deposit_util::get_message_signing_root(msg, network)?;
        let pubshares = pubshares_by_pk
            .get(pk)
            .ok_or_else(|| SigningError::MissingPartialSig(pk.to_string()))?;

        let mut partial_sigs: HashMap<u8, CryptoSignature> = HashMap::new();
        for psig in psigs {
            let raw_sig: CryptoSignature = sig_bytes(
                &psig
                    .signed_data
                    .signature()
                    .map_err(|_| SigningError::InvalidPubKey)?,
            );
            let pubshare = pubshares
                .get(&psig.share_idx)
                .ok_or_else(|| SigningError::MissingPartialSig(pk.to_string()))?;
            BlstImpl
                .verify(pubshare, signing_root.as_ref(), &raw_sig)
                .map_err(|_| SigningError::InvalidDepositPartialSignature {
                    share_idx: psig.share_idx,
                    pubkey: pk.to_string(),
                })?;
            let idx = u8::try_from(psig.share_idx).map_err(|_| SigningError::Overflow)?;
            partial_sigs.insert(idx, raw_sig);
        }

        let agg_sig = BlstImpl.threshold_aggregate(&partial_sigs)?;
        let pk_arr = pk_bytes(pk);
        BlstImpl
            .verify(&pk_arr, signing_root.as_ref(), &agg_sig)
            .map_err(|_| SigningError::InvalidDepositAggregateSignature {
                pubkey: pk.to_string(),
            })?;

        result.push(Eth2DepositData {
            pubkey: msg.pubkey,
            withdrawal_credentials: msg.withdrawal_credentials,
            amount: msg.amount,
            signature: agg_sig,
        }); // DepositMessage + sig → DepositData
    }

    Ok(result)
}

/// Signs, exchanges, and aggregates deposit data.
/// Reference: charon/dkg/dkg.go:688 `signAndAggDepositData`.
pub async fn sign_and_agg_deposit_data(
    exchanger: &Exchanger,
    shares: &[Share],
    withdrawal_addresses: &[String],
    network: &str,
    node_idx: &NodeIdx,
    deposit_amounts: &[u64],
    compounding: bool,
) -> Result<Vec<Vec<Eth2DepositData>>, SigningError> {
    let mut result = Vec::new();

    for (i, &amount) in deposit_amounts.iter().enumerate() {
        let (set, msgs): (ParSignedDataSet, HashMap<PubKey, Eth2DepositMessage>) =
            sign_deposit_msgs(
                shares,
                node_idx.share_idx,
                withdrawal_addresses,
                network,
                amount,
                compounding,
            )?;

        let sig_type = SIG_DEPOSIT_DATA
            .checked_add(u64::try_from(i).map_err(|_| SigningError::Overflow)?)
            .ok_or(SigningError::Overflow)?;
        let peer_sigs = exchanger.exchange(sig_type, set).await?;
        let deposit_data = agg_deposit_data(&peer_sigs, shares, &msgs, network)?;
        result.push(deposit_data);
    }

    Ok(result)
}

// ── Validator registrations ─────────────────────────────────────────────────

/// Signs validator registration messages for each DV share.
/// Reference: charon/dkg/dkg.go:859 `signValidatorRegistrations`.
fn sign_validator_registrations(
    shares: &[Share],
    share_idx: usize,
    fee_recipients: &[String],
    gas_limit: u64,
    fork_version: &[u8],
) -> Result<
    (
        ParSignedDataSet,
        HashMap<PubKey, VersionedSignedValidatorRegistration>,
    ),
    SigningError,
> {
    let timestamp = u64::try_from(
        fork_version_to_genesis_time(fork_version)
            .map_err(|e| SigningError::GenesisTime(e.to_string()))?
            .timestamp(),
    )
    .map_err(|_| SigningError::GenesisTime("timestamp out of u64 range".into()))?;

    let genesis_fork_version: Version = fork_version
        .try_into()
        .map_err(|_| SigningError::ForkVersion("wrong length".into()))?;

    let mut msgs: HashMap<PubKey, VersionedSignedValidatorRegistration> = HashMap::new();
    let mut set = ParSignedDataSet::new();

    for (i, share) in shares.iter().enumerate() {
        let fee_recipient = fee_recipients
            .get(i)
            .map(String::as_str)
            .unwrap_or_default();
        let reg_msg = reg_util::new_message(share.pub_key, fee_recipient, gas_limit, timestamp)?;
        let signing_root = reg_util::get_message_signing_root(&reg_msg, genesis_fork_version);

        let raw_sig = BlstImpl.sign(&share.secret_share, signing_root.as_ref())?;

        let versioned_reg = VersionedSignedValidatorRegistration {
            version: BuilderVersion::V1,
            v1: Some(SignedValidatorRegistration {
                message: reg_msg,
                signature: raw_sig,
            }),
        };

        let pk = PubKey::new(share.pub_key);
        set.insert(
            pk,
            ParSignedData::new(Signature::new(raw_sig), share_idx as u64),
        );
        msgs.insert(pk, versioned_reg);
    }

    Ok((set, msgs))
}

/// Threshold-aggregates partial registration signatures.
/// Reference: charon/dkg/dkg.go:992 `aggValidatorRegistrations`.
fn agg_validator_registrations(
    data: &HashMap<PubKey, Vec<ParSignedData>>,
    shares: &[Share],
    msgs: &HashMap<PubKey, VersionedSignedValidatorRegistration>,
    fork_version: &[u8],
) -> Result<Vec<VersionedSignedValidatorRegistration>, SigningError> {
    let genesis_fork_version: Version = fork_version
        .try_into()
        .map_err(|_| SigningError::ForkVersion("wrong length".into()))?;

    let pubshares_by_pk: HashMap<PubKey, &HashMap<u64, PublicKey>> = shares
        .iter()
        .map(|s| (PubKey::new(s.pub_key), &s.public_shares))
        .collect();

    let mut result = Vec::new();

    for (pk, psigs) in data {
        let versioned_reg = msgs.get(pk).ok_or(SigningError::MissingRegistration)?;
        let v1 = versioned_reg
            .v1
            .as_ref()
            .ok_or(SigningError::MissingRegistration)?;
        let reg_msg = v1.message.clone();

        let signing_root = reg_util::get_message_signing_root(&reg_msg, genesis_fork_version);
        let pubshares = pubshares_by_pk
            .get(pk)
            .ok_or_else(|| SigningError::MissingPartialSig(pk.to_string()))?;

        let mut partial_sigs: HashMap<u8, CryptoSignature> = HashMap::new();
        for psig in psigs {
            let raw_sig: CryptoSignature = sig_bytes(
                &psig
                    .signed_data
                    .signature()
                    .map_err(|_| SigningError::InvalidPubKey)?,
            );
            let pubshare = pubshares
                .get(&psig.share_idx)
                .ok_or_else(|| SigningError::MissingPartialSig(pk.to_string()))?;
            BlstImpl.verify(pubshare, signing_root.as_ref(), &raw_sig)?;
            let idx = u8::try_from(psig.share_idx).map_err(|_| SigningError::Overflow)?;
            partial_sigs.insert(idx, raw_sig);
        }

        let agg_sig = BlstImpl.threshold_aggregate(&partial_sigs)?;
        let pk_arr = pk_bytes(pk);
        BlstImpl.verify(&pk_arr, signing_root.as_ref(), &agg_sig)?;

        result.push(VersionedSignedValidatorRegistration {
            version: BuilderVersion::V1,
            v1: Some(SignedValidatorRegistration {
                message: reg_msg,
                signature: agg_sig,
            }),
        });
    }

    Ok(result)
}

/// Signs, exchanges, and aggregates validator registrations.
/// Reference: charon/dkg/dkg.go:717 `signAndAggValidatorRegistrations`.
pub async fn sign_and_agg_validator_registrations(
    exchanger: &Exchanger,
    shares: &[Share],
    fee_recipients: &[String],
    gas_limit: u64,
    node_idx: &NodeIdx,
    fork_version: &[u8],
) -> Result<Vec<VersionedSignedValidatorRegistration>, SigningError> {
    let effective_gas_limit = if gas_limit == 0 {
        warn!(
            default = reg_util::DEFAULT_GAS_LIMIT,
            "gas_limit not set, using default"
        );
        reg_util::DEFAULT_GAS_LIMIT
    } else {
        gas_limit
    };

    let (set, msgs) = sign_validator_registrations(
        shares,
        node_idx.share_idx,
        fee_recipients,
        effective_gas_limit,
        fork_version,
    )?;

    let peer_sigs = exchanger.exchange(SIG_VALIDATOR_REG, set).await?;
    agg_validator_registrations(&peer_sigs, shares, &msgs, fork_version)
}

// ── create_dist_validators ──────────────────────────────────────────────────

/// Builds cluster [`DistValidator`]s from DKG shares, deposit data, and
/// validator registrations.
/// Reference: charon/dkg/dkg.go:1077 `createDistValidators`.
pub fn create_dist_validators(
    shares: &[Share],
    deposit_datas: &[Vec<Eth2DepositData>],
    val_regs: &[VersionedSignedValidatorRegistration],
) -> Result<Vec<DistValidator>, SigningError> {
    // Build deposit data lookup: pubkey → all deposit data for that validator.
    let mut deposit_by_pk: HashMap<[u8; 48], Vec<Eth2DepositData>> = HashMap::new();
    for amount_deposits in deposit_datas {
        for dd in amount_deposits {
            deposit_by_pk.entry(dd.pubkey).or_default().push(dd.clone());
        }
    }

    let mut dvs = Vec::with_capacity(shares.len());

    for share in shares {
        let reg = val_regs
            .iter()
            .find(|r| {
                r.v1.as_ref()
                    .map(|v| v.message.pubkey == share.pub_key)
                    .unwrap_or(false)
            })
            .ok_or(SigningError::MissingRegistration)?;

        let v1 = reg.v1.as_ref().ok_or(SigningError::MissingRegistration)?;

        // Public shares sorted by share index (1-indexed per cluster convention).
        let mut pub_share_entries: Vec<(u64, PublicKey)> =
            share.public_shares.iter().map(|(&k, &v)| (k, v)).collect();
        pub_share_entries.sort_by_key(|(k, _)| *k);
        let pub_shares: Vec<Vec<u8>> = pub_share_entries
            .into_iter()
            .map(|(_, pk)| pk.to_vec())
            .collect();

        let eth2_deposits = deposit_by_pk
            .get(&share.pub_key)
            .ok_or(SigningError::MissingDepositMsg)?;

        let partial_deposit_data: Vec<ClusterDepositData> = eth2_deposits
            .iter()
            .map(|dd| ClusterDepositData {
                pub_key: dd.pubkey,
                withdrawal_credentials: dd.withdrawal_credentials,
                amount: dd.amount,
                signature: dd.signature,
            })
            .collect();

        let timestamp =
            DateTime::from_timestamp(v1.message.timestamp.cast_signed(), 0).unwrap_or_default();

        let builder_registration = BuilderRegistration {
            message: Registration {
                fee_recipient: v1.message.fee_recipient,
                gas_limit: v1.message.gas_limit,
                timestamp,
                pub_key: v1.message.pubkey,
            },
            signature: v1.signature,
        };

        dvs.push(DistValidator {
            pub_key: share.pub_key.to_vec(),
            pub_shares,
            partial_deposit_data,
            builder_registration,
        });
    }

    Ok(dvs)
}
