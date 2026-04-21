use std::collections::HashMap;

use pluto_core::{
    signeddata::{SignedDataError, VersionedSignedValidatorRegistration},
    types::{ParSignedData, PubKey, Signature as CoreSignature},
};
use pluto_crypto::{
    blst_impl::BlstImpl,
    tbls::Tbls,
    tblsconv::signature_from_bytes,
    types::{PublicKey, Signature},
};
use pluto_eth2api::spec::phase0;
use pluto_eth2util::{deposit, registration};

use crate::{
    share::Share,
    validators::{ValidatorsError, set_registration_signature},
};

/// Result type for DKG aggregation helpers.
pub type Result<T> = std::result::Result<T, AggregateError>;

/// Error type for DKG aggregation helpers.
#[derive(Debug, thiserror::Error)]
pub enum AggregateError {
    /// Failed to convert raw bytes into a threshold signature.
    #[error(transparent)]
    SignatureBytes(#[from] pluto_crypto::tblsconv::ConvError),

    /// Failed to verify or aggregate threshold signatures.
    #[error(transparent)]
    Crypto(#[from] pluto_crypto::types::Error),

    /// Failed to derive the deposit signing root.
    #[error(transparent)]
    Deposit(#[from] deposit::DepositError),

    /// Failed to derive the validator-registration signing root.
    #[error(transparent)]
    Registration(#[from] registration::RegistrationError),

    /// Failed to update the aggregated validator registration.
    #[error(transparent)]
    Validators(#[from] ValidatorsError),

    /// Failed to extract a signature from partially signed data.
    #[error(transparent)]
    SignedData(#[from] SignedDataError),

    /// Partial signatures referenced a pubkey that is not in the local share
    /// set.
    #[error("invalid pubkey in {context} partial signature from peer")]
    InvalidPubKeyFromPeer {
        /// Context string for the error.
        context: &'static str,
    },

    /// Partial signatures referenced a missing public share.
    #[error("invalid pubshare")]
    InvalidPubshare,

    /// Partial signature verification failed for deposit data.
    #[error("invalid deposit data partial signature from peer")]
    InvalidDepositPartialSignature,

    /// Partial signature verification failed for validator registrations.
    #[error("invalid validator registration partial signature from peer")]
    InvalidValidatorRegistrationPartialSignature,

    /// Partial signature verification failed for lock hash.
    #[error("invalid lock hash partial signature from peer: {0}")]
    InvalidLockHashPartialSignature(pluto_crypto::types::Error),

    /// Aggregate signature verification failed for deposit data.
    #[error("invalid deposit data aggregated signature: {0}")]
    InvalidDepositAggregatedSignature(pluto_crypto::types::Error),

    /// Aggregate signature verification failed for validator registrations.
    #[error("invalid validator registration aggregated signature: {0}")]
    InvalidValidatorRegistrationAggregatedSignature(pluto_crypto::types::Error),

    /// Deposit message was missing for a validator.
    #[error("deposit message not found")]
    DepositMessageNotFound,

    /// Validator registration was missing for a validator.
    #[error("validator registration not found")]
    ValidatorRegistrationNotFound,

    /// Failed to convert a share index to the threshold-signature index type.
    #[error(transparent)]
    ShareIndex(#[from] std::num::TryFromIntError),

    /// Fork version is not 4 bytes.
    #[error("invalid fork version length")]
    InvalidForkVersionLength,
}

/// Aggregates all lock-hash partial signatures across validators.
pub fn agg_lock_hash_sig(
    data: &HashMap<PubKey, Vec<ParSignedData>>,
    shares: &HashMap<PubKey, Share>,
    hash: &[u8],
) -> Result<(Signature, Vec<PublicKey>)> {
    let mut sigs = Vec::new();
    let mut pubkeys = Vec::new();

    for (pub_key, partials) in data {
        let share = shares
            .get(pub_key)
            .ok_or(AggregateError::InvalidPubKeyFromPeer {
                context: "lock hash",
            })?;

        for partial in partials {
            let sig = extract_partial_signature(partial)?;
            let pubshare = share
                .public_shares
                .get(&partial.share_idx)
                .ok_or(AggregateError::InvalidPubshare)?;

            BlstImpl
                .verify(pubshare, hash, &sig)
                .map_err(AggregateError::InvalidLockHashPartialSignature)?;

            sigs.push(sig);
            pubkeys.push(*pubshare);
        }
    }

    Ok((BlstImpl.aggregate(&sigs)?, pubkeys))
}

/// Aggregates threshold deposit-data signatures per validator.
pub fn agg_deposit_data(
    data: &HashMap<PubKey, Vec<ParSignedData>>,
    shares: &[Share],
    msgs: &HashMap<PubKey, phase0::DepositMessage>,
    network_name: &str,
) -> Result<Vec<phase0::DepositData>> {
    let shares_by_pubkey = shares_by_pubkey(shares)?;
    let mut res = Vec::with_capacity(data.len());

    for (pub_key, partials) in data {
        let msg = msgs
            .get(pub_key)
            .ok_or(AggregateError::DepositMessageNotFound)?;
        let sig_root = deposit::get_message_signing_root(msg, network_name)?;
        let share = shares_by_pubkey
            .get(pub_key)
            .ok_or(AggregateError::InvalidPubKeyFromPeer {
                context: "deposit data",
            })?;
        let partial_sigs =
            verify_threshold_partials(partials, &share.public_shares, &sig_root, || {
                AggregateError::InvalidDepositPartialSignature
            })?;

        let agg_sig = BlstImpl.threshold_aggregate(&partial_sigs)?;
        BlstImpl
            .verify(&share.pub_key, &sig_root, &agg_sig)
            .map_err(AggregateError::InvalidDepositAggregatedSignature)?;

        res.push(phase0::DepositData {
            pubkey: msg.pubkey,
            withdrawal_credentials: msg.withdrawal_credentials,
            amount: msg.amount,
            signature: agg_sig,
        });
    }

    Ok(res)
}

/// Aggregates threshold validator-registration signatures per validator.
pub fn agg_validator_registrations(
    data: &HashMap<PubKey, Vec<ParSignedData>>,
    shares: &[Share],
    msgs: &HashMap<PubKey, VersionedSignedValidatorRegistration>,
    fork_version: &[u8],
) -> Result<Vec<VersionedSignedValidatorRegistration>> {
    let shares_by_pubkey = shares_by_pubkey(shares)?;
    let fork_version: phase0::Version = fork_version
        .try_into()
        .map_err(|_| AggregateError::InvalidForkVersionLength)?;
    let mut res = Vec::with_capacity(data.len());

    for (pub_key, partials) in data {
        let msg = msgs
            .get(pub_key)
            .ok_or(AggregateError::ValidatorRegistrationNotFound)?;
        let v1 = msg
            .0
            .v1
            .as_ref()
            .ok_or(ValidatorsError::MissingV1Registration)?;
        let sig_root = registration::get_message_signing_root(&v1.message, fork_version);
        let share = shares_by_pubkey
            .get(pub_key)
            .ok_or(AggregateError::InvalidPubKeyFromPeer {
                context: "validator registrations",
            })?;
        let partial_sigs =
            verify_threshold_partials(partials, &share.public_shares, &sig_root, || {
                AggregateError::InvalidValidatorRegistrationPartialSignature
            })?;

        let agg_sig = BlstImpl.threshold_aggregate(&partial_sigs)?;
        BlstImpl
            .verify(&share.pub_key, &sig_root, &agg_sig)
            .map_err(AggregateError::InvalidValidatorRegistrationAggregatedSignature)?;

        res.push(set_registration_signature(
            msg,
            CoreSignature::new(agg_sig),
        )?);
    }

    Ok(res)
}

fn shares_by_pubkey(shares: &[Share]) -> Result<HashMap<PubKey, &Share>> {
    shares
        .iter()
        .map(|share| {
            let pub_key = PubKey::try_from(share.pub_key.as_slice()).map_err(|_| {
                AggregateError::InvalidPubKeyFromPeer {
                    context: "local share",
                }
            })?;
            Ok((pub_key, share))
        })
        .collect()
}

fn extract_partial_signature(partial: &ParSignedData) -> Result<Signature> {
    let sig = partial.signed_data.signature()?;
    Ok(signature_from_bytes(sig.as_ref())?)
}

fn verify_threshold_partials(
    partials: &[ParSignedData],
    public_shares: &HashMap<u64, PublicKey>,
    message: &[u8],
    invalid_signature_error: fn() -> AggregateError,
) -> Result<HashMap<u8, Signature>> {
    let mut res = HashMap::with_capacity(partials.len());

    for partial in partials {
        let sig = extract_partial_signature(partial)?;
        let pubshare = public_shares
            .get(&partial.share_idx)
            .ok_or(AggregateError::InvalidPubshare)?;

        BlstImpl
            .verify(pubshare, message, &sig)
            .map_err(|_| invalid_signature_error())?;

        res.insert(u8::try_from(partial.share_idx)?, sig);
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    use pluto_core::signeddata::VersionedSignedValidatorRegistration as CoreRegistration;
    use pluto_crypto::tblsconv::pubkey_to_eth2;
    use pluto_eth2api::{
        v1,
        versioned::{BuilderVersion, VersionedSignedValidatorRegistration},
    };
    use pluto_eth2util::network;
    use rand::SeedableRng;

    fn build_share_fixture() -> (Share, HashMap<u8, pluto_crypto::types::PrivateKey>) {
        let tbls = BlstImpl;
        let secret = tbls
            .generate_insecure_secret(rand::rngs::StdRng::seed_from_u64(7))
            .expect("secret generation should succeed");
        let pub_key = tbls
            .secret_to_public_key(&secret)
            .expect("public key derivation should succeed");
        let secret_shares = tbls
            .threshold_split(&secret, 4, 3)
            .expect("threshold split should succeed");
        let public_shares = secret_shares
            .iter()
            .map(|(idx, share)| {
                (
                    u64::from(*idx),
                    tbls.secret_to_public_key(share)
                        .expect("public share derivation should succeed"),
                )
            })
            .collect();

        (
            Share {
                pub_key,
                secret_share: *secret_shares.get(&1).expect("share 1 should exist"),
                public_shares,
            },
            secret_shares,
        )
    }

    fn partial_signature(sig: Signature, share_idx: u64) -> ParSignedData {
        ParSignedData::new(CoreSignature::new(sig), share_idx)
    }

    #[test]
    fn agg_deposit_data_rejects_invalid_partial_signature() {
        let (share, secret_shares) = build_share_fixture();
        let core_pub_key = PubKey::try_from(share.pub_key.as_slice()).expect("pubkey should fit");
        let msg = deposit::new_message(
            pubkey_to_eth2(share.pub_key),
            "0x000000000000000000000000000000000000dEaD",
            deposit::DEFAULT_DEPOSIT_AMOUNT,
            true,
        )
        .expect("message should build");
        let sig_root =
            deposit::get_message_signing_root(&msg, "goerli").expect("root should build");
        let mut partials = Vec::new();

        for idx in [1_u8, 2, 3] {
            let message = if idx == 3 {
                b"invalid msg".as_slice()
            } else {
                &sig_root
            };
            let sig = BlstImpl
                .sign(
                    secret_shares.get(&idx).expect("share should exist"),
                    message,
                )
                .expect("signing should succeed");
            partials.push(partial_signature(sig, u64::from(idx)));
        }

        let err = agg_deposit_data(
            &HashMap::from([(core_pub_key, partials)]),
            &[share],
            &HashMap::from([(core_pub_key, msg)]),
            "goerli",
        )
        .expect_err("aggregation should fail");

        assert!(matches!(
            err,
            AggregateError::InvalidDepositPartialSignature
        ));
    }

    #[test]
    fn agg_lock_hash_sig_rejects_invalid_partial_signature() {
        let (share, secret_shares) = build_share_fixture();
        let core_pub_key = PubKey::try_from(share.pub_key.as_slice()).expect("pubkey should fit");
        let hash = b"cluster lock hash";
        let mut partials = Vec::new();

        for idx in [1_u8, 2, 3] {
            let message = if idx == 3 {
                b"invalid msg".as_slice()
            } else {
                hash
            };
            let sig = BlstImpl
                .sign(
                    secret_shares.get(&idx).expect("share should exist"),
                    message,
                )
                .expect("signing should succeed");
            partials.push(partial_signature(sig, u64::from(idx)));
        }

        let err = agg_lock_hash_sig(
            &HashMap::from([(core_pub_key, partials)]),
            &HashMap::from([(core_pub_key, share)]),
            hash,
        )
        .expect_err("aggregation should fail");

        assert!(matches!(
            err,
            AggregateError::InvalidLockHashPartialSignature(_)
        ));
    }

    #[test]
    fn agg_deposit_data_accepts_valid_signatures() {
        let (share, secret_shares) = build_share_fixture();
        let core_pub_key = PubKey::try_from(share.pub_key.as_slice()).expect("pubkey should fit");
        let msg = deposit::new_message(
            pubkey_to_eth2(share.pub_key),
            "0x000000000000000000000000000000000000dEaD",
            deposit::DEFAULT_DEPOSIT_AMOUNT,
            true,
        )
        .expect("message should build");
        let sig_root =
            deposit::get_message_signing_root(&msg, "goerli").expect("root should build");
        let partials = [1_u8, 2, 3]
            .into_iter()
            .map(|idx| {
                partial_signature(
                    BlstImpl
                        .sign(
                            secret_shares.get(&idx).expect("share should exist"),
                            &sig_root,
                        )
                        .expect("signing should succeed"),
                    u64::from(idx),
                )
            })
            .collect::<Vec<_>>();

        let deposit_datas = agg_deposit_data(
            &HashMap::from([(core_pub_key, partials)]),
            &[share],
            &HashMap::from([(core_pub_key, msg)]),
            "goerli",
        )
        .expect("aggregation should succeed");

        assert_eq!(deposit_datas.len(), 1);
    }

    #[test]
    fn agg_lock_hash_sig_accepts_valid_signatures() {
        let (share, secret_shares) = build_share_fixture();
        let core_pub_key = PubKey::try_from(share.pub_key.as_slice()).expect("pubkey should fit");
        let hash = b"cluster lock hash";
        let partials = [1_u8, 2, 3]
            .into_iter()
            .map(|idx| {
                partial_signature(
                    BlstImpl
                        .sign(secret_shares.get(&idx).expect("share should exist"), hash)
                        .expect("signing should succeed"),
                    u64::from(idx),
                )
            })
            .collect::<Vec<_>>();

        let (sig, pubkeys) = agg_lock_hash_sig(
            &HashMap::from([(core_pub_key, partials)]),
            &HashMap::from([(core_pub_key, share)]),
            hash,
        )
        .expect("aggregation should succeed");

        assert_ne!(sig, [0; 96]);
        assert_eq!(pubkeys.len(), 3);
    }

    #[test]
    fn agg_validator_registrations_rejects_unknown_pubkeys() {
        let (share, secret_shares) = build_share_fixture();
        let pub_key = pubkey_to_eth2(share.pub_key);
        let reg_msg = registration::new_message(
            pub_key,
            "0x000000000000000000000000000000000000dEaD",
            registration::DEFAULT_GAS_LIMIT,
            1_616_508_000,
        )
        .expect("message should build");
        let sig_root = registration::get_message_signing_root(
            &reg_msg,
            network::network_to_fork_version_bytes("goerli")
                .expect("network should exist")
                .as_slice()
                .try_into()
                .expect("fork version should fit"),
        );
        let partials = [1_u8, 2, 3]
            .into_iter()
            .map(|idx| {
                partial_signature(
                    BlstImpl
                        .sign(
                            secret_shares.get(&idx).expect("share should exist"),
                            &sig_root,
                        )
                        .expect("signing should succeed"),
                    u64::from(idx),
                )
            })
            .collect::<Vec<_>>();

        let reg = CoreRegistration::new(VersionedSignedValidatorRegistration {
            version: BuilderVersion::V1,
            v1: Some(v1::SignedValidatorRegistration {
                message: reg_msg,
                signature: [0; 96],
            }),
        })
        .expect("registration wrapper should be valid");
        let unknown_pubkey = PubKey::new([0x42; 48]);

        let err = agg_validator_registrations(
            &HashMap::from([(unknown_pubkey, partials)]),
            &[share],
            &HashMap::from([(unknown_pubkey, reg)]),
            &network::network_to_fork_version_bytes("goerli").expect("network should exist"),
        )
        .expect_err("aggregation should fail");

        assert!(matches!(
            err,
            AggregateError::InvalidPubKeyFromPeer {
                context: "validator registrations"
            }
        ));
    }
}
