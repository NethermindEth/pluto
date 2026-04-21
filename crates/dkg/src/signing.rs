use std::collections::HashMap;

use crate::share::Share;
use pluto_core::{
    signeddata::VersionedSignedValidatorRegistration,
    types::{ParSignedData, ParSignedDataSet, PubKey},
};
use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls, tblsconv::pubkey_to_eth2};
use pluto_eth2api::{spec::phase0, v1, versioned};
use pluto_eth2util::{deposit, network, registration};

/// Result type for DKG signing helpers.
pub type Result<T> = std::result::Result<T, SigningError>;

/// Error type for DKG signing helpers.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// Failed to build a core public key from bytes.
    #[error("invalid public key length")]
    InvalidPublicKeyLength,

    /// Failed to sign or verify with threshold BLS.
    #[error(transparent)]
    Crypto(#[from] pluto_crypto::types::Error),

    /// Failed to build or hash deposit data.
    #[error(transparent)]
    Deposit(#[from] deposit::DepositError),

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
}

/// Returns partially signed signatures of the lock hash.
pub fn sign_lock_hash(share_idx: u64, shares: &[Share], hash: &[u8]) -> Result<ParSignedDataSet> {
    let mut set = ParSignedDataSet::new();

    for share in shares {
        let pub_key = PubKey::try_from(share.pub_key.as_slice())
            .map_err(|_| SigningError::InvalidPublicKeyLength)?;
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
        let pub_key = share_pubkey(share)?;
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
    let fork_version: phase0::Version = fork_version
        .try_into()
        .map_err(|_| SigningError::InvalidForkVersionLength)?;

    let mut msgs = HashMap::with_capacity(shares.len());
    let mut set = ParSignedDataSet::new();

    for (share, fee_recipient) in shares.iter().zip(fee_recipients.iter()) {
        let eth2_pubkey = pubkey_to_eth2(share.pub_key);
        let pub_key = share_pubkey(share)?;

        let reg_msg = registration::new_message(
            eth2_pubkey,
            fee_recipient,
            gas_limit,
            u64::try_from(timestamp.timestamp())?,
        )?;
        let sig_root = registration::get_message_signing_root(&reg_msg, fork_version);
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

fn share_pubkey(share: &Share) -> Result<PubKey> {
    PubKey::try_from(share.pub_key.as_slice()).map_err(|_| SigningError::InvalidPublicKeyLength)
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
