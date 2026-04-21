use std::collections::HashMap;

use pluto_cluster::{
    deposit::DepositData,
    distvalidator::DistValidator,
    registration::{BuilderRegistration, Registration},
};
use pluto_core::{
    signeddata::{SignedDataError, VersionedSignedValidatorRegistration},
    types::SignedData,
};
use pluto_eth2api::{spec::phase0, v1, versioned};

use crate::share::{Share, ShareMsg};

/// Result type for DKG validator helpers.
pub type Result<T> = std::result::Result<T, ValidatorsError>;

/// Error type for DKG validator helpers.
#[derive(Debug, thiserror::Error)]
pub enum ValidatorsError {
    /// Builder registration payload is missing.
    #[error("no V1 registration")]
    MissingV1Registration,

    /// Builder registration version is unsupported.
    #[error("unknown version")]
    UnknownVersion,

    /// Failed to update the registration signature.
    #[error(transparent)]
    SignedData(#[from] SignedDataError),

    /// Registration timestamp is outside the supported range.
    #[error("invalid registration timestamp: {0}")]
    InvalidRegistrationTimestamp(u64),

    /// Validator registration for a distributed validator was not found.
    #[error("validator registration not found")]
    ValidatorRegistrationNotFound,

    /// Deposit data for the given distributed validator public key was not
    /// found.
    #[error("deposit data not found for pubkey: {0}")]
    DepositDataNotFound(String),
}

/// Converts a versioned validator registration into cluster lock format.
pub fn builder_registration_from_eth2(
    reg: &VersionedSignedValidatorRegistration,
) -> Result<BuilderRegistration> {
    let v1 = registration_v1(reg)?;

    Ok(BuilderRegistration {
        message: Registration {
            fee_recipient: v1.message.fee_recipient,
            gas_limit: v1.message.gas_limit,
            timestamp: chrono::DateTime::from_timestamp(
                i64::try_from(v1.message.timestamp).map_err(|_| {
                    ValidatorsError::InvalidRegistrationTimestamp(v1.message.timestamp)
                })?,
                0,
            )
            .ok_or(ValidatorsError::InvalidRegistrationTimestamp(
                v1.message.timestamp,
            ))?,
            pub_key: v1.message.pubkey,
        },
        signature: v1.signature,
    })
}

/// Returns a copy of the registration with the signature replaced.
pub fn set_registration_signature(
    reg: &VersionedSignedValidatorRegistration,
    sig: pluto_core::types::Signature,
) -> Result<VersionedSignedValidatorRegistration> {
    Ok(reg.set_signature(sig)?)
}

/// Builds distributed validators from shares, deposit data, and registrations.
pub fn create_dist_validators(
    shares: &[Share],
    deposit_datas: &[Vec<phase0::DepositData>],
    val_regs: &[VersionedSignedValidatorRegistration],
) -> Result<Vec<DistValidator>> {
    let mut deposit_datas_map: HashMap<phase0::BLSPubKey, Vec<DepositData>> = HashMap::new();
    for amount_level in deposit_datas {
        for dd in amount_level {
            deposit_datas_map
                .entry(dd.pubkey)
                .or_default()
                .push(deposit_data_from_phase0(dd));
        }
    }

    let registrations_by_pubkey: HashMap<phase0::BLSPubKey, BuilderRegistration> = val_regs
        .iter()
        .map(|reg| {
            Ok((
                registration_pubkey(reg)?,
                builder_registration_from_eth2(reg)?,
            ))
        })
        .collect::<Result<_>>()?;

    let mut dvs = Vec::with_capacity(shares.len());
    for share in shares {
        let msg = ShareMsg::from(share);
        let builder_registration = registrations_by_pubkey
            .get(&share.pub_key)
            .cloned()
            .ok_or(ValidatorsError::ValidatorRegistrationNotFound)?;

        let partial_deposit_data = deposit_datas_map
            .remove(&share.pub_key)
            .ok_or_else(|| ValidatorsError::DepositDataNotFound(hex::encode(share.pub_key)))?;

        dvs.push(DistValidator {
            pub_key: msg.pub_key,
            pub_shares: msg.pub_shares,
            partial_deposit_data,
            builder_registration,
        });
    }

    Ok(dvs)
}

fn registration_pubkey(reg: &VersionedSignedValidatorRegistration) -> Result<phase0::BLSPubKey> {
    Ok(registration_v1(reg)?.message.pubkey)
}

fn registration_v1(
    reg: &VersionedSignedValidatorRegistration,
) -> Result<&v1::SignedValidatorRegistration> {
    match reg.0.version {
        versioned::BuilderVersion::V1 => reg
            .0
            .v1
            .as_ref()
            .ok_or(ValidatorsError::MissingV1Registration),
        versioned::BuilderVersion::Unknown => Err(ValidatorsError::UnknownVersion),
    }
}

fn deposit_data_from_phase0(dd: &phase0::DepositData) -> DepositData {
    DepositData {
        pub_key: dd.pubkey,
        withdrawal_credentials: dd.withdrawal_credentials,
        amount: dd.amount,
        signature: dd.signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    use pluto_core::signeddata::VersionedSignedValidatorRegistration as CoreRegistration;
    use pluto_eth2api::{
        spec::phase0::BLSPubKey, v1, versioned::VersionedSignedValidatorRegistration,
    };

    fn make_core_registration(
        pub_key: BLSPubKey,
        fee_recipient: [u8; 20],
        gas_limit: u64,
        timestamp: u64,
        signature: [u8; 96],
    ) -> CoreRegistration {
        CoreRegistration::new(VersionedSignedValidatorRegistration {
            version: versioned::BuilderVersion::V1,
            v1: Some(v1::SignedValidatorRegistration {
                message: v1::ValidatorRegistration {
                    fee_recipient,
                    gas_limit,
                    timestamp,
                    pubkey: pub_key,
                },
                signature,
            }),
        })
        .expect("registration should be valid")
    }

    #[test]
    fn builder_registration_from_eth2_preserves_fields() {
        let pub_key = [0x11; 48];
        let fee_recipient = [0x22; 20];
        let gas_limit = 30_000_000;
        let timestamp = 1_746_843_400;
        let signature = [0x33; 96];
        let reg = make_core_registration(pub_key, fee_recipient, gas_limit, timestamp, signature);

        let builder_registration =
            builder_registration_from_eth2(&reg).expect("conversion should succeed");

        assert_eq!(builder_registration.message.pub_key, pub_key);
        assert_eq!(builder_registration.message.fee_recipient, fee_recipient);
        assert_eq!(builder_registration.message.gas_limit, gas_limit);
        assert_eq!(
            u64::try_from(builder_registration.message.timestamp.timestamp())
                .expect("timestamp should fit"),
            timestamp
        );
        assert_eq!(builder_registration.signature, signature);
    }

    #[test]
    fn set_registration_signature_updates_v1_signature() {
        let reg =
            make_core_registration([0x11; 48], [0x22; 20], 30_000_000, 1_746_843_400, [0; 96]);
        let updated =
            set_registration_signature(&reg, pluto_core::types::Signature::new([0x44; 96]))
                .expect("should work");

        let builder_registration =
            builder_registration_from_eth2(&updated).expect("conversion should succeed");
        assert_eq!(builder_registration.signature, [0x44; 96]);
    }

    #[test]
    fn create_dist_validators_builds_expected_shape() {
        let (lock, ..) = pluto_cluster::test_cluster::new_for_test(1, 3, 4, 0);
        let dv = &lock.distributed_validators[0];
        let deposit_data = phase0::DepositData {
            pubkey: dv
                .pub_key
                .as_slice()
                .try_into()
                .expect("pubkey should be 48 bytes"),
            withdrawal_credentials: [0x11; 32],
            amount: 32_000_000_000,
            signature: [0x22; 96],
        };

        let public_shares = dv
            .pub_shares
            .iter()
            .enumerate()
            .map(|(idx, share)| {
                (
                    u64::try_from(idx + 1).expect("share index should fit"),
                    share
                        .as_slice()
                        .try_into()
                        .expect("public share should be 48 bytes"),
                )
            })
            .collect::<HashMap<_, _>>();
        let shares = vec![Share {
            pub_key: dv
                .pub_key
                .as_slice()
                .try_into()
                .expect("pubkey should be 48 bytes"),
            secret_share: [0x55; 32],
            public_shares,
        }];

        let deposit_datas = vec![vec![deposit_data]];

        let reg = CoreRegistration::new(dv.eth2_registration().expect("registration should exist"))
            .expect("registration wrapper should be valid");

        let validators =
            create_dist_validators(&shares, &deposit_datas, &[reg]).expect("should succeed");

        assert_eq!(validators.len(), 1);
        assert_eq!(validators[0].pub_key, dv.pub_key);
        assert_eq!(validators[0].pub_shares, dv.pub_shares);
        assert_eq!(
            validators[0].partial_deposit_data,
            vec![DepositData {
                pub_key: deposit_datas[0][0].pubkey,
                withdrawal_credentials: deposit_datas[0][0].withdrawal_credentials,
                amount: deposit_datas[0][0].amount,
                signature: deposit_datas[0][0].signature,
            }]
        );
        assert_eq!(validators[0].builder_registration, dv.builder_registration);
    }

    #[test]
    fn create_dist_validators_fails_when_registration_missing() {
        let (lock, ..) = pluto_cluster::test_cluster::new_for_test(1, 3, 4, 0);
        let dv = &lock.distributed_validators[0];
        let deposit_data = phase0::DepositData {
            pubkey: dv
                .pub_key
                .as_slice()
                .try_into()
                .expect("pubkey should be 48 bytes"),
            withdrawal_credentials: [0x11; 32],
            amount: 32_000_000_000,
            signature: [0x22; 96],
        };
        let shares = vec![Share {
            pub_key: dv
                .pub_key
                .as_slice()
                .try_into()
                .expect("pubkey should be 48 bytes"),
            secret_share: [0x55; 32],
            public_shares: HashMap::new(),
        }];
        let deposit_datas = vec![vec![deposit_data]];

        let err = create_dist_validators(&shares, &deposit_datas, &[]).expect_err("should fail");
        assert!(matches!(
            err,
            ValidatorsError::ValidatorRegistrationNotFound
        ));
    }

    #[test]
    fn create_dist_validators_fails_when_deposit_data_missing() {
        let (lock, ..) = pluto_cluster::test_cluster::new_for_test(1, 3, 4, 0);
        let dv = &lock.distributed_validators[0];
        let shares = vec![Share {
            pub_key: dv
                .pub_key
                .as_slice()
                .try_into()
                .expect("pubkey should be 48 bytes"),
            secret_share: [0x55; 32],
            public_shares: HashMap::new(),
        }];
        let reg = CoreRegistration::new(dv.eth2_registration().expect("registration should exist"))
            .expect("registration wrapper should be valid");

        let err = create_dist_validators(&shares, &[], &[reg]).expect_err("should fail");
        assert!(matches!(err, ValidatorsError::DepositDataNotFound(_)));
    }
}
