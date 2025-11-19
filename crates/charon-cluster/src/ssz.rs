#![allow(unused)]

use ssz::Encode;

use crate::{
    definition::{ADDRESS_LEN, Definition, DefinitionSSZ},
    deposit::DepositData,
    distvalidator::DistValidator,
    helpers::{from_0x_hex_str, put_byte_list, put_bytes_n, put_hex_bytes_20},
    lock::Lock,
    manifestpb::v1::Validator,
    registration::{BuilderRegistration, Registration},
    ssz_hasher::{HashWalker, Hasher, HasherError},
    version::{ZERO_NONCE, versions::*},
};

/// Maximum length of the ENR.
pub const SSZ_MAX_ENR: usize = 1024;
/// Maximum length of a name.
pub const SSZ_MAX_NAME: usize = 256;
/// Maximum length of a UUID.
pub const SSZ_MAX_UUID: usize = 64;
/// Maximum length of a version identifier.
pub const SSZ_MAX_VERSION: usize = 16;
/// Maximum length of a timestamp.
pub const SSZ_MAX_TIMESTAMP: usize = 32;
/// Maximum length of a DKG (Distributed Key Generation) algorithm name.
pub const SSZ_MAX_DKG_ALGORITHM: usize = 32;
/// Maximum number of operators.
pub const SSZ_MAX_OPERATORS: usize = 256;
/// Maximum number of validators.
pub const SSZ_MAX_VALIDATORS: usize = 65536;
/// Maximum number of deposit amounts.
pub const SSZ_MAX_DEPOSIT_AMOUNTS: usize = 256;
/// Length of the fork version.
pub const SSZ_LEN_FORK_VERSION: usize = 4;
/// Length of a K1 signature.
pub const SSZ_LEN_K1_SIG: usize = 65;
/// Length of a BLS signature.
pub const SSZ_LEN_BLS_SIG: usize = 96;
/// Length of a hash.
pub const SSZ_LEN_HASH: usize = 32;
/// Length of withdrawal credentials.
pub const SSZ_LEN_WITHDRAW_CREDS: usize = 32;
/// Length of a public key.
pub const SSZ_LEN_PUB_KEY: usize = 48;

/// HashFunc is a function that hashes a definition
pub type HashFuncWithBool<T, H> = fn(&T, &mut H, bool) -> Result<(), SSZError<H>>;

/// HashFuncWithVersion is a function that hashes a definition with a version.
pub type HashFuncWithVersion<T, H> = fn(&T, &mut H, &str) -> Result<(), SSZError<H>>;

/// HashFunc is a function that hashes a definition.
pub type HashFunc<T, H> = fn(&T, &mut H) -> Result<(), SSZError<H>>;

/// SSZError is an error type for SSZ errors.
#[derive(Debug, thiserror::Error)]
pub enum SSZError<H: HashWalker> {
    /// Invalid length
    #[error(
        "Invalid list size: function: {namespace}, field: {field}, actual: {actual}, expected: {expected}"
    )]
    IncorrectListSize {
        /// Namespace of the field.
        namespace: &'static str,
        /// Field name.
        field: String,
        /// Actual size of the list.
        actual: usize,
        /// Expected size of the list.
        expected: usize,
    },

    /// Hash walker error
    #[error("Hash walker error: {0}")]
    HashWalkerError(<H as HashWalker>::Error),

    /// Unsupported version
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(String),

    /// Definition error
    #[error("Definition error: {0}")]
    DefinitionError(#[from] crate::definition::DefinitionError),

    /// Failed to convert hex string
    #[error("Failed to convert hex string: {0}")]
    FailedToConvertHexString(#[from] hex::FromHexError),
}

impl From<HasherError> for SSZError<Hasher> {
    fn from(error: HasherError) -> Self {
        SSZError::HashWalkerError(error)
    }
}

fn get_definition_hash_func<H: HashWalker>(
    version: &str,
) -> Result<HashFuncWithBool<Definition, H>, SSZError<H>> {
    Ok(match version {
        V1_0 | V1_1 | V1_2 => hash_definition_legacy::<H>,
        V1_3 | V1_4 => hash_definition_v1x3or4::<H>,
        V1_5 | V1_6 | V1_7 => hash_definition_v1x5to7::<H>,
        V1_8 => hash_definition_v1x8::<H>,
        V1_9 => hash_definition_v1x9::<H>,
        V1_10 => hash_definition_v1x10::<H>,
        version => return Err(SSZError::UnsupportedVersion(version.to_string())),
    })
}

pub(crate) fn hash_definition(
    definition: Definition,
    config_only: bool,
) -> Result<[u8; 32], SSZError<Hasher>> {
    let hash_func = get_definition_hash_func::<Hasher>(&definition.version)?;

    let mut hh = Hasher::new();

    hash_func(&definition, &mut hh, config_only)?;

    Ok(hh.hash_root()?)
}

pub(crate) fn hash_definition_legacy<H: HashWalker>(
    definition: &Definition,
    hh: &mut H,
    config_only: bool,
) -> Result<(), SSZError<H>> {
    let vaddrs = definition.legacy_validator_addresses()?;

    let indx = hh.index();

    // Field(0) 'uuid'
    hh.put_bytes(definition.uuid.as_bytes())
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (1) 'name'
    hh.put_bytes(definition.name.as_bytes())
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (2) 'version'
    hh.put_bytes(definition.version.as_bytes())
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (3) 'numValidators'
    hh.put_uint64(definition.num_validators)
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (4) 'threshold'
    hh.put_uint64(definition.threshold)
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (5) 'feeRecipientAddress'
    hh.put_bytes(vaddrs.fee_recipient_address.as_bytes())
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (6) 'withdrawalAddress'
    hh.put_bytes(vaddrs.withdrawal_address.as_bytes())
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (7) 'dkgAlgorithm'
    hh.put_bytes(definition.dkg_algorithm.as_bytes())
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (8) 'forkVersion'
    hh.put_bytes(&definition.fork_version)
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (9) 'addresses'
    {
        let sub_indx = hh.index();

        let num = definition.operators.len();

        for o in &definition.operators {
            if config_only {
                hh.put_bytes(o.address.as_bytes())
                    .map_err(SSZError::<H>::HashWalkerError)?;
                continue;
            }

            let op_sub_idx = hh.index();

            // Field (0) 'Address'
            hh.put_bytes(o.address.as_bytes())
                .map_err(SSZError::<H>::HashWalkerError)?;

            // Field (1) 'ENR'
            hh.put_bytes(o.enr.as_bytes())
                .map_err(SSZError::<H>::HashWalkerError)?;

            // Note: This depends on the version: add zero nonce for v1.0/v1.1 ("legacy")
            if matches!(definition.version.as_str(), V1_0 | V1_1) {
                // Field (2) 'Nonce'
                hh.put_uint64(ZERO_NONCE)
                    .map_err(SSZError::<H>::HashWalkerError)?;
            }

            // Field (2 or 3) 'ConfigSignature'
            hh.put_bytes(&o.config_signature)
                .map_err(SSZError::<H>::HashWalkerError)?;

            // Field (3 or 4) 'ENRSignature'
            hh.put_bytes(&o.enr_signature)
                .map_err(SSZError::<H>::HashWalkerError)?;

            hh.merkleize(op_sub_idx)
                .map_err(SSZError::<H>::HashWalkerError)?;
        }

        hh.merkleize_with_mixin(sub_indx, num, num)
            .map_err(SSZError::<H>::HashWalkerError)?;
    }

    // Field (10) 'timestamp' (optional for backwards compatibility)
    if config_only && definition.timestamp.timestamp() != 0 {
        hh.put_bytes(&definition.timestamp.to_rfc3339().as_bytes())
            .map_err(SSZError::<H>::HashWalkerError)?;
    } else if definition.version != V1_0 {
        hh.put_bytes(&definition.timestamp.to_rfc3339().as_bytes())
            .map_err(SSZError::<H>::HashWalkerError)?;
    }

    hh.merkleize(indx).map_err(SSZError::<H>::HashWalkerError)?;

    Ok(())
}

pub(crate) fn hash_definition_v1x3or4<H: HashWalker>(
    definition: &Definition,
    hh: &mut H,
    config_only: bool,
) -> Result<(), SSZError<H>> {
    let vaddrs = definition.legacy_validator_addresses()?;

    let fee_recipient_address = from_0x_hex_str(&vaddrs.fee_recipient_address, ADDRESS_LEN)?;
    let withdrawal_address = from_0x_hex_str(&vaddrs.withdrawal_address, ADDRESS_LEN)?;

    let indx = hh.index();

    // Field (0) 'uuid'
    hh.put_bytes(definition.uuid.as_bytes())
        .map_err(SSZError::<H>::HashWalkerError)?;
    // Field (1) 'name'
    hh.put_bytes(definition.name.as_bytes())
        .map_err(SSZError::<H>::HashWalkerError)?;
    // Field (2) 'version'
    hh.put_bytes(definition.version.as_bytes())
        .map_err(SSZError::<H>::HashWalkerError)?;
    // Field (3) 'timestamp'
    hh.put_bytes(definition.timestamp.to_rfc3339().as_bytes())
        .map_err(SSZError::<H>::HashWalkerError)?;
    // Field (4) 'numValidators'
    hh.put_uint64(definition.num_validators)
        .map_err(SSZError::<H>::HashWalkerError)?;
    // Field (5) 'threshold'
    hh.put_uint64(definition.threshold)
        .map_err(SSZError::<H>::HashWalkerError)?;
    // Field (6) 'feeRecipientAddress'
    hh.put_bytes(&fee_recipient_address)
        .map_err(SSZError::<H>::HashWalkerError)?;
    // Field (7) 'withdrawalAddress'
    hh.put_bytes(&withdrawal_address)
        .map_err(SSZError::<H>::HashWalkerError)?;
    // Field (8) 'dkgAlgorithm'
    hh.put_bytes(definition.dkg_algorithm.as_bytes())
        .map_err(SSZError::<H>::HashWalkerError)?;
    // Field (9) 'forkVersion'
    hh.put_bytes(&definition.fork_version)
        .map_err(SSZError::<H>::HashWalkerError)?;
    // Field (10) 'operators'
    {
        let operators_idx = hh.index();
        let num = definition.operators.len();
        for o in &definition.operators {
            let op_sub_idx = hh.index();

            // Field (0) 'Address'
            hh.put_bytes(from_0x_hex_str(&o.address, ADDRESS_LEN)?.as_slice())
                .map_err(SSZError::<H>::HashWalkerError)?;
        }
        hh.merkleize_with_mixin(operators_idx, num, num)
            .map_err(SSZError::<H>::HashWalkerError)?;
    }

    if definition.version != V1_3 {
        // Field (11) 'Creator' Composite for v1.4 and later
        let creator_idx = hh.index();

        // Field (0) 'Address' Bytes20
        let addr_bytes = from_0x_hex_str(&definition.creator.address, ADDRESS_LEN)?;

        hh.put_bytes(&addr_bytes)
            .map_err(SSZError::<H>::HashWalkerError)?;

        if !config_only {
            hh.put_bytes(&definition.creator.config_signature)
                .map_err(SSZError::<H>::HashWalkerError)?;
        }

        hh.merkleize(creator_idx)
            .map_err(SSZError::<H>::HashWalkerError)?;
    }

    if !config_only {
        // Field (12) 'ConfigHash' Bytes32
        hh.put_bytes(&definition.config_hash)
            .map_err(SSZError::<H>::HashWalkerError)?;
    }

    hh.merkleize(indx).map_err(SSZError::<H>::HashWalkerError)?;

    Ok(())
}

pub(crate) fn hash_definition_v1x5to9<H: HashWalker, F>(
    definition: &Definition,
    hh: &mut H,
    config_only: bool,
    extra: Vec<F>,
) -> Result<(), SSZError<H>>
where
    F: FnOnce(&Definition, &mut H) -> Result<(), SSZError<H>> + Send + Sync,
{
    let indx = hh.index();

    // Field (0) 'uuid' ByteList[64]
    hh.put_bytes(definition.uuid.as_bytes())
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (1) 'name' ByteList[256]
    hh.put_bytes(definition.name.as_bytes())
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (2) 'version' ByteList[16]
    hh.put_bytes(definition.version.as_bytes())
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (3) 'timestamp' ByteList[32]
    hh.put_bytes(definition.timestamp.to_rfc3339().as_bytes())
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (4) 'numValidators' Uint64
    hh.put_uint64(definition.num_validators)
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (5) 'threshold' Uint64
    hh.put_uint64(definition.threshold)
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (6) 'DKGAlgorithm' ByteList[32]
    hh.put_bytes(definition.dkg_algorithm.as_bytes())
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (7) 'forkVersion' ByteList[4]
    hh.put_bytes(&definition.fork_version)
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (8) 'Operators' CompositeList[256]
    {
        let operators_idx = hh.index();

        let num = definition.operators.len();

        for operator in &definition.operators {
            let op_sub_idx = hh.index();

            // Field (0) 'Address' Bytes20
            put_hex_bytes_20(hh, &operator.address)?;

            if !config_only {
                // Field (1) 'ENR' ByteList[1024]
                put_byte_list(hh, operator.enr.as_bytes(), SSZ_MAX_ENR, "ENR")?;

                // Field (2) 'ConfigSignature' Bytes65
                put_bytes_n(hh, &operator.config_signature, SSZ_LEN_K1_SIG)?;

                // Field (3) 'ENRSignature' Bytes65
                put_bytes_n(hh, &operator.enr_signature, SSZ_LEN_K1_SIG)?;
            }

            hh.merkleize(op_sub_idx)
                .map_err(SSZError::<H>::HashWalkerError)?;
        }

        hh.merkleize_with_mixin(operators_idx, num, SSZ_MAX_OPERATORS)
            .map_err(SSZError::<H>::HashWalkerError)?;
    }

    // Field (9) 'Creator' Composite for v1.4 and later
    {
        let creator_idx = hh.index();

        // Field (0) 'Address' Bytes20
        put_hex_bytes_20(hh, &definition.creator.address)?;

        if !config_only {
            // Field (1) 'ConfigSignature' Bytes65
            put_bytes_n(hh, &definition.creator.config_signature, SSZ_LEN_K1_SIG)?;
        }

        hh.merkleize(creator_idx)
            .map_err(SSZError::<H>::HashWalkerError)?;
    }

    // Field (10) 'ValidatorAddresses' CompositeList[65536]
    {
        let validator_addresses_idx = hh.index();
        let num = definition.validator_addresses.len();
        for validator_address in &definition.validator_addresses {
            let validator_address_sub_idx = hh.index();

            // Field (0) 'FeeRecipientAddress' Bytes20
            put_hex_bytes_20(hh, &validator_address.fee_recipient_address)?;

            // Field (1) 'WithdrawalAddress' Bytes20
            put_hex_bytes_20(hh, &validator_address.withdrawal_address)?;

            hh.merkleize(validator_address_sub_idx)
                .map_err(SSZError::<H>::HashWalkerError)?;
        }

        hh.merkleize_with_mixin(validator_addresses_idx, num, SSZ_MAX_VALIDATORS)
            .map_err(SSZError::<H>::HashWalkerError)?;
    }

    // Fields from index 11 onwards
    for f in extra {
        f(definition, hh)?;
    }

    if !config_only {
        // Field (last) 'ConfigHash' Bytes32
        hh.put_bytes(&definition.config_hash)
            .map_err(SSZError::<H>::HashWalkerError)?;
    }

    hh.merkleize(indx).map_err(SSZError::<H>::HashWalkerError)?;

    Ok(())
}

/// Empty extra function that does nothing. Used as a default when no extra
/// functions are provided.
fn empty_extra_func<H: HashWalker>(
    _definition: &Definition,
    _hh: &mut H,
) -> Result<(), SSZError<H>> {
    Ok(())
}

pub(crate) fn hash_definition_v1x5to7<H: HashWalker>(
    definition: &Definition,
    hh: &mut H,
    config_only: bool,
) -> Result<(), SSZError<H>> {
    hash_definition_v1x5to9(definition, hh, config_only, vec![empty_extra_func::<H>])
}

pub(crate) fn hash_definition_v1x8to10<H: HashWalker, F>(
    definition: &Definition,
    hh: &mut H,
    config_only: bool,
    extra: Vec<F>,
) -> Result<(), SSZError<H>>
where
    F: FnOnce(&Definition, &mut H) -> Result<(), SSZError<H>> + Send + Sync,
{
    hash_definition_v1x5to9(
        definition,
        hh,
        config_only,
        vec![Box::new(
            |definition: &Definition, hh: &mut H| -> Result<(), SSZError<H>> {
                // Field (11) 'DepositAmounts' Uint64[256]
                let amounts64: Vec<u64> = definition
                    .deposit_amounts
                    .iter()
                    .map(|a| *a as u64)
                    .collect();

                hh.put_uint64_array(&amounts64, SSZ_MAX_DEPOSIT_AMOUNTS)
                    .map_err(SSZError::<H>::HashWalkerError)?;

                for f in extra {
                    f(definition, hh)?;
                }

                Ok(())
            },
        )],
    )
}

fn extra_func_consensus_protocol<H: HashWalker>(
    definition: &Definition,
    hh: &mut H,
) -> Result<(), SSZError<H>> {
    put_byte_list(
        hh,
        definition.consensus_protocol.as_bytes(),
        SSZ_MAX_NAME,
        "consensus_protocol",
    )?;

    Ok(())
}

fn extra_func_target_gas_limit_and_compounding<H: HashWalker>(
    definition: &Definition,
    hh: &mut H,
) -> Result<(), SSZError<H>> {
    hh.put_uint64(definition.target_gas_limit)
        .map_err(SSZError::<H>::HashWalkerError)?;

    hh.put_bool(definition.compounding)
        .map_err(SSZError::<H>::HashWalkerError)?;

    Ok(())
}

pub(crate) fn hash_definition_v1x8<H: HashWalker>(
    definition: &Definition,
    hh: &mut H,
    config_only: bool,
) -> Result<(), SSZError<H>> {
    hash_definition_v1x8to10(definition, hh, config_only, vec![empty_extra_func::<H>])
}

pub(crate) fn hash_definition_v1x9<H: HashWalker>(
    definition: &Definition,
    hh: &mut H,
    config_only: bool,
) -> Result<(), SSZError<H>> {
    hash_definition_v1x8to10(
        definition,
        hh,
        config_only,
        vec![extra_func_consensus_protocol::<H>],
    )
}

pub(crate) fn hash_definition_v1x10<H: HashWalker>(
    definition: &Definition,
    hh: &mut H,
    config_only: bool,
) -> Result<(), SSZError<H>> {
    hash_definition_v1x8to10(
        definition,
        hh,
        config_only,
        vec![
            extra_func_consensus_protocol::<H>,
            extra_func_target_gas_limit_and_compounding::<H>,
        ],
    )
}

// ==== Lock Hashing ====

pub(crate) fn hash_lock(lock: &Lock) -> Result<[u8; 32], SSZError<Hasher>> {
    let hash_func = match lock.version.as_str() {
        V1_0 | V1_1 | V1_2 => hash_lock_legacy,
        V1_3 | V1_4 | V1_5 | V1_6 | V1_7 | V1_8 | V1_9 | V1_10 => hash_lock_v1x3_or_later,
        _ => return Err(SSZError::UnsupportedVersion(lock.version.clone())),
    };

    let mut hh = Hasher::new();
    hash_func(lock, &mut hh)?;
    Ok(hh.hash_root()?)
}

pub(crate) fn hash_lock_v1x3_or_later<H: HashWalker>(
    lock: &Lock,
    hh: &mut H,
) -> Result<(), SSZError<H>> {
    let indx = hh.index();

    let def_hash_func = get_definition_hash_func::<H>(&lock.version)?;

    let val_hash_func = get_validator_hash_func::<H>(&lock.version)?;

    // Field (0) 'Definition' Composite
    def_hash_func(&lock.definition, hh, false)?;

    // Field (1) 'Validators' CompositeList[65536]
    {
        let validators_idx = hh.index();

        let num = lock.distributed_validators.len();

        for validator in &lock.distributed_validators {
            val_hash_func(validator, hh, &lock.version)?;
        }

        hh.merkleize_with_mixin(validators_idx, num, SSZ_MAX_VALIDATORS)
            .map_err(SSZError::<H>::HashWalkerError)?;
    }

    hh.merkleize(indx).map_err(SSZError::<H>::HashWalkerError)?;

    Ok(())
}

// ==== Validator Hashing ====

pub(crate) fn get_validator_hash_func<H: HashWalker>(
    version: &str,
) -> Result<HashFuncWithVersion<DistValidator, H>, SSZError<H>> {
    Ok(match version {
        V1_3 | V1_4 => hash_validator_v1x3or4::<H>,
        V1_5 | V1_6 | V1_7 => hash_validator_v1x5to7::<H>,
        V1_8 | V1_9 | V1_10 => hash_validator_v1x8_or_later::<H>,
        version => return Err(SSZError::UnsupportedVersion(version.to_string())),
    })
}

pub(crate) fn hash_validator_pubshares_field<H: HashWalker>(
    validator: &DistValidator,
    hh: &mut H,
) -> Result<(), SSZError<H>> {
    let sub_idx = hh.index();
    let num = validator.pub_shares.len();

    for pub_share in &validator.pub_shares {
        put_bytes_n(hh, pub_share, SSZ_LEN_PUB_KEY)?;
    }

    hh.merkleize_with_mixin(sub_idx, num, SSZ_MAX_OPERATORS)
        .map_err(SSZError::<H>::HashWalkerError)?;

    Ok(())
}

pub(crate) fn hash_validator_v1x3or4<H: HashWalker>(
    validator: &DistValidator,
    hh: &mut H,
    version: &str,
) -> Result<(), SSZError<H>> {
    let indx = hh.index();

    // Field (0) 'Pubkey' Bytes48
    hh.put_bytes(&validator.pub_key)
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (1) 'PubShares' CompositeList[256]
    hash_validator_pubshares_field(validator, hh)?;

    // Field (2) 'FeeRecipientAddress' Bytes20
    hh.put_bytes(&[]);

    hh.merkleize(indx).map_err(SSZError::<H>::HashWalkerError)?;

    Ok(())
}

pub(crate) fn hash_validator_v1x5to7<H: HashWalker>(
    validator: &DistValidator,
    hh: &mut H,
    version: &str,
) -> Result<(), SSZError<H>> {
    let indx = hh.index();

    // Field (0) 'Pubkey' Bytes48
    put_bytes_n(hh, &validator.pub_key, SSZ_LEN_PUB_KEY)?;

    // Field (1) 'PubShares' CompositeList[256]
    hash_validator_pubshares_field(validator, hh)?;

    let deposit_hash_func = get_deposit_data_hash_func(version)?;

    // Field (2) 'DepositData' Composite
    let deposit_data = if validator.partial_deposit_data.len() > 0 {
        &validator.partial_deposit_data[0]
    } else {
        &DepositData::default()
    };

    deposit_hash_func(deposit_data, hh)?;

    let reg_hash_func = get_registration_hash_func(version)?;

    // Field (3) 'BuilderRegistration' Composite
    reg_hash_func(&validator.builder_registration, hh)?;

    hh.merkleize(indx).map_err(SSZError::<H>::HashWalkerError)?;

    Ok(())
}

pub(crate) fn hash_validator_v1x8_or_later<H: HashWalker>(
    validator: &DistValidator,
    hh: &mut H,
    version: &str,
) -> Result<(), SSZError<H>> {
    let indx = hh.index();

    put_bytes_n(hh, &validator.pub_key, SSZ_LEN_PUB_KEY)?;

    hash_validator_pubshares_field(validator, hh)?;

    let deposit_hash_func = get_deposit_data_hash_func(version)?;

    let reg_hash_func = get_registration_hash_func(version)?;

    // Field (2) 'PartialDepositData' Composite[256]
    {
        let pdd_indx = hh.index();
        let num = validator.partial_deposit_data.len();

        for dd in &validator.partial_deposit_data {
            let dd_indx = hh.index();
            deposit_hash_func(dd, hh)?;
            hh.merkleize(dd_indx)
                .map_err(SSZError::<H>::HashWalkerError)?;
        }

        hh.merkleize_with_mixin(pdd_indx, num, SSZ_MAX_DEPOSIT_AMOUNTS)
            .map_err(SSZError::<H>::HashWalkerError)?;
    }

    // Field (3) 'BuilderRegistration' Composite
    reg_hash_func(&validator.builder_registration, hh)?;

    hh.merkleize(indx).map_err(SSZError::<H>::HashWalkerError)?;

    Ok(())
}

pub(crate) fn hash_lock_legacy<H: HashWalker>(lock: &Lock, hh: &mut H) -> Result<(), SSZError<H>> {
    let indx = hh.index();

    // Field (0) 'Definition' Composite
    hash_definition_legacy(&lock.definition, hh, false)?;

    // Field (1) 'ValidatorAddresses'
    {
        let sub_idx = hh.index();
        let num = lock.validator_addresses.len();

        for validator in &lock.distributed_validators {
            hash_validator_legacy(validator, hh)?;
        }

        hh.merkleize_with_mixin(sub_idx, num, num)
            .map_err(SSZError::<H>::HashWalkerError)?;
    }

    hh.merkleize(indx).map_err(SSZError::<H>::HashWalkerError)?;

    Ok(())
}

pub(crate) fn hash_validator_legacy<H: HashWalker>(
    validator: &DistValidator,
    hh: &mut H,
) -> Result<(), SSZError<H>> {
    let indx = hh.index();

    // Field (0) 'Pubkey' Bytes48
    hh.put_bytes(&validator.pub_key)
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (1) 'PubShares'
    {
        let sub_idx = hh.index();

        let num = validator.pub_shares.len();

        for pub_share in &validator.pub_shares {
            hh.put_bytes(pub_share)
                .map_err(SSZError::<H>::HashWalkerError)?;
        }

        hh.merkleize_with_mixin(sub_idx, num, num)
            .map_err(SSZError::<H>::HashWalkerError)?;
    }

    // Field (2) 'FeeRecipientAddress'
    hh.put_bytes(&[]);

    hh.merkleize(indx).map_err(SSZError::<H>::HashWalkerError)?;

    Ok(())
}

fn noop_hash_func<T, H: HashWalker>(_: &T, _hh: &mut H) -> Result<(), SSZError<H>> {
    Ok(())
}

pub(crate) fn get_deposit_data_hash_func<H: HashWalker>(
    version: &str,
) -> Result<HashFunc<DepositData, H>, SSZError<H>> {
    Ok(match version {
        // Noop hash function for v1.0 to v1.5 that do not support deposit data.
        V1_0 | V1_1 | V1_2 | V1_3 | V1_4 | V1_5 => noop_hash_func::<DepositData, H>,
        V1_6 => hash_deposit_data_v1x6::<H>,
        V1_7 | V1_8 | V1_9 | V1_10 => hash_deposit_data_v1x7_or_later::<H>,
        _ => return Err(SSZError::UnsupportedVersion(version.to_string())),
    })
}

pub(crate) fn get_registration_hash_func<H: HashWalker>(
    version: &str,
) -> Result<HashFunc<BuilderRegistration, H>, SSZError<H>> {
    Ok(match version {
        // Noop hash function for v1.0 to v1.6 that do not support builder registration.
        V1_0 | V1_1 | V1_2 | V1_3 | V1_4 | V1_5 | V1_6 => noop_hash_func::<BuilderRegistration, H>,
        V1_7 | V1_8 | V1_9 | V1_10 => hash_builder_registration::<H>,
        _ => return Err(SSZError::UnsupportedVersion(version.to_string())),
    })
}

pub(crate) fn hash_deposit_data_v1x6<H: HashWalker>(
    deposit_data: &DepositData,
    hh: &mut H,
) -> Result<(), SSZError<H>> {
    let indx = hh.index();

    // Field (0) 'Pubkey' Bytes48
    put_bytes_n(hh, &deposit_data.pub_key, SSZ_LEN_PUB_KEY)?;

    // Field (1) 'WithdrawalCredentials' Bytes32
    put_bytes_n(
        hh,
        &deposit_data.withdrawal_credentials,
        SSZ_LEN_WITHDRAW_CREDS,
    )?;

    // Field (2) 'Amount' Uint64
    hh.put_uint64(deposit_data.amount)
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (3) 'Signature' Bytes96
    put_bytes_n(hh, &deposit_data.signature, SSZ_LEN_BLS_SIG)?;

    // todo(varex83): question why we don't merkleize here?
    Ok(())
}

pub(crate) fn hash_deposit_data_v1x7_or_later<H: HashWalker>(
    deposit_data: &DepositData,
    hh: &mut H,
) -> Result<(), SSZError<H>> {
    let indx = hh.index();

    // Field (0) 'Pubkey' Bytes48
    put_bytes_n(hh, &deposit_data.pub_key, SSZ_LEN_PUB_KEY)?;

    // Field (1) 'WithdrawalCredentials' Bytes32
    put_bytes_n(
        hh,
        &deposit_data.withdrawal_credentials,
        SSZ_LEN_WITHDRAW_CREDS,
    )?;

    // Field (2) 'Amount' Uint64
    hh.put_uint64(deposit_data.amount)
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (3) 'Signature' Bytes96
    put_bytes_n(hh, &deposit_data.signature, SSZ_LEN_BLS_SIG)?;

    hh.merkleize(indx).map_err(SSZError::<H>::HashWalkerError)?;

    Ok(())
}

pub(crate) fn hash_builder_registration<H: HashWalker>(
    builder_registration: &BuilderRegistration,
    hh: &mut H,
) -> Result<(), SSZError<H>> {
    let indx = hh.index();

    // Field (0) 'Message' Composite
    hash_registration(&builder_registration.message, hh)?;

    // Field (1) 'Signature' Bytes96
    put_bytes_n(hh, &builder_registration.signature, SSZ_LEN_BLS_SIG)?;

    hh.merkleize(indx).map_err(SSZError::<H>::HashWalkerError)?;

    Ok(())
}

pub(crate) fn hash_registration<H: HashWalker>(
    registration: &Registration,
    hh: &mut H,
) -> Result<(), SSZError<H>> {
    let indx = hh.index();

    // Field (0) 'FeeRecipient'
    hh.put_bytes(&registration.fee_recipient)
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (1) 'GasLimit' Uint64
    hh.put_uint64(registration.gas_limit)
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (2) 'Timestamp' Uint64
    hh.put_uint64(registration.timestamp.timestamp() as u64)
        .map_err(SSZError::<H>::HashWalkerError)?;

    // Field (3) 'Pubkey' Bytes48
    put_bytes_n(hh, &registration.pub_key, SSZ_LEN_PUB_KEY)?;

    hh.merkleize(indx).map_err(SSZError::<H>::HashWalkerError)?;

    Ok(())
}
