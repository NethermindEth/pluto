use crate::{definition, distvalidator, helpers, lock, operator, registration, version};
use chrono::{TimeZone, Utc};
use pluto_crypto::tbls::Tbls;
use rand::{RngCore, SeedableRng};

/// Returns a new cluster lock with `dv` number of distributed validators, `k`
/// threshold and `n` peers. It also returns the peer p2p keys and BLS secret
/// shares.
///
/// If the seed is zero, a random cluster on available loopback ports
/// is generated, else a deterministic cluster is generated.
pub fn new_for_test(
    dv: u64,
    k: pluto_crypto::types::Index,
    n: pluto_crypto::types::Index,
    seed: u64,
) -> (
    lock::Lock,
    Vec<k256::SecretKey>,
    Vec<Vec<pluto_crypto::types::PrivateKey>>,
) {
    let mut rng = {
        let inner = if seed == 0 {
            rand::rngs::OsRng::next_u64(&mut rand::rngs::OsRng)
        } else {
            seed
        };
        rand::rngs::StdRng::seed_from_u64(inner)
    };

    let mut vals = Vec::new();
    let mut p2p_keys = Vec::new();
    let mut ops = Vec::new();
    let mut dv_shares = Vec::new();

    let mut fee_recipient_addresses = Vec::new();
    let mut withdrawal_addresses = Vec::new();

    for _ in 0..dv {
        let blst = pluto_crypto::blst_impl::BlstImpl;
        let root_secret = blst.generate_insecure_secret(&mut rng).unwrap();
        let root_public = blst.secret_to_public_key(&root_secret).unwrap();
        let shares = blst
            .threshold_split_insecure(&root_secret, n, k, &mut rng)
            .unwrap();

        let mut pub_shares: Vec<pluto_crypto::types::PublicKey> = Vec::new();
        let mut priv_shares: Vec<pluto_crypto::types::PrivateKey> = Vec::new();

        for i in 0..n {
            let share_priv_key = *shares.get(&i).unwrap(); // NOTE: Pluto implementation does not use 1-based indexing for shares
            let share_pub = blst.secret_to_public_key(&share_priv_key).unwrap();

            pub_shares.push(share_pub);
            priv_shares.push(share_priv_key);
        }

        let fee_recipient_address = pluto_testutil::random::random_eth_address(&mut rng);

        let network_name = pluto_eth2util::network::GOERLI.name;
        let reg = get_signed_registration(&root_secret, fee_recipient_address, network_name);

        let dist_validator = distvalidator::DistValidator {
            pub_key: root_public.to_vec(),
            pub_shares: pub_shares.iter().map(|pk| pk.to_vec()).collect(),
            builder_registration: reg,
            partial_deposit_data: Vec::new(),
        };

        vals.push(dist_validator);
        dv_shares.push(priv_shares);

        fee_recipient_addresses.push(helpers::to_0x_hex(&fee_recipient_address));
        withdrawal_addresses.push(helpers::to_0x_hex(
            &pluto_testutil::random::random_eth_address(&mut rng),
        ));
    }

    for i in 0..n {
        // Generate ENR
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "matches the original implementation, test code only"
        )]
        #[allow(
            clippy::cast_possible_truncation,
            reason = "intentional truncation for testing purposes"
        )]
        let p2p_key = pluto_testutil::random::generate_insecure_k1_key(seed as u8 + i);
        let addr = pluto_eth2util::helpers::public_key_to_address(&p2p_key.public_key());
        let record = pluto_eth2util::enr::Record::new(&p2p_key, Vec::new()).unwrap();
        let op = operator::Operator {
            address: addr,
            enr: record.to_string(),
            enr_signature: Vec::new(),
            config_signature: Vec::new(),
        };

        ops.push(op);
        p2p_keys.push(p2p_key);
    }

    // Use operator 0 as the creator.
    let creator = definition::Creator {
        address: ops[0].address.clone(),
        ..Default::default()
    };

    let mut definition = definition::Definition::new(
        "test_cluster".into(),
        dv,
        k.into(),
        fee_recipient_addresses,
        withdrawal_addresses,
        pluto_eth2util::network::GOERLI
            .genesis_fork_version_hex
            .into(),
        creator,
        ops,
        Vec::new(),
        "".into(),
        30_000_000,
        false,
        Vec::new(),
    )
    .unwrap();

    // Definition version prior to v1.3.0 don't support EIP712 signatures.
    if definition::Definition::support_eip712_sigs(&definition.version) {
        let mut operators = std::mem::take(&mut definition.operators);
        for (operator, p2p_key) in operators.iter_mut().zip(p2p_keys.iter()) {
            helpers::sign_operator(p2p_key, &definition, operator).unwrap();
        }
        definition.operators = operators;

        helpers::sign_creator(&p2p_keys[0], &mut definition).unwrap();

        // Recalculate definition hash after adding signatures.
        definition.set_definition_hashes().unwrap();
    }

    let mut lock = lock::Lock {
        definition,
        distributed_validators: vals,
        signature_aggregate: Vec::new(),
        lock_hash: Vec::new(),
        node_signatures: Vec::new(),
    };

    lock.set_lock_hash().unwrap();

    let signature_aggregate = helpers::agg_sign(&dv_shares, &lock.lock_hash).unwrap();
    lock.signature_aggregate = signature_aggregate.to_vec();

    if version::support_node_signatures(&lock.version) {
        for p2p_key in p2p_keys.iter() {
            let node_sig = pluto_k1util::sign(p2p_key, &lock.lock_hash).unwrap();
            lock.node_signatures.push(node_sig.to_vec());
        }
    }

    (lock, p2p_keys, dv_shares)
}

fn get_signed_registration(
    secret: &pluto_crypto::types::PrivateKey,
    fee_recipient: [u8; 20],
    network_name: impl AsRef<str>,
) -> registration::BuilderRegistration {
    let blst = pluto_crypto::blst_impl::BlstImpl;

    let timestamp =
        pluto_eth2util::network::network_to_genesis_time(network_name.as_ref()).unwrap();
    let pubkey = blst.secret_to_public_key(secret).unwrap();
    let eth2pubkey = pluto_crypto::tblsconv::pubkey_to_eth2(pubkey);

    let msg = pluto_eth2api::v1::ValidatorRegistration {
        fee_recipient,
        gas_limit: pluto_eth2util::registration::DEFAULT_GAS_LIMIT,
        timestamp: timestamp.timestamp().try_into().unwrap(),
        pubkey: eth2pubkey,
    };

    let fork_version = pluto_eth2util::network::network_to_fork_version_bytes(network_name)
        .unwrap()
        .try_into()
        .unwrap();

    let sig_root = pluto_eth2util::registration::get_message_signing_root(&msg, fork_version);
    let signature = blst.sign(secret, &sig_root).unwrap();

    registration::BuilderRegistration {
        message: registration::Registration {
            fee_recipient: msg.fee_recipient,
            gas_limit: msg.gas_limit,
            timestamp: Utc
                .timestamp_opt(msg.timestamp.try_into().unwrap(), 0)
                .unwrap(),
            pub_key: msg.pubkey,
        },
        signature,
    }
}
