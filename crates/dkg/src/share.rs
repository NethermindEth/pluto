use std::collections::HashMap;

/// The co-validator public key, tbls public shares, and private key share.
/// Each node in the cluster will receive one for each distributed validator.
pub(crate) struct Share {
    pub pub_key: pluto_crypto::types::PublicKey,
    pub secret_share: pluto_crypto::types::PrivateKey,

    pub public_shares: HashMap<u64, pluto_crypto::types::PublicKey>, // u64 == Share index
}
