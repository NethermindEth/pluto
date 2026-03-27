use std::collections::HashMap;
use zeroize::Zeroizing;

/// The co-validator public key, tbls public shares, and private key share.
/// Each node in the cluster will receive one for each distributed validator.
#[derive(Debug, Clone)]
pub struct Share {
    /// Public key
    pub pub_key: pluto_crypto::types::PublicKey,
    /// Private key share
    pub secret_share: pluto_crypto::types::PrivateKey,
    /// TBLS public shares, indexed by share id.
    pub public_shares: HashMap<u64, pluto_crypto::types::PublicKey>, // u64 == Share index
}

/// The [`Share`] message wire format sent by the dealer.
#[derive(Debug, Clone)]
pub struct ShareMsg {
    /// Public key
    pub pub_key: Vec<u8>,
    /// TBLS public shares, sorted in ascending order by share id.
    pub pub_shares: Vec<Vec<u8>>,
    /// Private key share
    pub secret_share: Zeroizing<Vec<u8>>,
}

impl From<&Share> for ShareMsg {
    fn from(share: &Share) -> Self {
        let pub_key = share.pub_key.to_vec();
        let secret_share = Zeroizing::new(share.secret_share.to_vec());

        // Sort pub shares by id.
        let pub_shares = {
            let mut entries: Vec<_> = share.public_shares.iter().collect();
            entries.sort_by_key(|(id, _)| *id);
            entries.into_iter().map(|(_, pk)| pk.to_vec()).collect()
        };

        Self {
            pub_key,
            pub_shares,
            secret_share,
        }
    }
}
