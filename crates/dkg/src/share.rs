use std::collections::HashMap;

/// The co-validator public key, tbls public shares, and private key share.
/// Each node in the cluster will receive one for each distributed validator.
pub(crate) struct Share {
    pub pub_key: pluto_crypto::types::PublicKey,
    pub secret_share: pluto_crypto::types::PrivateKey,

    pub public_shares: HashMap<u64, pluto_crypto::types::PublicKey>, // u64 == Share index
}

/// The [`Share`] message wire format sent by the dealer.
pub(crate) struct ShareMsg {
    pub pub_key: Vec<u8>,
    pub pub_shares: Vec<Vec<u8>>,
    pub secret_share: Vec<u8>,
}

impl From<&Share> for ShareMsg {
    fn from(share: &Share) -> Self {
        let pub_key = share.pub_key.to_vec();
        let secret_share = share.secret_share.to_vec();

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
