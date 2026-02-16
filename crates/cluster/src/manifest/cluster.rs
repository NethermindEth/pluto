use std::collections::{HashMap, HashSet};

use k256::PublicKey as K256PublicKey;
use libp2p::PeerId;
use pluto_core::types::PubKey;
use pluto_crypto::{
    blst_impl::BlstImpl,
    tbls::Tbls,
    types::{PUBLIC_KEY_LENGTH, PrivateKey, PublicKey},
};
use pluto_eth2util::enr::Record;
use pluto_p2p::peer::{Peer, peer_id_from_key};

use crate::{
    definition::NodeIdx,
    helpers::to_0x_hex,
    manifestpb::v1::{Cluster, Validator},
};

use super::error::{ManifestError, Result};

/// A share in the context of a Pluto cluster, alongside its index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedKeyShare {
    /// The private key share.
    pub share: PrivateKey,
    /// The 1-indexed share index.
    pub index: usize,
}

/// Maps each validator pubkey to the associated key share.
pub type ValidatorShares = HashMap<PubKey, IndexedKeyShare>;

impl Cluster {
    /// Returns the cluster operators as a slice of p2p peers.
    pub fn peers(&self) -> Result<Vec<Peer>> {
        if self.operators.is_empty() {
            return Err(ManifestError::InvalidCluster);
        }

        let mut resp = Vec::new();
        let mut dedup = HashSet::new();

        for (i, operator) in self.operators.iter().enumerate() {
            if dedup.contains(&operator.enr) {
                return Err(ManifestError::DuplicatePeerENR {
                    enr: operator.enr.clone(),
                });
            }
            dedup.insert(&operator.enr);

            let record = Record::try_from(operator.enr.as_str())?;

            let peer = Peer::from_enr(&record, i)?;

            resp.push(peer);
        }

        Ok(resp)
    }

    /// Returns the operators p2p peer IDs.
    pub fn peer_ids(&self) -> Result<Vec<PeerId>> {
        let peers = self.peers()?;
        Ok(peers.iter().map(|p| p.id).collect())
    }

    /// Returns the node index for the peer in the cluster.
    pub fn node_idx(&self, peer_id: &PeerId) -> Result<NodeIdx> {
        let peers = self.peers()?;

        for (i, p) in peers.iter().enumerate() {
            if p.id == *peer_id {
                return Ok(NodeIdx {
                    peer_idx: i,                    // 0-indexed
                    share_idx: i.saturating_add(1), // 1-indexed
                });
            }
        }

        Err(ManifestError::PeerNotInDefinition)
    }

    /// Maps each share in cluster to the associated validator private key.
    ///
    /// Returns an error if a keyshare does not appear in cluster, or if there's
    /// a validator public key associated to no keyshare.
    pub fn keyshares_to_validator_pubkey(&self, shares: &[PrivateKey]) -> Result<ValidatorShares> {
        let mut res: ValidatorShares = HashMap::new();

        let mut pub_shares = Vec::with_capacity(shares.len());
        for share in shares {
            let ps = BlstImpl.secret_to_public_key(share).map_err(|e| {
                ManifestError::Crypto(format!("private share to public share: {e}"))
            })?;
            pub_shares.push(ps);
        }

        // O(n^2) search
        for validator in &self.validators {
            let val_pubkey: PubKey = validator.public_key()?.into();

            // Build a set of this validator's public shares
            let val_pub_shares: HashSet<PublicKey> = validator
                .pub_shares
                .iter()
                .filter_map(|s| {
                    let arr: PublicKey = s.as_ref().try_into().ok()?;
                    Some(arr)
                })
                .collect();

            let mut found = false;
            for (share_idx, pub_share) in pub_shares.iter().enumerate() {
                if !val_pub_shares.contains(pub_share) {
                    continue;
                }

                res.insert(
                    val_pubkey,
                    IndexedKeyShare {
                        share: shares[share_idx],
                        index: share_idx.saturating_add(1), // 1-indexed
                    },
                );
                found = true;
                break;
            }

            if !found {
                return Err(ManifestError::PubShareNotFound);
            }
        }

        if res.len() != self.validators.len() {
            return Err(ManifestError::KeyShareCountMismatch);
        }

        Ok(res)
    }

    /// Returns the share index for the Charon cluster's ENR identity key.
    pub fn share_idx(&self, identity_key: &K256PublicKey) -> Result<u64> {
        let pids = self.peer_ids()?;

        let identity_peer_id = peer_id_from_key(*identity_key)?;

        for pid in &pids {
            if *pid != identity_peer_id {
                continue;
            }

            let n_idx = self.node_idx(pid)?;
            return Ok(n_idx.share_idx as u64);
        }

        Err(ManifestError::NodeIdxNotFound)
    }
}

impl Validator {
    /// Returns the validator BLS group public key.
    pub fn public_key(&self) -> Result<PublicKey> {
        let pk_vec = self.public_key.to_vec();
        pk_vec
            .try_into()
            .map_err(|_| ManifestError::InvalidHexLength {
                expect: PUBLIC_KEY_LENGTH,
                actual: self.public_key.len(),
            })
    }

    /// Returns the validator hex group public key.
    pub fn public_key_hex(&self) -> String {
        to_0x_hex(&self.public_key)
    }

    /// Returns the validator's peerIdx'th BLS public share.
    pub fn public_share(&self, peer_idx: usize) -> Result<PublicKey> {
        let share = self
            .pub_shares
            .get(peer_idx)
            .ok_or(ManifestError::InvalidCluster)?;

        let share_vec = share.to_vec();
        share_vec
            .try_into()
            .map_err(|_| ManifestError::InvalidHexLength {
                expect: PUBLIC_KEY_LENGTH,
                actual: share.len(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifestpb::v1::Operator;
    use pluto_testutil::random::{generate_insecure_k1_key, generate_test_bls_key};
    use rand::{Rng, SeedableRng, seq::SliceRandom};

    #[test]
    fn cluster_peers_empty() {
        let cluster = Cluster::default();
        let result = cluster.peers();
        assert!(result.is_err());
    }

    #[test]
    fn cluster_peers_duplicate_enr() {
        let duplicate_enr = "enr:-HW4QIHPUOMb34YoizKGhz7nsDNQ7hCaiuwyscmeaOQ04awdH05gDnGrZhxDfzcfHssCDeB-esi99A2RoZia6UaYBCuAgmlkgnY0iXNlY3AyNTZrMaECTUts0TYQMsqb0q652QCqTUXZ6tgKyUIzdMRRpyVNB2Y".to_string();

        let cluster = Cluster {
            operators: vec![
                Operator {
                    address: "0x123".to_string(),
                    enr: duplicate_enr.clone(),
                },
                Operator {
                    address: "0x456".to_string(),
                    enr: duplicate_enr, // duplicate
                },
            ],
            ..Default::default()
        };
        let result = cluster.peers();
        assert!(matches!(
            result.unwrap_err(),
            ManifestError::DuplicatePeerENR { .. }
        ));
    }

    #[test]
    fn cluster_node_idx_test() {
        let enr0 = "enr:-HW4QMOF6QNn4DRhSznyqhoRitA0R1P_p-Cf8I_phn-qR5EQEqFVV0_OtVuSWPj_HjGPd8lcXmcTen8j-9VT9hadVFyAgmlkgnY0iXNlY3AyNTZrMaECOx8LaV0436lNYE4XiqbGbVmXrEhUTg73e3M7HdRUWao".to_string();
        let enr1 = "enr:-HW4QKFO6PyCQdVXUdNEn80MJL7O048nRgZvheMhdT4LL9DGPjXlhrP1beyj8OEfZrapZVWNPEjfkUJubybvOPqkEhmAgmlkgnY0iXNlY3AyNTZrMaECGzgOLCm1ShATtBj1sh0VvshUOPkGW20ruTPPo5N_HZM".to_string();
        let enr2 = "enr:-HW4QJV3uqiuCqreW6nn794r-SxTC1fTXCnZQ4smu3l5F4DofbW566Zo8G0A9WL_wfGzkGRPPdGu6vYT7JfskEmbjIKAgmlkgnY0iXNlY3AyNTZrMaECh69y5mTVFNZQSh8Kc_57VwcK39WfY68y2F2WkeLa7EY".to_string();

        let cluster = Cluster {
            operators: vec![
                Operator {
                    address: "0x123".to_string(),
                    enr: enr0,
                },
                Operator {
                    address: "0x456".to_string(),
                    enr: enr1,
                },
                Operator {
                    address: "0x789".to_string(),
                    enr: enr2,
                },
            ],
            ..Default::default()
        };

        let peers = cluster.peers().unwrap();
        let peer_id = peers[1].id;

        let node_idx = cluster.node_idx(&peer_id).unwrap();
        assert_eq!(node_idx.peer_idx, 1);
        assert_eq!(node_idx.share_idx, 2);
    }

    #[test]
    fn validator_public_key_test() {
        let public_key = vec![0x42u8; PUBLIC_KEY_LENGTH];
        let validator = Validator {
            public_key: public_key.clone().into(),
            ..Default::default()
        };

        let result = validator.public_key().unwrap();
        assert_eq!(result[0], 0x42);
        assert_eq!(result.len(), PUBLIC_KEY_LENGTH);
    }

    #[test]
    fn validator_public_key_hex_test() {
        let mut public_key = vec![0u8; PUBLIC_KEY_LENGTH];
        public_key[0] = 0xab;
        public_key[1] = 0xcd;

        let validator = Validator {
            public_key: public_key.into(),
            ..Default::default()
        };

        let hex = validator.public_key_hex();
        let expected = "0xabcd".to_string() + &"00".repeat(PUBLIC_KEY_LENGTH - 2);
        assert_eq!(hex, expected);
    }

    #[test]
    fn validator_public_share_test() {
        let mut share0 = vec![0u8; PUBLIC_KEY_LENGTH];
        share0[0] = 0x01;
        let mut share1 = vec![0u8; PUBLIC_KEY_LENGTH];
        share1[0] = 0x02;

        let validator = Validator {
            pub_shares: vec![share0.into(), share1.into()],
            ..Default::default()
        };

        let result0 = validator.public_share(0).unwrap();
        assert_eq!(result0[0], 0x01);
        assert_eq!(result0.len(), PUBLIC_KEY_LENGTH);

        let result1 = validator.public_share(1).unwrap();
        assert_eq!(result1[0], 0x02);
        assert_eq!(result1.len(), PUBLIC_KEY_LENGTH);

        assert!(validator.public_share(5).is_err());
    }

    #[test]
    fn keyshare_to_validator_pubkey() {
        let tbls = BlstImpl;
        let val_amt = 4;
        let shares_amt = 10;

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let mut private_shares: Vec<PrivateKey> = vec![PrivateKey::default(); val_amt];
        let mut cluster = Cluster::default();

        for (val_idx, private_share) in private_shares.iter_mut().enumerate() {
            // Generate a random validator public key
            let val_priv = generate_test_bls_key(1000 + val_idx as u64);
            let val_pubk = tbls.secret_to_public_key(&val_priv).unwrap();

            let mut validator = Validator {
                public_key: val_pubk.to_vec().into(),
                pub_shares: Vec::new(),
                ..Default::default()
            };

            let mut random_share_selected = false;

            for share_idx in 0..shares_amt {
                let share_priv = generate_test_bls_key((val_idx * 100 + share_idx + 1) as u64);
                let share_pub = tbls.secret_to_public_key(&share_priv).unwrap();

                // Randomly select one share as the "private share" for this validator
                if rng.gen_bool(0.5) && !random_share_selected {
                    *private_share = share_priv;
                    random_share_selected = true;
                }

                validator.pub_shares.push(share_pub.to_vec().into());
            }

            // Ensure at least one share is selected
            if !random_share_selected {
                let share_priv = generate_test_bls_key((val_idx * 100 + 1) as u64);
                *private_share = share_priv;
            }

            validator.pub_shares.shuffle(&mut rng);

            cluster.validators.push(validator);
        }

        let ret = cluster
            .keyshares_to_validator_pubkey(&private_shares)
            .unwrap();

        assert_eq!(ret.len(), val_amt);

        // Verify each validator pubkey is found and each share private key is found
        for (val_pub_key, share_priv_key) in &ret {
            let val_found = cluster.validators.iter().any(|val| {
                if let Ok(pk) = val.public_key() {
                    let val_pubkey: PubKey = pk.into();
                    val_pub_key == &val_pubkey
                } else {
                    false
                }
            });
            assert!(val_found, "validator pubkey not found");

            let share_priv_key_found = private_shares
                .iter()
                .any(|share| share == &share_priv_key.share);
            assert!(share_priv_key_found, "share priv key not found");
        }
    }

    #[test]
    fn keyshares_to_validator_pubkey_not_found() {
        let tbls = BlstImpl;

        // Generate a private key share that won't match
        let share0 = generate_test_bls_key(1);
        let pub_share0 = tbls.secret_to_public_key(&share0).unwrap();

        // Create a validator with different pub_shares
        let other_share = generate_test_bls_key(200);
        let other_pub_share = tbls.secret_to_public_key(&other_share).unwrap();

        let validator_pubkey = generate_test_bls_key(100);
        let validator_pubkey_bytes = tbls.secret_to_public_key(&validator_pubkey).unwrap();

        let validator = Validator {
            public_key: validator_pubkey_bytes.to_vec().into(),
            pub_shares: vec![other_pub_share.to_vec().into()],
            ..Default::default()
        };

        let cluster = Cluster {
            validators: vec![validator],
            ..Default::default()
        };

        let shares = vec![share0];
        let result = cluster.keyshares_to_validator_pubkey(&shares);

        assert!(matches!(
            result.unwrap_err(),
            ManifestError::PubShareNotFound
        ));

        // Suppress unused warning
        let _ = pub_share0;
    }

    #[test]
    fn share_idx_for_cluster_test() {
        let operator_amt: u8 = 4;

        let mut k1_keys = Vec::new();
        let mut operators = Vec::new();

        for i in 0..operator_amt {
            let k1_key = generate_insecure_k1_key(i);
            let enr = Record::new(k1_key.clone(), vec![]).unwrap();

            operators.push(Operator {
                address: format!("0x{:040x}", i),
                enr: enr.to_string(),
            });
            k1_keys.push(k1_key);
        }

        let cluster = Cluster {
            operators,
            ..Default::default()
        };

        // Test first operator's public key returns share index 1
        let pubkey = k1_keys[0].public_key();
        let res = cluster.share_idx(&pubkey).unwrap();
        assert_eq!(res, 1); // 1-indexed

        // Test all operators
        for (i, k1_key) in k1_keys.iter().enumerate() {
            let res = cluster.share_idx(&k1_key.public_key()).unwrap();
            assert_eq!(res, (i + 1) as u64); // 1-indexed
        }
    }

    #[test]
    fn share_idx_for_cluster_not_found() {
        let k1_key0 = generate_insecure_k1_key(1);
        let k1_key_unknown = generate_insecure_k1_key(200);

        let enr0 = Record::new(k1_key0, vec![]).unwrap();

        let cluster = Cluster {
            operators: vec![Operator {
                address: "0x123".to_string(),
                enr: enr0.to_string(),
            }],
            ..Default::default()
        };

        let result = cluster.share_idx(&k1_key_unknown.public_key());
        assert!(matches!(
            result.unwrap_err(),
            ManifestError::NodeIdxNotFound
        ));
    }
}
