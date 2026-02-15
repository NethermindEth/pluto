use std::collections::HashSet;

use libp2p::PeerId;
use pluto_crypto::types::{PUBLIC_KEY_LENGTH, PublicKey};
use pluto_eth2util::enr::Record;
use pluto_p2p::peer::Peer;

use crate::{
    definition::NodeIdx,
    helpers::to_0x_hex,
    manifestpb::v1::{Cluster, Validator},
};

use super::error::{ManifestError, Result};

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
}
