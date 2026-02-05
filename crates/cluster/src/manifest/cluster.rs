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

use super::{ManifestError, Result};

/// Returns the cluster operators as a slice of p2p peers.
pub fn cluster_peers(cluster: &Cluster) -> Result<Vec<Peer>> {
    if cluster.operators.is_empty() {
        return Err(ManifestError::InvalidCluster);
    }

    let mut resp = Vec::new();
    let mut dedup = HashSet::new();

    for (i, operator) in cluster.operators.iter().enumerate() {
        if dedup.contains(&operator.enr) {
            return Err(ManifestError::DuplicatePeerENR {
                enr: operator.enr.clone(),
            });
        }
        dedup.insert(operator.enr.clone());

        let record = Record::try_from(operator.enr.as_str())
            .map_err(|e| ManifestError::EnrParse(format!("decode enr: {}", e)))?;

        let peer = Peer::from_enr(&record, i)
            .map_err(|e| ManifestError::P2p(format!("create peer from enr: {}", e)))?;

        resp.push(peer);
    }

    Ok(resp)
}

/// Returns the operators p2p peer IDs.
pub fn cluster_peer_ids(cluster: &Cluster) -> Result<Vec<PeerId>> {
    let peers = cluster_peers(cluster)?;
    Ok(peers.iter().map(|p| p.id).collect())
}

/// Returns the node index for the peer in the cluster.
pub fn cluster_node_idx(cluster: &Cluster, peer_id: &PeerId) -> Result<NodeIdx> {
    let peers = cluster_peers(cluster)?;

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

/// Returns the validator BLS group public key.
pub fn validator_public_key(validator: &Validator) -> Result<PublicKey> {
    let pk_vec = validator.public_key.to_vec();
    pk_vec
        .try_into()
        .map_err(|_| ManifestError::InvalidHexLength {
            expect: PUBLIC_KEY_LENGTH,
            actual: validator.public_key.len(),
        })
}

/// Returns the validator hex group public key.
pub fn validator_public_key_hex(validator: &Validator) -> String {
    to_0x_hex(&validator.public_key)
}

/// Returns the validator's peerIdx'th BLS public share.
pub fn validator_public_share(validator: &Validator, peer_idx: usize) -> Result<PublicKey> {
    let share = validator
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifestpb::v1::Operator;

    #[test]
    fn cluster_peers_empty() {
        let cluster = Cluster::default();
        let result = cluster_peers(&cluster);
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
        let result = cluster_peers(&cluster);
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

        let result0 = validator_public_share(&validator, 0).unwrap();
        assert_eq!(result0[0], 0x01);
        assert_eq!(result0.len(), PUBLIC_KEY_LENGTH);

        let result1 = validator_public_share(&validator, 1).unwrap();
        assert_eq!(result1[0], 0x02);
        assert_eq!(result1.len(), PUBLIC_KEY_LENGTH);

        assert!(validator_public_share(&validator, 5).is_err());
    }
}
