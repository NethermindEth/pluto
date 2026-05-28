//! QBFT consensus message sniffer.

// TODO: Remove once the consensus component exports sniffer lifecycle hooks.
#![allow(dead_code)]

use std::{
    sync::{Mutex, PoisonError},
    time::SystemTime,
};

use prost_types::Timestamp;

use crate::{
    consensus::protocols::QBFT_V2_PROTOCOL_ID,
    corepb::v1::consensus::{QbftConsensusMsg, SniffedConsensusInstance, SniffedConsensusMsg},
};

/// Buffers consensus messages for the debug API.
#[derive(Debug)]
pub(crate) struct Sniffer {
    nodes: i64,
    peer_idx: i64,
    started_at: SystemTime,
    msgs: Mutex<Vec<SniffedConsensusMsg>>,
}

impl Sniffer {
    /// Returns a new QBFT consensus sniffer.
    pub(crate) fn new(nodes: i64, peer_idx: i64) -> Self {
        Self {
            nodes,
            peer_idx,
            started_at: SystemTime::now(),
            msgs: Mutex::default(),
        }
    }

    /// Adds a message to the sniffer buffer.
    pub(crate) fn add(&self, msg: QbftConsensusMsg) {
        self.msgs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(SniffedConsensusMsg {
                timestamp: Some(Timestamp::from(SystemTime::now())),
                msg: Some(msg),
            });
    }

    /// Returns the buffered messages as a sniffed consensus instance.
    pub(crate) fn instance(&self) -> SniffedConsensusInstance {
        SniffedConsensusInstance {
            nodes: self.nodes,
            peer_idx: self.peer_idx,
            started_at: Some(Timestamp::from(self.started_at)),
            msgs: self
                .msgs
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
            protocol_id: QBFT_V2_PROTOCOL_ID.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corepb::v1::consensus::QbftMsg;

    #[test]
    fn sniffer_add_records_messages() {
        let sniffer = Sniffer::new(4, 2);
        let msg = consensus_msg(7);

        sniffer.add(msg.clone());

        let instance = sniffer.instance();
        assert_eq!(instance.msgs.len(), 1);
        assert_eq!(instance.msgs[0].msg, Some(msg));
        assert!(instance.msgs[0].timestamp.is_some());
    }

    #[test]
    fn sniffer_instance_maps_fields() {
        let sniffer = Sniffer::new(4, 3);

        let instance = sniffer.instance();

        assert_eq!(instance.nodes, 4);
        assert_eq!(instance.peer_idx, 3);
        assert!(instance.started_at.is_some());
        assert!(instance.msgs.is_empty());
        assert_eq!(instance.protocol_id, QBFT_V2_PROTOCOL_ID);
    }

    fn consensus_msg(round: i64) -> QbftConsensusMsg {
        QbftConsensusMsg {
            msg: Some(QbftMsg {
                round,
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}
