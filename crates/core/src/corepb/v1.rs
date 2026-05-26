#[path = "v1/core.corepb.v1.rs"]
mod generated;

pub use generated::*;

/// Core protobuf definitions.
pub mod core {
    pub use super::{Duty, ParSignedData, ParSignedDataSet, UnsignedDataSet};
}

/// Consensus protobuf definitions.
pub mod consensus {
    pub use super::{
        QbftConsensusMsg, QbftMsg, SniffedConsensusInstance, SniffedConsensusInstances,
        SniffedConsensusMsg,
    };
}

/// ParSigEx protobuf definitions.
pub mod parsigex {
    pub use super::ParSigExMsg;
}

/// Priority protobuf definitions.
pub mod priority {
    pub use super::{
        PriorityMsg, PriorityResult, PriorityScoredResult, PriorityTopicProposal,
        PriorityTopicResult,
    };
}
