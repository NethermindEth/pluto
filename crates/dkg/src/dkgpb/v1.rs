/// All DKG protobuf definitions (package dkg.dkgpb.v1).
#[path = "v1/dkg.dkgpb.v1.rs"]
mod all;

/// BCast protobuf definitions.
pub mod bcast {
    pub use super::all::{BCastMessage, BCastSigRequest, BCastSigResponse};
}

/// Frost protobuf definitions.
pub mod frost {
    pub use super::all::{
        FrostMsgKey, FrostRound1Cast, FrostRound1Casts, FrostRound1P2p, FrostRound1ShamirShare,
        FrostRound2Cast, FrostRound2Casts,
    };
}

/// Nodesigs protobuf definitions.
pub mod nodesigs {
    pub use super::all::MsgNodeSig;
}

/// Sync protobuf definitions.
pub mod sync {
    pub use super::all::{MsgSync, MsgSyncResponse};
}
