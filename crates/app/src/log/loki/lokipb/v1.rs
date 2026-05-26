#[path = "v1/app.log.loki.lokipb.v1.rs"]
mod generated;

pub use generated::*;

/// Loki protobuf definitions.
pub mod loki {
    pub use super::{Entry, PushRequest, Stream};
}
