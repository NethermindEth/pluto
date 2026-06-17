//! Consensus debug message buffer.
//!
//! [`Debugger`] stores completed QBFT sniffer instances in a bounded FIFO
//! buffer and serves them as a gzipped [`SniffedConsensusInstances`] protobuf.
//!
//! # Usage
//!
//! Create one debugger during node startup, wire its sniffer callback into the
//! QBFT consensus config, and mount its router on the debug HTTP server:
//!
//! ```no_run
//! use axum::Router;
//! use pluto_consensus::debugger::Debugger;
//!
//! let debugger = Debugger::new();
//!
//! let sniffer = debugger.sniffer();
//! let app = Router::new().merge(debugger.router("/debug/consensus"));
//!
//! // Pass `sniffer` into `qbft::Config { sniffer, .. }`.
//! // Serve `app` with the node's debug HTTP server.
//! ```
//!
//! Lower-level callers can use [`Debugger::add_instance`] to store an instance,
//! [`Debugger::get_zipped_proto`] to get the raw gzipped protobuf bytes, or
//! [`Debugger::serve_http`] to build a single HTTP response without using
//! [`Debugger::router`].

use std::{
    collections::VecDeque,
    io::Write,
    sync::{Arc, Mutex, PoisonError},
};

use axum::{
    Router,
    body::Body,
    http::{
        HeaderValue, Response, StatusCode,
        header::{CONTENT_DISPOSITION, CONTENT_TYPE},
    },
    routing::get,
};
use flate2::{Compression, write::GzEncoder};
use pluto_core::{
    corepb::v1::consensus::{SniffedConsensusInstance, SniffedConsensusInstances},
    version,
};
use prost::Message;

use crate::qbft::SnifferSink;

const DEFAULT_MAX_BUFFER_SIZE: usize = 52_428_800;
const DEBUGGER_CONTENT_TYPE: &str = "application/octet-stream";
const DEBUGGER_FILENAME: &str = r#"attachment; filename="consensus_messages.pb.gz""#;
const DEBUGGER_ERROR_BODY: &str = "something went wrong, see logs\n";

/// Consensus debug message buffer.
#[derive(Clone, Debug)]
pub struct Debugger {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    git_hash: String,
    max_buffer_size: usize,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    total_size: usize,
    instances: VecDeque<SniffedConsensusInstance>,
}

/// Debugger serialization error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Protobuf encoding failed.
    #[error("marshal proto: {0}")]
    MarshalProto(#[from] prost::EncodeError),
    /// Gzip writer failed.
    #[error("gzip: {0}")]
    Gzip(std::io::Error),
}

impl Debugger {
    /// Returns a new consensus debugger.
    pub fn new() -> Self {
        let (git_hash, _) = version::git_commit();
        Self::with_git_hash_and_max_buffer(git_hash, DEFAULT_MAX_BUFFER_SIZE)
    }

    /// Adds a sniffed consensus instance to the FIFO buffer.
    pub fn add_instance(&self, instance: SniffedConsensusInstance) {
        let size = instance.encoded_len();
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        state.total_size = state.total_size.saturating_add(size);
        state.instances.push_back(instance);

        while state.total_size > self.inner.max_buffer_size {
            let Some(dropped) = state.instances.pop_front() else {
                state.total_size = 0;
                break;
            };
            state.total_size = state.total_size.saturating_sub(dropped.encoded_len());
        }
    }

    /// Returns the buffered consensus instances as a gzipped protobuf payload.
    pub fn get_zipped_proto(&self) -> Result<Vec<u8>, Error> {
        let instances = {
            let state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            state.instances.iter().cloned().collect()
        };

        let mut encoded = Vec::new();
        SniffedConsensusInstances {
            instances,
            git_hash: self.inner.git_hash.clone(),
        }
        .encode(&mut encoded)?;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&encoded).map_err(Error::Gzip)?;
        encoder.finish().map_err(Error::Gzip)
    }

    /// Returns an HTTP response containing the gzipped protobuf payload.
    pub fn serve_http(&self) -> Response<Body> {
        match self.get_zipped_proto() {
            Ok(body) => Response::builder()
                .header(
                    CONTENT_TYPE,
                    HeaderValue::from_static(DEBUGGER_CONTENT_TYPE),
                )
                .header(
                    CONTENT_DISPOSITION,
                    HeaderValue::from_static(DEBUGGER_FILENAME),
                )
                .body(Body::from(body))
                .unwrap_or_else(|error| {
                    tracing::warn!(%error, "Error serving consensus debug");
                    error_response()
                }),
            Err(error) => {
                tracing::warn!(%error, "Error serving consensus debug");
                error_response()
            }
        }
    }

    /// Returns a sink that stores completed QBFT sniffer instances.
    pub fn sniffer(&self) -> SnifferSink {
        let debugger = self.clone();
        Arc::new(move |instance| debugger.add_instance(instance))
    }

    /// Returns an axum router serving this debugger at `path`.
    pub fn router(&self, path: &'static str) -> Router {
        let debugger = self.clone();
        Router::new().route(
            path,
            get(move || {
                let debugger = debugger.clone();
                async move { debugger.serve_http() }
            }),
        )
    }

    fn with_git_hash_and_max_buffer(git_hash: String, max_buffer_size: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                git_hash,
                max_buffer_size,
                state: Mutex::default(),
            }),
        }
    }
}

impl Default for Debugger {
    fn default() -> Self {
        Self::new()
    }
}

fn error_response() -> Response<Body> {
    let mut response = Response::new(Body::from(DEBUGGER_ERROR_BODY));
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use axum::body;
    use flate2::read::GzDecoder;
    use pluto_core::corepb::v1::consensus::{QbftConsensusMsg, QbftMsg, SniffedConsensusMsg};
    use prost_types::Timestamp;

    use super::*;

    #[tokio::test]
    async fn debugger_serves_gzipped_sniffed_consensus_instances() {
        let debugger = Debugger::with_git_hash_and_max_buffer("test-hash".to_string(), usize::MAX);
        let instances = (0..10).map(sniffed_instance).collect::<Vec<_>>();

        for instance in instances.clone() {
            debugger.add_instance(instance);
        }

        let response = debugger.serve_http();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE),
            Some(&HeaderValue::from_static(DEBUGGER_CONTENT_TYPE))
        );
        assert_eq!(
            response.headers().get(CONTENT_DISPOSITION),
            Some(&HeaderValue::from_static(DEBUGGER_FILENAME))
        );

        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("debug response body is readable");
        let decoded = decode_gzipped_instances(&body);

        assert_eq!(
            decoded,
            SniffedConsensusInstances {
                instances,
                git_hash: "test-hash".to_string(),
            }
        );
    }

    #[test]
    fn add_instance_drops_oldest_instances_when_capacity_is_exceeded() {
        let first = sniffed_instance(1);
        let second = sniffed_instance(2);
        let third = sniffed_instance(3);
        let max_buffer = second
            .encoded_len()
            .checked_add(third.encoded_len())
            .expect("test instances fit usize");
        let debugger = Debugger::with_git_hash_and_max_buffer("test-hash".to_string(), max_buffer);

        debugger.add_instance(first);
        debugger.add_instance(second.clone());
        debugger.add_instance(third.clone());

        let decoded = decode_gzipped_instances(
            &debugger
                .get_zipped_proto()
                .expect("debugger payload should encode"),
        );

        assert_eq!(decoded.instances, vec![second, third]);
    }

    #[test]
    fn new_debugger_sets_git_hash() {
        let debugger = Debugger::new();
        let decoded = decode_gzipped_instances(
            &debugger
                .get_zipped_proto()
                .expect("debugger payload should encode"),
        );

        assert_eq!(decoded.git_hash, version::git_commit().0);
    }

    #[test]
    fn cloned_debugger_shares_buffer() {
        let debugger = Debugger::with_git_hash_and_max_buffer("test-hash".to_string(), usize::MAX);
        let cloned = debugger.clone();
        let instance = sniffed_instance(1);

        cloned.add_instance(instance.clone());

        let decoded = decode_gzipped_instances(
            &debugger
                .get_zipped_proto()
                .expect("debugger payload should encode"),
        );

        assert_eq!(decoded.instances, vec![instance]);
    }

    #[test]
    fn sniffer_adds_instances() {
        let debugger = Debugger::with_git_hash_and_max_buffer("test-hash".to_string(), usize::MAX);
        let sniffer = debugger.sniffer();
        let instance = sniffed_instance(1);

        sniffer(instance.clone());

        let decoded = decode_gzipped_instances(
            &debugger
                .get_zipped_proto()
                .expect("debugger payload should encode"),
        );

        assert_eq!(decoded.instances, vec![instance]);
    }

    #[test]
    fn router_constructs_debug_endpoint() {
        let debugger = Debugger::with_git_hash_and_max_buffer("test-hash".to_string(), usize::MAX);
        let _router = debugger.router("/debug/consensus");
    }

    fn decode_gzipped_instances(bytes: &[u8]) -> SniffedConsensusInstances {
        let mut decoder = GzDecoder::new(bytes);
        let mut decoded = Vec::new();
        decoder
            .read_to_end(&mut decoded)
            .expect("gzip payload should decode");
        SniffedConsensusInstances::decode(decoded.as_slice())
            .expect("sniffed consensus instances should decode")
    }

    fn sniffed_instance(seed: i64) -> SniffedConsensusInstance {
        SniffedConsensusInstance {
            started_at: Some(Timestamp {
                seconds: seed,
                nanos: 0,
            }),
            nodes: 4,
            peer_idx: seed,
            msgs: vec![SniffedConsensusMsg {
                timestamp: Some(Timestamp {
                    seconds: seed
                        .checked_add(1)
                        .expect("test timestamp increment fits i64"),
                    nanos: 0,
                }),
                msg: Some(QbftConsensusMsg {
                    msg: Some(QbftMsg {
                        r#type: seed,
                        peer_idx: seed,
                        round: seed,
                        prepared_round: seed,
                        ..Default::default()
                    }),
                    justification: vec![
                        QbftMsg {
                            round: seed
                                .checked_add(1)
                                .expect("test justification round fits i64"),
                            ..Default::default()
                        },
                        QbftMsg {
                            round: seed
                                .checked_add(2)
                                .expect("test justification round fits i64"),
                            ..Default::default()
                        },
                    ],
                    values: Vec::new(),
                }),
            }],
            protocol_id: "test-protocol".to_string(),
        }
    }
}
