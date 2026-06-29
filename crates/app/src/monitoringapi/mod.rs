//! Monitoring API for liveness and readiness probes.
//!
//! The module exposes a small router that can be mounted by application wiring
//! when the monitoring listener is enabled. Readiness is deliberately injected
//! so the HTTP layer remains independent from node lifecycle, p2p, beacon-node,
//! and validator-client wiring.
//!
//! # Examples
//!
//! Custom readiness can be supplied as any `Fn() -> ReadyResult`.
//!
//! ```rust
//! use std::sync::{
//!     Arc,
//!     atomic::{AtomicBool, Ordering},
//! };
//!
//! use pluto_app::monitoringapi::{ReadinessError, router};
//!
//! let upstream_ready = Arc::new(AtomicBool::new(false));
//! let check_ready = Arc::clone(&upstream_ready);
//!
//! let _app = router(move || {
//!     if check_ready.load(Ordering::Relaxed) {
//!         Ok(())
//!     } else {
//!         Err(ReadinessError::Custom(
//!             "upstream service not ready".to_owned(),
//!         ))
//!     }
//! });
//!
//! upstream_ready.store(true, Ordering::Relaxed);
//! ```

mod checker;
mod metrics;
mod readiness;
mod router;

pub use checker::{quorum_peers_connected, start_ready_checker};
pub use metrics::{MONITORING_METRICS, MonitoringMetrics, stack_components};
pub use readiness::{ReadinessCheck, ReadinessError, ReadyResult, ReadyState};
pub use router::{MonitoringState, router, router_with_state};
