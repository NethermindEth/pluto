//! Deadline calculator trait and beacon-node-derived implementation.

use chrono::{DateTime, Utc};

use crate::types::Duty;

use super::Result;

/// Computes deadlines for duties.
///
/// `Ok(Some(deadline))` — duty expires at the given wall-clock time.
/// `Ok(None)`           — duty never expires (e.g. Exit, BuilderRegistration).
/// `Err(_)`             — arithmetic or conversion failure.
pub trait DeadlineCalculator: Send + Sync + 'static {
    /// Computes the deadline for the given duty. See trait docs for return
    /// semantics.
    fn deadline(&self, duty: &Duty) -> Result<Option<DateTime<Utc>>>;
}
