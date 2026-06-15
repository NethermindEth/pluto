use crate::types;

/// Errors for AggSigDB operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Data for the same duty and public key already exists but does not match
    /// the new data.
    #[error("Mismatching data")]
    MismatchingData,

    /// The request cannot be processed because the instance has been
    /// terminated.
    #[error("The instance has been terminated")]
    Terminated,
}

/// A persistent store for aggregated signed duty data.
#[async_trait::async_trait]
pub trait AggSigDB {
    /// Stores aggregated signed duty data set.
    async fn store(&self, duty: types::Duty, data: types::SignedDataSet) -> Result<(), Error>;

    /// Blocks and returns the aggregated signed duty data when available.
    ///
    /// Might block indefinitely if no data is ever stored for the given duty
    /// and public key.
    ///
    /// To avoid blocking indefinitely, consider using a timeout,
    /// [`CancellationToken`] or racing using `tokio::select!` against other
    /// events.
    async fn wait_for(
        &self,
        duty: types::Duty,
        pub_key: types::PubKey,
    ) -> Result<Box<dyn types::SignedData>, Error>;
}
