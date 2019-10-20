use thiserror::Error;

use crate::Integrity;

/// Integrity-related error values.
#[derive(Error, Debug)]
pub enum Error {
    /// Error parsing an SRI string into an Integrity object.
    #[error("Failed to parse subresource integrity string: {0}")]
    ParseIntegrityError(String),
    /// Error matching two Integrity values.
    #[error("Integrity check failed.\n\tWanted: {0}\n\tActual: {1}")]
    IntegrityCheckError(Integrity, Integrity),
}
