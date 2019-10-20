use thiserror::Error;

use crate::Integrity;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to parse subresource integrity string: {0}")]
    ParseIntegrityError(String),
    #[error("Integrity check failed.\n\tWanted: {0}\n\tActual: {1}")]
    IntegrityCheckError(Integrity, Integrity),
}
