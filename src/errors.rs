// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

use thiserror::Error;

use crate::Integrity;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to parse subresource integrity string: {0}")]
    ParseIntegrityError(String),
    #[error("Integrity check failed.\n\tWanted: {0}\n\tActual: {1}")]
    IntegrityCheckError(Integrity, Integrity),
}
