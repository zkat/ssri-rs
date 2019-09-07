// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

use std::cmp::Ordering;
use std::fmt;

use serde_derive::{Serialize, Deserialize};

use crate::algorithm::Algorithm;
use crate::errors::Error;

/**
Represents a single algorithm/digest pair.

This is mostly internal, although users might interact with it directly on
occasion.
*/
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hash {
    pub algorithm: Algorithm,
    pub digest: String
}

impl PartialOrd for Hash {
    fn partial_cmp(&self, other: &Hash) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hash {
    fn cmp(&self, other: &Hash) -> Ordering {
        self.algorithm.cmp(&other.algorithm)
    }
}
impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}-{}", self.algorithm, self.digest)
    }
}

impl std::str::FromStr for Hash {
    type Err = Error;

    fn from_str(s: &str) -> Result<Hash, Self::Err> {
        let mut parsed = s.trim().split(|c| c == '-');
        let algorithm = parsed.next().ok_or(Error::ParseIntegrityError)?.parse()?;
        let digest = String::from(parsed.next().ok_or(Error::ParseIntegrityError)?);
        Ok(Hash { algorithm, digest })
    }
}

#[cfg(test)]
mod tests {
    use super::Hash;
    use super::Algorithm;

    #[test]
    fn hash_stringify() {
        assert_eq!(
            format!("{}", Hash {
                algorithm: Algorithm::Sha256,
                digest: String::from("deadbeef==")
            }),
            "sha256-deadbeef=="
        )
    }

    #[test]
    fn parsing() {
        assert_eq!(
            " sha256-deadbeef== \n".parse::<Hash>().unwrap(),
            Hash {
                algorithm: Algorithm::Sha256,
                digest: String::from("deadbeef==")
            }
        )
    }

    #[test]
    #[should_panic]
    fn bad_algorithm() {
        // TODO - test the actual error returned when it's more valuable
        "sha7-deadbeef==".parse::<Hash>().unwrap();
    }

    #[test]
    fn ordering() {
        let mut arr = [
            Hash {
                algorithm: Algorithm::Sha1,
                digest: String::from("foo==")
            },
            Hash {
                algorithm: Algorithm::Sha256,
                digest: String::from("foo==")
            },
            Hash {
                algorithm: Algorithm::Sha384,
                digest: String::from("foo==")
            },
            Hash {
                algorithm: Algorithm::Sha512,
                digest: String::from("foo==")
            }
        ];
        arr.sort_unstable();
        assert_eq!(arr, [
            Hash {
                algorithm: Algorithm::Sha512,
                digest: String::from("foo==")
            },
            Hash {
                algorithm: Algorithm::Sha384,
                digest: String::from("foo==")
            },
            Hash {
                algorithm: Algorithm::Sha256,
                digest: String::from("foo==")
            },
            Hash {
                algorithm: Algorithm::Sha1,
                digest: String::from("foo==")
            }
        ])
    }
}
