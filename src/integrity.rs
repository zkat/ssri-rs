use std::fmt;

use hex;
use serde_derive::{Serialize, Deserialize};

use crate::algorithm::Algorithm;
use crate::builder::Builder;
use crate::checker::Checker;
use crate::errors::Error;
use crate::hash::Hash;

/**
Representation of a full [Subresource Integrity string](https://w3c.github.io/webappsec/specs/subresourceintegrity/).

`Integrity` can be used for parsing and also includes convenience methods
for shorthand versions of [`Builder`](struct.Builder.html) and
[`Checker`](struct.Checker.html).
*/
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Integrity {
    pub hashes: Vec<Hash>
}

impl fmt::Display for Integrity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.hashes.iter()
            .map(|h| h.to_string())
            .collect::<Vec<String>>()
            .join(" "))
    }
}

impl std::str::FromStr for Integrity {
    type Err = Error;

    fn from_str(s: &str) -> Result<Integrity, Self::Err> {
        let hashes = String::from(s)
            .split_whitespace()
            .map(|x| x.parse())
            .collect::<Result<Vec<Hash>, Self::Err>>()?;
        Ok(Integrity { hashes })
    }
}

impl Integrity {
    /// Pick the most secure available `Algorithm` in this `Integrity`.
    pub fn pick_algorithm(&self) -> Algorithm {
        self.hashes[0].algorithm.clone()
    }
    /// Create a new `Integrity` based on `data`. Use [`Builder`](struct.Builder.html) for more options.
    pub fn from<B: AsRef<[u8]>>(data: B, algorithm: Algorithm) -> Integrity {
        Builder::new()
            .algorithm(algorithm)
            .chain(&data)
            .result()
    }
    /// Join together two `Integrity` instances. Hashes will be bucketed by algorithm but otherwise kept in the same order.
    pub fn concat(&self, other: Integrity) -> Self {
        let mut hashes = [self.hashes.clone(), other.hashes.clone()].concat();
        hashes.sort();
        hashes.dedup();
        Integrity { hashes }
    }
    /// Check some data against this `Integrity`. For more options, use [`Checker`](struct.Checker.html). This method consumes `self`.
    pub fn check<B: AsRef<[u8]>>(self, data: B) -> Option<Algorithm> {
        let mut checker = Checker::new(self);
        checker.input(&data);
        checker.result()
    }
    /// Converts the first `Hash` in this `Integrity` into its hex string format.
    pub fn to_hex(&self) -> (Algorithm, String) {
        let hash = self.hashes.get(0).unwrap();
        (
            hash.algorithm.clone(),
            hex::encode(base64::decode(&hash.digest).unwrap())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Hash;
    use super::Algorithm;
    use super::Integrity;

    #[test]
    fn parse() {
        let sri: Integrity = "sha1-deadbeef=".parse().unwrap();
        assert_eq!(
            sri.hashes.get(0).unwrap(),
            &Hash {
                algorithm: Algorithm::Sha1,
                digest: String::from("deadbeef=")
            }
        )
    }

    #[test]
    fn to_hex() {
        let sri = Integrity::from(b"hello world", Algorithm::Sha1);
        assert_eq!(
            sri.to_hex(),
            (
                Algorithm::Sha1,
                String::from("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")
            )
        )
    }
}
