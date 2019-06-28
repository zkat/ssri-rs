use std::fmt;

use hex;
use serde_derive::{Serialize, Deserialize};

use crate::algorithm::Algorithm;
use crate::opts::IntegrityOpts;
use crate::checker::IntegrityChecker;
use crate::errors::Error;
use crate::hash::Hash;

/**
Representation of a full [Subresource Integrity string](https://w3c.github.io/webappsec/specs/subresourceintegrity/).

`Integrity` can be used for parsing and also includes convenience methods
for shorthand versions of [`IntegrityOpts`](struct.IntegrityOpts.html) and
[`IntegrityChecker`](struct.IntegrityChecker.html).
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
        self.hashes[0].algorithm
    }
    /// Create a new `Integrity` based on `data`. Use [`IntegrityOpts`](struct.IntegrityOpts.html) for more options.
    pub fn from<B: AsRef<[u8]>>(data: B) -> Integrity {
        IntegrityOpts::new()
            .algorithm(Algorithm::Sha256)
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
    /// Check some data against this `Integrity`. For more options, use [`Checker`](struct.Checker.html).
    pub fn check<B: AsRef<[u8]>>(&self, data: B) -> Option<Algorithm> {
        let mut checker = IntegrityChecker::new(self.clone());
        checker.input(&data);
        checker.result()
    }
    /// Converts the first `Hash` in this `Integrity` into its hex string format.
    pub fn to_hex(&self) -> (Algorithm, String) {
        let hash = self.hashes.get(0).unwrap();
        (
            hash.algorithm,
            hex::encode(base64::decode(&hash.digest).unwrap())
        )
    }
    /// Compares `self` against a given SRI to see if there's a match. The deciding algorithm is determined by `other`.
    pub fn matches(&self, other: &Self) -> Option<Algorithm> {
        let algo = other.pick_algorithm();
        self
            .hashes
            .iter()
            .filter(|h| h.algorithm == algo)
            .find(|&h| {
                other.hashes
                    .iter()
                    .filter(|i| i.algorithm == algo)
                    .any(|i| h == i)
            })
            .map(|h| h.algorithm)
    }
}

#[cfg(test)]
mod tests {
    use super::{Hash, Algorithm, Integrity, IntegrityOpts};

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
        let sri = Integrity::from(b"hello world");
        assert_eq!(
            sri.to_hex(),
            (
                Algorithm::Sha256,
                String::from("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
            )
        )
    }

    #[test]
    fn matches() {
        let sri1 = IntegrityOpts::new()
            .algorithm(Algorithm::Sha512)
            .algorithm(Algorithm::Sha256)
            .chain(b"hello world")
            .result();
        let sri2 = Integrity::from(b"hello world");
        let sri3 = Integrity::from(b"goodbye world");
        assert_eq!(
            sri1.matches(&sri2),
            Some(Algorithm::Sha256)
        );
        assert_eq!(
            sri1.matches(&sri3),
            None
        );
        assert_eq!(
            sri2.matches(&sri1),
            None
        )
    }
}
