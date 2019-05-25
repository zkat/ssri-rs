use crate::algorithm::Algorithm;
use crate::builder::Builder;
use crate::checker::Checker;
use crate::hash::Hash;
use std::fmt;
use std::error::Error;
use hex;

/**
Representation of a full [Subresource Integrity string](https://w3c.github.io/webappsec/specs/subresourceintegrity/).

`Integrity` can be used for parsing and also includes convenience methods
for shorthand versions of [`Builder`](struct.Builder.html) and
[`Checker`](struct.Checker.html).
*/
#[derive(Clone, Debug)]
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
    type Err = ParseIntegrityError;

    fn from_str(s: &str) -> Result<Integrity, Self::Err> {
        let hashes = String::from(s)
            .split_whitespace()
            .map(|x| x.parse())
            .collect::<Result<Vec<Hash>, Self::Err>>()?;
        Ok(Integrity { hashes })
    }
}

impl Integrity {
    pub fn pick_algorithm(&self) -> Algorithm {
        self.hashes[0].algorithm.clone()
    }
    pub fn from<B: AsRef<[u8]>>(data: B, algorithm: Algorithm) -> Integrity {
        Builder::new()
            .algorithm(algorithm)
            .chain(&data)
            .result()
    }
    pub fn concat(&self, other: Integrity) -> Self {
        let mut hashes = [self.hashes.clone(), other.hashes.clone()].concat();
        hashes.sort();
        hashes.dedup();
        Integrity { hashes }
    }
    pub fn check<B: AsRef<[u8]>>(self, data: B) -> Option<Algorithm> {
        let mut checker = Checker::new(self);
        checker.input(&data);
        checker.result()
    }
    pub fn to_hex(&self) -> (Algorithm, String) {
        let hash = self.hashes.get(0).unwrap();
        (
            hash.algorithm.clone(),
            hex::encode(base64::decode(&hash.digest).unwrap())
        )
    }
}

/**
Error parsing an integrity string into an [`Integrity`](struct.Integrity.html).
*/
#[derive(Debug)]
pub struct ParseIntegrityError {}
impl fmt::Display for ParseIntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "failed to parse Subresource Integrity string")
    }
}
impl Error for ParseIntegrityError {}

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
