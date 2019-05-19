use crate::hash::Hash;
use crate::algorithm::Algorithm;
use std::fmt;
use std::error::Error;

#[derive(Clone, Debug)]
pub struct Integrity {
    pub hashes: Vec<Hash>
}

impl fmt::Display for Integrity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!()
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
    pub fn concat(&self, other: Integrity) -> Self {
        unimplemented!()
    }
    pub fn check<B: AsRef<[u8]>>(&self, data: B) -> Result<Algorithm, ParseIntegrityError> {
        unimplemented!()
    }
}

pub fn from<B: AsRef<[u8]>>(data: B, algorithm: Algorithm) -> Integrity {
    unimplemented!()
}

#[derive(Debug)]
pub struct ParseIntegrityError {}
impl fmt::Display for ParseIntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!()
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
            &Hash::new(Algorithm::Sha1, String::from("deadbeef="))
        )
    }
}
