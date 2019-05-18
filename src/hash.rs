use crate::algorithm::Algorithm;
use crate::integrity::ParseIntegrityError;
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub struct Hash {
    pub algorithm: Algorithm,
    pub digest: String
}

impl Hash {
    pub fn new(algo: Algorithm, digest: String) -> Hash {
        Hash {
            algorithm: algo,
            digest: digest
        }
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}-{}", self.algorithm, self.digest)
    }
}

impl std::str::FromStr for Hash {
    type Err = ParseIntegrityError;

    fn from_str(s: &str) -> Result<Hash, Self::Err> {
        let mut parsed = s.split(|c| c == '-');
        let algorithm = parsed.next().ok_or(ParseIntegrityError{})?.parse()?;
        let digest = String::from(parsed.next().ok_or(ParseIntegrityError{})?);
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
            format!("{}", Hash::new(Algorithm::Sha256, String::from("deadbeef=="))),
            "sha256-deadbeef=="
        )
    }
}
