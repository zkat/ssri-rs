use crate::algorithm::Algorithm;
use crate::integrity::ParseIntegrityError;
use std::cmp::Ordering;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
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
    type Err = ParseIntegrityError;

    fn from_str(s: &str) -> Result<Hash, Self::Err> {
        let mut parsed = s.trim().split(|c| c == '-');
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
            format!("{}", Hash {
                algorithm: Algorithm::Sha256,
                digest: String::from("deadbeef==")
            }),
            "sha256-deadbeef=="
        )
    }
}
