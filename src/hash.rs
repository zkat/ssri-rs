use crate::algorithm::Algorithm;
use std::fmt;

#[derive(Clone, Debug)]
pub struct Hash<'a> {
    pub algorithm: Algorithm,
    pub digest: &'a [u8]
}

impl<'a> Hash<'a> {
    pub fn new(algo: Algorithm, digest: &[u8]) -> Hash {
        Hash {
            algorithm: algo,
            digest: digest
        }
    }
}

impl<'a> fmt::Display for Hash<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}-{}", self.algorithm, base64::encode(&self.digest))
    }
}

#[cfg(test)]
mod tests {
    use super::Hash;
    use super::Algorithm;

    #[test]
    fn hash_stringify() {
        assert_eq!(
            format!("{}", Hash::new(Algorithm::Sha256, &[1, 2, 3, 4])),
            "sha256-AQIDBA=="
        )
    }
}
