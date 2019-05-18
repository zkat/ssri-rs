use std::fmt;
use crate::integrity::ParseIntegrityError;

#[derive(Debug, Clone, PartialEq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", format!("{:?}", self).to_lowercase())
    }
}

impl std::str::FromStr for Algorithm {
    type Err = ParseIntegrityError;

    fn from_str(s: &str) -> Result<Algorithm, Self::Err> {
        match s {
            "sha1" => Ok(Algorithm::Sha1),
            "sha256" => Ok(Algorithm::Sha256),
            "sha384" => Ok(Algorithm::Sha384),
            "sha512" => Ok(Algorithm::Sha512),
            _ => Err(ParseIntegrityError{})
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Algorithm;

    #[test]
    fn algorithm_formatting() {
        assert_eq!(format!("{}", Algorithm::Sha1), "sha1");
        assert_eq!(format!("{}", Algorithm::Sha256), "sha256");
        assert_eq!(format!("{}", Algorithm::Sha384), "sha384");
        assert_eq!(format!("{}", Algorithm::Sha512), "sha512");
    }
}
