use std::fmt;
use crate::integrity::ParseIntegrityError;

/**
Valid algorithms for integrity strings.

`Sha1` is a special case in this library -- it's not allowed by the
current SRI spec, but it's useful enough that having first-class support
makes sense. It should also be completely harmless to have in your strings
if you do use it in a browser context.
*/
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Algorithm {
    Sha512,
    Sha384,
    Sha256,
    Sha1,
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

    #[test]
    fn ordering() {
        let mut arr = [
            Algorithm::Sha1,
            Algorithm::Sha256,
            Algorithm::Sha384,
            Algorithm::Sha512,
        ];
        arr.sort_unstable();
        assert_eq!(arr, [
            Algorithm::Sha512,
            Algorithm::Sha384,
            Algorithm::Sha256,
            Algorithm::Sha1,
        ])
    }
}
