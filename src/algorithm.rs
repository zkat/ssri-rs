use std::fmt;

use serde_derive::{Serialize, Deserialize};

use crate::errors::Error;

/**
Valid algorithms for integrity strings.

`Sha1` is a special case in this library -- it's not allowed by the
current SRI spec, but it's useful enough that having first-class support
makes sense. It should also be completely harmless to have in your strings
if you do use it in a browser context.
*/
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
    type Err = Error;

    fn from_str(s: &str) -> Result<Algorithm, Self::Err> {
        match s {
            "sha1" => Ok(Algorithm::Sha1),
            "sha256" => Ok(Algorithm::Sha256),
            "sha384" => Ok(Algorithm::Sha384),
            "sha512" => Ok(Algorithm::Sha512),
            _ => Err(Error::ParseIntegrityError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Algorithm::*;

    #[test]
    fn algorithm_formatting() {
        assert_eq!(format!("{}", Sha1), "sha1");
        assert_eq!(format!("{}", Sha256), "sha256");
        assert_eq!(format!("{}", Sha384), "sha384");
        assert_eq!(format!("{}", Sha512), "sha512");
    }

    #[test]
    fn ordering() {
        let mut arr = [
            Sha1,
            Sha256,
            Sha384,
            Sha512,
        ];
        arr.sort_unstable();
        assert_eq!(arr, [
            Sha512,
            Sha384,
            Sha256,
            Sha1,
        ])
    }
}
