use std::fmt;

#[derive(Debug, Clone)]
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
