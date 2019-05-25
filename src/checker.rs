use crate::algorithm::Algorithm;
use crate::builder::Builder;
use crate::integrity::Integrity;

pub struct Checker {
    sri: Integrity,
    builder: Builder
}

impl Checker {
    pub fn new(sri: Integrity) -> Checker {
        let hash = sri.hashes.get(0).unwrap();
        let builder = Builder::new().algorithm(hash.algorithm.clone());
        Checker { sri, builder }
    }
    pub fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.builder.input(data);
    }
    pub fn chain<B: AsRef<[u8]>>(mut self, data: B) -> Self {
        self.builder.input(data);
        self
    }
    pub fn result(self) -> Option<Algorithm> {
        let sri = self.builder.result();
        let hash = sri.hashes.get(0).unwrap();
        for h in self.sri.hashes.iter() {
            if h.algorithm != hash.algorithm {
                return None
            } else if h == hash {
                return Some(h.algorithm.clone())
            } else {
                continue
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::Checker;
    use super::Integrity;
    use super::Algorithm;

    #[test]
    fn basic_test() {
        let sri = Integrity::from(b"hello world", Algorithm::Sha256);
        let result = Checker::new(sri).chain(b"hello world").result();
        assert_eq!(
            result,
            Some(Algorithm::Sha256)
        )
    }
}
