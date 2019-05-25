use crate::algorithm::Algorithm;
use crate::builder::Builder;
use crate::integrity::Integrity;

/**
Check data against an [`Integrity`](struct.Integrity.html).

# Examples

```
# use ssri::{Algorithm, Integrity, Checker};
let data = b"hello world";
let sri = Integrity::from(&data, Algorithm::Sha256);
let checker = Checker::new(sri).chain(&data);
assert_eq!(checker.result(), Some(Algorithm::Sha256));
```
*/
pub struct Checker {
    sri: Integrity,
    builder: Builder
}

impl Checker {
    pub fn new(sri: Integrity) -> Checker {
        let builder = Builder::new().algorithm(sri.pick_algorithm());
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
        let algo = self.sri.pick_algorithm();
        self.sri.hashes.iter()
            .take_while(|h| h.algorithm == algo)
            .find(|&h| *h == sri.hashes[0])
            .map(|_| algo)
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
    #[test]
    fn multi_hash() {
        let sri = "sha256-deadbeef".parse::<Integrity>().unwrap()
            .concat(Integrity::from(b"hello world", Algorithm::Sha256));
        eprintln!("\n{}", sri);
        let result = Checker::new(sri).chain(b"hello world").result();
        assert_eq!(
            result,
            Some(Algorithm::Sha256)
        )
    }
}
