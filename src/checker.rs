use crate::algorithm::Algorithm;
use crate::opts::IntegrityOpts;
use crate::integrity::Integrity;

/**
Check data against an [`Integrity`](struct.Integrity.html).

# Examples

```
# use ssri::{Algorithm, Integrity, IntegrityChecker};
let data = b"hello world";
let sri = Integrity::from(&data);
let checker = IntegrityChecker::new(&sri).chain(&data);
assert_eq!(checker.result(), Some(Algorithm::Sha256));
```
*/
pub struct IntegrityChecker<'a> {
    sri: &'a Integrity,
    builder: IntegrityOpts
}

impl<'a> IntegrityChecker<'a> {
    /// Creates a new `IntegrityChecker` builder. Use this to verify chunked
    /// data.
    pub fn new(sri: &'a Integrity) -> IntegrityChecker<'a> {
        let builder = IntegrityOpts::new().algorithm(sri.pick_algorithm());
        IntegrityChecker { sri: &sri, builder }
    }
    /// Add some data to the running checker.
    pub fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.builder.input(data);
    }
    /// Same as `IntegrityChecker::input`, but allows chained calls.
    pub fn chain<B: AsRef<[u8]>>(mut self, data: B) -> Self {
        self.builder.input(data);
        self
    }
    /// Returns the matching algorithm if the inputted data matches the input `Integrity`.
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
    use super::IntegrityChecker;
    use super::Integrity;
    use super::Algorithm;

    #[test]
    fn basic_test() {
        let sri = Integrity::from(b"hello world");
        let result = IntegrityChecker::new(&sri).chain(b"hello world").result();
        assert_eq!(
            result,
            Some(Algorithm::Sha256)
        )
    }
    #[test]
    fn multi_hash() {
        let sri = "sha256-deadbeef".parse::<Integrity>().unwrap()
            .concat(Integrity::from(b"hello world"));
        eprintln!("\n{}", sri);
        let result = IntegrityChecker::new(&sri).chain(b"hello world").result();
        assert_eq!(
            result,
            Some(Algorithm::Sha256)
        )
    }
}
