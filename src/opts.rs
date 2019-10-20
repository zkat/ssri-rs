use crate::algorithm::Algorithm;
use crate::hash::Hash;
use crate::integrity::Integrity;

use base64;
use digest::Digest;
use sha1;
use sha2;

#[allow(clippy::enum_variant_names)]
#[derive(Clone)]
enum Hasher {
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

/**
Builds a new [`Integrity`](struct.Integrity.html), allowing multiple algorithms and incremental input.

# Examples

```
use ssri::{Algorithm, IntegrityOpts};
let contents = b"hello world";
let sri = IntegrityOpts::new()
    .algorithm(Algorithm::Sha512)
    .algorithm(Algorithm::Sha1)
    .chain(&contents)
    .result();
```

*/
#[derive(Clone, Default)]
pub struct IntegrityOpts {
    hashers: Vec<Hasher>,
    disturbed: bool,
}

impl IntegrityOpts {
    /// Creates a new hashing IntegrityOpts.
    pub fn new() -> IntegrityOpts {
        IntegrityOpts {
            hashers: vec![],
            disturbed: false,
        }
    }

    /// Generate a hash for this algorithm. Can be called multiple times to generate an `Integrity` string with multiple entries.
    pub fn algorithm(mut self, algo: Algorithm) -> Self {
        if self.disturbed {
            panic!("Can't add new algorithms if IntegrityOpts::input() has already been called");
        }
        self.hashers.push(match algo {
            Algorithm::Sha1 => Hasher::Sha1(sha1::Sha1::new()),
            Algorithm::Sha256 => Hasher::Sha256(sha2::Sha256::new()),
            Algorithm::Sha384 => Hasher::Sha384(sha2::Sha384::new()),
            Algorithm::Sha512 => Hasher::Sha512(sha2::Sha512::new()),
        });
        self
    }

    /// Add some data to this IntegrityOpts. All internal hashers will be updated for all configured `Algorithm`s.
    pub fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        self.disturbed = true;
        for hasher in self.hashers.iter_mut() {
            match hasher {
                Hasher::Sha1(h) => digest::Digest::input(h, &input),
                Hasher::Sha256(h) => digest::Digest::input(h, &input),
                Hasher::Sha384(h) => digest::Digest::input(h, &input),
                Hasher::Sha512(h) => digest::Digest::input(h, &input),
            }
        }
    }

    /// Same as `IntegrityOpts::input`, but allows chaining.
    pub fn chain<B: AsRef<[u8]>>(mut self, input: B) -> Self {
        self.input(&input);
        self
    }

    /// Resets internal state for this IntegrityOpts.
    pub fn reset(&mut self) {
        self.hashers = vec![];
        self.disturbed = false;
    }

    /// Generate a new `Integrity` from the inputted data and configured algorithms.
    pub fn result(self) -> Integrity {
        let mut hashes = self
            .hashers
            .into_iter()
            .map(|h| {
                let (algorithm, data) = match h {
                    Hasher::Sha1(h) => (Algorithm::Sha1, base64::encode(&h.result())),
                    Hasher::Sha256(h) => (Algorithm::Sha256, base64::encode(&h.result())),
                    Hasher::Sha384(h) => (Algorithm::Sha384, base64::encode(&h.result())),
                    Hasher::Sha512(h) => (Algorithm::Sha512, base64::encode(&h.result())),
                };
                Hash {
                    algorithm,
                    digest: data,
                }
            })
            .collect::<Vec<Hash>>();
        hashes.sort();
        Integrity { hashes }
    }
}

impl digest::Input for IntegrityOpts {
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        self.input(input)
    }
    fn chain<B: AsRef<[u8]>>(self, input: B) -> Self {
        self.chain(input)
    }
}

impl digest::Reset for IntegrityOpts {
    fn reset(&mut self) {
        self.reset()
    }
}

#[cfg(test)]
mod tests {
    use super::Algorithm;
    use super::IntegrityOpts;

    #[test]
    fn basic_test() {
        let result = IntegrityOpts::new()
            .algorithm(Algorithm::Sha1)
            .algorithm(Algorithm::Sha256)
            .chain(b"hello world")
            .result();
        assert_eq!(
            result.to_string(),
            "sha256-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek= sha1-Kq5sNclPz7QV2+lfQIuc6R7oRu0="
        )
    }
}
