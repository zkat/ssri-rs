use crate::algorithm::Algorithm;
use crate::hash::Hash;
use crate::integrity::Integrity;

extern crate sha1;
use sha2;
use digest::Digest;
use base64;

#[derive(Clone)]
enum Hasher {
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

#[derive(Clone)]
pub struct Builder {
    hashers: Vec<Hasher>,
    disturbed: bool
}

impl Builder {
    pub fn new() -> Builder {
        Builder { hashers: vec!(), disturbed: false }
    }
    pub fn algorithm(&mut self, algo: Algorithm) {
        if self.disturbed {
            panic!("Can't add new algorithms if Builder::input() has already been called");
        }
        self.hashers.push(match algo {
            Algorithm::Sha1 => Hasher::Sha1(sha1::Sha1::new()),
            Algorithm::Sha256 => Hasher::Sha256(sha2::Sha256::new()),
            Algorithm::Sha384 => Hasher::Sha384(sha2::Sha384::new()),
            Algorithm::Sha512 => Hasher::Sha512(sha2::Sha512::new()),
        })
    }
    // This is Digest::Input
    pub fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        self.disturbed = true;
        for hasher in self.hashers.iter_mut() {
            match hasher {
                Hasher::Sha1(h) => h.input(&input),
                Hasher::Sha256(h) => h.input(&input),
                Hasher::Sha384(h) => h.input(&input),
                Hasher::Sha512(h) => h.input(&input),
            }
        }
    }
    // Digest::Reset
    pub fn reset(&mut self) {
        self.hashers = vec!();
        self.disturbed = false;
    }
    pub fn result(self) -> Integrity {
        let mut hashes = self.hashers.into_iter().map(|h| {
            let (algorithm, data) = match h {
                Hasher::Sha1(h) => (
                    Algorithm::Sha1, base64::encode(&h.result())
                ),
                Hasher::Sha256(h) => (
                    Algorithm::Sha256, base64::encode(&h.result())
                ),
                Hasher::Sha384(h) => (
                    Algorithm::Sha384, base64::encode(&h.result())
                ),
                Hasher::Sha512(h) => (
                    Algorithm::Sha512, base64::encode(&h.result())
                ),
            };
            Hash {
                algorithm,
                digest: data
            }
        }).collect::<Vec<Hash>>();
        hashes.sort_unstable();
        Integrity { hashes }
    }
}

#[cfg(test)]
mod tests {
    use super::Builder;
    use super::Algorithm;

    #[test]
    fn basic_test() {
        let mut builder = Builder::new();
        builder.algorithm(Algorithm::Sha1);
        builder.algorithm(Algorithm::Sha256);
        builder.input(b"hello world");
        let result = builder.result();
        assert_eq!(
            result.to_string(),
            "sha256-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek= sha1-Kq5sNclPz7QV2+lfQIuc6R7oRu0="
        )
    }
}
