/*!
[`ssri`](https://github.com/zkat/ssri-rs), short for Standard Subresource
Integrity, is a Rust library for parsing, manipulating, serializing,
generating, and verifying [Subresource Integrity](https://w3c.github.io/webappsec/specs/subresourceintegrity/)
hashes.

# Usage

Parsing and serializing Subresource Integrity strings:
```no_run
let integrity = String::from("sha512-9KhgCRIx/AmzC8xqYJTZRrnO8OW2Pxyl2DIMZSBOr0oDvtEFyht3xpp71j/r/pAe1DM+JI/A+line3jUBgzQ7A==");

let parsed: ssri::Integrity = integrity.parse().unwrap();
assert_eq!(parsed.to_string(), integrity)
```

Generating a new hash from file data:
```no_run
# use ssri::{Algorithm, Integrity};
# use std::fs::File;
# use std::io::prelude::*;
// Get file data...
let mut file = File::open("foo.txt").unwrap();
let mut contents = String::new();
file.read_to_string(&mut contents).unwrap();

// Hand it to ssri.
let mut hasher = Integrity::new();
hasher.algorithm(Algorithm::Sha256);
hasher.input(&contents);

let sri = hasher.result();

assert_eq!(sri.to_string(), "sha256-deadbeef");

// Verify the data:
assert_eq!(sri.check(&contents).unwrap(), Algorithm::Sha256);
```
*/
mod algorithm;
mod hash;
mod integrity;
mod builder;

pub use algorithm::Algorithm;
pub use hash::Hash;
pub use integrity::*;
