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
# use ssri::{Integrity, Algorithm};
# use std::fs::File;
# use std::io::prelude::*;
// Get file data...
let mut file = File::open("foo.txt").unwrap();
let mut contents = String::new();
file.read_to_string(&mut contents).unwrap();

// Use a builder for more options + streaming data support.
let mut builder = ssri::Builder::new();
builder.algorithm(Algorithm::Sha512);
builder.algorithm(Algorithm::Sha1);
builder.input(&contents);
// builder.input(...more stuff);
let sri = builder.result();

// Or use from() for a simpler interface that works in most cases.
let sri = Integrity::from(&contents, Algorithm::Sha256);

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
pub use builder::Builder;
pub use hash::Hash;
pub use integrity::*;
