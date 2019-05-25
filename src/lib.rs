/*!
[`ssri`](https://github.com/zkat/ssri-rs), short for Standard Subresource
Integrity, is a Rust library for parsing, manipulating, serializing,
generating, and verifying [Subresource Integrity](https://w3c.github.io/webappsec/specs/subresourceintegrity/)
hashes.

# Examples

Parse a string as [`Integrity`](struct.Integrity.html) to convert it to a struct:
```
# use ssri::Integrity;
let source = String::from("sha512-9KhgCRIx/AmzC8xqYJTZRrnO8OW2Pxyl2DIMZSBOr0oDvtEFyht3xpp71j/r/pAe1DM+JI/A+line3jUBgzQ7A==");

let parsed: Integrity = source.parse().unwrap();
assert_eq!(parsed.to_string(), source)
```

Generating a new hash from file data:
```
# use ssri::{Integrity, Algorithm};
let sri = Integrity::from(b"hello world", Algorithm::Sha256);
assert_eq!(sri.to_string(), "sha256-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=");
```

Verifying data against an SRI:
```
# use ssri::{Integrity, Algorithm};
let sri = Integrity::from(b"hello world", Algorithm::Sha256);
assert_eq!(sri.check(b"hello world").unwrap(), Algorithm::Sha256);
```

You can also use [`Builder`](struct.Builder.html) and [`Checker`](struct.Checker.html) to generate
and check subresource integrity, respectively. These allow things like multiple algorithms, and
incremental/streamed data input.
*/

mod algorithm;
mod hash;
mod integrity;
mod builder;
mod checker;

pub use algorithm::Algorithm;
pub use builder::Builder;
pub use checker::Checker;
pub use hash::Hash;
pub use integrity::*;
