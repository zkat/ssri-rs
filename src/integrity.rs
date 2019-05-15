use crate::hash::Hash;
use crate::algorithm::Algorithm;
use crate::builder::IntegrityBuilder;
use std::fmt;

#[derive(Clone, Debug)]
pub struct Integrity<'a> {
    pub hashes: Vec<Hash<'a>>
}

impl<'a> fmt::Display for Integrity<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!()
    }
}

impl<'a> Integrity<'a> {
    pub fn new() -> IntegrityBuilder {
        unimplemented!()
    }
    pub fn concat(&self, other: Integrity) -> Self {
        unimplemented!()
    }
    pub fn check<B: AsRef<[u8]>>(&self, data: B) -> Result<Algorithm, IntegrityError> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct IntegrityError {}
impl fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!()
    }
}
