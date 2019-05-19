use crate::algorithm::Algorithm;
use crate::integrity::Integrity;

pub struct Checker {
    sri: Integrity
}

impl Checker {
    pub fn new(sri: Integrity) -> Checker {
        // TODO - calculate target algorithm early
        Checker { sri }
    }
    pub fn input<B: AsRef<[u8]>>(&self, data: B) {
        unimplemented!()
    }
    pub fn result(&self) -> Option<Algorithm> {
        unimplemented!()
    }
}
