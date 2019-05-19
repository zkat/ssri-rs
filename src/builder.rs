use crate::algorithm::Algorithm;
use crate::integrity::Integrity;

#[derive(Clone)]
pub struct Builder {}
impl Builder {
    pub fn new() -> Builder {
        Builder {}
    }
    pub fn algorithm(&mut self, algo: Algorithm) {
        unimplemented!()
    }
    // This is Digest::Input
    pub fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        unimplemented!()
    }
    pub fn chain<B: AsRef<[u8]>>(&mut self, data: B) -> Self {
        unimplemented!()
    }
    // Digest::Reset
    pub fn reset(&mut self) {
        unimplemented!()
    }
    pub fn result(&mut self) -> Integrity {
        unimplemented!()
    }
}
