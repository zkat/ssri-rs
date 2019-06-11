use failure::Fail;

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "failed to parse subresource integrity string")]
    ParseIntegrityError
}
