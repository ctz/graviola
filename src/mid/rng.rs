use crate::Error;

/// The library's external and internal trait for all
/// random consumption.
pub trait RandomSource {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error>;
}

/// Random generation from the system entropy source via
/// the `getrandom` crate.
pub struct SystemRandom;

impl RandomSource for SystemRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        getrandom::getrandom(out).map_err(|_| Error::RngFailed)
    }
}
