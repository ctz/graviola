// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

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

/// Random generation from a slice.
///
/// Returns an error once exhausted.  Intended only for testing.
pub(crate) struct SliceRandomSource<'a>(pub &'a [u8]);

impl RandomSource for SliceRandomSource<'_> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        if out.len() > self.0.len() {
            return Err(Error::RngFailed);
        }

        let (chunk, rest) = self.0.split_at(out.len());
        self.0 = rest;
        out.copy_from_slice(chunk);
        Ok(())
    }
}
