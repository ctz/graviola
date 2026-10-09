// Written for Graviola by Joe Birr-Pixton, 2026.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::{ptr, slice};

/// A pair of `len`-byte regions: one to read from, one to write to.
///
/// The regions may be identical (for in-place operation), or disjoint.
/// Partial overlap is not permitted.
#[derive(Copy, Clone, Debug)]
pub(crate) struct InOut {
    pub(crate) read: *const u8,
    pub(crate) write: *mut u8,
    pub(crate) len: usize,
}

impl InOut {
    /// # Safety
    /// For the lifetime of the returned value (and anything derived from it):
    /// `read` must be valid for reads of `len` bytes, `write` must be valid for
    /// writes of `len` bytes, and they must be either equal or non-overlapping.
    /// No other references may access either region.
    pub(crate) unsafe fn new(read: *const u8, write: *mut u8, len: usize) -> Self {
        Self { read, write, len }
    }

    fn empty() -> Self {
        Self {
            read: ptr::null(),
            write: ptr::null_mut(),
            len: 0,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the input side as a slice.
    pub(crate) fn read_slice(&self) -> &[u8] {
        match self.len {
            0 => &[],
            // SAFETY: `read` is valid for `len` bytes of reads, per `new()`
            n => unsafe { slice::from_raw_parts(self.read, n) },
        }
    }

    /// Returns the output side as a slice, eg. to read back what was written.
    pub(crate) fn write_slice(&self) -> &[u8] {
        match self.len {
            0 => &[],
            // SAFETY: `write` is valid for `len` bytes, per `new()`
            n => unsafe { slice::from_raw_parts(self.write, n) },
        }
    }

    /// Copies `src` to the output side.
    ///
    /// Panics if `src.len()` is not `self.len`.
    pub(crate) fn write_from(&self, src: &[u8]) {
        assert_eq!(src.len(), self.len);
        if self.len == 0 {
            return;
        }
        // SAFETY: `write` is valid for `len` bytes of writes, per `new()`;
        // `src` is a live shared reference so cannot overlap that region.
        unsafe { ptr::copy_nonoverlapping(src.as_ptr(), self.write, self.len) };
    }
}

/// An iterator over an `InOut` in whole, non-overlapping chunks.
pub(crate) struct ChunksIter<const N: usize>(InOut);

impl<const N: usize> ChunksIter<N> {
    /// Iterates over `whole` in `N`-sized chunks.
    ///
    /// Returns the iterator, plus the remainder (which is shorter than `N`).
    pub(crate) fn new(whole: InOut) -> (Self, InOut) {
        let rem_len = whole.len % N;
        let chunks_len = whole.len - rem_len;
        let remainder = match rem_len {
            0 => InOut::empty(),
            // SAFETY: `chunks_len < whole.len`, so these offsets are in-bounds and
            // the sub-regions inherit `whole`'s validity
            _ => unsafe {
                InOut::new(
                    whole.read.add(chunks_len),
                    whole.write.add(chunks_len),
                    rem_len,
                )
            },
        };
        let chunks = InOut {
            len: chunks_len,
            ..whole
        };
        (Self(chunks), remainder)
    }
}

impl<const N: usize> Iterator for ChunksIter<N> {
    type Item = InOut;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.len < N {
            return None;
        }
        let out = InOut { len: N, ..self.0 };
        // SAFETY: `self.0.len >= N`, so these offsets are in-bounds (or one-past-the-end)
        unsafe {
            self.0.read = self.0.read.add(N);
            self.0.write = self.0.write.add(N);
        }
        self.0.len -= N;
        Some(out)
    }
}
