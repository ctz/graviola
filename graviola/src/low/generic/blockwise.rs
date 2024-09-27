// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

#[derive(Clone)]
pub(crate) struct Blockwise<const N: usize> {
    buffer: [u8; N],
    used: usize,
}

impl<const N: usize> Blockwise<N> {
    pub(crate) const fn new() -> Self {
        Self {
            buffer: [0u8; N],
            used: 0,
        }
    }

    pub(crate) const fn used(&self) -> usize {
        self.used
    }

    pub(crate) fn add_leading<'a>(&mut self, bytes: &'a [u8]) -> &'a [u8] {
        if self.used == 0 {
            return bytes;
        }

        let space = N - self.used;
        let take = core::cmp::min(bytes.len(), space);
        let (taken, returned) = bytes.split_at(take);
        self.buffer[self.used..self.used + take].copy_from_slice(taken);
        self.used += take;
        returned
    }

    pub(crate) fn take(&mut self) -> Option<[u8; N]> {
        if self.used == N {
            self.used = 0;
            Some(self.buffer)
        } else {
            None
        }
    }

    pub(crate) fn peek_remaining(&self) -> Option<&[u8]> {
        if self.used > 0 {
            Some(&self.buffer[..self.used])
        } else {
            None
        }
    }

    pub(crate) fn add_trailing(&mut self, trailing: &[u8]) {
        self.buffer[..trailing.len()].copy_from_slice(trailing);
        self.used += trailing.len();
    }
}
