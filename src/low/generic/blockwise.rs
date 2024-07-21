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

    pub(crate) fn add_trailing(&mut self, trailing: &[u8]) {
        self.buffer[..trailing.len()].copy_from_slice(trailing);
        self.used += trailing.len();
    }
}

/// Iterator over N-length arrays from a byte slice.
///
/// The last block is padded with the given padding byte,
/// if necessary.
///
/// If the buffer is empty, no blocks are produced.
pub(crate) struct BlockwisePadded<'a, const N: usize> {
    buffer: [u8; N],
    input: &'a [u8],
}

impl<'a, const N: usize> BlockwisePadded<'a, N> {
    /// Makes a new one.
    pub(crate) fn new(input: &'a [u8], pad: u8) -> Self {
        Self {
            buffer: [pad; N],
            input,
        }
    }
}

impl<'a, const N: usize> Iterator for BlockwisePadded<'a, N> {
    type Item = [u8; N];

    fn next(&mut self) -> Option<Self::Item> {
        match self.input.get(..N) {
            Some(chunk) => {
                self.input = &self.input[N..];
                Some(chunk.try_into().unwrap())
            }

            None => {
                let left = self.input.len();
                if left == 0 {
                    return None;
                }

                self.buffer[..left].copy_from_slice(self.input);
                self.input = &[];
                Some(self.buffer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blockwise_padded() {
        assert!(BlockwisePadded::<4>::new(&[], 0xff).next().is_none());
        assert_eq!(
            BlockwisePadded::<4>::new(&[1], 0xff).collect::<Vec<_>>(),
            &[[1, 0xff, 0xff, 0xff]]
        );
        assert_eq!(
            BlockwisePadded::<4>::new(&[1, 2], 0xff).collect::<Vec<_>>(),
            &[[1, 2, 0xff, 0xff]]
        );
        assert_eq!(
            BlockwisePadded::<4>::new(&[1, 2, 3], 0xff).collect::<Vec<_>>(),
            &[[1, 2, 3, 0xff]]
        );
        assert_eq!(
            BlockwisePadded::<4>::new(&[1, 2, 3, 4], 0xff).collect::<Vec<_>>(),
            &[[1, 2, 3, 4]]
        );
        assert_eq!(
            BlockwisePadded::<4>::new(&[1, 2, 3, 4, 5, 6, 7, 8], 0xff).collect::<Vec<_>>(),
            &[[1, 2, 3, 4], [5, 6, 7, 8]]
        );
    }
}
