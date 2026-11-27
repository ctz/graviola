// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// A generic driver for the ChaCha algorithm, with a trait interface to
// plug in architecture-specific vectorised code for the internal computations.

use std::convert::TryInto;
use std::marker::PhantomData;
use core::mem;

pub(crate) struct ChaCha20<T: ChaChaState, const B: usize> {
    key0: [u32; 4],
    key1: [u32; 4],
    nonce: [u32; 4],
    _data: PhantomData<T>,
}

impl<T: ChaChaState, const B: usize> ChaCha20<T, B> {
    pub(crate) fn new(key: &[u8; 32], nonce: &[u8; 16]) -> Self {
        fn four(b: &[u8; 16]) -> [u32; 4] {
            [
                u32::from_le_bytes(b[0..4].try_into().unwrap()),
                u32::from_le_bytes(b[4..8].try_into().unwrap()),
                u32::from_le_bytes(b[8..12].try_into().unwrap()),
                u32::from_le_bytes(b[12..16].try_into().unwrap()),
            ]
        }

        Self {
            key0: four(key[0..16].try_into().unwrap()),
            key1: four(key[16..32].try_into().unwrap()),
            nonce: four(nonce),
            _data: Default::default(),
        }
    }

    pub(crate) fn cipher(&mut self, buffer: &mut [u8]) {
        const BATCH_SIZE: usize = B * 64;
        let (multi_block, remainder) = buffer.as_chunks_mut::<BATCH_SIZE>();
        for blocks in multi_block {
            let mut state = T::new_multi_block(&self.key0, &self.key1, &self.nonce);
        }
    }
}

pub(crate) trait ChaChaState {
    // Data type that holds one block of ChaCha state.
    type Block;

    // Data type that holds multiple blocks of ChaCha state
    type MultiBlock;

    type MultiBlockBuffer;

    fn new_block(key0: &[u32; 4], key1: &[u32; 4], nonce: &[u32; 4]) -> Self::Block;

    fn new_multi_block(key0: &[u32; 4], key1: &[u32; 4], nonce: &[u32; 4]) -> Self::MultiBlock;

    fn even_round(&mut self, block: &mut Self::MultiBlockBuffer);
    fn odd_round(&mut self, block: &mut Self::MultiBlockBuffer);
}
