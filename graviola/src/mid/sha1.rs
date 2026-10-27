// Written for Graviola by Joe Birr-Pixton, 2025.
// Based on 2014 version written for cifra.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! The SHA1 hash function.
//!
//! Do not use SHA1 for new applications or for applications involving signatures.
//!
//! This is described in [FIPS180-1](https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/fipspub180-1.pdf).

use crate::low::Blockwise;

/// A context for incremental computation of SHA1.
#[derive(Clone)]
pub struct Sha1Context {
    h: [u32; 5],
    blockwise: Blockwise<{ Self::BLOCK_SZ }>,
    nblocks: usize,
}

impl Sha1Context {
    /// Start a new SHA1 hash computation.
    pub const fn new() -> Self {
        Self {
            h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            blockwise: Blockwise::new(),
            nblocks: 0,
        }
    }

    /// Add `bytes` to the ongoing hash computation.
    pub fn update(&mut self, bytes: &[u8]) {
        if self.blockwise.used() == 0 && bytes.len().is_multiple_of(Self::BLOCK_SZ) {
            self.update_blocks(bytes);
            return;
        }

        let bytes = self.blockwise.add_leading(bytes);

        if let Some(block) = self.blockwise.take() {
            self.update_blocks(&block);
        }

        let (whole_blocks, remainder) = {
            let whole_len = bytes.len() - (bytes.len() & (Self::BLOCK_SZ - 1));
            (&bytes[..whole_len], &bytes[whole_len..])
        };

        self.update_blocks(whole_blocks);

        self.blockwise.add_trailing(remainder);
    }

    /// Complete the SHA1 computation, returning the hash output.
    pub fn finish(mut self) -> [u8; Self::OUTPUT_SZ] {
        let bytes = self
            .nblocks
            .checked_mul(Self::BLOCK_SZ)
            .and_then(|bytes| bytes.checked_add(self.blockwise.used()))
            .unwrap();

        let bits = bytes
            .checked_mul(8)
            .expect("excess data processed by hash function");

        let last_blocks = self
            .blockwise
            .md_pad_with_length(&(bits as u64).to_be_bytes());
        self.update_blocks(last_blocks.as_ref());

        let mut r = [0u8; Self::OUTPUT_SZ];
        for (out, state) in r.chunks_exact_mut(4).zip(self.h.iter()) {
            out.copy_from_slice(&state.to_be_bytes());
        }
        r
    }

    fn update_blocks(&mut self, blocks: &[u8]) {
        debug_assert!(blocks.len().is_multiple_of(Self::BLOCK_SZ));
        if !blocks.is_empty() {
            sha1_compress_blocks(&mut self.h, blocks);
            self.nblocks = self.nblocks.saturating_add(blocks.len() / Self::BLOCK_SZ);
        }
    }

    /// The internal block size of SHA1.
    pub const BLOCK_SZ: usize = 64;

    /// The output size of SHA1.
    pub const OUTPUT_SZ: usize = 20;
}

fn sha1_compress_block(state: &mut [u32; 5], block: &[u8]) {
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];

    // This is a 16-word window into the whole W array.
    let mut w: [u32; 16] = [0; 16];

    for t in 0..80 {
        // For W[0..16] we process the input into W.
        // For W[16..80] we compute the next W value:
        //
        // W[t] = (W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]) <<< 1
        //
        // But all W indices are reduced mod 16 into our window.
        let w_t = if t < 16 {
            let w_t = u32::from_be_bytes(block[t * 4..(t + 1) * 4].try_into().unwrap());
            w[t] = w_t;
            w_t
        } else {
            let w_t = (w[(t - 3) % 16] ^ w[(t - 8) % 16] ^ w[(t - 14) % 16] ^ w[(t - 16) % 16])
                .rotate_left(1);
            w[t % 16] = w_t;
            w_t
        };

        let (f, k) = match t {
            0..20 => ((b & c) | (!b & d), 0x5a827999),
            20..40 => (b ^ c ^ d, 0x6ed9eba1),
            40..60 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
            _ => (b ^ c ^ d, 0xca62c1d6),
        };

        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w_t);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

pub(crate) fn sha1_compress_blocks(state: &mut [u32; 5], blocks: &[u8]) {
    debug_assert!(blocks.len().is_multiple_of(64));

    for block in blocks.chunks_exact(64) {
        sha1_compress_block(state, block);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn test_vectors() {
        vector(
            b"",
            b"\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x07\x09",
        );
        vector(
            b"abc",
            b"\xa9\x99\x3e\x36\x47\x06\x81\x6a\xba\x3e\x25\x71\x78\x50\xc2\x6c\x9c\xd0\xd8\x9d",
        );
        vector(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            b"\x84\x98\x3e\x44\x1c\x3b\xd2\x6e\xba\xae\x4a\xa1\xf9\x51\x29\xe5\xe5\x46\x70\xf1",
        );
        vector(
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            b"\xa4\x9b\x24\x46\xa0\x2c\x64\x5b\xf4\x19\xf9\x95\xb6\x70\x91\x25\x3a\x04\xa2\x59",
        );

        fn vector(message: &[u8], expected: &[u8; Sha1Context::OUTPUT_SZ]) {
            let mut ctx = Sha1Context::new();
            ctx.update(message);
            assert_eq!(&ctx.finish(), expected);
        }
    }

    #[test]
    fn sha1_all_lengths() {
        // see cifra `vector_length` and associated
        let mut outer = Sha1Context::new();

        for len in 0..1024 {
            let mut inner = Sha1Context::new();

            for _ in 0..len {
                inner.update(&[len as u8]);
            }

            outer.update(&inner.finish());
        }

        assert_eq!(
            &outer.finish(),
            b"\x15\x53\x65\xcf\x77\xee\xd4\x8f\x46\xe2\x55\xc7\xdd\xdf\xfd\x0a\xf6\x99\x88\xbe"
        );
    }
}
