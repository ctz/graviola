// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
// Originally from cifra

use super::blockwise::Blockwise;

pub(crate) struct Poly1305 {
    /// Current accumulator
    h: [u32; 17],

    /// Block multiplier
    r: [u32; 17],

    /// Final XOR offset
    s: [u8; 16],

    /// Unprocessed input
    bw: Blockwise<16>,
}

impl Poly1305 {
    pub(crate) fn new(key: &[u8; 32]) -> Self {
        let h = [0; 17];
        let r = [
            u32::from(key[0]),
            u32::from(key[1]),
            u32::from(key[2]),
            u32::from(key[3] & 0x0f),
            u32::from(key[4] & 0xfc),
            u32::from(key[5]),
            u32::from(key[6]),
            u32::from(key[7] & 0x0f),
            u32::from(key[8] & 0xfc),
            u32::from(key[9]),
            u32::from(key[10]),
            u32::from(key[11] & 0x0f),
            u32::from(key[12] & 0xfc),
            u32::from(key[13]),
            u32::from(key[14]),
            u32::from(key[15] & 0x0f),
            0,
        ];
        let s = key[16..32].try_into().unwrap();
        Self {
            h,
            r,
            s,
            bw: Blockwise::new(),
        }
    }

    pub(crate) fn add_bytes(&mut self, bytes: &[u8]) {
        let bytes = self.bw.add_leading(bytes);

        if let Some(block) = self.bw.take() {
            self.process_whole_block(&block);
        }

        let mut full_blocks = bytes.chunks_exact(16);
        for block in full_blocks.by_ref() {
            self.process_whole_block(block.try_into().unwrap());
        }

        self.bw.add_trailing(full_blocks.remainder());
    }

    pub(crate) fn finish(mut self) -> [u8; 16] {
        if let Some(block) = self.bw.clone().peek_remaining() {
            self.process_last_block(block);
        }

        let mut s32 = [0u32; 17];
        for (out, ss) in s32.iter_mut().zip(self.s.iter()) {
            *out = u32::from(*ss);
        }

        full_reduce(&mut self.h);
        add(&mut self.h, &s32);

        let mut r = [0u8; 16];
        for (out, hh) in r.iter_mut().zip(self.h.iter()) {
            *out = *hh as u8;
        }

        r
    }

    fn process_whole_block(&mut self, inp: &[u8; 16]) {
        let block = [
            u32::from(inp[0]),
            u32::from(inp[1]),
            u32::from(inp[2]),
            u32::from(inp[3]),
            u32::from(inp[4]),
            u32::from(inp[5]),
            u32::from(inp[6]),
            u32::from(inp[7]),
            u32::from(inp[8]),
            u32::from(inp[9]),
            u32::from(inp[10]),
            u32::from(inp[11]),
            u32::from(inp[12]),
            u32::from(inp[13]),
            u32::from(inp[14]),
            u32::from(inp[15]),
            1,
        ];
        self.process_block(&block);
    }

    fn process_last_block(&mut self, inp: &[u8]) {
        let mut block = [0u32; 17];
        for (out, ii) in block.iter_mut().zip(inp.iter()) {
            *out = u32::from(*ii);
        }
        block[inp.len()] = 0x01;
        self.process_block(&block);
    }

    fn process_block(&mut self, block: &[u32; 17]) {
        add(&mut self.h, block);
        mul(&mut self.h, &self.r);
    }
}

fn add(h: &mut [u32; 17], x: &[u32; 17]) {
    let mut carry = 0;
    for (hh, xx) in h.iter_mut().zip(x.iter()) {
        carry += *hh + *xx;
        *hh = carry & 0xff;
        carry >>= 8;
    }
}

fn mul(x: &mut [u32; 17], y: &[u32; 17]) {
    let mut r = [0u32; 17];

    for i in 0..17 {
        let mut accum = 0;
        for j in 0..=i {
            accum += x[j] * y[i - j];
        }

        // Add in carries.  These get shifted 130 bits
        // to the right, with a combination of byte indexing
        // and shifting (136 bits right, then 6 bits left).
        //
        // nb. 5 << 6 is made up of two parts:
        //   5: reduction of 2 ** 130 leaves a multiple 5
        //   shift 6 places left
        //     17 * 8: byte indexing shift (136 bits)
        //     130: desired shift

        for j in i + 1..17 {
            accum += (5 << 6) * x[j] * y[i + 17 - j];
        }

        r[i] = accum;
    }

    min_reduce(&mut r);
    *x = r;
}

fn min_reduce(x: &mut [u32; 17]) {
    // Minimal reduction/carry chain.

    let mut carry = 0;
    for xx in x[..16].iter_mut() {
        carry += *xx;
        *xx = carry & 0xff;
        carry >>= 8;
    }

    // 2 ** 130 - 5 = 0x3fffffffffffffffffffffffffffffffb
    //                 ^
    // So 2 bits of carry are put into top word.
    // Remaining bits get multiplied by 5 and carried back
    // into bottom */
    carry += x[16];
    x[16] = carry & 0x03;
    carry = 5 * (carry >> 2);

    for xx in x[..16].iter_mut() {
        carry += *xx;
        *xx = carry & 0xff;
        carry >>= 8;
    }

    x[16] += carry;
}

fn full_reduce(x: &mut [u32; 17]) {
    let mut xsub = *x;
    add(&mut xsub, &NEGATIVE_1305);

    // If x - (2 ** 130 - 5) is negative, then
    // x didn't need reduction: we discard the results.
    // Do this without branching.
    let negative_mask = equal_mask(xsub[16] & 0x80, 0x80);
    let positive_mask = negative_mask ^ 0xffffffff;

    for (xx, xs) in x.iter_mut().zip(xsub.iter()) {
        *xx = (*xx & negative_mask) | (*xs & positive_mask);
    }
}

/// Produce 0xffffffff if x == y, zero
fn equal_mask(x: u32, y: u32) -> u32 {
    let diff = x ^ y;
    let diff_is_zero = !diff & diff.wrapping_sub(1);
    0u32.wrapping_sub(diff_is_zero >> 31)
}

/// This is - 2 ** 130 - 5 in twos complement, little endian
const NEGATIVE_1305: [u32; 17] = [0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfc];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vectors() {
        // From draft-agl-tls-chacha20poly1305-04 section 7
        let key = &[
            0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x33, 0x32, 0x2d, 0x62, 0x79, 0x74,
            0x65, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x50, 0x6f, 0x6c, 0x79,
            0x31, 0x33, 0x30, 0x35,
        ];

        let mut p = Poly1305::new(key);
        p.add_bytes(&[0u8; 32]);
        assert_eq!(
            p.finish(),
            [
                0x49, 0xec, 0x78, 0x09, 0x0e, 0x48, 0x1e, 0xc6, 0xc2, 0x6b, 0x33, 0xb9, 0x1c, 0xcc,
                0x03, 0x07
            ]
        );

        let mut p = Poly1305::new(key);
        p.add_bytes(&[
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21,
        ]);
        assert_eq!(
            p.finish(),
            [
                0xa6, 0xf7, 0x45, 0x00, 0x8f, 0x81, 0xc9, 0x16, 0xa2, 0x0d, 0xcc, 0x74, 0xee, 0xf2,
                0xb2, 0xf0
            ]
        );
    }
}
