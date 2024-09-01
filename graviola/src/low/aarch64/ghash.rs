// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! Basic implementation using vmull_p64.
//!
//! Based on:
//! clmul-arm.c - ARMv8 Carryless Multiply using C intrinsics
//! Written and placed in public domain by Jeffrey Walton
//! Based on code from ARM, and by Johannes Schneiders, Skip
//! Hovsmith and Barry O'Rourke for the mbedTLS project.

use core::arch::aarch64::*;
use core::mem;

pub(crate) struct GhashTable {
    h: uint8x16_t,
    //h2: uint8x16_t,
    //h3: uint8x16_t,
    //h4: uint8x16_t,
}

impl GhashTable {
    pub(crate) fn new(h: u128) -> Self {
        let h = from_u128(&h);
        //let h2 = mul(h, h);
        //let h3 = mul(h2, h);
        //let h4 = mul(h3, h);
        Self { h } //, h2, h3, h4 }
    }
}

pub(crate) struct Ghash<'a> {
    table: &'a GhashTable,
    current: uint8x16_t,
}

impl<'a> Ghash<'a> {
    pub(crate) fn new(table: &'a GhashTable) -> Self {
        Self {
            table,
            current: zero(),
        }
    }

    /// Input `bytes` to the computation.
    ///
    /// `bytes` is zero-padded, if required.
    pub(crate) fn add(&mut self, bytes: &[u8]) {
        let mut by4_blocks = bytes.chunks_exact(64);

        for chunk4 in by4_blocks.by_ref() {
            self.four_blocks(
                u128::from_be_bytes(chunk4[0..16].try_into().unwrap()),
                u128::from_be_bytes(chunk4[16..32].try_into().unwrap()),
                u128::from_be_bytes(chunk4[32..48].try_into().unwrap()),
                u128::from_be_bytes(chunk4[48..64].try_into().unwrap()),
            );
        }

        let mut whole_blocks = by4_blocks.remainder().chunks_exact(16);

        for chunk in whole_blocks.by_ref() {
            let u = u128::from_be_bytes(chunk.try_into().unwrap());
            self.one_block(u);
        }

        let bytes = whole_blocks.remainder();
        if !bytes.is_empty() {
            let mut block = [0u8; 16];
            block[..bytes.len()].copy_from_slice(bytes);

            let u = u128::from_be_bytes(block);
            self.one_block(u);
        }
    }

    pub(crate) fn into_bytes(self) -> [u8; 16] {
        to_u128(self.current).to_be_bytes()
    }

    fn one_block(&mut self, block: u128) {
        unsafe { self.current = veorq_u8(self.current, from_u128(&block)) };
        self.current = mul(self.current, self.table.h);
    }

    fn four_blocks(&mut self, b1: u128, b2: u128, b3: u128, b4: u128) {
        self.one_block(b1);
        self.one_block(b2);
        self.one_block(b3);
        self.one_block(b4);
    }
}

#[inline]
fn mul(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    unsafe { _mul(a, b) }
}

#[target_feature(enable = "neon,aes")]
unsafe fn _mul(a8: uint8x16_t, b8: uint8x16_t) -> uint8x16_t {
    unsafe {
        /* polynomial multiply */
        let z = vdupq_n_u8(0);
        let r0 = vmull_p64_fix(a8, b8);
        let r1 = vmull_high_p64_fix(a8, b8);
        let t0 = vextq_u8(b8, b8, 8);
        let t1 = vmull_p64_fix(a8, t0);
        let t0 = vmull_high_p64_fix(a8, t0);
        let t0 = veorq_u8(t0, t1);
        let t1 = vextq_u8(z, t0, 8);
        let r0 = veorq_u8(r0, t1);
        let t1 = vextq_u8(t0, z, 8);
        let r1 = veorq_u8(r1, t1);

        /* polynomial reduction */
        let p = vdupq_n_u64(0x0000000000000087); // nb. rev(0xe100..)
        let p = vreinterpretq_u8_u64(p);
        let t0 = vmull_high_p64_fix(r1, p);
        let t1 = vextq_u8(t0, z, 8);
        let r1 = veorq_u8(r1, t1);
        let t1 = vextq_u8(z, t0, 8);
        let r0 = veorq_u8(r0, t1);
        let t0 = vmull_p64_fix(r1, p);
        veorq_u8(r0, t0)
    }
}

// the intrinsics exist, but have the wrong types :(

#[inline]
#[target_feature(enable = "neon,aes")]
unsafe fn vmull_p64_fix(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    let a = vreinterpretq_u64_u8(a);
    let a = vgetq_lane_u64::<0>(a);
    let b = vreinterpretq_u64_u8(b);
    let b = vgetq_lane_u64::<0>(b);
    mem::transmute(vmull_p64(a, b))
}

#[inline]
#[target_feature(enable = "neon,aes")]
unsafe fn vmull_high_p64_fix(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    let a = vreinterpretq_u64_u8(a);
    let a = vgetq_lane_u64::<1>(a);
    let b = vreinterpretq_u64_u8(b);
    let b = vgetq_lane_u64::<1>(b);
    mem::transmute(vmull_p64(a, b))
}

#[inline]
fn zero() -> uint8x16_t {
    unsafe { mem::transmute(0u128) }
}

#[inline]
fn from_u128(u: &u128) -> uint8x16_t {
    unsafe {
        // do the whole computation in the wildly bizarre
        // bit ordering of ghash, by reversing the inputs
        let t = vld1q_u8(u.to_be_bytes().as_ptr());
        vrbitq_u8(t)
    }
}

#[inline]
fn to_u128(u: uint8x16_t) -> u128 {
    unsafe {
        let t = vrbitq_u8(u);

        let mut r = [0; 16];
        vst1q_u8(r.as_mut_ptr(), t);
        u128::from_be_bytes(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mul() {
        assert_eq!(0, to_u128(mul(from_u128(&1), zero())));

        let x = u128::from_be_bytes(
            *b"\x03\x88\xda\xce\x60\xb6\xa3\x92\xf3\x28\xc2\xb9\x71\xb2\xfe\x78",
        );
        let y = u128::from_be_bytes(
            *b"\x66\xe9\x4b\xd4\xef\x8a\x2c\x3b\x88\x4c\xfa\x59\xca\x34\x2b\x2e",
        );
        assert_eq!(
            b"\x5e\x2e\xc7\x46\x91\x70\x62\x88\x2c\x85\xb0\x68\x53\x53\xde\xb7",
            &to_u128(mul(from_u128(&x), from_u128(&y))).to_be_bytes()
        );
    }
}
