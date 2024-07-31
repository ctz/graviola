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
    h: u128,
}

impl GhashTable {
    pub(crate) fn new(h: u128) -> Self {
        Self { h }
    }
}

pub(crate) struct Ghash<'a> {
    table: &'a GhashTable,
    current: u128,
}
impl<'a> Ghash<'a> {
    pub(crate) fn new(table: &'a GhashTable) -> Self {
        Self { table, current: 0 }
    }

    /// Input `bytes` to the computation.
    ///
    /// `bytes` is zero-padded, if required.
    pub(crate) fn add(&mut self, bytes: &[u8]) {
        let mut whole_blocks = bytes.chunks_exact(16);

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
        self.current.to_be_bytes()
    }

    fn one_block(&mut self, block: u128) {
        self.current ^= block;
        self.current = mul(self.current, self.table.h);
    }
}

fn mul(a: u128, b: u128) -> u128 {
    unsafe { _mul(a, b) }
}

#[target_feature(enable = "neon,aes")]
unsafe fn _mul(a: u128, b: u128) -> u128 {
    unsafe {
        // do the whole computation in the wildly bizarre
        // bit ordering of ghash, by reversing the inputs
        let a8 = vld1q_u8(a.to_be_bytes().as_ptr());
        let b8 = vld1q_u8(b.to_be_bytes().as_ptr());
        let a8 = vrbitq_u8(a8);
        let b8 = vrbitq_u8(b8);

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
        let c8 = veorq_u8(r0, t0);

        let c8 = vrbitq_u8(c8);
        let mut r = [0; 16];
        vst1q_u8(r.as_mut_ptr(), c8);
        u128::from_be_bytes(r)
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

const R: u128 = 0xe1000000_00000000_00000000_00000000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mul() {
        assert_eq!(0, mul(1, 0));

        let x = u128::from_be_bytes(
            *b"\x03\x88\xda\xce\x60\xb6\xa3\x92\xf3\x28\xc2\xb9\x71\xb2\xfe\x78",
        );
        let y = u128::from_be_bytes(
            *b"\x66\xe9\x4b\xd4\xef\x8a\x2c\x3b\x88\x4c\xfa\x59\xca\x34\x2b\x2e",
        );
        assert_eq!(
            b"\x5e\x2e\xc7\x46\x91\x70\x62\x88\x2c\x85\xb0\x68\x53\x53\xde\xb7",
            &mul(x, y).to_be_bytes()
        );
    }
}
