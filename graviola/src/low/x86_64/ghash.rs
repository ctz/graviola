// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
//
//! Refs.
//! - <https://www.intel.com/content/dam/www/public/us/en/documents/software-support/enabling-high-performance-gcm.pdf>
//! - <https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf>

use core::arch::x86_64::*;
use core::mem;

pub(crate) struct GhashTable {
    /// H, H^2, H^3, H^4
    pub(crate) h: __m128i,
    pub(crate) h2: __m128i,
    pub(crate) h3: __m128i,
    pub(crate) h4: __m128i,
}

impl GhashTable {
    pub(crate) fn new(h: u128) -> Self {
        let h = u128_to_m128i(h);
        let h2 = unsafe { _mul(h, h) };
        let h3 = unsafe { _mul(h2, h) };
        let h4 = unsafe { _mul(h3, h) };

        Self { h, h2, h3, h4 }
    }
}

#[inline]
fn zero() -> __m128i {
    unsafe { _mm_setzero_si128() }
}

#[inline]
fn u128_to_m128i(v: u128) -> __m128i {
    // safety: sizeof(u128) == sizeof(__m128i), all bits have same meaning
    unsafe { mem::transmute(v) }
}

pub(crate) struct Ghash<'a> {
    pub(crate) table: &'a GhashTable,
    pub(crate) current: __m128i,
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
        let mut four_blocks = bytes.chunks_exact(64);

        for chunk4 in four_blocks.by_ref() {
            let u1 = u128::from_be_bytes(chunk4[0..16].try_into().unwrap());
            let u2 = u128::from_be_bytes(chunk4[16..32].try_into().unwrap());
            let u3 = u128::from_be_bytes(chunk4[32..48].try_into().unwrap());
            let u4 = u128::from_be_bytes(chunk4[48..64].try_into().unwrap());
            self.four_blocks(
                u128_to_m128i(u1),
                u128_to_m128i(u2),
                u128_to_m128i(u3),
                u128_to_m128i(u4),
            );
        }

        let bytes = four_blocks.remainder();
        let mut whole_blocks = bytes.chunks_exact(16);

        for chunk in whole_blocks.by_ref() {
            let u = u128::from_be_bytes(chunk.try_into().unwrap());
            self.one_block(u128_to_m128i(u));
        }

        let bytes = whole_blocks.remainder();
        if !bytes.is_empty() {
            let mut block = [0u8; 16];
            block[..bytes.len()].copy_from_slice(bytes);

            let u = u128::from_be_bytes(block);
            self.one_block(u128_to_m128i(u));
        }
    }

    pub(crate) fn into_bytes(self) -> [u8; 16] {
        let mut out: i128 = 0;
        unsafe { _mm_store_si128(&mut out as *mut i128 as *mut __m128i, self.current) };
        out.to_be_bytes()
    }

    fn one_block(&mut self, block: __m128i) {
        unsafe {
            self.current = _mm_xor_si128(self.current, block);
            self.current = _mul(self.current, self.table.h);
        }
    }

    #[inline]
    pub(crate) fn four_blocks(&mut self, b1: __m128i, b2: __m128i, b3: __m128i, b4: __m128i) {
        unsafe {
            let b1 = _mm_xor_si128(self.current, b1);
            self.current = _mul4(
                self.table.h,
                self.table.h2,
                self.table.h3,
                self.table.h4,
                b4,
                b3,
                b2,
                b1,
            );
        }
    }
}

#[inline]
#[target_feature(enable = "pclmulqdq")]
unsafe fn _mul(a: __m128i, b: __m128i) -> __m128i {
    // This is almost verbatim from "Intel® Carry-Less Multiplication
    // Instruction and its Usage for Computing the GCM Mode"
    // figure 5.

    unsafe {
        let t3 = _mm_clmulepi64_si128(a, b, 0x00);
        let t4 = _mm_clmulepi64_si128(a, b, 0x10);
        let t5 = _mm_clmulepi64_si128(a, b, 0x01);
        let t6 = _mm_clmulepi64_si128(a, b, 0x11);

        let t4 = _mm_xor_si128(t4, t5);
        let t5 = _mm_slli_si128(t4, 8);
        let t4 = _mm_srli_si128(t4, 8);
        let t3 = _mm_xor_si128(t3, t5);
        let t6 = _mm_xor_si128(t6, t4);

        let t7 = _mm_srli_epi32(t3, 31);
        let t8 = _mm_srli_epi32(t6, 31);
        let t3 = _mm_slli_epi32(t3, 1);
        let t6 = _mm_slli_epi32(t6, 1);

        let t9 = _mm_srli_si128(t7, 12);
        let t8 = _mm_slli_si128(t8, 4);
        let t7 = _mm_slli_si128(t7, 4);
        let t3 = _mm_or_si128(t3, t7);
        let t6 = _mm_or_si128(t6, t8);
        let t6 = _mm_or_si128(t6, t9);

        let t7 = _mm_slli_epi32(t3, 31);
        let t8 = _mm_slli_epi32(t3, 30);
        let t9 = _mm_slli_epi32(t3, 25);

        let t7 = _mm_xor_si128(t7, t8);
        let t7 = _mm_xor_si128(t7, t9);
        let t8 = _mm_srli_si128(t7, 4);
        let t7 = _mm_slli_si128(t7, 12);
        let t3 = _mm_xor_si128(t3, t7);

        let t2 = _mm_srli_epi32(t3, 1);
        let t4 = _mm_srli_epi32(t3, 2);
        let t5 = _mm_srli_epi32(t3, 7);
        let t2 = _mm_xor_si128(t2, t4);
        let t2 = _mm_xor_si128(t2, t5);
        let t2 = _mm_xor_si128(t2, t8);
        let t3 = _mm_xor_si128(t3, t2);
        _mm_xor_si128(t6, t3)
    }
}

#[inline]
#[target_feature(enable = "pclmulqdq")]
pub(crate) unsafe fn _mul4(
    h1: __m128i,
    h2: __m128i,
    h3: __m128i,
    h4: __m128i,
    x1: __m128i,
    x2: __m128i,
    x3: __m128i,
    x4: __m128i,
) -> __m128i {
    // This is almost verbatim from "Intel® Carry-Less Multiplication
    // Instruction and its Usage for Computing the GCM Mode"
    // figure 8.
    //
    // algorithm by Krzysztof Jankowski, Pierre Laurent - Intel

    let h1_x1_lo = _mm_clmulepi64_si128(h1, x1, 0x00);
    let h2_x2_lo = _mm_clmulepi64_si128(h2, x2, 0x00);
    let h3_x3_lo = _mm_clmulepi64_si128(h3, x3, 0x00);
    let h4_x4_lo = _mm_clmulepi64_si128(h4, x4, 0x00);

    let lo = _mm_xor_si128(h1_x1_lo, h2_x2_lo);
    let lo = _mm_xor_si128(lo, h3_x3_lo);
    let lo = _mm_xor_si128(lo, h4_x4_lo);

    let h1_x1_hi = _mm_clmulepi64_si128(h1, x1, 0x11);
    let h2_x2_hi = _mm_clmulepi64_si128(h2, x2, 0x11);
    let h3_x3_hi = _mm_clmulepi64_si128(h3, x3, 0x11);
    let h4_x4_hi = _mm_clmulepi64_si128(h4, x4, 0x11);

    let hi = _mm_xor_si128(h1_x1_hi, h2_x2_hi);
    let hi = _mm_xor_si128(hi, h3_x3_hi);
    let hi = _mm_xor_si128(hi, h4_x4_hi);

    let tmp0 = _mm_shuffle_epi32(h1, 0b01_00_11_10);
    let tmp4 = _mm_shuffle_epi32(x1, 0b01_00_11_10);
    let tmp0 = _mm_xor_si128(tmp0, h1);
    let tmp4 = _mm_xor_si128(tmp4, x1);
    let tmp1 = _mm_shuffle_epi32(h2, 0b01_00_11_10);
    let tmp5 = _mm_shuffle_epi32(x2, 0b01_00_11_10);
    let tmp1 = _mm_xor_si128(tmp1, h2);
    let tmp5 = _mm_xor_si128(tmp5, x2);
    let tmp2 = _mm_shuffle_epi32(h3, 0b01_00_11_10);
    let tmp6 = _mm_shuffle_epi32(x3, 0b01_00_11_10);
    let tmp2 = _mm_xor_si128(tmp2, h3);
    let tmp6 = _mm_xor_si128(tmp6, x3);
    let tmp3 = _mm_shuffle_epi32(h4, 0b01_00_11_10);
    let tmp7 = _mm_shuffle_epi32(x4, 0b01_00_11_10);
    let tmp3 = _mm_xor_si128(tmp3, h4);
    let tmp7 = _mm_xor_si128(tmp7, x4);

    let tmp0 = _mm_clmulepi64_si128(tmp0, tmp4, 0x00);
    let tmp1 = _mm_clmulepi64_si128(tmp1, tmp5, 0x00);
    let tmp2 = _mm_clmulepi64_si128(tmp2, tmp6, 0x00);
    let tmp3 = _mm_clmulepi64_si128(tmp3, tmp7, 0x00);

    let tmp0 = _mm_xor_si128(tmp0, lo);
    let tmp0 = _mm_xor_si128(tmp0, hi);
    let tmp0 = _mm_xor_si128(tmp1, tmp0);
    let tmp0 = _mm_xor_si128(tmp2, tmp0);
    let tmp0 = _mm_xor_si128(tmp3, tmp0);

    let tmp4 = _mm_slli_si128(tmp0, 8);
    let tmp0 = _mm_srli_si128(tmp0, 8);

    let lo = _mm_xor_si128(tmp4, lo);
    let hi = _mm_xor_si128(tmp0, hi);

    let tmp3 = lo;
    let tmp6 = hi;

    let tmp7 = _mm_srli_epi32(tmp3, 31);
    let tmp8 = _mm_srli_epi32(tmp6, 31);
    let tmp3 = _mm_slli_epi32(tmp3, 1);
    let tmp6 = _mm_slli_epi32(tmp6, 1);

    let tmp9 = _mm_srli_si128(tmp7, 12);
    let tmp8 = _mm_slli_si128(tmp8, 4);
    let tmp7 = _mm_slli_si128(tmp7, 4);
    let tmp3 = _mm_or_si128(tmp3, tmp7);
    let tmp6 = _mm_or_si128(tmp6, tmp8);
    let tmp6 = _mm_or_si128(tmp6, tmp9);

    let tmp7 = _mm_slli_epi32(tmp3, 31);
    let tmp8 = _mm_slli_epi32(tmp3, 30);
    let tmp9 = _mm_slli_epi32(tmp3, 25);

    let tmp7 = _mm_xor_si128(tmp7, tmp8);
    let tmp7 = _mm_xor_si128(tmp7, tmp9);
    let tmp8 = _mm_srli_si128(tmp7, 4);
    let tmp7 = _mm_slli_si128(tmp7, 12);
    let tmp3 = _mm_xor_si128(tmp3, tmp7);

    let tmp2 = _mm_srli_epi32(tmp3, 1);
    let tmp4 = _mm_srli_epi32(tmp3, 2);
    let tmp5 = _mm_srli_epi32(tmp3, 7);
    let tmp2 = _mm_xor_si128(tmp2, tmp4);
    let tmp2 = _mm_xor_si128(tmp2, tmp5);
    let tmp2 = _mm_xor_si128(tmp2, tmp8);
    let tmp3 = _mm_xor_si128(tmp3, tmp2);
    _mm_xor_si128(tmp6, tmp3)
}
