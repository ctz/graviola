// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
//
//! Refs.
//! - <https://www.intel.com/content/dam/www/public/us/en/documents/software-support/enabling-high-performance-gcm.pdf>
//! - <https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf>
//! - <https://patchwork.kernel.org/project/linux-crypto/patch/20240527075626.142576-3-ebiggers@kernel.org/>
//!   (especially, as we're using the arithmetic from this implementation)

use core::arch::x86_64::*;
use core::mem;

use crate::low;

pub(crate) struct GhashTable {
    /// H, H^2, H^3, H^4, ... H^8
    powers: [__m128i; 8],

    /// `powers_xor[i]` is `powers[i].lo64 ^ powers[i].hi64`
    ///
    /// This can be used directly in the middle Karatsuba term.
    powers_xor: [__m128i; 8],
}

impl GhashTable {
    pub(crate) fn new(h: u128) -> Self {
        let mut powers = [zero(); 8];
        let mut powers_xor = powers;
        let h = u128_to_m128i(h);

        // SAFETY: this crate requires the `avx` cpu feature
        let h = unsafe { gf128_big_endian(h) };
        powers[0] = h;

        for i in 1..8 {
            // SAFETY: this crate requires the `avx` and `pclmulqdq` cpu features
            powers[i] = unsafe { _mul(powers[i - 1], h) };
        }

        for i in 0..8 {
            // SAFETY: this crate requires the `avx` cpu feature
            powers_xor[i] = unsafe { xor_halves(powers[i]) };
        }

        Self { powers, powers_xor }
    }
}

impl Drop for GhashTable {
    fn drop(&mut self) {
        low::zeroise(&mut self.powers);
        low::zeroise(&mut self.powers_xor);
    }
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
        let mut eight_blocks = bytes.chunks_exact(128);

        for chunk8 in eight_blocks.by_ref() {
            let u1 = u128::from_be_bytes(chunk8[0..16].try_into().unwrap());
            let u2 = u128::from_be_bytes(chunk8[16..32].try_into().unwrap());
            let u3 = u128::from_be_bytes(chunk8[32..48].try_into().unwrap());
            let u4 = u128::from_be_bytes(chunk8[48..64].try_into().unwrap());
            let u5 = u128::from_be_bytes(chunk8[64..80].try_into().unwrap());
            let u6 = u128::from_be_bytes(chunk8[80..96].try_into().unwrap());
            let u7 = u128::from_be_bytes(chunk8[96..112].try_into().unwrap());
            let u8 = u128::from_be_bytes(chunk8[112..128].try_into().unwrap());
            self.eight_blocks(
                u128_to_m128i(u1),
                u128_to_m128i(u2),
                u128_to_m128i(u3),
                u128_to_m128i(u4),
                u128_to_m128i(u5),
                u128_to_m128i(u6),
                u128_to_m128i(u7),
                u128_to_m128i(u8),
            );
        }

        let bytes = eight_blocks.remainder();
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
        // SAFETY: this crate requires the `avx` cpu feature
        unsafe {
            let reverse = _mm_shuffle_epi8(self.current, BYTESWAP);
            _mm_store_si128(&mut out as *mut i128 as *mut __m128i, reverse)
        };
        out.to_le_bytes()
    }

    fn one_block(&mut self, block: __m128i) {
        // SAFETY: this crate requires the `avx` and `pclmulqdq` cpu features
        unsafe {
            self.current = _mm_xor_si128(self.current, block);
            self.current = _mul(self.current, self.table.powers[0]);
        }
    }

    #[inline]
    pub(crate) fn eight_blocks(
        &mut self,
        b1: __m128i,
        b2: __m128i,
        b3: __m128i,
        b4: __m128i,
        b5: __m128i,
        b6: __m128i,
        b7: __m128i,
        b8: __m128i,
    ) {
        // SAFETY: this crate requires the `avx` and `pclmulqdq` cpu features
        unsafe {
            let b1 = _mm_xor_si128(self.current, b1);
            self.current = _mul8(self.table, b1, b2, b3, b4, b5, b6, b7, b8);
        }
    }
}

macro_rules! mul {
    ($lo:ident, $mi:ident, $hi:ident, $x:ident, $h:expr, $hx:expr) => {
        let tlo = _mm_clmulepi64_si128($x, $h, 0x00);
        $lo = _mm_xor_si128(tlo, $lo);

        let xx = _mm_shuffle_epi32($x, 0b01_00_11_10);
        let xx = _mm_xor_si128(xx, $x);

        let thi = _mm_clmulepi64_si128($x, $h, 0x11);
        $hi = _mm_xor_si128(thi, $hi);

        let tmi = _mm_clmulepi64_si128(xx, $hx, 0x00);
        $mi = _mm_xor_si128(tmi, $mi);
    };
}

macro_rules! reduce {
    ($lo:ident, $mi:ident, $hi:ident) => {{
        let $mi = _mm_xor_si128($mi, $lo);
        let $mi = _mm_xor_si128($mi, $hi);

        let ls = _mm_shuffle_epi32($lo, 0b01_00_11_10);
        let $lo = _mm_clmulepi64_si128(GF128_POLY_HI, $lo, 0x00);
        let $mi = _mm_xor_si128($mi, ls);
        let $mi = _mm_xor_si128($mi, $lo);

        let ms = _mm_shuffle_epi32($mi, 0b01_00_11_10);
        let $mi = _mm_clmulepi64_si128(GF128_POLY_HI, $mi, 0x00);
        let $hi = _mm_xor_si128($hi, ms);
        let $hi = _mm_xor_si128($hi, $mi);
        $hi
    }};
}

#[inline]
#[target_feature(enable = "pclmulqdq,avx")]
unsafe fn _mul(a: __m128i, b: __m128i) -> __m128i {
    let (mut lo, mut mi, mut hi) = (zero(), zero(), zero());
    let bx = xor_halves(b);
    mul!(lo, mi, hi, a, b, bx);
    reduce!(lo, mi, hi)
}

#[inline]
#[target_feature(enable = "pclmulqdq,avx")]
pub(crate) unsafe fn _mul8(
    table: &GhashTable,
    x1: __m128i,
    x2: __m128i,
    x3: __m128i,
    x4: __m128i,
    x5: __m128i,
    x6: __m128i,
    x7: __m128i,
    x8: __m128i,
) -> __m128i {
    let (mut lo, mut mi, mut hi) = (zero(), zero(), zero());
    mul!(lo, mi, hi, x1, table.powers[7], table.powers_xor[7]);
    mul!(lo, mi, hi, x2, table.powers[6], table.powers_xor[6]);
    mul!(lo, mi, hi, x3, table.powers[5], table.powers_xor[5]);
    mul!(lo, mi, hi, x4, table.powers[4], table.powers_xor[4]);
    mul!(lo, mi, hi, x5, table.powers[3], table.powers_xor[3]);
    mul!(lo, mi, hi, x6, table.powers[2], table.powers_xor[2]);
    mul!(lo, mi, hi, x7, table.powers[1], table.powers_xor[1]);
    mul!(lo, mi, hi, x8, table.powers[0], table.powers_xor[0]);
    reduce!(lo, mi, hi)
}

#[target_feature(enable = "avx")]
unsafe fn gf128_big_endian(h: __m128i) -> __m128i {
    // takes a raw hash subkey, and arranges that it can
    // be used in big endian ordering.
    let t = _mm_shuffle_epi32(h, 0b11_01_00_11);
    let t = _mm_srai_epi32(t, 31);
    let h = _mm_add_epi64(h, h);
    let t = _mm_and_si128(GF128_POLY_CARRY_MASK, t);
    _mm_xor_si128(h, t)
}

#[target_feature(enable = "avx")]
unsafe fn xor_halves(h: __m128i) -> __m128i {
    let hx = _mm_shuffle_epi32(h, 0b01_00_11_10);
    _mm_xor_si128(hx, h)
}

#[inline]
fn zero() -> __m128i {
    // SAFETY: this crate requires the `avx` cpu feature
    unsafe { _mm_setzero_si128() }
}

#[inline]
fn u128_to_m128i(v: u128) -> __m128i {
    // SAFETY: sizeof(u128) == sizeof(__m128i), all bits have same meaning
    unsafe { mem::transmute(v) }
}

const BYTESWAP: __m128i = unsafe { mem::transmute(0x00010203_04050607_08090a0b_0c0d0e0fu128) };

/// The high half of the ghash polynomial R, rotated left by one
///
/// R is 0xe100..00u128
///
/// We need this in a __m128i, but only the bottom 64-bits are used.
const GF128_POLY_HI: __m128i = unsafe { mem::transmute(0xc2000000_00000000u128) };

/// This is, again, R rotated left by one, but with a 2^64 term
const GF128_POLY_CARRY_MASK: __m128i =
    unsafe { mem::transmute(0xc2000000_00000001_00000000_00000001u128) };

#[cfg(test)]
mod tests {
    use super::*;
    use crate::low::generic::ghash as model;

    #[test]
    fn pairwise() {
        check(0, b"");
        check(0, b"hello");
        check(1, b"");
        check(1, b"hello");
        let k = 0x00112233_44556677_8899aabb_ccddeeffu128;
        check(k, b"hello");
        check(k, b"hello world!");
        check(k, &[b'a'; 32]);
        check(k, &[b'b'; 64]);
        check(k, &[b'c'; 512 + 64 + 32 + 16]);

        let mut pattern = [0; 512 + 64 + 32 + 16];
        for (i, p) in pattern.iter_mut().enumerate() {
            *p = i as u8;
        }
        check(k, &pattern);

        let k = 0xffeeeedd_ffeeeedd_ff0000dd_ff0000ddu128;
        for (i, p) in pattern.iter_mut().enumerate() {
            *p = 0xf0 | (i & 0xf) as u8;
        }
        check(k, &pattern);
    }

    fn check(key: u128, input: &[u8]) {
        println!("check: input={input:02x?}");
        let ta = GhashTable::new(key);
        let tb = model::GhashTable::new(key);
        let mut a = Ghash::new(&ta);
        let mut b = model::Ghash::new(&tb);
        a.add(input);
        b.add(input);

        let fa = a.into_bytes();
        let fb = b.into_bytes();

        if fa != fb {
            panic!(
                "for input: {:02x?}:\n\n impl  {:02x?}\n    !=\nmodel  {:02x?}",
                input, fa, fb
            );
        }
    }
}
