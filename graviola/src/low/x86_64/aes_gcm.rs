// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
//
//! Ref. <https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/communications-ia-cryptographic-paper.pdf>

use core::arch::x86_64::*;
use core::mem;

use super::aes::AesKey;
use super::ghash::{self, Ghash};

pub(crate) fn encrypt(
    key: &AesKey,
    ghash: &mut Ghash<'_>,
    initial_counter: &[u8; 16],
    aad: &[u8],
    cipher_inout: &mut [u8],
) {
    // SAFETY: this crate requires the `aes`, `ssse3`, `pclmulqdq` and `avx` cpu features
    unsafe { _cipher::<true>(key, ghash, initial_counter, aad, cipher_inout) }
}

pub(crate) fn decrypt(
    key: &AesKey,
    ghash: &mut Ghash<'_>,
    initial_counter: &[u8; 16],
    aad: &[u8],
    cipher_inout: &mut [u8],
) {
    // SAFETY: this crate requires the `aes`, `ssse3`, `pclmulqdq` and `avx` cpu features
    unsafe { _cipher::<false>(key, ghash, initial_counter, aad, cipher_inout) }
}

#[target_feature(enable = "aes,ssse3,pclmulqdq,avx")]
unsafe fn _cipher<const ENC: bool>(
    key: &AesKey,
    ghash: &mut Ghash<'_>,
    initial_counter: &[u8; 16],
    aad: &[u8],
    cipher_inout: &mut [u8],
) {
    ghash.add(aad);

    let (rk_first, rks, rk_last) = key.round_keys();

    let mut counter = Counter::new(initial_counter);
    let mut by8_iter = cipher_inout.chunks_exact_mut(128);

    for blocks in by8_iter.by_ref() {
        // SAFETY: intrinsics. see [crate::low::inline_assembly_safety#safety-of-intrinsics] for safety info.
        unsafe {
            // prefetch to avoid any stall later
            _mm_prefetch(blocks.as_ptr().add(0) as *const _, _MM_HINT_T0);
            _mm_prefetch(blocks.as_ptr().add(64) as *const _, _MM_HINT_T0);

            let c1 = counter.next();
            let c2 = counter.next();
            let c3 = counter.next();
            let c4 = counter.next();
            let c5 = counter.next();
            let c6 = counter.next();
            let c7 = counter.next();
            let c8 = counter.next();

            let mut c1 = _mm_xor_si128(c1, rk_first);
            let mut c2 = _mm_xor_si128(c2, rk_first);
            let mut c3 = _mm_xor_si128(c3, rk_first);
            let mut c4 = _mm_xor_si128(c4, rk_first);
            let mut c5 = _mm_xor_si128(c5, rk_first);
            let mut c6 = _mm_xor_si128(c6, rk_first);
            let mut c7 = _mm_xor_si128(c7, rk_first);
            let mut c8 = _mm_xor_si128(c8, rk_first);

            for rk in rks {
                c1 = _mm_aesenc_si128(c1, *rk);
                c2 = _mm_aesenc_si128(c2, *rk);
                c3 = _mm_aesenc_si128(c3, *rk);
                c4 = _mm_aesenc_si128(c4, *rk);
                c5 = _mm_aesenc_si128(c5, *rk);
                c6 = _mm_aesenc_si128(c6, *rk);
                c7 = _mm_aesenc_si128(c7, *rk);
                c8 = _mm_aesenc_si128(c8, *rk);
            }

            let c1 = _mm_aesenclast_si128(c1, rk_last);
            let c2 = _mm_aesenclast_si128(c2, rk_last);
            let c3 = _mm_aesenclast_si128(c3, rk_last);
            let c4 = _mm_aesenclast_si128(c4, rk_last);
            let c5 = _mm_aesenclast_si128(c5, rk_last);
            let c6 = _mm_aesenclast_si128(c6, rk_last);
            let c7 = _mm_aesenclast_si128(c7, rk_last);
            let c8 = _mm_aesenclast_si128(c8, rk_last);

            let p1 = _mm_loadu_si128(blocks.as_ptr().add(0) as *const _);
            let p2 = _mm_loadu_si128(blocks.as_ptr().add(16) as *const _);
            let p3 = _mm_loadu_si128(blocks.as_ptr().add(32) as *const _);
            let p4 = _mm_loadu_si128(blocks.as_ptr().add(48) as *const _);
            let p5 = _mm_loadu_si128(blocks.as_ptr().add(64) as *const _);
            let p6 = _mm_loadu_si128(blocks.as_ptr().add(80) as *const _);
            let p7 = _mm_loadu_si128(blocks.as_ptr().add(96) as *const _);
            let p8 = _mm_loadu_si128(blocks.as_ptr().add(112) as *const _);

            let c1 = _mm_xor_si128(c1, p1);
            let c2 = _mm_xor_si128(c2, p2);
            let c3 = _mm_xor_si128(c3, p3);
            let c4 = _mm_xor_si128(c4, p4);
            let c5 = _mm_xor_si128(c5, p5);
            let c6 = _mm_xor_si128(c6, p6);
            let c7 = _mm_xor_si128(c7, p7);
            let c8 = _mm_xor_si128(c8, p8);

            _mm_storeu_si128(blocks.as_mut_ptr().add(0) as *mut _, c1);
            _mm_storeu_si128(blocks.as_mut_ptr().add(16) as *mut _, c2);
            _mm_storeu_si128(blocks.as_mut_ptr().add(32) as *mut _, c3);
            _mm_storeu_si128(blocks.as_mut_ptr().add(48) as *mut _, c4);
            _mm_storeu_si128(blocks.as_mut_ptr().add(64) as *mut _, c5);
            _mm_storeu_si128(blocks.as_mut_ptr().add(80) as *mut _, c6);
            _mm_storeu_si128(blocks.as_mut_ptr().add(96) as *mut _, c7);
            _mm_storeu_si128(blocks.as_mut_ptr().add(112) as *mut _, c8);

            let (a1, a2, a3, a4, a5, a6, a7, a8) = if ENC {
                (c1, c2, c3, c4, c5, c6, c7, c8)
            } else {
                (p1, p2, p3, p4, p5, p6, p7, p8)
            };

            let a1 = _mm_shuffle_epi8(a1, BYTESWAP);
            let a2 = _mm_shuffle_epi8(a2, BYTESWAP);
            let a3 = _mm_shuffle_epi8(a3, BYTESWAP);
            let a4 = _mm_shuffle_epi8(a4, BYTESWAP);
            let a5 = _mm_shuffle_epi8(a5, BYTESWAP);
            let a6 = _mm_shuffle_epi8(a6, BYTESWAP);
            let a7 = _mm_shuffle_epi8(a7, BYTESWAP);
            let a8 = _mm_shuffle_epi8(a8, BYTESWAP);

            let a1 = _mm_xor_si128(ghash.current, a1);
            ghash.current = ghash::_mul8(ghash.table, a1, a2, a3, a4, a5, a6, a7, a8);
        }
    }

    let cipher_inout = by8_iter.into_remainder();

    if !ENC {
        ghash.add(cipher_inout);
    }

    {
        let mut blocks_iter = cipher_inout.chunks_exact_mut(16);
        for block in blocks_iter.by_ref() {
            let c1 = counter.next();

            // SAFETY: intrinsics. see [crate::low::inline_assembly_safety#safety-of-intrinsics] for safety info.
            unsafe {
                let mut c1 = _mm_xor_si128(c1, rk_first);

                for rk in rks {
                    c1 = _mm_aesenc_si128(c1, *rk);
                }

                let c1 = _mm_aesenclast_si128(c1, rk_last);

                let c1 = _mm_xor_si128(c1, _mm_loadu_si128(block.as_ptr() as *const _));

                _mm_storeu_si128(block.as_mut_ptr() as *mut _, c1);
            }
        }

        let cipher_inout = blocks_iter.into_remainder();
        if !cipher_inout.is_empty() {
            let mut block = [0u8; 16];
            let len = cipher_inout.len();
            debug_assert!(len < 16);
            block[..len].copy_from_slice(cipher_inout);

            let c1 = counter.next();

            // SAFETY: intrinsics. see [crate::low::inline_assembly_safety#safety-of-intrinsics] for safety info.
            unsafe {
                let mut c1 = _mm_xor_si128(c1, rk_first);

                for rk in rks {
                    c1 = _mm_aesenc_si128(c1, *rk);
                }

                let c1 = _mm_aesenclast_si128(c1, rk_last);

                let p1 = _mm_loadu_si128(block.as_ptr() as *const _);
                let c1 = _mm_xor_si128(c1, p1);

                _mm_storeu_si128(block.as_mut_ptr() as *mut _, c1);
            }

            cipher_inout.copy_from_slice(&block[..len]);
        }
    }

    if ENC {
        ghash.add(cipher_inout);
    }
}

/// This stores the next counter value, in big endian.
#[derive(Clone, Copy, Debug)]
struct Counter(__m128i);

impl Counter {
    #[target_feature(enable = "sse3,ssse3")]
    #[inline]
    unsafe fn new(bytes: &[u8; 16]) -> Self {
        // SAFETY: `bytes` is 128-bits and can be loaded from
        let c = _mm_lddqu_si128(bytes.as_ptr() as *const _);
        Self(_mm_shuffle_epi8(c, BYTESWAP_EPI64))
    }

    #[target_feature(enable = "sse3,ssse3")]
    #[must_use]
    #[inline]
    unsafe fn next(&mut self) -> __m128i {
        self.0 = _mm_add_epi32(self.0, COUNTER_1);
        _mm_shuffle_epi8(self.0, BYTESWAP_EPI64)
    }
}

// SAFETY: both u128 and __m128i have the same size and all bits mean the same thing
const COUNTER_1: __m128i = unsafe { mem::transmute(1u128 << 64) };
// SAFETY: both u128 and __m128i have the same size and all bits mean the same thing
const BYTESWAP: __m128i = unsafe { mem::transmute(0x00010203_04050607_08090a0b_0c0d0e0fu128) };
// SAFETY: both u128 and __m128i have the same size and all bits mean the same thing
const BYTESWAP_EPI64: __m128i =
    unsafe { mem::transmute(0x08090a0b_0c0d0e0f_00010203_04050607u128) };
