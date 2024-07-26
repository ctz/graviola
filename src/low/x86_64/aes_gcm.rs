//! Ref. https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/communications-ia-cryptographic-paper.pdf

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
    unsafe { _encrypt(key, ghash, initial_counter, aad, cipher_inout) }
}

#[target_feature(enable = "aes,ssse3,pclmulqdq")]
unsafe fn _encrypt(
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
        unsafe {
            // prefetch to avoid any stall later
            _mm_prefetch(blocks.as_ptr().add(0) as *const _, _MM_HINT_T0);
            _mm_prefetch(blocks.as_ptr().add(64) as *const _, _MM_HINT_T0);

            let c1 = counter.add(COUNTER_1);
            let c2 = counter.add(COUNTER_2);
            let c3 = counter.add(COUNTER_3);
            let c4 = counter.add(COUNTER_4);
            let c5 = counter.add(COUNTER_5);
            let c6 = counter.add(COUNTER_6);
            let c7 = counter.add(COUNTER_7);
            let c8 = counter.add(COUNTER_8);
            counter = c8;

            let mut c1 = _mm_xor_si128(c1.0, rk_first);
            let mut c2 = _mm_xor_si128(c2.0, rk_first);
            let mut c3 = _mm_xor_si128(c3.0, rk_first);
            let mut c4 = _mm_xor_si128(c4.0, rk_first);
            let mut c5 = _mm_xor_si128(c5.0, rk_first);
            let mut c6 = _mm_xor_si128(c6.0, rk_first);
            let mut c7 = _mm_xor_si128(c7.0, rk_first);
            let mut c8 = _mm_xor_si128(c8.0, rk_first);

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

            let c1 = _mm_xor_si128(c1, _mm_loadu_si128(blocks.as_ptr().add(0) as *const _));
            let c2 = _mm_xor_si128(c2, _mm_loadu_si128(blocks.as_ptr().add(16) as *const _));
            let c3 = _mm_xor_si128(c3, _mm_loadu_si128(blocks.as_ptr().add(32) as *const _));
            let c4 = _mm_xor_si128(c4, _mm_loadu_si128(blocks.as_ptr().add(48) as *const _));
            let c5 = _mm_xor_si128(c5, _mm_loadu_si128(blocks.as_ptr().add(64) as *const _));
            let c6 = _mm_xor_si128(c6, _mm_loadu_si128(blocks.as_ptr().add(80) as *const _));
            let c7 = _mm_xor_si128(c7, _mm_loadu_si128(blocks.as_ptr().add(96) as *const _));
            let c8 = _mm_xor_si128(c8, _mm_loadu_si128(blocks.as_ptr().add(112) as *const _));

            _mm_storeu_si128(blocks.as_mut_ptr().add(0) as *mut _, c1);
            let c1 = _mm_shuffle_epi8(c1, BYTESWAP);
            _mm_storeu_si128(blocks.as_mut_ptr().add(16) as *mut _, c2);
            let c2 = _mm_shuffle_epi8(c2, BYTESWAP);
            _mm_storeu_si128(blocks.as_mut_ptr().add(32) as *mut _, c3);
            let c3 = _mm_shuffle_epi8(c3, BYTESWAP);
            _mm_storeu_si128(blocks.as_mut_ptr().add(48) as *mut _, c4);
            let c4 = _mm_shuffle_epi8(c4, BYTESWAP);
            _mm_storeu_si128(blocks.as_mut_ptr().add(64) as *mut _, c5);
            let c5 = _mm_shuffle_epi8(c5, BYTESWAP);
            _mm_storeu_si128(blocks.as_mut_ptr().add(80) as *mut _, c6);
            let c6 = _mm_shuffle_epi8(c6, BYTESWAP);
            _mm_storeu_si128(blocks.as_mut_ptr().add(96) as *mut _, c7);
            let c7 = _mm_shuffle_epi8(c7, BYTESWAP);
            _mm_storeu_si128(blocks.as_mut_ptr().add(112) as *mut _, c8);
            let c8 = _mm_shuffle_epi8(c8, BYTESWAP);

            let c1 = _mm_xor_si128(ghash.current, c1);
            let c1 = ghash::_mul4(
                ghash.table.h,
                ghash.table.h2,
                ghash.table.h3,
                ghash.table.h4,
                c4,
                c3,
                c2,
                c1,
            );

            let c5 = _mm_xor_si128(c1, c5);
            let c5 = ghash::_mul4(
                ghash.table.h,
                ghash.table.h2,
                ghash.table.h3,
                ghash.table.h4,
                c8,
                c7,
                c6,
                c5,
            );
            ghash.current = c5;
        }
    }

    let cipher_inout = by8_iter.into_remainder();
    {
        let mut blocks_iter = cipher_inout.chunks_exact_mut(16);
        for block in blocks_iter.by_ref() {
            counter = counter.add(COUNTER_1);

            unsafe {
                let mut c1 = _mm_xor_si128(counter.0, rk_first);

                for rk in rks {
                    c1 = _mm_aesenc_si128(c1, *rk);
                }

                let c1 = _mm_aesenclast_si128(c1, rk_last);

                let c1 = _mm_xor_si128(c1, _mm_loadu_si128(block.as_ptr().add(0) as *const _));

                _mm_storeu_si128(block.as_mut_ptr().add(0) as *mut _, c1);
            }
        }

        let cipher_inout = blocks_iter.into_remainder();
        if !cipher_inout.is_empty() {
            let mut block = [0u8; 16];
            let len = cipher_inout.len();
            debug_assert!(len < 16);
            block[..len].copy_from_slice(cipher_inout);

            counter = counter.add(COUNTER_1);

            unsafe {
                let mut c1 = _mm_xor_si128(counter.0, rk_first);

                for rk in rks {
                    c1 = _mm_aesenc_si128(c1, *rk);
                }

                let c1 = _mm_aesenclast_si128(c1, rk_last);

                let c1 = _mm_xor_si128(c1, _mm_loadu_si128(block.as_ptr() as *const _));

                _mm_storeu_si128(block.as_mut_ptr() as *mut _, c1);
            }

            cipher_inout.copy_from_slice(&block[..len]);
        }
    }

    ghash.add(cipher_inout);
}

#[derive(Clone, Copy, Debug)]
struct Counter(__m128i);

impl Counter {
    fn new(bytes: &[u8; 16]) -> Self {
        Self(unsafe { _mm_lddqu_si128(bytes.as_ptr() as *const _) })
    }

    #[must_use]
    #[inline]
    fn add(&self, a: __m128i) -> Self {
        Self(unsafe { _mm_add_epi32(self.0, a) })
    }
}

const COUNTER_1: __m128i = unsafe { mem::transmute(1u128 << 120) };
const COUNTER_2: __m128i = unsafe { mem::transmute(2u128 << 120) };
const COUNTER_3: __m128i = unsafe { mem::transmute(3u128 << 120) };
const COUNTER_4: __m128i = unsafe { mem::transmute(4u128 << 120) };
const COUNTER_5: __m128i = unsafe { mem::transmute(5u128 << 120) };
const COUNTER_6: __m128i = unsafe { mem::transmute(6u128 << 120) };
const COUNTER_7: __m128i = unsafe { mem::transmute(7u128 << 120) };
const COUNTER_8: __m128i = unsafe { mem::transmute(8u128 << 120) };

const BYTESWAP: __m128i = unsafe { mem::transmute(0x00010203_04050607_08090a0b_0c0d0e0fu128) };
