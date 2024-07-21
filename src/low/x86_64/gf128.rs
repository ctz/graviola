/// Refs.
/// - https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf
/// - https://www.intel.com/content/dam/www/public/us/en/documents/software-support/enabling-high-performance-gcm.pdf
/// - https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf
use std::arch::x86_64::*;

pub(crate) fn mul(x: u128, y: u128) -> u128 {
    unsafe { _mul(x, y) }
}

#[target_feature(enable = "pclmulqdq")]
unsafe fn _mul(x: u128, y: u128) -> u128 {
    // This is almost verbatim from "Intel® Carry-Less Multiplication
    // Instruction and its Usage for Computing the GCM Mode"
    // figure 5.

    let mut ret = 0;

    unsafe {
        let a = _mm_load_si128(&x as *const u128 as *const __m128i);
        let b = _mm_load_si128(&y as *const u128 as *const __m128i);

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
        let t6 = _mm_xor_si128(t6, t3);

        _mm_store_si128(&mut ret as *mut u128 as *mut _, t6);
    }

    ret
}
