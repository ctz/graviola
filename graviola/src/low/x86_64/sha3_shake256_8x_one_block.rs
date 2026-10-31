// Written for Graviola by Joe Birr-Pixton, 2026.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::arch::x86_64::*;

use super::cpu::HaveAvx512ForMlKem;
use super::sha3_keccak8_f1600::sha3_keccak8_f1600;
use crate::low::KECCAK_RC;
use crate::low::generic::sha3::Shake256x8FallbackFn;

/// This does SHAKE256 for up to eight single-block messages, yielding 128 bytes of output for each.
///
/// `inputs` are pre-formatted SHAKE256 inputs (already containing the domain separation bits).
/// The remainder of each block is zero, apart from the final padding bit.
///
/// If `spare_permute` is provided, that state is permuted in place using the eighth lane,
/// which would otherwise be idle.  `N` must then be at most 7.
///
/// `fallback_fn` is a complete fallback implementation of the whole function.
pub(crate) fn sha3_shake256_8x_one_block<const N: usize>(
    inputs: &[&[u8; 40]; N],
    outputs: &mut [[u8; 128]; N],
    spare_permute: Option<&mut [u64; 25]>,
    fallback_fn: Shake256x8FallbackFn<N>,
) {
    match HaveAvx512ForMlKem::check() {
        // SAFETY: `HaveAvx512ForMlKem` checks for required target features
        Some(proof) => unsafe {
            shake256_8x_one_block_avx512(inputs, outputs, spare_permute, proof)
        },
        None => fallback_fn(inputs, outputs, spare_permute),
    }
}

#[target_feature(enable = "avx512f")]
fn shake256_8x_one_block_avx512<const N: usize>(
    inputs: &[&[u8; 40]; N],
    outputs: &mut [[u8; 128]; N],
    spare_permute: Option<&mut [u64; 25]>,
    proof: HaveAvx512ForMlKem,
) {
    const { assert!(N <= 8) };
    debug_assert!(N < 8 || spare_permute.is_none());

    // Build the state directly in transposed form: `states[word]` holds `word` for all
    // eight lanes.  Only the first five words of each input can be non-zero.
    let mut states = [_mm512_setzero_si512(); 25];

    let word = |lane: usize, w: usize| match inputs.get(lane) {
        Some(input) => u64::from_le_bytes(input.as_chunks::<8>().0[w]) as i64,
        None => 0,
    };
    for (w, state) in states[..5].iter_mut().enumerate() {
        *state = _mm512_setr_epi64(
            word(0, w),
            word(1, w),
            word(2, w),
            word(3, w),
            word(4, w),
            word(5, w),
            word(6, w),
            word(7, w),
        );
    }
    states[16] = _mm512_set1_epi64(0x8000_0000_0000_0000_u64 as i64);

    if let Some(spare) = &spare_permute {
        for (state, word) in states.iter_mut().zip(spare.iter()) {
            *state = _mm512_mask_set1_epi64(*state, 1 << 7, *word as i64);
        }
    }

    sha3_keccak8_f1600(&mut states, &KECCAK_RC, proof);

    // The 128 output bytes are the first 16 words of each lane.
    let low = transpose_8x8(states[..8].try_into().unwrap());
    let high = transpose_8x8(states[8..16].try_into().unwrap());
    for (output, (low, high)) in outputs.iter_mut().zip(low.iter().zip(&high)) {
        let (halves, _) = output.as_chunks_mut::<64>();
        // SAFETY: each half is 64 bytes, exactly the width of one `__m512i`.
        unsafe {
            _mm512_storeu_si512(halves[0].as_mut_ptr().cast(), *low);
            _mm512_storeu_si512(halves[1].as_mut_ptr().cast(), *high);
        }
    }

    if let Some(spare) = spare_permute {
        // Words 0..16 of the eighth lane are already gathered by the transposes above.
        let (chunks, tail) = spare.as_chunks_mut::<8>();
        // SAFETY: each chunk is 8 words, exactly the width of one `__m512i`.
        unsafe {
            _mm512_storeu_si512(chunks[0].as_mut_ptr().cast(), low[7]);
            _mm512_storeu_si512(chunks[1].as_mut_ptr().cast(), high[7]);
        }
        for (out, state) in chunks[2].iter_mut().chain(tail).zip(&states[16..]) {
            *out = _mm_extract_epi64::<1>(_mm512_extracti32x4_epi32::<3>(*state)) as u64;
        }
    }
}

/// Transpose an 8x8 matrix of 64-bit words, held as eight rows.
#[target_feature(enable = "avx512f")]
fn transpose_8x8(r: [__m512i; 8]) -> [__m512i; 8] {
    // Interleave pairs of rows: a[0] = r0[0] r1[0] r0[2] r1[2] r0[4] r1[4] r0[6] r1[6], etc.
    let a = [
        _mm512_unpacklo_epi64(r[0], r[1]),
        _mm512_unpackhi_epi64(r[0], r[1]),
        _mm512_unpacklo_epi64(r[2], r[3]),
        _mm512_unpackhi_epi64(r[2], r[3]),
        _mm512_unpacklo_epi64(r[4], r[5]),
        _mm512_unpackhi_epi64(r[4], r[5]),
        _mm512_unpacklo_epi64(r[6], r[7]),
        _mm512_unpackhi_epi64(r[6], r[7]),
    ];

    // Gather 128-bit pairs: b[0] = r0[0] r1[0] r0[4] r1[4] r2[0] r3[0] r2[4] r3[4], etc.
    let b = [
        _mm512_shuffle_i64x2::<0x88>(a[0], a[2]),
        _mm512_shuffle_i64x2::<0xdd>(a[0], a[2]),
        _mm512_shuffle_i64x2::<0x88>(a[1], a[3]),
        _mm512_shuffle_i64x2::<0xdd>(a[1], a[3]),
        _mm512_shuffle_i64x2::<0x88>(a[4], a[6]),
        _mm512_shuffle_i64x2::<0xdd>(a[4], a[6]),
        _mm512_shuffle_i64x2::<0x88>(a[5], a[7]),
        _mm512_shuffle_i64x2::<0xdd>(a[5], a[7]),
    ];

    [
        _mm512_shuffle_i64x2::<0x88>(b[0], b[4]),
        _mm512_shuffle_i64x2::<0x88>(b[2], b[6]),
        _mm512_shuffle_i64x2::<0x88>(b[1], b[5]),
        _mm512_shuffle_i64x2::<0x88>(b[3], b[7]),
        _mm512_shuffle_i64x2::<0xdd>(b[0], b[4]),
        _mm512_shuffle_i64x2::<0xdd>(b[2], b[6]),
        _mm512_shuffle_i64x2::<0xdd>(b[1], b[5]),
        _mm512_shuffle_i64x2::<0xdd>(b[3], b[7]),
    ]
}
