// Written for Graviola by Joe Birr-Pixton, 2026.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::{arch::x86_64::*, ops::Range};

use super::cpu::HaveAvx512ForMlKem;
use super::sha3_keccak8_f1600::sha3_keccak8_f1600;
use crate::low::KECCAK_RC;

pub(crate) fn mlkem768_sample_poly_ntt_8x(
    inputs: &[[u8; 40]; 8],
    outputs: &mut [i16; 256 * 8],
    fallback_fn: fn(&[[u8; 40]; 8], &mut [i16; 256 * 8]),
    tail_fn: fn(&mut [u64; 25], &mut [i16]),
) {
    match HaveAvx512ForMlKem::check() {
        // SAFETY: `HaveAvx512ForMlKem` checks for required target features
        Some(proof) => unsafe { sample_poly_ntt_8x_avx512(inputs, outputs, tail_fn, proof) },
        None => fallback_fn(inputs, outputs),
    }
}

#[target_feature(enable = "avx512f,avx512bw,avx512vbmi,avx512vbmi2")]
unsafe fn sample_poly_ntt_8x_avx512(
    inputs: &[[u8; 40]; 8],
    outputs: &mut [i16; 256 * 8],
    tail_fn: fn(&mut [u64; 25], &mut [i16]),
    proof: HaveAvx512ForMlKem,
) {
    let mut keccak_states = [_mm512_setzero_si512(); 25];

    keccak_states[20] = _mm512_set1_epi64(0x8000_0000_0000_0000_u64 as i64);

    let word = |i: usize, range: Range<usize>| {
        u64::from_le_bytes(inputs[i][range].try_into().unwrap()) as i64
    };
    for (i, state) in keccak_states[..5].iter_mut().enumerate() {
        *state = _mm512_setr_epi64(
            word(0, i * 8..(i + 1) * 8),
            word(1, i * 8..(i + 1) * 8),
            word(2, i * 8..(i + 1) * 8),
            word(3, i * 8..(i + 1) * 8),
            word(4, i * 8..(i + 1) * 8),
            word(5, i * 8..(i + 1) * 8),
            word(6, i * 8..(i + 1) * 8),
            word(7, i * 8..(i + 1) * 8),
        );
    }

    // This tracks the number of unwritten coefficients in each output polynomial.
    let mut left = [256; 8];

    // Like the generic version, we generate three squeezes of data to
    // sample coefficients from.  This gives up to 336 candidates for 256 output
    // coefficients.
    for _ in 0..3 {
        sha3_keccak8_f1600(&mut keccak_states, &KECCAK_RC, proof);
        squeeze_rate_and_reject(&keccak_states, outputs, &mut left, proof);
    }

    for (i, (left, output)) in left
        .iter()
        .zip(outputs.as_chunks_mut::<256>().0.iter_mut())
        .enumerate()
    {
        if *left > 0 {
            let mut state = extract_state(&keccak_states, i);
            tail_fn(&mut state, &mut output[256 - *left..]);
        }
    }
}

/// Extract a single keccak state from the 8-way `states`, where `index` is in `0..8`.
///
/// `states[lane]` holds `lane` for all eight states, so the result collects the
/// `index`th 64-bit word of each lane.
#[target_feature(enable = "avx512f")]
fn extract_state(states: &[__m512i; 25], index: usize) -> [u64; 25] {
    let mut r = [0u64; 25];
    for (lane, out) in r.iter_mut().enumerate() {
        let mut words = [0u64; 8];
        // SAFETY: `words` is 8 * 8 = 64 bytes, exactly the width of one `__m512i`.
        unsafe { _mm512_storeu_si512(words.as_mut_ptr().cast(), states[lane]) };
        *out = words[index];
    }
    r
}

/// Squeeze rate bytes from `state`, rejection sampling into `output`.
///
/// `left` indicates how many items in each polynomial in `output` remains unwritten.
/// It should be updated to indicate how many were written.
#[target_feature(enable = "avx512f,avx512bw,avx512vbmi,avx512vbmi2")]
#[inline]
fn squeeze_rate_and_reject(
    state: &[__m512i; 25],
    output: &mut [i16; 256 * 8],
    left: &mut [usize; 8],
    _proof: HaveAvx512ForMlKem,
) {
    let rate = transpose_rate(state);

    // SAFETY: `SPREAD` is 64 bytes, exactly the width of one `__m512i`.
    let spread = unsafe { _mm512_loadu_si512(SPREAD.as_ptr().cast()) };

    // Each state's rate is held in three registers, covering bytes 0..64, 64..128 and
    // 128..168.  Group `g` starts at byte `g * GROUP_BYTES`; groups 1 and 2 straddle
    // two registers, so are spread using the two-source byte permutation.  These are
    // `SPREAD`, offset to the group's starting byte within the first register.
    let spread_0 = spread;
    let spread_48 = _mm512_add_epi8(spread, _mm512_set1_epi8(48));
    let spread_32 = _mm512_add_epi8(spread, _mm512_set1_epi8(32));
    let spread_16 = _mm512_add_epi8(spread, _mm512_set1_epi8(16));

    let q = _mm512_set1_epi16(Q as i16);
    let twelve_bits = _mm512_set1_epi16(0x0fff);

    // Within each pair of 16-bit lanes, the first candidate needs no shift and the
    // second needs to lose the four bits it shares with the first.
    let shifts = _mm512_set1_epi32(0x0004_0000);

    for ((left, poly), [r0, r1, r2]) in left
        .iter_mut()
        .zip(output.as_chunks_mut::<256>().0.iter_mut())
        .zip(rate)
    {
        let groups = [
            _mm512_permutexvar_epi8(spread_0, r0),
            _mm512_permutex2var_epi8(r0, spread_48, r1),
            _mm512_permutex2var_epi8(r1, spread_32, r2),
            _mm512_permutexvar_epi8(spread_16, r2),
        ];

        let mut used = 256 - *left;

        for (group, raw) in groups.into_iter().enumerate() {
            if used == 256 {
                break;
            }

            // Rejection sample, per FIPS-203 `SampleNTT()`: each three bytes give two
            // 12-bit candidates.  `raw` has each three-byte group spread into a pair
            // of 16-bit lanes, which are then reduced to the candidates themselves.
            let candidates = _mm512_and_si512(_mm512_srlv_epi16(raw, shifts), twelve_bits);

            // Accept candidates less than Q.  Lanes past the end of the rate read as
            // zero, which would otherwise be accepted, so discard them.
            let mut accept = _mm512_cmplt_epu16_mask(candidates, q);
            let offset = group * GROUP_BYTES;
            let valid = ((RATE_BYTES - offset) / 3 * 2).min(GROUP_CANDIDATES);
            if valid < GROUP_CANDIDATES {
                accept &= (1u32 << valid) - 1;
            }

            // Compact the accepted candidates to the bottom of a register, then store
            // only as many as fit.
            let take = (accept.count_ones() as usize).min(256 - used);
            let compacted = _mm512_maskz_compress_epi16(accept, candidates);
            // SAFETY: only the low `take` lanes are written, and `take <= 256 - used`.
            unsafe {
                _mm512_mask_storeu_epi16(
                    poly[used..].as_mut_ptr(),
                    ((1u64 << take) - 1) as u32,
                    compacted,
                )
            };
            used += take;
        }

        *left = 256 - used;
    }
}

/// Transpose the rate lanes of the 8-way `state` into each state's rate bytes.
///
/// Element `i` of the result holds the rate of state `i`: words 0..8, 8..16 and
/// 16..21 (followed by zeroes) of that state.
#[target_feature(enable = "avx512f")]
#[inline]
fn transpose_rate(state: &[__m512i; 25]) -> [[__m512i; 3]; 8] {
    let zero = _mm512_setzero_si512();
    let blocks = [
        transpose_8x8([
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        ]),
        transpose_8x8([
            state[8], state[9], state[10], state[11], state[12], state[13], state[14], state[15],
        ]),
        transpose_8x8([
            state[16], state[17], state[18], state[19], state[20], zero, zero, zero,
        ]),
    ];
    core::array::from_fn(|i| [blocks[0][i], blocks[1][i], blocks[2][i]])
}

/// Transpose an 8x8 matrix of 64-bit elements, held one row per register.
#[target_feature(enable = "avx512f")]
#[inline]
fn transpose_8x8(rows: [__m512i; 8]) -> [__m512i; 8] {
    // Pair up adjacent rows: `even[p]` has, in its 128-bit lane `l`, element `2l` of
    // rows `2p` and `2p + 1`.  `odd[p]` likewise has element `2l + 1`.
    let even: [__m512i; 4] =
        core::array::from_fn(|p| _mm512_unpacklo_epi64(rows[2 * p], rows[2 * p + 1]));
    let odd: [__m512i; 4] =
        core::array::from_fn(|p| _mm512_unpackhi_epi64(rows[2 * p], rows[2 * p + 1]));

    // Now each of `even` and `odd` is a 4x4 transpose of 128-bit lanes.
    let [e0, e2, e1, e3] = transpose_4x4_128(even);
    let [o0, o2, o1, o3] = transpose_4x4_128(odd);
    [e0, o0, e1, o1, e2, o2, e3, o3]
}

/// Transpose a 4x4 matrix of 128-bit elements, held one row per register.
///
/// The result is returned in the order: columns 0, 2, 1, 3.
#[target_feature(enable = "avx512f")]
#[inline]
fn transpose_4x4_128([a, b, c, d]: [__m512i; 4]) -> [__m512i; 4] {
    // `_MM_SHUFFLE(2, 0, 2, 0)` selects lanes 0 and 2 from each source,
    // `_MM_SHUFFLE(3, 1, 3, 1)` selects lanes 1 and 3.
    const EVEN: i32 = 0b10_00_10_00;
    const ODD: i32 = 0b11_01_11_01;
    let ab_even = _mm512_shuffle_i64x2::<EVEN>(a, b); // a0 a2 b0 b2
    let ab_odd = _mm512_shuffle_i64x2::<ODD>(a, b); // a1 a3 b1 b3
    let cd_even = _mm512_shuffle_i64x2::<EVEN>(c, d); // c0 c2 d0 d2
    let cd_odd = _mm512_shuffle_i64x2::<ODD>(c, d); // c1 c3 d1 d3
    [
        _mm512_shuffle_i64x2::<EVEN>(ab_even, cd_even), // a0 b0 c0 d0
        _mm512_shuffle_i64x2::<ODD>(ab_even, cd_even),  // a2 b2 c2 d2
        _mm512_shuffle_i64x2::<EVEN>(ab_odd, cd_odd),   // a1 b1 c1 d1
        _mm512_shuffle_i64x2::<ODD>(ab_odd, cd_odd),    // a3 b3 c3 d3
    ]
}

/// SHAKE128's rate, in bytes.
const RATE_BYTES: usize = (1600 - 256) / 8;

/// Candidates produced by one vector pass.
const GROUP_CANDIDATES: usize = 32;

/// Bytes consumed by one vector pass; three bytes give two candidates.
const GROUP_BYTES: usize = GROUP_CANDIDATES / 2 * 3;

/// Byte permutation spreading `GROUP_BYTES` packed bytes into 32 16-bit lanes.
///
/// Lane `k` (where `j = k / 2`) takes bytes `3j` and `3j + 1` when `k` is even,
/// or `3j + 1` and `3j + 2` when it is odd.
static SPREAD: [u8; 64] = {
    let mut r = [0u8; 64];
    let mut k = 0;
    while k < GROUP_CANDIDATES {
        let low = match k % 2 {
            0 => 3 * (k / 2),
            _ => 3 * (k / 2) + 1,
        };
        r[k * 2] = low as u8;
        r[k * 2 + 1] = (low + 1) as u8;
        k += 1;
    }
    r
};

/// The ML-KEM prime.
const Q: u16 = 3329;
