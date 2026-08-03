// Written for Graviola by Joe Birr-Pixton, 2026.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::{arch::x86_64::*, ops::Range};

use super::cpu::HaveAvx512ForMlKem;

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
    _proof: HaveAvx512ForMlKem,
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
    _sha3_keccak8_f1600(&mut keccak_states, &RC);
    _squeeze_rate_and_reject(&keccak_states, outputs, &mut left);
    _sha3_keccak8_f1600(&mut keccak_states, &RC);
    _squeeze_rate_and_reject(&keccak_states, outputs, &mut left);
    _sha3_keccak8_f1600(&mut keccak_states, &RC);
    _squeeze_rate_and_reject(&keccak_states, outputs, &mut left);

    for (i, (left, output)) in left.iter().zip(outputs.chunks_exact_mut(256)).enumerate() {
        if *left > 0 {
            let mut state = extract_state(&keccak_states, i);
            tail_fn(&mut state, &mut output[256 - *left..]);
        }
    }
}

#[target_feature(enable = "avx512f")]
fn _sha3_keccak8_f1600(state: &mut [__m512i; 25], rc: &[u64; 24]) {
    for round_constant in rc {
        // Theta step.
        //
        // Compute the column parities C[x], then D[x] = C[x-1] ^ ROL(C[x+1], 1),
        // and fold D[x] into every lane of column x.
        let mut c = [_mm512_setzero_si512(); 5];
        for x in 0..5 {
            c[x] = xor(
                xor(
                    xor(state[x], state[x + 5]),
                    xor(state[x + 10], state[x + 15]),
                ),
                state[x + 20],
            );
        }

        let mut d = [_mm512_setzero_si512(); 5];
        for x in 0..5 {
            d[x] = xor(c[(x + 4) % 5], rotate_left(c[(x + 1) % 5], 1));
        }

        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] = xor(state[x + 5 * y], d[x]);
            }
        }

        // Rho and Pi steps.
        //
        // Rotate each lane by its rho offset and scatter it to its pi position
        // B[y, 2x + 3y] = ROL(A[x, y], RHO[x][y]).
        let mut b = [_mm512_setzero_si512(); 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotate_left(state[x + 5 * y], RHO[x][y]);
            }
        }

        // Chi step.
        //
        // A[x, y] = B[x, y] ^ ((~B[x+1, y]) & B[x+2, y]).
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] = xor(
                    b[x + 5 * y],
                    _mm512_andnot_si512(b[(x + 1) % 5 + 5 * y], b[(x + 2) % 5 + 5 * y]),
                );
            }
        }

        // Iota step.
        state[0] = xor(state[0], _mm512_set1_epi64(*round_constant as i64));
    }
}

/// Rotation offsets for the rho step, indexed `RHO[x][y]`.
static RHO: [[i32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

const RC: [u64; 24] = [
    0x00000000_00000001,
    0x00000000_00008082,
    0x80000000_0000808A,
    0x80000000_80008000,
    0x00000000_0000808B,
    0x00000000_80000001,
    0x80000000_80008081,
    0x80000000_00008009,
    0x00000000_0000008A,
    0x00000000_00000088,
    0x00000000_80008009,
    0x00000000_8000000A,
    0x00000000_8000808B,
    0x80000000_0000008B,
    0x80000000_00008089,
    0x80000000_00008003,
    0x80000000_00008002,
    0x80000000_00000080,
    0x00000000_0000800A,
    0x80000000_8000000A,
    0x80000000_80008081,
    0x80000000_00008080,
    0x00000000_80000001,
    0x80000000_80008008,
];

#[inline]
#[target_feature(enable = "avx512f")]
fn xor(a: __m512i, b: __m512i) -> __m512i {
    _mm512_xor_si512(a, b)
}

/// Rotate each 64-bit lane of `x` left by `n` bits, where `n` is in `0..64`.
#[inline]
#[target_feature(enable = "avx512f")]
fn rotate_left(x: __m512i, n: i32) -> __m512i {
    _mm512_rolv_epi64(x, _mm512_set1_epi64(n as i64))
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
fn _squeeze_rate_and_reject(
    state: &[__m512i; 25],
    output: &mut [i16; 256 * 8],
    left: &mut [usize; 8],
) {
    let mut rate = [[0u64; 8]; RATE_WORDS];
    for (lane, out) in rate.iter_mut().enumerate() {
        // SAFETY: `out` is 8 * 8 = 64 bytes, exactly the width of one `__m512i`.
        unsafe { _mm512_storeu_si512(out.as_mut_ptr().cast(), state[lane]) };
    }

    // SAFETY: `SPREAD` is 64 bytes, exactly the width of one `__m512i`.
    let spread = unsafe { _mm512_loadu_si512(SPREAD.as_ptr().cast()) };

    let q = _mm512_set1_epi16(Q as i16);
    let twelve_bits = _mm512_set1_epi16(0x0fff);

    // Within each pair of 16-bit lanes, the first candidate needs no shift and the
    // second needs to lose the four bits it shares with the first.
    let shifts = _mm512_set1_epi32(0x0004_0000);

    let mut bytes = [0u8; RATE_BYTES + 64];

    for (i, (left, poly)) in left
        .iter_mut()
        .zip(output.chunks_exact_mut(256))
        .enumerate()
    {
        if *left == 0 {
            continue;
        }

        // Collect this state's rate bytes.  Candidates straddle the 64-bit lanes,
        // so it is simplest to linearise them first.  The trailing padding means a
        // 64-byte load from anywhere within the rate stays in bounds.
        for (lane, chunk) in bytes[..RATE_BYTES].chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&rate[lane][i].to_le_bytes());
        }

        let mut used = 256 - *left;

        for offset in (0..RATE_BYTES).step_by(GROUP_BYTES) {
            if used == 256 {
                break;
            }

            // Rejection sample, per FIPS-203 `SampleNTT()`: each three bytes give two
            // 12-bit candidates.  `SPREAD` gathers each three-byte group into a pair
            // of 16-bit lanes, which are then reduced to the candidates themselves.
            // SAFETY: `bytes` is padded to allow a 64-byte load from `offset`.
            let raw = unsafe { _mm512_loadu_si512(bytes[offset..].as_ptr().cast()) };
            let candidates = _mm512_and_si512(
                _mm512_srlv_epi16(_mm512_permutexvar_epi8(spread, raw), shifts),
                twelve_bits,
            );

            // Accept candidates less than Q.  Lanes past the end of the rate read as
            // zero, which would otherwise be accepted, so discard them.
            let mut accept = _mm512_cmplt_epu16_mask(candidates, q);
            let valid = ((RATE_BYTES - offset) / 3 * 2).min(GROUP_CANDIDATES);
            if valid < GROUP_CANDIDATES {
                accept &= (1u32 << valid) - 1;
            }

            let accepted = accept.count_ones() as usize;

            if used + GROUP_CANDIDATES <= 256 {
                // Compaction cannot overrun `poly`, so write straight into it.
                // SAFETY: `accepted` is at most `GROUP_CANDIDATES`, which fits.
                unsafe {
                    _mm512_mask_compressstoreu_epi16(poly[used..].as_mut_ptr(), accept, candidates)
                };
                used += accepted;
            } else {
                // Otherwise compact aside, and take only as much as fits.
                let mut scratch = [0i16; GROUP_CANDIDATES];
                // SAFETY: `accepted` is at most `GROUP_CANDIDATES`, the size of `scratch`.
                unsafe {
                    _mm512_mask_compressstoreu_epi16(scratch.as_mut_ptr(), accept, candidates)
                };
                let take = accepted.min(256 - used);
                poly[used..used + take].copy_from_slice(&scratch[..take]);
                used += take;
            }
        }

        *left = 256 - used;
    }
}

/// SHAKE128's rate, in 64-bit words: 168 bytes.
const RATE_WORDS: usize = (1600 - 256) / 64;

/// SHAKE128's rate, in bytes.
const RATE_BYTES: usize = RATE_WORDS * 8;

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
