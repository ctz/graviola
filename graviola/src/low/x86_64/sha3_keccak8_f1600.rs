// Written for Graviola by Joe Birr-Pixton, 2026.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::arch::x86_64::*;

use crate::low::x86_64::cpu::HaveAvx512ForMlKem;

/// Compute Keccak-f1600 on eight states at once.
///
/// `state[lane]` holds `lane` for all eight states.
///
/// `_proof` guarantees a CPU feature check was done.
#[target_feature(enable = "avx512f")]
pub(super) fn sha3_keccak8_f1600(
    state: &mut [__m512i; 25],
    rc: &[u64; 24],
    _proof: HaveAvx512ForMlKem,
) {
    for round_constant in rc {
        // Theta step.
        //
        // Compute the column parities C[x], then fold D[x] = C[x-1] ^ ROL(C[x+1], 1)
        // into every lane of column x.  This is fused with the rho and pi steps below.
        let mut c = [_mm512_setzero_si512(); 5];
        for x in 0..5 {
            c[x] = xor3(
                xor3(state[x], state[x + 5], state[x + 10]),
                state[x + 15],
                state[x + 20],
            );
        }

        let mut c_rotated = [_mm512_setzero_si512(); 5];
        for x in 0..5 {
            c_rotated[x] = rotate_left(c[x], 1);
        }

        // Rho and Pi steps.
        //
        // Rotate each lane by its rho offset and scatter it to its pi position
        // B[y, 2x + 3y] = ROL(A[x, y], RHO[x][y]).
        let mut b = [_mm512_setzero_si512(); 25];
        for x in 0..5 {
            for y in 0..5 {
                let lane = xor3(state[x + 5 * y], c[(x + 4) % 5], c_rotated[(x + 1) % 5]);
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotate_left(lane, RHO[x][y]);
            }
        }

        // Chi step.
        //
        // A[x, y] = B[x, y] ^ ((~B[x+1, y]) & B[x+2, y]).
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] =
                    xor_andnot(b[x + 5 * y], b[(x + 1) % 5 + 5 * y], b[(x + 2) % 5 + 5 * y]);
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

#[inline]
#[target_feature(enable = "avx512f")]
fn xor(a: __m512i, b: __m512i) -> __m512i {
    _mm512_xor_si512(a, b)
}

/// `a ^ b ^ c`
#[inline]
#[target_feature(enable = "avx512f")]
fn xor3(a: __m512i, b: __m512i, c: __m512i) -> __m512i {
    _mm512_ternarylogic_epi64::<0x96>(a, b, c)
}

/// `a ^ (!b & c)`
#[inline]
#[target_feature(enable = "avx512f")]
fn xor_andnot(a: __m512i, b: __m512i, c: __m512i) -> __m512i {
    _mm512_ternarylogic_epi64::<0xd2>(a, b, c)
}

/// Rotate each 64-bit lane of `x` left by `n` bits, where `n` is in `0..64`.
#[inline]
#[target_feature(enable = "avx512f")]
fn rotate_left(x: __m512i, n: i32) -> __m512i {
    _mm512_or_si512(
        _mm512_sllv_epi64(x, _mm512_set1_epi64(n as i64)),
        _mm512_srlv_epi64(x, _mm512_set1_epi64((64 - n) as i64)),
    )
}
