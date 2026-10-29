// Written for Graviola by Joe Birr-Pixton, 2026.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::arch::x86_64::*;

use super::cpu::HaveAvx512ForMlKem;

/// Compute Keccak-f1600 on all eight states in `a`.
///
/// This uses AVX-512 where available, otherwise falls back to two 4-way permutations.
#[inline]
pub(crate) fn sha3_keccak8_f1600(a: &mut [[u64; 25]; 8], rc: &[u64; 24]) {
    match HaveAvx512ForMlKem::check() {
        // SAFETY: `HaveAvx512ForMlKem` checks for required target features
        Some(proof) => unsafe { sha3_keccak8_f1600_avx512(a, rc, proof) },
        None => {
            for a in a.as_chunks_mut::<4>().0.iter_mut() {
                super::sha3_keccak4_f1600_shim::sha3_keccak4_f1600(a, rc);
            }
        }
    }
}

#[target_feature(enable = "avx512f")]
fn sha3_keccak8_f1600_avx512(a: &mut [[u64; 25]; 8], rc: &[u64; 24], proof: HaveAvx512ForMlKem) {
    // Transpose into one register per lane, holding that lane for all eight states.
    let mut states = [_mm512_setzero_si512(); 25];
    for (lane, state) in states.iter_mut().enumerate() {
        *state = _mm512_setr_epi64(
            a[0][lane] as i64,
            a[1][lane] as i64,
            a[2][lane] as i64,
            a[3][lane] as i64,
            a[4][lane] as i64,
            a[5][lane] as i64,
            a[6][lane] as i64,
            a[7][lane] as i64,
        );
    }

    super::mlkem768_sample_poly_ntt_8x::sha3_keccak8_f1600(&mut states, rc, proof);

    for (lane, state) in states.iter().enumerate() {
        let mut words = [0u64; 8];
        // SAFETY: `words` is 8 * 8 = 64 bytes, exactly the width of one `__m512i`.
        unsafe { _mm512_storeu_si512(words.as_mut_ptr().cast(), *state) };
        for (a, word) in a.iter_mut().zip(words) {
            a[lane] = word;
        }
    }
}
