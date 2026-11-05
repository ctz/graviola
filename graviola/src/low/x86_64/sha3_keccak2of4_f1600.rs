// Written for Graviola by Joe Birr-Pixton, 2026.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use super::cpu::HaveAvx512ForSha3;

/// Compute Keccak-f1600 on the first two states in `a`.
///
/// With AVX512VL this uses the two-state XMM permutation, which is much
/// faster than the 4-way AVX2 permutation with two lanes going spare.
#[inline]
pub(crate) fn sha3_keccak2of4_f1600(a: &mut [[u64; 25]; 4], rc: &[u64; 24]) {
    match HaveAvx512ForSha3::check() {
        // SAFETY: `HaveAvx512ForSha3` checks for required target features
        Some(proof) => unsafe {
            let [a0, a1, _, _] = a;
            super::sha3_keccak_f1600_avx512vl::sha3_keccak2_f1600(a0, a1, rc, proof)
        },
        None => super::sha3_keccak4_f1600_shim::sha3_keccak4_f1600(a, rc),
    }
}
