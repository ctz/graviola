// Written for Graviola by Joe Birr-Pixton, 2026.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use super::cpu::HaveAvx512ForSha3;

pub(crate) fn sha3_keccak_f1600(a: &mut [u64; 25], rc: &[u64; 24]) {
    match HaveAvx512ForSha3::check() {
        // SAFETY: `HaveAvx512ForSha3` checks for required target features
        Some(proof) => unsafe {
            super::sha3_keccak_f1600_avx512vl::sha3_keccak_f1600(a, rc, proof)
        },
        None => super::sha3_keccak_f1600::sha3_keccak_f1600(a, rc),
    }
}
