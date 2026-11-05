// Written for Graviola by Joe Birr-Pixton, 2026.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use super::cpu::HaveAvx512ForSha3;

pub(crate) fn sha3_keccak_f1600(a: &mut [u64; 25], rc: &[u64; 24]) {
    match HaveAvx512ForSha3::check() {
        // SAFETY: `HaveAvx512ForSha3` checks for required target features
        Some(proof) => unsafe {
            super::sha3_keccak_f1600_avx512vl::sha3_keccak_f1600(a, rc, proof)
        },
        None => sha3_keccak_f1600_scalar(a, rc),
    }
}

/// Compute Keccak-f1600 on two independent states, `a0` and `a1`.
pub(crate) fn sha3_keccak2_f1600(a0: &mut [u64; 25], a1: &mut [u64; 25], rc: &[u64; 24]) {
    match HaveAvx512ForSha3::check() {
        // SAFETY: `HaveAvx512ForSha3` checks for required target features
        Some(proof) => unsafe {
            super::sha3_keccak_f1600_avx512vl::sha3_keccak2_f1600(a0, a1, rc, proof)
        },
        None => {
            sha3_keccak_f1600_scalar(a0, rc);
            sha3_keccak_f1600_scalar(a1, rc);
        }
    }
}

/// The scalar fallback is a single large `asm!` block, which LLVM would otherwise
/// inline into every caller of the mux.
#[inline(never)]
fn sha3_keccak_f1600_scalar(a: &mut [u64; 25], rc: &[u64; 24]) {
    super::sha3_keccak_f1600::sha3_keccak_f1600(a, rc)
}
