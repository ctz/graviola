// Written for Graviola by Joe Birr-Pixton, 2026.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

/// Compute Keccak-f1600 on all eight states in `a`.
#[inline]
pub(crate) fn sha3_keccak8_f1600(a: &mut [[u64; 25]; 8], rc: &[u64; 24]) {
    for a in a.as_chunks_mut::<4>().0.iter_mut() {
        super::sha3_keccak4_f1600_mux::sha3_keccak4_f1600(a, rc);
    }
}
