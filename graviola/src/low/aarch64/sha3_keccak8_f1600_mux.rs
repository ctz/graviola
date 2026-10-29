// Written for Graviola by Joe Birr-Pixton, 2026.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

/// Compute Keccak-f1600 on all eight states in `a`.
#[inline]
pub(crate) fn sha3_keccak8_f1600(a: &mut [[u64; 25]; 8], rc: &[u64; 24]) {
    for a in a.as_chunks_mut::<4>().0.iter_mut() {
        super::sha3_keccak4_f1600_mux::sha3_keccak4_f1600(a, rc);
    }
}

/// Compute Keccak-f1600 on the first six states in `a`.
#[inline]
pub(crate) fn sha3_keccak6of8_f1600(a: &mut [[u64; 25]; 8], rc: &[u64; 24]) {
    let (first, second) = a.split_at_mut(4);
    super::sha3_keccak4_f1600_mux::sha3_keccak4_f1600(first.try_into().unwrap(), rc);
    super::sha3_keccak2of4_f1600::sha3_keccak2of4_f1600(second.try_into().unwrap(), rc);
}
