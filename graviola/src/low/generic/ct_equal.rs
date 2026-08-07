// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::low::{ct_compare_bytes, ct_compare_u128};

pub(crate) fn ct_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // SAFETY: prior code guarantees a.len() == b.len()
    let diff = unsafe { ct_compare_bytes(a.as_ptr(), b.as_ptr(), a.len()) };
    diff == 0
}

pub(crate) fn ct_equal_u128(a: u128, b: u128) -> bool {
    // SAFETY: this crate requires SSE2 on x86_64 and NEON on aarch64.
    (unsafe { ct_compare_u128(a, b) }) == 0
}
