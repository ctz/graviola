// Written for Graviola by Joe Birr-Pixton, 2026.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! Unlike the assembly versions, this relies on the compiler not
//! introducing an early exit or branches.  `black_box` makes that
//! less likely, but it is not a guarantee.

use core::hint::black_box;

/// # Safety
/// `a` and `b` must be valid for reads of `len` bytes.
pub(crate) unsafe fn ct_compare_bytes(a: *const u8, b: *const u8, len: usize) -> u8 {
    // SAFETY: the caller guarantees `a` and `b` are valid for `len` bytes.
    let (a, b) = unsafe {
        (
            core::slice::from_raw_parts(a, len),
            core::slice::from_raw_parts(b, len),
        )
    };

    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc = black_box(acc | (x ^ y));
    }
    acc
}
