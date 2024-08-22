// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::low::optimise_barrier_u8;

pub fn ct_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (aa, bb) in a.iter().zip(b.iter()) {
        diff |= *aa ^ *bb;
    }

    optimise_barrier_u8(diff) == 0
}
