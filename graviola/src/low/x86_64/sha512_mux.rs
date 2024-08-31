// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::low::generic;
use crate::low::x86_64;

pub fn sha512_compress_blocks(state: &mut [u64; 8], blocks: &[u8]) {
    if is_x86_feature_detected!("bmi2") && is_x86_feature_detected!("avx2") {
        x86_64::sha512::sha512_compress_blocks(state, blocks)
    } else {
        generic::sha512::sha512_compress_blocks(state, blocks)
    }
}
