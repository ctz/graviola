// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::low::generic;
use crate::low::x86_64;

pub fn sha256_compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
    if is_x86_feature_detected!("sha") {
        x86_64::sha256::sha256_compress_blocks_shaext(state, blocks)
    } else {
        generic::sha256::sha256_compress_blocks(state, blocks)
    }
}
