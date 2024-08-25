// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::low::generic;
use crate::low::x86_64::sha256::{
    sha256_block_data_order_avx, sha256_block_data_order_avx2, sha256_block_data_order_shaext,
    sha256_block_data_order_ssse3,
};

pub fn sha256_compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
    if is_x86_feature_detected!("sha") {
        sha256_block_data_order_shaext(state, blocks)
    } else if is_x86_feature_detected!("bmi1")
        && is_x86_feature_detected!("bmi2")
        && is_x86_feature_detected!("avx2")
    {
        sha256_block_data_order_avx2(state, blocks)
    } else if is_x86_feature_detected!("avx") && is_x86_feature_detected!("ssse3") {
        sha256_block_data_order_avx(state, blocks)
    } else if is_x86_feature_detected!("ssse3") {
        sha256_block_data_order_ssse3(state, blocks)
    } else {
        generic::sha256::sha256_compress_blocks(state, blocks)
    }
}
