use crate::low::generic;
use crate::low::x86_64::sha512::{sha512_block_data_order_avx, sha512_block_data_order_avx2};

pub fn sha512_compress_blocks(state: &mut [u64; 8], blocks: &[u8]) {
    if is_x86_feature_detected!("bmi1")
        && is_x86_feature_detected!("bmi2")
        && is_x86_feature_detected!("avx2")
    {
        sha512_block_data_order_avx2(state, blocks)
    } else if is_x86_feature_detected!("avx") && is_x86_feature_detected!("ssse3") {
        sha512_block_data_order_avx(state, blocks)
    } else {
        generic::sha512::sha512_compress_blocks(state, blocks)
    }
}
