// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::low::aarch64;
use crate::low::generic;

pub(crate) fn sha512_compress_blocks(state: &mut [u64; 8], blocks: &[u8]) {
    if let Some(token) = aarch64::cpu::HaveSha512::check() {
        aarch64::sha512::sha512_compress_blocks(state, blocks, token)
    } else {
        generic::sha512::sha512_compress_blocks(state, blocks)
    }
}
