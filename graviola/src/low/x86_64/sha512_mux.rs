// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::low::generic;
use crate::low::x86_64;

pub(crate) fn sha512_compress_blocks(state: &mut [u64; 8], blocks: &[u8]) {
    // nb. avx2 is in our required set.
    if x86_64::cpu::have_cpu_feature!("bmi2") {
        x86_64::sha512::sha512_compress_blocks(state, blocks)
    } else {
        generic::sha512::sha512_compress_blocks(state, blocks)
    }
}
