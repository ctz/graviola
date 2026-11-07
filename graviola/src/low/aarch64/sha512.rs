// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::arch::aarch64::{
    uint64x2_t, vaddq_u64, vextq_u64, vgetq_lane_u64, vld1q_u64, vld1q_u64_x4, vsha512h2q_u64,
    vsha512hq_u64, vsha512su0q_u64, vsha512su1q_u64, vst1q_u64,
};
use core::mem;

use crate::low::aarch64::cpu::HaveSha512;
use crate::low::generic::sha512::K;

pub(crate) fn sha512_compress_blocks(state: &mut [u64; 8], blocks: &[u8], _token: HaveSha512) {
    debug_assert!(blocks.len().is_multiple_of(128));
    // SAFETY: `_token` proves caller checked cpu features for `sha3`; `neon` required by crate.
    unsafe { sha512(state, blocks) }
}

// Pack two u64 values into a uint64x2_t vector register
fn pack(lane0: u64, lane1: u64) -> uint64x2_t {
    // SAFETY: `u128` and `uint64x2_t` have compatible memory layouts.
    unsafe { mem::transmute::<u128, uint64x2_t>(lane0 as u128 | ((lane1 as u128) << 64)) }
}

// Swap the two lanes in a uint64x2_t vector register
#[target_feature(enable = "neon")]
fn swap(value: uint64x2_t) -> uint64x2_t {
    vextq_u64(value, value, 1)
}

#[target_feature(enable = "neon,sha3")]
fn sha512(state: &mut [u64; 8], blocks: &[u8]) {
    let (chunks, _) = blocks.as_chunks::<128>();
    for block in chunks {
        // SAFETY: `state` contains 8 x u64 of readable bytes.
        let current_state = unsafe { vld1q_u64_x4(state.as_mut_ptr()) };
        let mut ab = current_state.0;
        let mut cd = current_state.1;
        let mut ef = current_state.2;
        let mut gh = current_state.3;

        // This is a 16-word window into the whole W array.
        let mut w: [u64; 16] = [0; 16];

        // Process the 80 rounds of SHA-512 in pairs, because the ARM SHA-512 instructions
        // operate on two rounds at a time.

        // For W[0..16] we process the input into W.
        for t in (0..16).step_by(2) {
            let wt = u128::from_be_bytes(block[t * 8..(t + 2) * 8].try_into().unwrap());
            // SAFETY: uint64x2_t and u128 have compatible memory layouts.
            let wt: uint64x2_t = unsafe { mem::transmute(wt) };
            // SAFETY: `t` <= 14, and `w` is [u64; 16], so there is room to write
            // 2 x u64 starting at `w[t]`.
            unsafe { vst1q_u64(w.as_mut_ptr().add(t).cast(), swap(wt)) };

            // SAFETY: `t` <= 14, and `K` is [u64; 80], so there is room to read
            // 2 x u64 starting at `K[t]`.
            let k = unsafe { vld1q_u64(K.as_ptr().add(t)) };

            // Part 1 of hash update, for two rounds
            let hash0 = vsha512hq_u64(
                vaddq_u64(vaddq_u64(gh, swap(k)), wt),
                vextq_u64(ef, gh, 1), // [f, g]
                vextq_u64(cd, ef, 1), // [d, e]
            );

            // Part 2 of hash update, for two rounds
            let hash1 = vsha512h2q_u64(hash0, cd, ab);

            // Rotate inputs for next round
            gh = ef;
            ef = vaddq_u64(cd, hash0);
            cd = ab;
            ab = hash1;
        }

        // For W[16..80] we compute the next W value:
        //
        // W[t] = SSIG1(W[t - 2]) + W[t - 7] + SSIG0(W[t - 15]) + W[t - 16];
        //
        // But all W indices are reduced mod 16 into our window.
        for t in (16..80).step_by(2) {
            // 2 rounds of scheduling
            let update0 = vsha512su0q_u64(
                pack(w[(t - 16) % 16], w[(t - 15) % 16]),
                pack(w[(t - 14) % 16], 0),
            );
            let update1 = vsha512su1q_u64(
                update0,
                pack(w[(t - 2) % 16], w[(t - 1) % 16]),
                pack(w[(t - 7) % 16], w[(t - 6) % 16]),
            );
            // SAFETY: `t` is even, so `t % 16` is <= 14. And `w` is [u64; 16],
            // so there is room to write at 2 x u64 starting at `w[t % 16]`.
            unsafe { vst1q_u64(w.as_mut_ptr().add(t % 16), update1) };

            // SAFETY: `t` <= 78, and `K` is [u64; 80], so there is room to read
            // 2 x u64 starting at `K[t]`.
            let k = unsafe { vld1q_u64(K.as_ptr().add(t)) };

            // Part 1 of hash update, for two rounds
            let hash0 = vsha512hq_u64(
                vaddq_u64(vaddq_u64(gh, swap(update1)), swap(k)),
                vextq_u64(ef, gh, 1), // [f, g]
                vextq_u64(cd, ef, 1), // [d, e]
            );

            // Part 2 of hash update, for two rounds
            let hash1 = vsha512h2q_u64(hash0, cd, ab);

            // Rotate inputs for next round
            gh = ef;
            ef = vaddq_u64(cd, hash0);
            cd = ab;
            ab = hash1;
        }

        state[0] = state[0].wrapping_add(vgetq_lane_u64(ab, 0));
        state[1] = state[1].wrapping_add(vgetq_lane_u64(ab, 1));
        state[2] = state[2].wrapping_add(vgetq_lane_u64(cd, 0));
        state[3] = state[3].wrapping_add(vgetq_lane_u64(cd, 1));
        state[4] = state[4].wrapping_add(vgetq_lane_u64(ef, 0));
        state[5] = state[5].wrapping_add(vgetq_lane_u64(ef, 1));
        state[6] = state[6].wrapping_add(vgetq_lane_u64(gh, 0));
        state[7] = state[7].wrapping_add(vgetq_lane_u64(gh, 1));
    }
}
