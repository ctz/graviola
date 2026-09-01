// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::arch::aarch64::{
    uint64x2_t, vaddq_u64, vextq_u64, vgetq_lane_u64, vld1q_u64, vld1q_u64_x4, vst1q_u64,
};
use core::mem;

use crate::low::aarch64::cpu::HaveSha512;

pub(crate) fn sha512_compress_blocks(state: &mut [u64; 8], blocks: &[u8], _token: HaveSha512) {
    debug_assert!(blocks.len().is_multiple_of(128));
    // SAFETY: `_token` proves caller checked cpu features for `sha3`;
    // `neon` required by crate.
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

static K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

// Wrappers for the ARM SHA512 instructions, which don't have intrinsics until Rust 1.79.
// FIXME: Replace with the core::arch::aarch64 versions once Graviola MSRV >= 1.79.

// The SHA512H(x, y, w) instruction computes:
//   Vtmp[1] = BSIG1(y[1])
//             + CH(y[1], x[0], x[1])
//             + w[1]
//   tmp = Vtmp[1] + y[0]
//   Vtmp[0] = BSIG1(tmp)
//             + CH(tmp, y[1], x[0])
//             + w[0]
//   return Vtmp in w
//
// This wrapper function returns a new value rather than overwriting `w`.
//
// https://support.arm.com/documentation/ddi0602/2024-06/SIMD-FP-Instructions/SHA512H--SHA512-hash-update-part-1-
#[target_feature(enable = "neon,sha3")]
fn vsha512hq_u64(w: uint64x2_t, x: uint64x2_t, y: uint64x2_t) -> uint64x2_t {
    let mut ret = w;
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(
            "sha512h {w:v}, {x:v}, {y:v}.2d",
            w = inout(vreg) ret,
            x = in(vreg) x,
            y = in(vreg) y
        );
    }
    ret
}

// The SHA512H2(x, y, w) instruction computes:
//   Vtmp[1] = BSIG0(y[0])
//             + MAJ(x[0], y[1], y[0])
//             + w[1]
//   Vtmp[0] = BSIG0(Vtmp[1])
//             + MAJ(Vtmp[1], y[0], y[1])
//             + w[0]
//   return Vtmp in w
//
// This wrapper function returns a new value rather than overwriting `w`.
//
// https://support.arm.com/documentation/ddi0602/2024-06/SIMD-FP-Instructions/SHA512H2--SHA512-hash-update-part-2-
#[target_feature(enable = "neon,sha3")]
fn vsha512h2q_u64(w: uint64x2_t, x: uint64x2_t, y: uint64x2_t) -> uint64x2_t {
    let mut ret = w;
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(
            "sha512h2 {w:v}, {x:v}, {y:v}.2d",
            w = inout(vreg) ret,
            x = in(vreg) x,
            y = in(vreg) y
        );
    }
    ret
}

// The SHA512SU0(x, w) instruction computes:
//   Vtmp[0] = SSIG0(w[1])
//             + w[0]
//   Vtmp[1] = SSIG0(x[0])
//             + w[1]
//   return Vtmp in w
//
// This wrapper function returns a new value rather than overwriting `w`.
//
// https://support.arm.com/documentation/111108/2026-06/SIMD-FP-Instructions/SHA512SU0--SHA-512-schedule-update-0-
#[target_feature(enable = "neon,sha3")]
fn vsha512su0q_u64(w: uint64x2_t, x: uint64x2_t) -> uint64x2_t {
    let mut ret = w;
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(
            "sha512su0 {w:v}.2d, {x:v}.2d",
            w = inout(vreg) ret,
            x = in(vreg) x
        );
    }
    ret
}

// The SHA512SU1(x, y, w) instruction computes:
//   Vtmp[1] = SSIG1(x[1])
//             + y[1]
//             + w[1]
//   Vtmp[0] = SSIG1(x[0])
//             + y[0]
//             + w[0]
//   return Vtmp in w
//
// This wrapper function returns a new value rather than overwriting `w`.
//
// https://support.arm.com/documentation/111108/2026-06/SIMD-FP-Instructions/SHA512SU1--SHA-512-schedule-update-1-
#[target_feature(enable = "neon,sha3")]
fn vsha512su1q_u64(w: uint64x2_t, x: uint64x2_t, y: uint64x2_t) -> uint64x2_t {
    let mut ret = w;
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(
            "sha512su1 {w:v}.2d, {x:v}.2d, {y:v}.2d",
            w = inout(vreg) ret,
            x = in(vreg) x,
            y = in(vreg) y
        );
    }
    ret
}
