// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::arch::aarch64::*;
use core::mem;

/// Viewing table as rows of 8 words width, copy the 8 words at
/// table[idx - 1] into z.  If `idx` is zero or larger than `height`,
/// `z` is set to zero (ie, the affine point at infinity).
///
/// This is useful to select an affine p256 point from a table of
/// precomputed points.
pub(crate) fn bignum_aff_point_select_p256(z: &mut [u64; 8], table: &[u64], index: u8) {
    // SAFETY: crate requires `neon` cpu feature
    unsafe { _select_aff_p256(z, table, index) }
}

/// Viewing table as rows of 12 words width, copy the 12 words at
/// table[idx - 1] into z.  If `idx` is zero or larger than `height`,
/// `z` is set to zero (ie, a jacobian point at infinity).
pub(crate) fn bignum_jac_point_select_p256(z: &mut [u64; 12], table: &[u64], index: u8) {
    // SAFETY: crate requires `neon` cpu feature
    unsafe { _select_jac_p256(z, table, index) }
}

#[target_feature(enable = "neon")]
unsafe fn _select_aff_p256(z: &mut [u64; 8], table: &[u64], index: u8) {
    // SAFETY: intrinsics. see [crate::low::inline_assembly_safety#safety-of-intrinsics] for safety info.
    unsafe {
        // SAFETY: u128 and uint32x4_t have same size and meaning
        let mut acc0: uint32x4_t = mem::transmute(0u128);
        let mut acc1 = acc0;
        let mut acc2 = acc0;
        let mut acc3 = acc0;

        let desired_index = vdupq_n_u32(index as u32);
        let mut index = vdupq_n_u32(1);
        let ones = index;

        for point in table.chunks_exact(8) {
            let row0 = vld1q_u32(point.as_ptr().add(0).cast());
            let row1 = vld1q_u32(point.as_ptr().add(2).cast());
            let row2 = vld1q_u32(point.as_ptr().add(4).cast());
            let row3 = vld1q_u32(point.as_ptr().add(6).cast());

            let mask = vceqq_u32(index, desired_index);
            index = vaddq_u32(index, ones);

            let row0 = vandq_u32(row0, mask);
            let row1 = vandq_u32(row1, mask);
            let row2 = vandq_u32(row2, mask);
            let row3 = vandq_u32(row3, mask);

            acc0 = veorq_u32(acc0, row0);
            acc1 = veorq_u32(acc1, row1);
            acc2 = veorq_u32(acc2, row2);
            acc3 = veorq_u32(acc3, row3);
        }

        vst1q_u32(z.as_mut_ptr().add(0).cast(), acc0);
        vst1q_u32(z.as_mut_ptr().add(2).cast(), acc1);
        vst1q_u32(z.as_mut_ptr().add(4).cast(), acc2);
        vst1q_u32(z.as_mut_ptr().add(6).cast(), acc3);
    }
}

#[target_feature(enable = "neon")]
unsafe fn _select_jac_p256(z: &mut [u64; 12], table: &[u64], index: u8) {
    // SAFETY: intrinsics. see [crate::low::inline_assembly_safety#safety-of-intrinsics] for safety info.
    unsafe {
        let mut acc0: uint32x4_t = mem::transmute(0u128);
        let mut acc1 = acc0;
        let mut acc2 = acc0;
        let mut acc3 = acc0;
        let mut acc4 = acc0;
        let mut acc5 = acc0;

        let desired_index = vdupq_n_u32(index as u32);
        let mut index = vdupq_n_u32(1);
        let ones = index;

        for point in table.chunks_exact(12) {
            let row0 = vld1q_u32(point.as_ptr().add(0).cast());
            let row1 = vld1q_u32(point.as_ptr().add(2).cast());
            let row2 = vld1q_u32(point.as_ptr().add(4).cast());
            let row3 = vld1q_u32(point.as_ptr().add(6).cast());
            let row4 = vld1q_u32(point.as_ptr().add(8).cast());
            let row5 = vld1q_u32(point.as_ptr().add(10).cast());

            let mask = vceqq_u32(index, desired_index);
            index = vaddq_u32(index, ones);

            let row0 = vandq_u32(row0, mask);
            let row1 = vandq_u32(row1, mask);
            let row2 = vandq_u32(row2, mask);
            let row3 = vandq_u32(row3, mask);
            let row4 = vandq_u32(row4, mask);
            let row5 = vandq_u32(row5, mask);

            acc0 = veorq_u32(acc0, row0);
            acc1 = veorq_u32(acc1, row1);
            acc2 = veorq_u32(acc2, row2);
            acc3 = veorq_u32(acc3, row3);
            acc4 = veorq_u32(acc4, row4);
            acc5 = veorq_u32(acc5, row5);
        }

        vst1q_u32(z.as_mut_ptr().add(0).cast(), acc0);
        vst1q_u32(z.as_mut_ptr().add(2).cast(), acc1);
        vst1q_u32(z.as_mut_ptr().add(4).cast(), acc2);
        vst1q_u32(z.as_mut_ptr().add(6).cast(), acc3);
        vst1q_u32(z.as_mut_ptr().add(8).cast(), acc4);
        vst1q_u32(z.as_mut_ptr().add(10).cast(), acc5);
    }
}
