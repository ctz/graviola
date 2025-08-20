// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::arch::x86_64::*;

pub(crate) fn bignum_copy_row_from_table_8n_avx2(
    z: &mut [u64],
    table: &[u64],
    _height: u64,
    width: u64,
    index: u64,
) {
    debug_assert!(z.len() as u64 == width);
    debug_assert!(width % 8 == 0);
    debug_assert!(table.len() as u64 == _height * width);

    // SAFETY: this crate requires the `avx` and `avx2` cpu features
    unsafe { _bignum_copy_row_from_table_8n_avx2(z, table, width, index) }
}

#[target_feature(enable = "avx,avx2")]
fn _bignum_copy_row_from_table_8n_avx2(z: &mut [u64], table: &[u64], width: u64, index: u64) {
    super::cpu::prefetch(table, 16);

    z.fill(0);

    let desired_index = _mm_set1_epi64x(index as i64);
    let desired_index = _mm256_setr_m128i(desired_index, desired_index);

    let index = _mm_set1_epi64x(0);
    let mut index = _mm256_setr_m128i(index, index);

    let ones = _mm_set1_epi64x(1);
    let ones = _mm256_setr_m128i(ones, ones);

    for row in table.chunks_exact(width as usize) {
        let mask = _mm256_cmpeq_epi64(index, desired_index);
        index = _mm256_add_epi64(index, ones);

        for (row, zz) in row.chunks_exact(8).zip(z.chunks_exact_mut(8)) {
            let (row0, row1) = super::cpu::load_8x_u64_slice(row);

            let row0 = _mm256_and_si256(row0, mask);
            let row1 = _mm256_and_si256(row1, mask);

            let (store0, store1) = super::cpu::load_8x_u64_slice(zz);
            let store0 = _mm256_xor_si256(store0, row0);
            let store1 = _mm256_xor_si256(store1, row1);
            super::cpu::store_8x_u64_slice(zz, store0, store1);
        }
    }
}
