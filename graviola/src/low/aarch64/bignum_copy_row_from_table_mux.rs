// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

/// Multiplex between NEON specialisations of `bignum_copy_row_from_table`
#[inline]
pub(crate) fn bignum_copy_row_from_table(
    z: &mut [u64],
    table: &[u64],
    height: u64,
    width: u64,
    index: u64,
) {
    match width {
        32 => super::bignum_copy_row_from_table_32_neon::bignum_copy_row_from_table_32_neon(
            z, table, height, index,
        ),
        16 => super::bignum_copy_row_from_table_16_neon::bignum_copy_row_from_table_16_neon(
            z, table, height, index,
        ),
        width if width % 8 == 0 => {
            super::bignum_copy_row_from_table_8n_neon::bignum_copy_row_from_table_8n_neon(
                z, table, height, width, index,
            )
        }
        width => super::bignum_copy_row_from_table::bignum_copy_row_from_table(
            z, table, height, width, index,
        ),
    }
}
