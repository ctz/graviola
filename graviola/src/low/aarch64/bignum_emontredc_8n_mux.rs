// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use super::bignum_emontredc_8n::bignum_emontredc_8n as bignum_emontredc_8n_plain;
use super::bignum_emontredc_8n_cdiff::bignum_emontredc_8n_cdiff;

/// Extended Montgomery reduce in 8-digit blocks, results in input-output buffer.
///
/// Inputs z[2*k], m[k], w; outputs function return (extra result bit) and z[2*k].
///
/// For the RSA sizes (k = 16 and k = 32) this uses `bignum_emontredc_8n_cdiff`,
/// which caches the multiplied differences of `m` in a stack buffer of
/// 12 * (k / 4 - 1) words. Other sizes use `bignum_emontredc_8n`.
pub(crate) fn bignum_emontredc_8n(z: &mut [u64], m: &[u64], w: u64) -> u64 {
    match m.len() {
        16 => bignum_emontredc_8n_cdiff(z, m, w, &mut [0u64; 12 * (16 / 4 - 1)]),
        32 => bignum_emontredc_8n_cdiff(z, m, w, &mut [0u64; 12 * (32 / 4 - 1)]),
        _ => bignum_emontredc_8n_plain(z, m, w),
    }
}
