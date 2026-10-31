// Written for Graviola by Joe Birr-Pixton, 2026.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::low::generic::sha3::Shake256x8FallbackFn;

/// This does SHAKE256 for up to eight single-block messages, yielding 128 bytes of output for each.
///
/// See the x86_64 version for details.  This always uses `fallback_fn`.
pub(crate) fn sha3_shake256_8x_one_block<const N: usize>(
    inputs: &[&[u8; 40]; N],
    outputs: &mut [[u8; 128]; N],
    spare_permute: Option<&mut [u64; 25]>,
    fallback_fn: Shake256x8FallbackFn<N>,
) {
    fallback_fn(inputs, outputs, spare_permute)
}
