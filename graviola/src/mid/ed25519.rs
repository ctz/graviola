// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

/// Encode edwards25519 point into compressed form as 256-bit number
///
/// This assumes that the input buffer p points to a pair of 256-bit
/// numbers x (at p[0..4]) and y (at p[4..8]) representing a point (x,y)
/// on the edwards25519 curve. It is assumed that both x and y are < p_25519
/// but there is no checking of this, nor of the fact that (x,y) is in
/// fact on the curve.
///
/// The output is a little-endian array of bytes corresponding to the
/// standard compressed encoding of a point as 2^255 * x_0 + y where
/// x_0 is the least significant bit of x.
/// See "https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.2"
/// In this implementation, y is simply truncated to 255 bits, but if
/// it is reduced mod p_25519 as expected this does not affect values.
fn edwards25519_encode(out: &mut [u8; 32], p: &[u64; 8]) {
    // Do this in Rust to avoid the pessimistic endian handling in the
    // aarch64 s2n-bignum `edwards25519_encode` impl.
    //
    // godbolt: <https://godbolt.org/z/nKMWfe1hj>

    // Load lowest word of x coordinate
    let xb = p[0];
    // Load y coordinate as [y0, y1, y2, y3]
    let y0 = p[4];
    let y1 = p[5];
    let y2 = p[6];
    let y3 = p[7];

    // Compute the encoded form, making the LSB of x the MSB of the encoding
    let y3 = (y3 & 0x7fffffffffffffff) | (xb << 63);

    out[0..8].copy_from_slice(&y0.to_le_bytes());
    out[8..16].copy_from_slice(&y1.to_le_bytes());
    out[16..24].copy_from_slice(&y2.to_le_bytes());
    out[24..32].copy_from_slice(&y3.to_le_bytes());
}
