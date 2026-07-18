// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
// Originally from cifra

use core::arch::aarch64::{
    uint8x16_t, uint32x4_t, vaddq_u32, veorq_u32, vextq_u32, vorrq_u32, vreinterpretq_u16_u32,
    vreinterpretq_u32_u16, vrev32q_u16, vshlq_n_u32, vshrq_n_u32,
};
use core::mem;

pub(crate) struct ChaCha20 {
    key0: [u32; 4],
    key1: [u32; 4],
    nonce: [u32; 4],
}

fn four(b: &[u8; 16]) -> [u32; 4] {
    [
        u32::from_le_bytes(b[0..4].try_into().unwrap()),
        u32::from_le_bytes(b[4..8].try_into().unwrap()),
        u32::from_le_bytes(b[8..12].try_into().unwrap()),
        u32::from_le_bytes(b[12..16].try_into().unwrap()),
    ]
}

impl ChaCha20 {
    pub(crate) fn new(key: &[u8; 32], nonce: &[u8; 16]) -> Self {
        Self {
            key0: four(key[0..16].try_into().unwrap()),
            key1: four(key[16..32].try_into().unwrap()),
            nonce: four(nonce),
        }
    }

    pub(crate) fn cipher(&mut self, buffer: &mut [u8]) {
        let mut by4 = buffer.chunks_exact_mut(256);
        for block_x4 in by4.by_ref() {
            // SAFETY: this crate depends on the `neon` cpu feature.
            unsafe {
                core_x4(
                    &self.key0,
                    &self.key1,
                    &self.nonce,
                    block_x4.try_into().unwrap(),
                )
            };
            self.nonce[0] = self.nonce[0].wrapping_add(4);
        }
        for block in by4.into_remainder().chunks_mut(64) {
            let mut stream = [0u8; 64];
            core(&self.key0, &self.key1, &self.nonce, &mut stream);
            for (out, key) in block.iter_mut().zip(stream.iter()) {
                *out ^= *key;
            }
            self.nonce[0] = self.nonce[0].wrapping_add(1);
        }
    }
}

pub(crate) struct XChaCha20(ChaCha20);

impl XChaCha20 {
    pub(crate) fn new(key: &[u8; 32], nonce: &[u8; 24]) -> Self {
        let hchacha_nonce = four(nonce[..16].try_into().unwrap());
        let mut key0 = four(key[0..16].try_into().unwrap());
        let mut key1 = four(key[16..32].try_into().unwrap());

        hchacha(&mut key0, &mut key1, &hchacha_nonce);

        let mut chacha_nonce = [0u8; 16];
        chacha_nonce[8..16].copy_from_slice(&nonce[16..24]);
        let chacha_nonce = four(&chacha_nonce);

        Self(ChaCha20 {
            key0,
            key1,
            nonce: chacha_nonce,
        })
    }

    pub(crate) fn cipher(&mut self, buffer: &mut [u8]) {
        self.0.cipher(buffer)
    }
}

// Rotate each element of a uint32x4_t left by a specified number of bits.
macro_rules! rotate_left {
    ($reg:expr, 8) => {
        {
            const LEFT_SHIFT_8: uint8x16_t =
                // SAFETY: the memory layout of [u8; 16] is compatible with uint8x16_t.
                unsafe { mem::transmute::<[u8; 16], uint8x16_t>(
                    [3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14]
                ) };

            let mut result: uint32x4_t;
            // SAFETY: this asm block operates only on registers.
            unsafe {
                core::arch::asm!(
                    "tbl {result:v}.16B, {{ {n:v}.16B }}, {map:v}.16B",
                    result = out(vreg) result,
                    n = in(vreg) $reg,
                    map = in(vreg) LEFT_SHIFT_8,
                );
            }
            result
        }
    };
    ($reg:expr, 16) => {
        vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32($reg)))
    };
    ($reg:expr, $rot:literal) => {
        vorrq_u32(vshlq_n_u32($reg, $rot), vshrq_n_u32($reg, 32 - $rot))
    };
}

// Process one ChaCha20 block and store the result in `out`.
fn core(key0: &[u32; 4], key1: &[u32; 4], nonce: &[u32; 4], out: &mut [u8; 64]) {
    let [mut z0, mut z1, mut z2, mut z3] = SIGMA;
    let &[mut z4, mut z5, mut z6, mut z7] = key0;
    let &[mut z8, mut z9, mut za, mut zb] = key1;
    let &[mut zc, mut zd, mut ze, mut zf] = nonce;

    let (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf) = (
        z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, za, zb, zc, zd, ze, zf,
    );

    macro_rules! quarter {
        ($a:ident, $b:ident, $c:ident, $d:ident) => {
            $a = $a.wrapping_add($b);
            $d = ($d ^ $a).rotate_left(16);
            $c = $c.wrapping_add($d);
            $b = ($b ^ $c).rotate_left(12);
            $a = $a.wrapping_add($b);
            $d = ($d ^ $a).rotate_left(8);
            $c = $c.wrapping_add($d);
            $b = ($b ^ $c).rotate_left(7);
        };
    }

    for _ in 0..10 {
        quarter!(z0, z4, z8, zc);
        quarter!(z1, z5, z9, zd);
        quarter!(z2, z6, za, ze);
        quarter!(z3, z7, zb, zf);
        quarter!(z0, z5, za, zf);
        quarter!(z1, z6, zb, zc);
        quarter!(z2, z7, z8, zd);
        quarter!(z3, z4, z9, ze);
    }

    let x0 = x0.wrapping_add(z0);
    let x1 = x1.wrapping_add(z1);
    let x2 = x2.wrapping_add(z2);
    let x3 = x3.wrapping_add(z3);
    let x4 = x4.wrapping_add(z4);
    let x5 = x5.wrapping_add(z5);
    let x6 = x6.wrapping_add(z6);
    let x7 = x7.wrapping_add(z7);
    let x8 = x8.wrapping_add(z8);
    let x9 = x9.wrapping_add(z9);
    let xa = xa.wrapping_add(za);
    let xb = xb.wrapping_add(zb);
    let xc = xc.wrapping_add(zc);
    let xd = xd.wrapping_add(zd);
    let xe = xe.wrapping_add(ze);
    let xf = xf.wrapping_add(zf);

    out[0..4].copy_from_slice(&x0.to_le_bytes());
    out[4..8].copy_from_slice(&x1.to_le_bytes());
    out[8..12].copy_from_slice(&x2.to_le_bytes());
    out[12..16].copy_from_slice(&x3.to_le_bytes());
    out[16..20].copy_from_slice(&x4.to_le_bytes());
    out[20..24].copy_from_slice(&x5.to_le_bytes());
    out[24..28].copy_from_slice(&x6.to_le_bytes());
    out[28..32].copy_from_slice(&x7.to_le_bytes());
    out[32..36].copy_from_slice(&x8.to_le_bytes());
    out[36..40].copy_from_slice(&x9.to_le_bytes());
    out[40..44].copy_from_slice(&xa.to_le_bytes());
    out[44..48].copy_from_slice(&xb.to_le_bytes());
    out[48..52].copy_from_slice(&xc.to_le_bytes());
    out[52..56].copy_from_slice(&xd.to_le_bytes());
    out[56..60].copy_from_slice(&xe.to_le_bytes());
    out[60..64].copy_from_slice(&xf.to_le_bytes());
}

// Process four ChaCha20 blocks in an interleaved manner and exclusive-or
// the result onto the contents of `out`.
#[target_feature(enable = "neon")]
fn core_x4(key0: &[u32; 4], key1: &[u32; 4], nonce: &[u32; 4], out: &mut [u8; 256]) {
    const ONE: uint32x4_t = u32_slice_to_uint32x4_t(&[1, 0, 0, 0]);

    let mut a0: uint32x4_t = u32_slice_to_uint32x4_t(&SIGMA);
    let mut b0: uint32x4_t = u32_slice_to_uint32x4_t(key0);
    let mut c0: uint32x4_t = u32_slice_to_uint32x4_t(key1);
    let mut d0: uint32x4_t = u32_slice_to_uint32x4_t(nonce);
    let mut a1: uint32x4_t = u32_slice_to_uint32x4_t(&SIGMA);
    let mut b1: uint32x4_t = u32_slice_to_uint32x4_t(key0);
    let mut c1: uint32x4_t = u32_slice_to_uint32x4_t(key1);
    let mut d1: uint32x4_t = vaddq_u32(d0, ONE);
    let mut a2: uint32x4_t = u32_slice_to_uint32x4_t(&SIGMA);
    let mut b2: uint32x4_t = u32_slice_to_uint32x4_t(key0);
    let mut c2: uint32x4_t = u32_slice_to_uint32x4_t(key1);
    let mut d2: uint32x4_t = vaddq_u32(d1, ONE);
    let mut a3: uint32x4_t = u32_slice_to_uint32x4_t(&SIGMA);
    let mut b3: uint32x4_t = u32_slice_to_uint32x4_t(key0);
    let mut c3: uint32x4_t = u32_slice_to_uint32x4_t(key1);
    let mut d3: uint32x4_t = vaddq_u32(d2, ONE);

    let a0_initial = a0;
    let b0_initial = b0;
    let c0_initial = c0;
    let d0_initial = d0;
    let a1_initial = a1;
    let b1_initial = b1;
    let c1_initial = c1;
    let d1_initial = d1;
    let a2_initial = a2;
    let b2_initial = b2;
    let c2_initial = c2;
    let d2_initial = d2;
    let a3_initial = a3;
    let b3_initial = b3;
    let c3_initial = c3;
    let d3_initial = d3;

    macro_rules! quarter_x4 {
        ($a0:ident, $b0:ident, $c0:ident, $d0:ident,
         $a1:ident, $b1:ident, $c1:ident, $d1:ident,
         $a2:ident, $b2:ident, $c2:ident, $d2:ident,
         $a3:ident, $b3:ident, $c3:ident, $d3:ident) => {
            $a0 = vaddq_u32($a0, $b0);
            $a1 = vaddq_u32($a1, $b1);
            $a2 = vaddq_u32($a2, $b2);
            $a3 = vaddq_u32($a3, $b3);
            $d0 = rotate_left!(veorq_u32($d0, $a0), 16);
            $d1 = rotate_left!(veorq_u32($d1, $a1), 16);
            $d2 = rotate_left!(veorq_u32($d2, $a2), 16);
            $d3 = rotate_left!(veorq_u32($d3, $a3), 16);
            $c0 = vaddq_u32($c0, $d0);
            $c1 = vaddq_u32($c1, $d1);
            $c2 = vaddq_u32($c2, $d2);
            $c3 = vaddq_u32($c3, $d3);
            $b0 = rotate_left!(veorq_u32($b0, $c0), 12);
            $b1 = rotate_left!(veorq_u32($b1, $c1), 12);
            $b2 = rotate_left!(veorq_u32($b2, $c2), 12);
            $b3 = rotate_left!(veorq_u32($b3, $c3), 12);
            $a0 = vaddq_u32($a0, $b0);
            $a1 = vaddq_u32($a1, $b1);
            $a2 = vaddq_u32($a2, $b2);
            $a3 = vaddq_u32($a3, $b3);
            $d0 = rotate_left!(veorq_u32($d0, $a0), 8);
            $d1 = rotate_left!(veorq_u32($d1, $a1), 8);
            $d2 = rotate_left!(veorq_u32($d2, $a2), 8);
            $d3 = rotate_left!(veorq_u32($d3, $a3), 8);
            $c0 = vaddq_u32($c0, $d0);
            $c1 = vaddq_u32($c1, $d1);
            $c2 = vaddq_u32($c2, $d2);
            $c3 = vaddq_u32($c3, $d3);
            $b0 = rotate_left!(veorq_u32($b0, $c0), 7);
            $b1 = rotate_left!(veorq_u32($b1, $c1), 7);
            $b2 = rotate_left!(veorq_u32($b2, $c2), 7);
            $b3 = rotate_left!(veorq_u32($b3, $c3), 7);
        };
    }

    for _ in 0..10 {
        quarter_x4!(
            a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3
        );
        // For the next quarter-round, we need to rotate the order of
        // the lanes in some of the vectors.
        b0 = vextq_u32(b0, b0, 1);
        c0 = vextq_u32(c0, c0, 2);
        d0 = vextq_u32(d0, d0, 3);
        b1 = vextq_u32(b1, b1, 1);
        c1 = vextq_u32(c1, c1, 2);
        d1 = vextq_u32(d1, d1, 3);
        b2 = vextq_u32(b2, b2, 1);
        c2 = vextq_u32(c2, c2, 2);
        d2 = vextq_u32(d2, d2, 3);
        b3 = vextq_u32(b3, b3, 1);
        c3 = vextq_u32(c3, c3, 2);
        d3 = vextq_u32(d3, d3, 3);
        quarter_x4!(
            a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3
        );
        // Rotate the lanes back into their original arrangement.
        b0 = vextq_u32(b0, b0, 3);
        c0 = vextq_u32(c0, c0, 2);
        d0 = vextq_u32(d0, d0, 1);
        b1 = vextq_u32(b1, b1, 3);
        c1 = vextq_u32(c1, c1, 2);
        d1 = vextq_u32(d1, d1, 1);
        b2 = vextq_u32(b2, b2, 3);
        c2 = vextq_u32(c2, c2, 2);
        d2 = vextq_u32(d2, d2, 1);
        b3 = vextq_u32(b3, b3, 3);
        c3 = vextq_u32(c3, c3, 2);
        d3 = vextq_u32(d3, d3, 1);
    }

    a0 = vaddq_u32(a0_initial, a0);
    b0 = vaddq_u32(b0_initial, b0);
    c0 = vaddq_u32(c0_initial, c0);
    d0 = vaddq_u32(d0_initial, d0);
    a1 = vaddq_u32(a1_initial, a1);
    b1 = vaddq_u32(b1_initial, b1);
    c1 = vaddq_u32(c1_initial, c1);
    d1 = vaddq_u32(d1_initial, d1);
    a2 = vaddq_u32(a2_initial, a2);
    b2 = vaddq_u32(b2_initial, b2);
    c2 = vaddq_u32(c2_initial, c2);
    d2 = vaddq_u32(d2_initial, d2);
    a3 = vaddq_u32(a3_initial, a3);
    b3 = vaddq_u32(b3_initial, b3);
    c3 = vaddq_u32(c3_initial, c3);
    d3 = vaddq_u32(d3_initial, d3);

    fn xor(value: uint32x4_t, dst: &mut [u8; 16]) {
        // SAFETY: the memory layout of `uint32x4_t` is compatible with `u128`.
        let value128: u128 = unsafe { mem::transmute(value) };
        let current = u128::from_le_bytes(*dst);
        let result = value128 ^ current;
        dst.copy_from_slice(&result.to_le_bytes());
    }

    xor(a0, (&mut out[0..16]).try_into().unwrap());
    xor(b0, (&mut out[16..32]).try_into().unwrap());
    xor(c0, (&mut out[32..48]).try_into().unwrap());
    xor(d0, (&mut out[48..64]).try_into().unwrap());
    xor(a1, (&mut out[64..80]).try_into().unwrap());
    xor(b1, (&mut out[80..96]).try_into().unwrap());
    xor(c1, (&mut out[96..112]).try_into().unwrap());
    xor(d1, (&mut out[112..128]).try_into().unwrap());
    xor(a2, (&mut out[128..144]).try_into().unwrap());
    xor(b2, (&mut out[144..160]).try_into().unwrap());
    xor(c2, (&mut out[160..176]).try_into().unwrap());
    xor(d2, (&mut out[176..192]).try_into().unwrap());
    xor(a3, (&mut out[192..208]).try_into().unwrap());
    xor(b3, (&mut out[208..224]).try_into().unwrap());
    xor(c3, (&mut out[224..240]).try_into().unwrap());
    xor(d3, (&mut out[240..256]).try_into().unwrap());
}

fn hchacha(key0: &mut [u32; 4], key1: &mut [u32; 4], nonce: &[u32; 4]) {
    let [mut z0, mut z1, mut z2, mut z3] = SIGMA;
    let &mut [mut z4, mut z5, mut z6, mut z7] = key0;
    let &mut [mut z8, mut z9, mut za, mut zb] = key1;
    let &[mut zc, mut zd, mut ze, mut zf] = nonce;

    macro_rules! quarter {
        ($a:ident, $b:ident, $c:ident, $d:ident) => {
            $a = $a.wrapping_add($b);
            $d = ($d ^ $a).rotate_left(16);
            $c = $c.wrapping_add($d);
            $b = ($b ^ $c).rotate_left(12);
            $a = $a.wrapping_add($b);
            $d = ($d ^ $a).rotate_left(8);
            $c = $c.wrapping_add($d);
            $b = ($b ^ $c).rotate_left(7);
        };
    }

    for _ in 0..10 {
        quarter!(z0, z4, z8, zc);
        quarter!(z1, z5, z9, zd);
        quarter!(z2, z6, za, ze);
        quarter!(z3, z7, zb, zf);
        quarter!(z0, z5, za, zf);
        quarter!(z1, z6, zb, zc);
        quarter!(z2, z7, z8, zd);
        quarter!(z3, z4, z9, ze);
    }

    *key0 = [z0, z1, z2, z3];
    *key1 = [zc, zd, ze, zf];
}

const fn u32_slice_to_uint32x4_t(value: &[u32; 4]) -> uint32x4_t {
    // SAFETY: the memory layout of [u32; 4] is compatible with uint32x4_t.
    unsafe { mem::transmute(*value) }
}

// b"expand 32-byte k" in little-endian
const SIGMA: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn test_vectors() {
        // From draft-agl-tls-chacha20poly1305-04 section 7
        let mut c = ChaCha20::new(&[0u8; 32], &[0u8; 16]);
        let mut block = [0u8; 64];
        c.cipher(&mut block);
        assert_eq!(
            block,
            [
                0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
                0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
                0x8b, 0x77, 0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24,
                0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
                0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86
            ]
        );

        let mut key = [0u8; 32];
        key[31] = 0x01;
        let mut c = ChaCha20::new(&key, &[0u8; 16]);
        let mut block = [0u8; 64];
        c.cipher(&mut block);
        assert_eq!(
            block,
            [
                0x45, 0x40, 0xf0, 0x5a, 0x9f, 0x1f, 0xb2, 0x96, 0xd7, 0x73, 0x6e, 0x7b, 0x20, 0x8e,
                0x3c, 0x96, 0xeb, 0x4f, 0xe1, 0x83, 0x46, 0x88, 0xd2, 0x60, 0x4f, 0x45, 0x09, 0x52,
                0xed, 0x43, 0x2d, 0x41, 0xbb, 0xe2, 0xa0, 0xb6, 0xea, 0x75, 0x66, 0xd2, 0xa5, 0xd1,
                0xe7, 0xe2, 0x0d, 0x42, 0xaf, 0x2c, 0x53, 0xd7, 0x92, 0xb1, 0xc4, 0x3f, 0xea, 0x81,
                0x7e, 0x9a, 0xd2, 0x75, 0xae, 0x54, 0x69, 0x63
            ]
        );

        let mut nonce = [0u8; 16];
        nonce[15] = 0x01;
        let mut c = ChaCha20::new(&[0u8; 32], &nonce);
        let mut block = [0u8; 64];
        c.cipher(&mut block);
        assert_eq!(
            block[..60],
            [
                0xde, 0x9c, 0xba, 0x7b, 0xf3, 0xd6, 0x9e, 0xf5, 0xe7, 0x86, 0xdc, 0x63, 0x97, 0x3f,
                0x65, 0x3a, 0x0b, 0x49, 0xe0, 0x15, 0xad, 0xbf, 0xf7, 0x13, 0x4f, 0xcb, 0x7d, 0xf1,
                0x37, 0x82, 0x10, 0x31, 0xe8, 0x5a, 0x05, 0x02, 0x78, 0xa7, 0x08, 0x45, 0x27, 0x21,
                0x4f, 0x73, 0xef, 0xc7, 0xfa, 0x5b, 0x52, 0x77, 0x06, 0x2e, 0xb7, 0xa0, 0x43, 0x3e,
                0x44, 0x5f, 0x41, 0xe3
            ]
        );

        let mut nonce = [0u8; 16];
        nonce[8] = 0x01;
        let mut c = ChaCha20::new(&[0u8; 32], &nonce);
        let mut block = [0u8; 64];
        c.cipher(&mut block);
        assert_eq!(
            block,
            [
                0xef, 0x3f, 0xdf, 0xd6, 0xc6, 0x15, 0x78, 0xfb, 0xf5, 0xcf, 0x35, 0xbd, 0x3d, 0xd3,
                0x3b, 0x80, 0x09, 0x63, 0x16, 0x34, 0xd2, 0x1e, 0x42, 0xac, 0x33, 0x96, 0x0b, 0xd1,
                0x38, 0xe5, 0x0d, 0x32, 0x11, 0x1e, 0x4c, 0xaf, 0x23, 0x7e, 0xe5, 0x3c, 0xa8, 0xad,
                0x64, 0x26, 0x19, 0x4a, 0x88, 0x54, 0x5d, 0xdc, 0x49, 0x7a, 0x0b, 0x46, 0x6e, 0x7d,
                0x6b, 0xbd, 0xb0, 0x04, 0x1b, 0x2f, 0x58, 0x6b
            ]
        );

        let mut c = ChaCha20::new(
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ],
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                0x06, 0x07,
            ],
        );

        let mut block = [0u8; 256];
        c.cipher(&mut block);

        assert_eq!(
            block,
            [
                0xf7, 0x98, 0xa1, 0x89, 0xf1, 0x95, 0xe6, 0x69, 0x82, 0x10, 0x5f, 0xfb, 0x64, 0x0b,
                0xb7, 0x75, 0x7f, 0x57, 0x9d, 0xa3, 0x16, 0x02, 0xfc, 0x93, 0xec, 0x01, 0xac, 0x56,
                0xf8, 0x5a, 0xc3, 0xc1, 0x34, 0xa4, 0x54, 0x7b, 0x73, 0x3b, 0x46, 0x41, 0x30, 0x42,
                0xc9, 0x44, 0x00, 0x49, 0x17, 0x69, 0x05, 0xd3, 0xbe, 0x59, 0xea, 0x1c, 0x53, 0xf1,
                0x59, 0x16, 0x15, 0x5c, 0x2b, 0xe8, 0x24, 0x1a, 0x38, 0x00, 0x8b, 0x9a, 0x26, 0xbc,
                0x35, 0x94, 0x1e, 0x24, 0x44, 0x17, 0x7c, 0x8a, 0xde, 0x66, 0x89, 0xde, 0x95, 0x26,
                0x49, 0x86, 0xd9, 0x58, 0x89, 0xfb, 0x60, 0xe8, 0x46, 0x29, 0xc9, 0xbd, 0x9a, 0x5a,
                0xcb, 0x1c, 0xc1, 0x18, 0xbe, 0x56, 0x3e, 0xb9, 0xb3, 0xa4, 0xa4, 0x72, 0xf8, 0x2e,
                0x09, 0xa7, 0xe7, 0x78, 0x49, 0x2b, 0x56, 0x2e, 0xf7, 0x13, 0x0e, 0x88, 0xdf, 0xe0,
                0x31, 0xc7, 0x9d, 0xb9, 0xd4, 0xf7, 0xc7, 0xa8, 0x99, 0x15, 0x1b, 0x9a, 0x47, 0x50,
                0x32, 0xb6, 0x3f, 0xc3, 0x85, 0x24, 0x5f, 0xe0, 0x54, 0xe3, 0xdd, 0x5a, 0x97, 0xa5,
                0xf5, 0x76, 0xfe, 0x06, 0x40, 0x25, 0xd3, 0xce, 0x04, 0x2c, 0x56, 0x6a, 0xb2, 0xc5,
                0x07, 0xb1, 0x38, 0xdb, 0x85, 0x3e, 0x3d, 0x69, 0x59, 0x66, 0x09, 0x96, 0x54, 0x6c,
                0xc9, 0xc4, 0xa6, 0xea, 0xfd, 0xc7, 0x77, 0xc0, 0x40, 0xd7, 0x0e, 0xaf, 0x46, 0xf7,
                0x6d, 0xad, 0x39, 0x79, 0xe5, 0xc5, 0x36, 0x0c, 0x33, 0x17, 0x16, 0x6a, 0x1c, 0x89,
                0x4c, 0x94, 0xa3, 0x71, 0x87, 0x6a, 0x94, 0xdf, 0x76, 0x28, 0xfe, 0x4e, 0xaa, 0xf2,
                0xcc, 0xb2, 0x7d, 0x5a, 0xaa, 0xe0, 0xad, 0x7a, 0xd0, 0xf9, 0xd4, 0xb6, 0xad, 0x3b,
                0x54, 0x09, 0x87, 0x46, 0xd4, 0x52, 0x4d, 0x38, 0x40, 0x7a, 0x6d, 0xeb, 0x3a, 0xb7,
                0x8f, 0xab, 0x78, 0xc9
            ]
        );
    }

    #[test]
    fn hchacha_test_vectors() {
        // From draft-irtf-cfrg-xchacha-03

        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41,
            0x59, 0x27, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        ];

        let c = XChaCha20::new(&key, &nonce);
        assert_eq!(
            c.0.key0,
            [0x423b4182, 0xfe7bb227, 0x50420ed3, 0x737d878a],
            "{:x?}",
            c.0.key0
        );
        assert_eq!(
            c.0.key1,
            [0xd5e4f9a0, 0x53a8748a, 0x13c42ec1, 0xdcecd326],
            "{:x?}",
            c.0.key1
        );
        assert_eq!(
            c.0.nonce,
            [0, 0, 0x98badcfe, 0x10325476],
            "{:x?}",
            c.0.nonce
        );
    }

    #[test]
    fn xchacha_test_vectors() {
        // From draft-irtf-cfrg-xchacha-03, A.2
        // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#appendix-A.2

        let key = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce = *b"@ABCDEFGHIJKLMNOPQRSTUVX";
        let mut c = XChaCha20::new(&key, &nonce);

        let mut buffer = [
            0x54, 0x68, 0x65, 0x20, 0x64, 0x68, 0x6f, 0x6c, 0x65, 0x20, 0x28, 0x70, 0x72, 0x6f,
            0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x64, 0x20, 0x22, 0x64, 0x6f, 0x6c, 0x65, 0x22,
            0x29, 0x20, 0x69, 0x73, 0x20, 0x61, 0x6c, 0x73, 0x6f, 0x20, 0x6b, 0x6e, 0x6f, 0x77,
            0x6e, 0x20, 0x61, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x41, 0x73, 0x69, 0x61, 0x74,
            0x69, 0x63, 0x20, 0x77, 0x69, 0x6c, 0x64, 0x20, 0x64, 0x6f, 0x67, 0x2c, 0x20, 0x72,
            0x65, 0x64, 0x20, 0x64, 0x6f, 0x67, 0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x77, 0x68,
            0x69, 0x73, 0x74, 0x6c, 0x69, 0x6e, 0x67, 0x20, 0x64, 0x6f, 0x67, 0x2e, 0x20, 0x49,
            0x74, 0x20, 0x69, 0x73, 0x20, 0x61, 0x62, 0x6f, 0x75, 0x74, 0x20, 0x74, 0x68, 0x65,
            0x20, 0x73, 0x69, 0x7a, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x61, 0x20, 0x47, 0x65, 0x72,
            0x6d, 0x61, 0x6e, 0x20, 0x73, 0x68, 0x65, 0x70, 0x68, 0x65, 0x72, 0x64, 0x20, 0x62,
            0x75, 0x74, 0x20, 0x6c, 0x6f, 0x6f, 0x6b, 0x73, 0x20, 0x6d, 0x6f, 0x72, 0x65, 0x20,
            0x6c, 0x69, 0x6b, 0x65, 0x20, 0x61, 0x20, 0x6c, 0x6f, 0x6e, 0x67, 0x2d, 0x6c, 0x65,
            0x67, 0x67, 0x65, 0x64, 0x20, 0x66, 0x6f, 0x78, 0x2e, 0x20, 0x54, 0x68, 0x69, 0x73,
            0x20, 0x68, 0x69, 0x67, 0x68, 0x6c, 0x79, 0x20, 0x65, 0x6c, 0x75, 0x73, 0x69, 0x76,
            0x65, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x73, 0x6b, 0x69, 0x6c, 0x6c, 0x65, 0x64, 0x20,
            0x6a, 0x75, 0x6d, 0x70, 0x65, 0x72, 0x20, 0x69, 0x73, 0x20, 0x63, 0x6c, 0x61, 0x73,
            0x73, 0x69, 0x66, 0x69, 0x65, 0x64, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x77, 0x6f,
            0x6c, 0x76, 0x65, 0x73, 0x2c, 0x20, 0x63, 0x6f, 0x79, 0x6f, 0x74, 0x65, 0x73, 0x2c,
            0x20, 0x6a, 0x61, 0x63, 0x6b, 0x61, 0x6c, 0x73, 0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20,
            0x66, 0x6f, 0x78, 0x65, 0x73, 0x20, 0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x74,
            0x61, 0x78, 0x6f, 0x6e, 0x6f, 0x6d, 0x69, 0x63, 0x20, 0x66, 0x61, 0x6d, 0x69, 0x6c,
            0x79, 0x20, 0x43, 0x61, 0x6e, 0x69, 0x64, 0x61, 0x65, 0x2e,
        ];
        c.cipher(&mut buffer);

        let expected = [
            0x45, 0x59, 0xab, 0xba, 0x4e, 0x48, 0xc1, 0x61, 0x02, 0xe8, 0xbb, 0x2c, 0x05, 0xe6,
            0x94, 0x7f, 0x50, 0xa7, 0x86, 0xde, 0x16, 0x2f, 0x9b, 0x0b, 0x7e, 0x59, 0x2a, 0x9b,
            0x53, 0xd0, 0xd4, 0xe9, 0x8d, 0x8d, 0x64, 0x10, 0xd5, 0x40, 0xa1, 0xa6, 0x37, 0x5b,
            0x26, 0xd8, 0x0d, 0xac, 0xe4, 0xfa, 0xb5, 0x23, 0x84, 0xc7, 0x31, 0xac, 0xbf, 0x16,
            0xa5, 0x92, 0x3c, 0x0c, 0x48, 0xd3, 0x57, 0x5d, 0x4d, 0x0d, 0x2c, 0x67, 0x3b, 0x66,
            0x6f, 0xaa, 0x73, 0x10, 0x61, 0x27, 0x77, 0x01, 0x09, 0x3a, 0x6b, 0xf7, 0xa1, 0x58,
            0xa8, 0x86, 0x42, 0x92, 0xa4, 0x1c, 0x48, 0xe3, 0xa9, 0xb4, 0xc0, 0xda, 0xec, 0xe0,
            0xf8, 0xd9, 0x8d, 0x0d, 0x7e, 0x05, 0xb3, 0x7a, 0x30, 0x7b, 0xbb, 0x66, 0x33, 0x31,
            0x64, 0xec, 0x9e, 0x1b, 0x24, 0xea, 0x0d, 0x6c, 0x3f, 0xfd, 0xdc, 0xec, 0x4f, 0x68,
            0xe7, 0x44, 0x30, 0x56, 0x19, 0x3a, 0x03, 0xc8, 0x10, 0xe1, 0x13, 0x44, 0xca, 0x06,
            0xd8, 0xed, 0x8a, 0x2b, 0xfb, 0x1e, 0x8d, 0x48, 0xcf, 0xa6, 0xbc, 0x0e, 0xb4, 0xe2,
            0x46, 0x4b, 0x74, 0x81, 0x42, 0x40, 0x7c, 0x9f, 0x43, 0x1a, 0xee, 0x76, 0x99, 0x60,
            0xe1, 0x5b, 0xa8, 0xb9, 0x68, 0x90, 0x46, 0x6e, 0xf2, 0x45, 0x75, 0x99, 0x85, 0x23,
            0x85, 0xc6, 0x61, 0xf7, 0x52, 0xce, 0x20, 0xf9, 0xda, 0x0c, 0x09, 0xab, 0x6b, 0x19,
            0xdf, 0x74, 0xe7, 0x6a, 0x95, 0x96, 0x74, 0x46, 0xf8, 0xd0, 0xfd, 0x41, 0x5e, 0x7b,
            0xee, 0x2a, 0x12, 0xa1, 0x14, 0xc2, 0x0e, 0xb5, 0x29, 0x2a, 0xe7, 0xa3, 0x49, 0xae,
            0x57, 0x78, 0x20, 0xd5, 0x52, 0x0a, 0x1f, 0x3f, 0xb6, 0x2a, 0x17, 0xce, 0x6a, 0x7e,
            0x68, 0xfa, 0x7c, 0x79, 0x11, 0x1d, 0x88, 0x60, 0x92, 0x0b, 0xc0, 0x48, 0xef, 0x43,
            0xfe, 0x84, 0x48, 0x6c, 0xcb, 0x87, 0xc2, 0x5f, 0x0a, 0xe0, 0x45, 0xf0, 0xcc, 0xe1,
            0xe7, 0x98, 0x9a, 0x9a, 0xa2, 0x20, 0xa2, 0x8b, 0xdd, 0x48, 0x27, 0xe7, 0x51, 0xa2,
            0x4a, 0x6d, 0x5c, 0x62, 0xd7, 0x90, 0xa6, 0x63, 0x93, 0xb9, 0x31, 0x11, 0xc1, 0xa5,
            0x5d, 0xd7, 0x42, 0x1a, 0x10, 0x18, 0x49, 0x74, 0xc7, 0xc5,
        ];

        assert_eq!(buffer, expected);
    }
}
