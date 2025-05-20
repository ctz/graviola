// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

#![allow(dead_code)] // TODO(phlip9): remove

use crate::error::Error;
use crate::low;
use crate::mid::sha2::Sha512Context;
use crate::mid::util;

/// The little-endian encoded order of the base-point `B`,
/// `L := 2^252 + 27742317777372353535851937790883648493`.
const ORDER: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

pub(crate) struct SigningKey {
    seed: [u8; 32],
    s: UnreducedScalar,
    vk_bytes: [u8; 32],
    prefix: [u8; 32],
}

impl SigningKey {
    pub(crate) fn from_seed(seed: &[u8; 32]) -> Self {
        let _entry = low::Entry::new_secret();
        low::ct::secret_slice(seed);

        // Step: rfc8032 5.1.5.1, 5.1.5.2
        // `h := SHA512(seed)`
        // `s := ed25519-clamp(h[0..32])`
        // `prefix := h[32..64]`
        let mut h = {
            let mut ctx = Sha512Context::new();
            ctx.update(seed);
            ctx.finish()
        };
        let (s, prefix) = util::u8x64_split_u8x32x2_mut(&mut h);
        // Mangle the scalar:
        // <https://mailarchive.ietf.org/arch/msg/cfrg/pt2bt3fGQbNF8qdEcorp-rJSJrc/>
        // <https://neilmadden.blog/2020/05/28/whats-the-curve25519-clamping-all-about/>
        s[0] &= 248; // 0b1111_1000
        s[31] &= 127; // 0b0111_1111
        s[31] |= 64; // 0b0100_0000

        // Step: rfc8032 5.1.5.3, 5.1.5.4
        // Compute `[s]B` and compress to get the public key bytes
        let s = UnreducedScalar(util::little_endian_to_u64x4(&s));
        let vk_bytes = VerifyingKey::from_unreduced_scalar(&s).into_bytes();

        Self {
            seed: *seed,
            s,
            vk_bytes,
            prefix: *prefix,
        }
    }

    /// `PureEd25519` signing
    #[allow(non_snake_case)]
    pub(crate) fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let _entry = low::Entry::new_secret();

        // Step: rfc8032 5.1.6.2
        // Compute the deterministic nonce
        // `r := SHA-512(dom2(F, C) || prefix || PH(msg)) mod L`
        let r: Scalar = {
            let r = ed25519_digest(&self.prefix, msg, &[]);
            Scalar::reduce_from_u8x64_le_bytes(&r)
        };

        // Step: rfc8032 5.1.6.3
        // Compute the commitment point `R := [r]B`.
        let R: EdwardsPoint = r.mulbase();

        // `sig := (R || S)`
        // Start by writing `R` into the first 32 bytes of `sig`.
        let mut sig = [0u8; 64];
        let (sig_R, sig_S) = util::u8x64_split_u8x32x2_mut(&mut sig);
        R.compress_into(sig_R);

        // Step: rfc8032 5.1.6.4
        // Compute the challenge `k := SHA512(dom2(F, C) || R || A || PH(msg)) mod L`
        let k: Scalar = {
            let k = ed25519_digest(sig_R, &self.vk_bytes, msg);
            Scalar::reduce_from_u8x64_le_bytes(&k)
        };

        // Step: rfc8032 5.1.6.5
        // Compute the proof `S := (k * s + r) mod L`
        let S: Scalar = Scalar::madd_n25519(&k.0, &self.s.0, &r.0);
        let S_bytes = S.to_le_bytes();
        *sig_S = S_bytes;

        low::ct::into_public(sig)
    }

    // TODO(phlip9): unhack
    fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.vk_bytes)
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        low::zeroise(&mut self.seed);
        low::zeroise(&mut self.s.0);
        low::zeroise(&mut self.prefix);
    }
}

// TODO(phlip9): distinguish between unparsed and expanded verifying key
pub(crate) struct VerifyingKey([u8; 32]);

impl VerifyingKey {
    /// `PureEd25519` signature verification
    #[allow(non_snake_case)]
    pub(crate) fn verify(&self, sig: &[u8; 64], msg: &[u8]) -> Result<(), Error> {
        let _entry = low::Entry::new_public();

        // Step: rfc8032 5.1.7.1
        let A = EdwardsPoint::decompress_from(&self.0)?;
        let (R_sig, S) = util::u8x64_split_u8x32x2_ref(sig);

        // S must be in the range [0, order) to prevent signature malleability.
        let S = Scalar::try_from_le_bytes(S).ok_or(Error::BadSignature)?;

        // Step: rfc8032 5.1.7.2
        // Compute the challenge `k := SHA512(dom2(F, C) || R || A || PH(msg))`
        let k = {
            let k = ed25519_digest(R_sig, &self.0, msg);
            Scalar::reduce_from_u8x64_le_bytes(&k)
        };

        // Step: rfc8032 5.1.7.3
        // Compute `R := [S]B - [k]A`.
        let A_neg = A.negate();
        let R_have = EdwardsPoint::scalarmuldouble(&k, &A_neg, &S).compress();

        if R_sig == &R_have.0 {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }

    fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    fn from_unreduced_scalar(scalar: &UnreducedScalar) -> Self {
        let point = scalar.mulbase().compress();
        Self(low::ct::into_public(point.0))
    }
}

/// In ed25519 format, the curve point (x, y) is determined by the
/// y-coordinate and the sign of x.
///
/// The first 255 bits of a `CompressedEdwardsY` represent the y-coordinate.
/// The high bit of the 32nd byte gives the sign of x.
struct CompressedEdwardsY([u8; 32]);

/// Represents a point (x, y) on the edwards25519 curve. `[0..4]` is the
/// x-coordinate and `[4..8]` is the y-coordinate.
struct EdwardsPoint([u64; 8]);

impl EdwardsPoint {
    /// The base-point `B` of the edwards25519 curve.
    #[cfg(test)]
    const BASE_POINT: Self = EdwardsPoint([
        // X(B)
        0xc9562d608f25d51a,
        0x692cc7609525a7b2,
        0xc0a4e231fdd6dc5c,
        0x216936d3cd6e53fe,
        // Y(B)
        0x6666666666666658,
        0x6666666666666666,
        0x6666666666666666,
        0x6666666666666666,
    ]);

    /// The identity point `O` of the edwards25519 curve.
    #[cfg(test)]
    const IDENTITY: Self = EdwardsPoint([
        // X(O)
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        // Y(O)
        0x0000000000000001,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ]);

    /// Compute `A := [scalar]Point + [bscalar]B`.
    fn scalarmuldouble(scalar: &Scalar, point: &Self, bscalar: &Scalar) -> Self {
        let mut out = Self([0u64; 8]);
        low::edwards25519_scalarmuldouble(&mut out.0, &scalar.0, &point.0, &bscalar.0);
        out
    }

    /// Compute `B := -A` for this curve point.
    ///
    /// Point negation for the twisted edwards curve when points are represented
    /// in the extended coordinate system is simply:
    ///   -(X,Y,Z,T) = (-X,Y,Z,-T).
    /// See "Twisted Edwards curves revisited": <https://ia.cr/2008/522>.
    #[allow(non_snake_case)]
    fn negate(mut self) -> Self {
        let (X, _) = util::u64x8_split_u64x4x2_mut(&mut self.0);
        let mut X_neg = [0u64; 4];
        low::bignum_neg_p25519(&mut X_neg, X);
        *X = X_neg;
        self
    }

    /// Try to decompress a curve point from input bytes.
    /// Returns `Err(Error::NotOnCurve)` if the input is not reduced, not
    /// on the curve, or not canonically encoded.
    fn decompress_from(compressed: &[u8; 32]) -> Result<Self, Error> {
        let mut point = Self([0u64; 8]);
        if low::edwards25519_decode(&mut point.0, compressed) {
            Ok(point)
        } else {
            Err(Error::NotOnCurve)
        }
    }

    /// Encode this edwards25519 point into a [`CompressedEdwardsY`].
    fn compress(&self) -> CompressedEdwardsY {
        let mut out = CompressedEdwardsY([0u8; 32]);
        self.compress_into(&mut out.0);
        out
    }

    /// Encode edwards25519 point into compressed form as a 256-bit number
    ///
    /// The output is a little-endian array of bytes corresponding to the
    /// standard compressed encoding of a point as 2^255 * x_0 + y where
    /// x_0 is the least significant bit of x.
    /// See "https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.2"
    /// In this implementation, y is simply truncated to 255 bits, but if
    /// it is reduced mod p_25519 as expected this does not affect values.
    //
    // Do this in Rust to avoid the pessimistic endian handling in the
    // aarch64 s2n-bignum `edwards25519_encode` impl.
    //
    // godbolt: <https://godbolt.org/z/nKMWfe1hj>
    fn compress_into(&self, out: &mut [u8; 32]) {
        // Load lowest word of x coordinate
        let p = &self.0;
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
}

/// An unreduced 256-bit little-endian scalar.
// #[repr(transparent)]
struct UnreducedScalar([u64; 4]);

impl UnreducedScalar {
    fn from_le_bytes(x: &[u8; 32]) -> Self {
        Self(util::little_endian_to_u64x4(x))
    }

    /// Scalar multiply this scalar by the base-point: `[self]B`. Conveniently
    /// also reduces the scalar before multiplying.
    fn mulbase(&self) -> EdwardsPoint {
        let mut point = EdwardsPoint([0u64; 8]);
        low::edwards25519_scalarmulbase(&mut point.0, &self.0);
        point
    }

    /// Reduce this 256-bit little-endian number modulo [`ORDER`].
    #[cfg(test)]
    fn reduce(&self) -> Scalar {
        let mut s = Scalar([0u64; 4]);
        low::bignum_mod_n25519(&mut s.0, &self.0);
        s
    }
}

/// A little-endian 256-bit scalar reduced modulo [`ORDER`].
// #[repr(transparent)]
#[cfg_attr(test, derive(Debug))]
struct Scalar([u64; 4]);

impl Scalar {
    // TODO(phlip9): do I still need this?
    // /// "Forget" that a scalar is reduced and cast it to an [`UnreducedScalar`].
    // #[allow(unsafe_code)]
    // fn as_unreduced(&self) -> &UnreducedScalar {
    //     use std::mem::{align_of, size_of};
    //     const _: [(); size_of::<Scalar>()] = [(); size_of::<UnreducedScalar>()];
    //     const _: [(); align_of::<Scalar>()] = [(); align_of::<UnreducedScalar>()];
    //     // Safety: both `Scalar` and `UnreducedScalar` are `#[repr(transparent)]`
    //     // with identical size and alignment.
    //     unsafe { &*(self as *const Self as *const UnreducedScalar) }
    // }

    /// Read a 256-bit little-endian number from the public input bytes,
    /// additionally verifying that it's a valid `Scalar` reduced modulo
    /// [`ORDER`].
    // TODO(phlip9): bench against `low::bignum_cmp_lt(&s, &ORDER)`?
    fn try_from_le_bytes(x: &[u8; 32]) -> Option<Self> {
        use std::cmp::Ordering;

        // The first 3 bits of the last byte must be zero.
        if x[31] & 224 /* 0b1110_0000 */ != 0 {
            return None;
        }

        let s = util::little_endian_to_u64x4(x);
        for (s_i, o_i) in s.iter().zip(ORDER.iter()).rev() {
            match s_i.cmp(o_i) {
                Ordering::Less => return Some(Self(s)),
                Ordering::Greater => return None,
                Ordering::Equal => {}
            }
        }
        None
    }

    fn to_le_bytes(&self) -> [u8; 32] {
        util::u64x4_to_little_endian(&self.0)
    }

    /// Reduce a 512-bit little-endian scalar modulo [`ORDER`].
    fn reduce_from_u8x64_le_bytes(x: &[u8; 64]) -> Self {
        let mut s = Self([0u64; 4]);
        low::bignum_mod_n25519(&mut s.0, &util::little_endian_to_u64x8(&x));
        s
    }

    /// Scalar multiply by the base-point: `[self]B`
    fn mulbase(&self) -> EdwardsPoint {
        // self.as_unreduced().mulbase()
        let mut point = EdwardsPoint([0u64; 8]);
        low::edwards25519_scalarmulbase(&mut point.0, &self.0);
        point
    }

    /// Compute `z := (x * y + c)` modulo [`ORDER`].
    fn madd_n25519(x: &[u64; 4], y: &[u64; 4], c: &[u64; 4]) -> Self {
        let mut z = Self([0u64; 4]);
        low::bignum_madd_n25519(&mut z.0, x, y, c);
        z
    }
}

/// This is `H(..) := SHA-512(dom2(phflag, ctx) || ..)` from rfc8032 5.1, with
/// phflag=0 and ctx="".
fn ed25519_digest(x1: &[u8], x2: &[u8], x3: &[u8]) -> [u8; 64] {
    let mut h = Sha512Context::new();
    h.update(x1);
    h.update(x2);
    if x3.len() > 0 {
        h.update(x3);
    }
    h.finish()
}

#[cfg(test)]
mod test {
    use crate::{low::chacha20::ChaCha20, mid};

    use super::*;

    /// `p := 2^255 - 19`
    const P_25519: [u64; 4] = [
        0xffffffffffffffed,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x7fffffffffffffff,
    ];

    #[test]
    fn test_rfc8032_test_vectors() {
        // rfc8032 7.1.1
        let seed = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60";
        let sk = SigningKey::from_seed(&seed);
        let msg = b"";
        let sig = sk.sign(msg);
        assert_eq!(&sk.vk_bytes, b"\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a");
        assert_eq!(&sig, b"\xe5\x56\x43\x00\xc3\x60\xac\x72\x90\x86\xe2\xcc\x80\x6e\x82\x8a\x84\x87\x7f\x1e\xb8\xe5\xd9\x74\xd8\x73\xe0\x65\x22\x49\x01\x55\x5f\xb8\x82\x15\x90\xa3\x3b\xac\xc6\x1e\x39\x70\x1c\xf9\xb4\x6b\xd2\x5b\xf5\xf0\x59\x5b\xbe\x24\x65\x51\x41\x43\x8e\x7a\x10\x0b");
        sk.verifying_key().verify(&sig, msg).unwrap();

        // rfc8032 7.1.2
        let seed = b"\x4c\xcd\x08\x9b\x28\xff\x96\xda\x9d\xb6\xc3\x46\xec\x11\x4e\x0f\x5b\x8a\x31\x9f\x35\xab\xa6\x24\xda\x8c\xf6\xed\x4f\xb8\xa6\xfb";
        let sk = SigningKey::from_seed(&seed);
        let msg = b"\x72";
        let sig = sk.sign(msg);
        assert_eq!(&sk.vk_bytes, b"\x3d\x40\x17\xc3\xe8\x43\x89\x5a\x92\xb7\x0a\xa7\x4d\x1b\x7e\xbc\x9c\x98\x2c\xcf\x2e\xc4\x96\x8c\xc0\xcd\x55\xf1\x2a\xf4\x66\x0c");
        assert_eq!(&sig, b"\x92\xa0\x09\xa9\xf0\xd4\xca\xb8\x72\x0e\x82\x0b\x5f\x64\x25\x40\xa2\xb2\x7b\x54\x16\x50\x3f\x8f\xb3\x76\x22\x23\xeb\xdb\x69\xda\x08\x5a\xc1\xe4\x3e\x15\x99\x6e\x45\x8f\x36\x13\xd0\xf1\x1d\x8c\x38\x7b\x2e\xae\xb4\x30\x2a\xee\xb0\x0d\x29\x16\x12\xbb\x0c\x00");
        sk.verifying_key().verify(&sig, msg).unwrap();
    }

    #[test]
    fn test_scalar_reduction() {
        let zero = [0u64, 0, 0, 0];
        let one = [1u64, 0, 0, 0];

        assert_eq!(zero, UnreducedScalar(zero).reduce().0);
        assert_eq!(one, UnreducedScalar(one).reduce().0);
        assert_eq!(zero, UnreducedScalar(ORDER).reduce().0);

        let order_m1 = [ORDER[0] - 1, ORDER[1], ORDER[2], ORDER[3]];
        let order_p1 = [ORDER[0] + 1, ORDER[1], ORDER[2], ORDER[3]];
        assert_eq!(order_m1, UnreducedScalar(order_m1).reduce().0);
        assert_eq!(one, UnreducedScalar(order_p1).reduce().0);

        #[track_caller]
        fn scalar_ok(x1: &[u64; 4]) {
            let x1_bytes = util::u64x4_to_little_endian(x1);
            let x2 = Scalar::try_from_le_bytes(&x1_bytes).map(|x| x.0);
            assert_eq!(x2, Some(*x1));
        }
        #[track_caller]
        fn scalar_err(x1: &[u64; 4]) {
            let x1_bytes = util::u64x4_to_little_endian(x1);
            let x2 = Scalar::try_from_le_bytes(&x1_bytes).map(|x| x.0);
            assert_eq!(x2, None);
        }

        scalar_ok(&zero);
        scalar_ok(&one);
        scalar_ok(&order_m1);

        scalar_err(&ORDER);
        scalar_err(&order_p1);
        scalar_err(&[ORDER[0] - 1, ORDER[1], ORDER[2], ORDER[3] + 1]);

        let mut rng = TestRng::new(202505191702);
        for _ in 0..100 {
            let x_bytes = rng.next::<32>();
            let x = UnreducedScalar::from_le_bytes(&x_bytes);

            // [u8; 32] reduction
            let x_reduced = x.reduce();
            let x_reduced_bytes = x_reduced.to_le_bytes();
            assert_eq!(
                x_reduced.0,
                Scalar::try_from_le_bytes(&x_reduced_bytes).unwrap().0,
            );
            if x.0 != x_reduced.0 {
                let res = Scalar::try_from_le_bytes(&x_bytes).map(|x| x.0);
                assert_eq!(res, None);
            }

            // [u8; 64] reduction
            let mut x_bytes_64 = [0u8; 64];
            x_bytes_64[0..32].copy_from_slice(&x_bytes);
            assert_eq!(
                Scalar::reduce_from_u8x64_le_bytes(&x_bytes_64).0,
                x_reduced.0,
            );
        }
    }

    #[test]
    fn test_neg_p25519() {
        fn is_reduced_mod_p25519(x: &[u64; 4]) -> bool {
            low::bignum_cmp_lt(x, &P_25519) > 0
        }
        fn neg_p25519(x: &[u64; 4]) -> [u64; 4] {
            let mut z = [0u64; 4];
            low::bignum_neg_p25519(&mut z, x);
            z
        }
        fn neg_p25519_alt(x: &[u64; 4]) -> [u64; 4] {
            let mut z = [0u64; 4];
            low::bignum_modsub(&mut z, &[0; 4], x, &P_25519);
            z
        }

        let zero = [0u64; 4];
        let one = [1u64, 0, 0, 0];
        let p25519_m1 = [P_25519[0] - 1, P_25519[1], P_25519[2], P_25519[3]];

        // -0 := 0 mod p25519
        assert_eq!(neg_p25519(&zero), zero);
        // (-1) := (p25519 - 1) mod p25519
        assert_eq!(neg_p25519(&one), p25519_m1);
        // -(p25519 - 1) := 1 mod p25519
        assert_eq!(neg_p25519(&p25519_m1), one);

        let mut rng = TestRng::new(202505192149);
        for _ in 0..100 {
            let x_bytes = rng.next::<32>();
            let x = util::little_endian_to_u64x4(&x_bytes);
            if is_reduced_mod_p25519(&x) {
                // x := -(-x) mod p25519
                assert_eq!(neg_p25519(&neg_p25519(&x)), x);
                assert_eq!(neg_p25519(&x), neg_p25519_alt(&x));
            }
        }
    }

    #[test]
    fn scalar_madd_n25519() {
        const ZERO: [u64; 4] = [0u64; 4];
        const ONE: [u64; 4] = [1u64, 0, 0, 0];

        fn madd_n25519_alt(x: &[u64; 4], y: &[u64; 4], c: &[u64; 4]) -> [u64; 4] {
            let mut xy = [0u64; 8];
            low::bignum_mul(&mut xy, x, y);
            let mut xy_reduced = [0u64; 4];
            low::bignum_mod_n25519(&mut xy_reduced, &xy);
            let mut c_reduced = [0u64; 4];
            low::bignum_mod_n25519(&mut c_reduced, c);
            let mut z = [0u64; 4];
            low::bignum_modadd(&mut z, &xy_reduced, &c_reduced, &ORDER);
            z
        }

        fn assert_basic_identities(x: &[u64; 4]) {
            // x := (x * 1 + 0) mod p25519
            // x := (1 * x + 0) mod p25519
            assert_eq!(
                Scalar::madd_n25519(x, &ONE, &ZERO).0,
                UnreducedScalar(*x).reduce().0,
            );
            assert_eq!(
                Scalar::madd_n25519(&ONE, x, &ZERO).0,
                UnreducedScalar(*x).reduce().0,
            );

            // 0 := (x * 0 + 0) mod p25519
            // 0 := (0 * x + 0) mod p25519
            assert_eq!(Scalar::madd_n25519(x, &ZERO, &ZERO).0, ZERO);
            assert_eq!(Scalar::madd_n25519(&ZERO, x, &ZERO).0, ZERO);

            // x := (x * 0 + x) mod p25519
            // x := (0 * x + x) mod p25519
            assert_eq!(
                Scalar::madd_n25519(x, &ZERO, x).0,
                UnreducedScalar(*x).reduce().0,
            );
            assert_eq!(
                Scalar::madd_n25519(&ZERO, x, x).0,
                UnreducedScalar(*x).reduce().0,
            );
        }

        assert_eq!(ZERO, Scalar::madd_n25519(&ZERO, &ZERO, &ZERO).0);
        assert_eq!(ONE, Scalar::madd_n25519(&ZERO, &ZERO, &ONE).0);

        assert_basic_identities(&ZERO);
        assert_basic_identities(&ONE);

        let mut rng = TestRng::new(202505192230);
        for _ in 0..100 {
            let x = UnreducedScalar::from_le_bytes(&rng.next::<32>()).0;
            let y = UnreducedScalar::from_le_bytes(&rng.next::<32>()).0;
            let c = UnreducedScalar::from_le_bytes(&rng.next::<32>()).0;

            assert_basic_identities(&x);
            assert_eq!(
                Scalar::madd_n25519(&x, &y, &c).0,
                madd_n25519_alt(&x, &y, &c)
            );
        }
    }

    #[test]
    fn test_scalarmul() {
        const ONE: [u64; 4] = [1u64, 0, 0, 0];

        // O := [0]B
        assert_eq!(EdwardsPoint::IDENTITY.0, Scalar([0; 4]).mulbase().0);
        assert_eq!(
            EdwardsPoint::IDENTITY.0,
            EdwardsPoint::scalarmuldouble(
                &Scalar([0; 4]),
                &EdwardsPoint::BASE_POINT,
                &Scalar([0; 4]),
            )
            .0
        );
        assert_eq!(
            EdwardsPoint::IDENTITY.0,
            EdwardsPoint::scalarmuldouble(
                &Scalar([0x69; 4]),
                &EdwardsPoint::IDENTITY,
                &Scalar([0; 4]),
            )
            .0
        );

        // B := [1]B
        assert_eq!(EdwardsPoint::BASE_POINT.0, Scalar([1, 0, 0, 0]).mulbase().0);

        let mut rng = TestRng::new(202505192246);
        for _ in 0..100 {
            let bscalar = UnreducedScalar::from_le_bytes(&rng.next::<32>()).reduce();

            // [bscalar]B := [bscalar]B + [0]B
            assert_eq!(
                bscalar.mulbase().0,
                EdwardsPoint::scalarmuldouble(
                    &bscalar,
                    &EdwardsPoint::BASE_POINT,
                    &Scalar([0; 4]),
                ).0,
            );

            let scalar = UnreducedScalar::from_le_bytes(&rng.next::<32>()).reduce();
            let sum = Scalar::madd_n25519(&scalar.0, &ONE, &bscalar.0);

            // [scalar + bscalar]B := [scalar]B + [bscalar]B
            assert_eq!(
                sum.mulbase().0,
                EdwardsPoint::scalarmuldouble(&scalar, &EdwardsPoint::BASE_POINT, &bscalar).0,
            );
        }
    }

    #[test]
    fn test_point_compression() {
        assert_eq!(
            EdwardsPoint::IDENTITY.0,
            EdwardsPoint::decompress_from(b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00").unwrap().0,
        );
        assert_eq!(
            EdwardsPoint::BASE_POINT.0,
            EdwardsPoint::decompress_from(b"\x58\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66").unwrap().0,
        );

        let mut rng = TestRng::new(202505192346);
        for _ in 0..100 {
            let scalar = UnreducedScalar::from_le_bytes(&rng.next::<32>()).reduce();
            let point = scalar.mulbase();
            let compressed = point.compress();
            let decompressed = EdwardsPoint::decompress_from(&compressed.0).unwrap();
            assert_eq!(point.0, decompressed.0);
        }
    }

    struct TestRng {
        chacha: ChaCha20,
    }

    impl TestRng {
        fn new(seed: u64) -> Self {
            let seed = sha256_digest(&seed.to_le_bytes());
            let nonce = [0; 16];
            let chacha = ChaCha20::new(&seed, &nonce);
            Self { chacha }
        }

        fn next<const N: usize>(&mut self) -> [u8; N] {
            let mut out = [0u8; N];
            self.chacha.cipher(&mut out);
            out
        }
    }

    fn sha256_digest(x: &[u8]) -> [u8; 32] {
        let mut ctx = mid::sha2::Sha256Context::new();
        ctx.update(x);
        ctx.finish()
    }
}
