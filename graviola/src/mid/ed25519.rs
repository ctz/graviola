// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

#![allow(dead_code)] // TODO(phlip9): remove

use crate::error::Error;
use crate::low;
use crate::mid::sha2::Sha512Context;
use crate::mid::util;

/// Partially evaluated `dom2(phflag=1, _)`
const DOM_PREFIX_PH: &[u8] = b"SigEd25519 no Ed25519 collisions\x01";
/// Partially evaluted `dom2(phflag=0, _)`
const DOM_PREFIX_CTX: &[u8] = b"SigEd25519 no Ed25519 collisions\x00";

struct SigningKey {
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
        // `az := ed25519-clamp(h[0..32])`
        // `prefix := h[32..64]`
        let mut h = {
            let mut ctx = Sha512Context::new();
            ctx.update(seed);
            ctx.finish()
        };
        let prefix: [u8; 32] = *h.split_last_chunk::<32>().unwrap().1;
        let az = h.split_first_chunk_mut::<32>().unwrap().0;
        az[0] &= 248; // 0b1111_1000
        az[31] &= 127; // 0b0111_1111
        az[31] |= 64; // 0b0100_0000

        // Step: rfc8032 5.1.5.3, 5.1.5.4
        // Compute `[hashed_seed]B` and compress to get the public key bytes
        let s = UnreducedScalar(util::little_endian_to_u64x4(&az));
        let vk_bytes = VerifyingKey::from_unreduced_scalar(&s).into_bytes();

        Self {
            seed: *seed,
            s,
            vk_bytes,
            prefix,
        }
    }

    /// `PureEd25519` signing
    pub(crate) fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let _entry = low::Entry::new_secret();
        // TODO(phlip9): do we need to re-mark these as secrets?
        low::ct::secret_slice(&self.seed);
        low::ct::secret_slice(&self.s.0);
        low::ct::secret_slice(&self.prefix);

        low::ct::into_public(self.sign_with_dom(b"", 0, b"", msg))
    }

    /// `Ed25519ph` signing
    pub(crate) fn sign_ph(&self, ph_msg: &[u8; 64], ctx: &[u8]) -> Result<[u8; 64], Error> {
        let _entry = low::Entry::new_secret();
        // TODO(phlip9): do we need to re-mark these as secrets?
        low::ct::secret_slice(&self.seed);
        low::ct::secret_slice(&self.s.0);
        low::ct::secret_slice(&self.prefix);

        let ctx_len = u8::try_from(ctx.len()).map_err(|_| Error::OutOfRange)?;
        let sig = self.sign_with_dom(DOM_PREFIX_PH, ctx_len, ctx, ph_msg);
        Ok(low::ct::into_public(sig))
    }

    /// `Ed25519ctx` signing
    /// NOTE: not FIPS 186-5 compliant
    pub(crate) fn sign_ctx(&self, msg: &[u8], ctx: &[u8]) -> Result<[u8; 64], Error> {
        let _entry = low::Entry::new_secret();
        // TODO(phlip9): do we need to re-mark these as secrets?
        low::ct::secret_slice(&self.seed);
        low::ct::secret_slice(&self.s.0);
        low::ct::secret_slice(&self.prefix);

        // rfc8032 5.1, for Ed25519ctx, the context SHOULD NOT be empty.
        let ctx_len = match ctx.len() {
            1..=255 => ctx.len() as u8,
            _ => return Err(Error::OutOfRange),
        };
        let sig = self.sign_with_dom(DOM_PREFIX_CTX, ctx_len, ctx, msg);
        Ok(low::ct::into_public(sig))
    }

    #[allow(non_snake_case)]
    fn sign_with_dom(&self, dom_prefix: &[u8], ctx_len: u8, ctx: &[u8], msg: &[u8]) -> [u8; 64] {
        // Step: rfc8032 5.1.6.2
        // Compute `r := SHA-512(dom2(F, C) || prefix || PH(msg))`
        // Reduce `r` modulo the order of the base-point.
        let r = {
            let mh = ed25519_sha512(dom_prefix, ctx_len, ctx, &self.prefix, msg, &[]);
            Scalar::reduce_from_u8x64_le_bytes(&mh)
        };

        // Step: rfc8032 5.1.6.3
        // Compute `R := [r]B`.
        let R = r.mulbase();

        // `sig := (R || S)`
        // Start by writing `R` into the first 32 bytes of `sig`.
        let mut sig = [0u8; 64];
        let sig_R = sig.split_first_chunk_mut::<32>().unwrap().0;
        R.compress_into(sig_R);

        // Step: rfc8032 5.1.6.4
        // Compute `k := SHA512(dom2(F, C) || R || A || PH(msg))`
        let k = {
            let kh = ed25519_sha512(dom_prefix, ctx_len, ctx, sig_R, &self.vk_bytes, msg);
            Scalar::reduce_from_u8x64_le_bytes(&kh)
        };

        // Step: rfc8032 5.1.6.5
        // Compute `S := (r * s + k) mod L`
        let S = Scalar::madd_n25519(&r.0, &self.s.0, &k.0);
        let S_bytes = S.to_le_bytes();
        let sig_S = sig.split_last_chunk_mut::<32>().unwrap().1;
        *sig_S = S_bytes;

        sig
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        low::zeroise(&mut self.seed);
        low::zeroise(&mut self.s.0);
        low::zeroise(&mut self.prefix);
    }
}

struct VerifyingKey(CompressedEdwardsY);

impl VerifyingKey {
    #[allow(non_snake_case)]
    fn verify_with_dom(
        &self,
        dom_prefix: &[u8],
        ctx_len: u8,
        ctx: &[u8],
        sig: &[u8; 64],
        msg: &[u8],
    ) -> Result<(), Error> {
        // TODO(phlip9): complete impl

        // Step: rfc8032 5.1.7.1
        let A = EdwardsPoint::decompress_from(&self.0.0)?;
        let (R_sig, _) = sig.split_first_chunk::<32>().unwrap();
        let (_, S) = sig.split_last_chunk::<32>().unwrap();

        // rfc8032 5.1.6.6 "the three most significant bits of the final octet
        // are always zero"
        if S[31] & 224 /* 0b1110_0000 */ != 0 {
            return Err(Error::BadSignature);
        }

        // S must be in the range [0, order) in order to prevent signature
        // malleability.
        let S = Scalar::try_from_le_bytes(S)?;

        // Step: rfc8032 5.1.7.2
        // Compute `k := SHA512(dom2(F, C) || R || A || PH(msg))`
        let k = {
            let kh = ed25519_sha512(dom_prefix, ctx_len, ctx, R_sig, &self.0.0, msg);
            Scalar::reduce_from_u8x64_le_bytes(&kh)
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
        self.0.0
    }

    fn from_unreduced_scalar(scalar: &UnreducedScalar) -> Self {
        let point = scalar.mulbase().compress();
        Self(CompressedEdwardsY(low::ct::into_public(point.0)))
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
    fn negate(mut self) -> Self {
        let (x, _) = self.0.split_first_chunk_mut::<4>().unwrap();
        let mut neg_x = [0u64; 4];
        low::bignum_neg_p25519(&mut neg_x, x);
        *x = neg_x;
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

/// An unreduced 256-bit scalar.
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
}

/// A 256-bit scalar reduced modulo the order of the base-point,
/// `L = 2^252 + 27742317777372353535851937790883648493`.
// #[repr(transparent)]
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

    fn try_from_le_bytes(x: &[u8; 32]) -> Result<Self, Error> {
        let s = util::little_endian_to_u64x4(x);
        const ORDER: [u64; 4] = [
            0x5812631a5cf5d3ed,
            0x14def9dea2f79cd6,
            0x0000000000000000,
            0x1000000000000000,
        ];
        for (_s_i, _o_i) in s.iter().zip(ORDER.iter()).rev() {
            // TODO(phlip9): impl
        }
        Ok(Self(s))
        // for (size_t i = 3;; i--) {
        //   uint64_t word = CRYPTO_load_u64_le(S + i * 8);
        //   if (word > kOrder[i]) {
        //     return 0;
        //   } else if (word < kOrder[i]) {
        //     break;
        //   } else if (i == 0) {
        //     return 0;
        //   }
        // }
    }

    /// Reduce a `[u64; 8]` scalar modulo the order of the base-point
    fn reduce_from_u8x64_le_bytes(x: &[u8; 64]) -> Self {
        let mut s = Self([0u64; 4]);
        low::bignum_mod_n25519(&mut s.0, &util::little_endian_to_u64x8(&x));
        s
    }

    fn to_le_bytes(&self) -> [u8; 32] {
        util::u64x4_to_little_endian(&self.0)
    }

    /// Scalar multiply this scalar by the base-point: `[self]B`
    fn mulbase(&self) -> EdwardsPoint {
        // self.as_unreduced().mulbase()
        let mut point = EdwardsPoint([0u64; 8]);
        low::edwards25519_scalarmulbase(&mut point.0, &self.0);
        point
    }

    /// Compute `z := (x * y + c) mod L`, the order of the base-point
    fn madd_n25519(x: &[u64; 4], y: &[u64; 4], c: &[u64; 4]) -> Self {
        let mut z = Self([0u64; 4]);
        low::bignum_madd_n25519(&mut z.0, x, y, c);
        z
    }
}

/// This is `H(..) := SHA-512(dom2(phflag, ctx) || ..)` from rfc8032 5.1.
fn ed25519_sha512(
    dom_prefix: &[u8],
    ctx_len: u8,
    ctx: &[u8],
    x1: &[u8],
    x2: &[u8],
    x3: &[u8],
) -> [u8; 64] {
    debug_assert_eq!(ctx_len as usize, ctx.len());
    let mut mh = Sha512Context::new();
    if !dom_prefix.is_empty() {
        mh.update(dom_prefix);
        mh.update(&[ctx_len]);
        mh.update(ctx);
    }
    mh.update(x1);
    mh.update(x2);
    mh.update(x3);
    mh.finish()
}
