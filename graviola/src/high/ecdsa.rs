// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use super::curve::{Curve, PrivateKey, PublicKey, Scalar, MAX_SCALAR_LEN};
use super::hash::{Hash, HashContext};
use super::hmac_drbg::HmacDrbg;
use crate::mid::rng::{RandomSource, SystemRandom};
use crate::Error;

pub struct SigningKey<C: Curve> {
    pub private_key: C::PrivateKey,
}

impl<C: Curve> SigningKey<C> {
    /// ECDSA signing, returning a fixed-length signature.
    ///
    /// The `message` is hashed using `H`.  The message is a sequence of byte
    /// slices, so some workloads can avoid joining it into one buffer beforehand.
    ///
    /// `signature` is the output buffer; `Error::WrongLength` is returned
    /// if it is not long enough.  The used prefix of this buffer is returned
    /// on success.
    pub fn sign<H: Hash>(&self, message: &[&[u8]], signature: &mut [u8]) -> Result<(), Error> {
        let mut random = [0u8; 16];
        SystemRandom.fill(&mut random)?;
        self.rfc6979_sign_with_random::<H>(message, &random, signature)
    }

    /// This is RFC6979 deterministic ECDSA signing, _with added randomness_.
    ///
    /// What? Why?
    ///
    /// Deterministic ECDSA is good for implementation quality (we can test
    /// and validate the selection of `k` is good, and that is absolutely crucial),
    /// but theoretically behaves worse under fault attacks.
    ///
    /// The added randomness is non-critical, assuming the design of HMAC_DRBG
    /// is OK.
    ///
    /// RFC6979 allows for this: see section 3.6:
    /// <https://datatracker.ietf.org/doc/html/rfc6979#section-3.6>.  And HMAC_DRBG
    /// also allows for it, it is the `personalization_string` input.
    fn rfc6979_sign_with_random<H: Hash>(
        &self,
        message: &[&[u8]],
        random: &[u8],
        signature: &mut [u8],
    ) -> Result<(), Error> {
        let output = signature
            .get_mut(..C::Scalar::LEN_BYTES * 2)
            .ok_or(Error::WrongLength)?;

        let mut ctx = H::new();
        for m in message {
            ctx.update(m);
        }
        let hash = ctx.finish();

        let mut encoded_private_key = [0u8; MAX_SCALAR_LEN];
        let encoded_private_key = self.private_key.encode(&mut encoded_private_key)?;

        let e = hash_to_scalar::<C>(hash.as_ref())?;
        let mut e_bytes = [0u8; MAX_SCALAR_LEN];
        e.write_bytes(&mut e_bytes[..C::Scalar::LEN_BYTES]);
        let mut rng = HmacDrbg::<H>::new(
            encoded_private_key,
            &e_bytes[..C::Scalar::LEN_BYTES],
            random,
        );

        let (k, r) = loop {
            let k = C::generate_random_key(&mut rng)?;
            let x = k.public_key().x_scalar();
            if !x.is_zero() {
                break (k, x);
            }
        };
        let s = self.private_key.raw_ecdsa_sign(&k, &e, &r);

        r.write_bytes(&mut output[..C::Scalar::LEN_BYTES]);
        s.write_bytes(&mut output[C::Scalar::LEN_BYTES..]);
        Ok(())
    }
}

pub struct VerifyingKey<C: Curve> {
    pub public_key: C::PublicKey,
}

impl<C: Curve> VerifyingKey<C> {
    /// Create a `VerifyingKey` by decoding an X9.62 uncompressed point.
    pub fn from_x962_uncompressed(encoded: &[u8]) -> Result<Self, Error> {
        C::PublicKey::from_x962_uncompressed(encoded).map(|public_key| Self { public_key })
    }

    /// Verify an ECDSA fixed-length signature.
    ///
    /// The `message` is hashed with `H`.  The message is presented as a sequence of byte
    /// slices (effectively concatenated by this function).
    ///
    /// `signature` is the purported signature.
    ///
    /// Returns nothing when the signature is valid, or `Error::BadSignature` if not.
    pub fn verify<H: Hash>(&self, message: &[&[u8]], signature: &[u8]) -> Result<(), Error> {
        if signature.len() != C::Scalar::LEN_BYTES * 2 {
            return Err(Error::WrongLength);
        }

        // 1. If r and s are not both integers in the interval [1, n − 1], output “invalid” and stop.
        let r = C::Scalar::from_bytes_checked(&signature[..C::Scalar::LEN_BYTES])
            .map_err(|_| Error::BadSignature)?;
        let s = C::Scalar::from_bytes_checked(&signature[C::Scalar::LEN_BYTES..])
            .map_err(|_| Error::BadSignature)?;

        // 2. Use the hash function established during the setup procedure to compute the hash value:
        let mut ctx = H::new();
        for m in message {
            ctx.update(m);
        }
        let hash = ctx.finish();

        // 3. Derive an integer e from H as follows: (...)
        let e = hash_to_scalar::<C>(hash.as_ref())?;

        // 4. - 8. in `raw_ecdsa_verify`
        self.public_key.raw_ecdsa_verify(&r, &s, &e)
    }
}

fn hash_to_scalar<C: Curve>(hash: &[u8]) -> Result<C::Scalar, Error> {
    // TODO: drop this into C::Scalar for cases where a right shift
    // is required.
    let hash = if hash.len() > C::Scalar::LEN_BYTES {
        &hash[..C::Scalar::LEN_BYTES]
    } else {
        hash
    };
    Ok(C::Scalar::from_bytes_reduced(hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::high::curve::Curve;
    use crate::high::{curve, hash};
    use crate::mid::rng::SliceRandomSource;
    use crate::SystemRandom;

    #[test]
    fn smoke_test_ecdsa_sign() {
        let k = curve::P256::generate_random_key(&mut SystemRandom).unwrap();
        println!("public key {:?}", k.public_key().as_bytes_uncompressed());
        let k = SigningKey::<curve::P256> { private_key: k };
        let mut signature = [0u8; 64];
        k.sign::<hash::Sha256>(&[b"hello"], &mut signature).unwrap();
        println!("sig {:?}", signature);
    }

    #[test]
    fn rfc6979_test_vectors() {
        // from A.2.5.
        let mut rng = SliceRandomSource(b"\xC9\xAF\xA9\xD8\x45\xBA\x75\x16\x6B\x5C\x21\x57\x67\xB1\xD6\x93\x4E\x50\xC3\xDB\x36\xE8\x9B\x12\x7B\x8A\x62\x2B\x12\x0F\x67\x21");
        let private_key = curve::P256::generate_random_key(&mut rng).unwrap();
        let k = SigningKey::<curve::P256> { private_key };
        let mut signature = [0u8; 64];

        k.rfc6979_sign_with_random::<hash::Sha256>(&[b"sample"], &[], &mut signature)
            .unwrap();
        assert_eq!(
            signature,
            [
                0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd, 0x9c, 0xd4, 0x5e,
                0x81, 0xd6, 0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91, 0xc3, 0x4d, 0x0e, 0xa8,
                0x4e, 0xaf, 0x37, 0x16, 0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41, 0xd4, 0x36,
                0xc7, 0xa1, 0xb6, 0xe2, 0x9f, 0x65, 0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf, 0xf4, 0x06,
                0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8,
            ]
        );

        k.rfc6979_sign_with_random::<hash::Sha256>(&[b"test"], &[], &mut signature)
            .unwrap();
        assert_eq!(
            signature,
            [
                0xf1, 0xab, 0xb0, 0x23, 0x51, 0x83, 0x51, 0xcd, 0x71, 0xd8, 0x81, 0x56, 0x7b, 0x1e,
                0xa6, 0x63, 0xed, 0x3e, 0xfc, 0xf6, 0xc5, 0x13, 0x2b, 0x35, 0x4f, 0x28, 0xd3, 0xb0,
                0xb7, 0xd3, 0x83, 0x67, 0x01, 0x9f, 0x41, 0x13, 0x74, 0x2a, 0x2b, 0x14, 0xbd, 0x25,
                0x92, 0x6b, 0x49, 0xc6, 0x49, 0x15, 0x5f, 0x26, 0x7e, 0x60, 0xd3, 0x81, 0x4b, 0x4c,
                0x0c, 0xc8, 0x42, 0x50, 0xe4, 0x6f, 0x00, 0x83,
            ]
        );

        k.rfc6979_sign_with_random::<hash::Sha512>(&[b"sample"], &[], &mut signature)
            .unwrap();
        assert_eq!(
            signature,
            [
                0x84, 0x96, 0xa6, 0x0b, 0x5e, 0x9b, 0x47, 0xc8, 0x25, 0x48, 0x88, 0x27, 0xe0, 0x49,
                0x5b, 0x0e, 0x3f, 0xa1, 0x09, 0xec, 0x45, 0x68, 0xfd, 0x3f, 0x8d, 0x10, 0x97, 0x67,
                0x8e, 0xb9, 0x7f, 0x00, 0x23, 0x62, 0xab, 0x1a, 0xdb, 0xe2, 0xb8, 0xad, 0xf9, 0xcb,
                0x9e, 0xda, 0xb7, 0x40, 0xea, 0x60, 0x49, 0xc0, 0x28, 0x11, 0x4f, 0x24, 0x60, 0xf9,
                0x65, 0x54, 0xf6, 0x1f, 0xae, 0x33, 0x02, 0xfe,
            ]
        );

        k.rfc6979_sign_with_random::<hash::Sha512>(&[b"test"], &[], &mut signature)
            .unwrap();
        assert_eq!(
            signature,
            [
                0x46, 0x1d, 0x93, 0xf3, 0x1b, 0x65, 0x40, 0x89, 0x47, 0x88, 0xfd, 0x20, 0x6c, 0x07,
                0xcf, 0xa0, 0xcc, 0x35, 0xf4, 0x6f, 0xa3, 0xc9, 0x18, 0x16, 0xff, 0xf1, 0x04, 0x0a,
                0xd1, 0x58, 0x1a, 0x04, 0x39, 0xaf, 0x9f, 0x15, 0xde, 0x0d, 0xb8, 0xd9, 0x7e, 0x72,
                0x71, 0x9c, 0x74, 0x82, 0x0d, 0x30, 0x4c, 0xe5, 0x22, 0x6e, 0x32, 0xde, 0xda, 0xe6,
                0x75, 0x19, 0xe8, 0x40, 0xd1, 0x19, 0x4e, 0x55,
            ]
        );
    }
}
