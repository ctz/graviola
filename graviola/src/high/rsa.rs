// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::high::asn1::{self, pkix, Type};
use crate::high::hash::{self, Hash};
use crate::high::{pkcs1, pkcs8};
use crate::low::Entry;
use crate::low::PosInt;
use crate::mid::rng::SystemRandom;
use crate::mid::{rsa_priv, rsa_pub};
use crate::Error;

/// An RSA verification public key.
///
/// Keys supported by this library have public moduli between
/// 2048- and 8192-bits.
#[derive(Debug)]
pub struct VerifyingKey(rsa_pub::RsaPublicKey);

impl VerifyingKey {
    /// Decodes an RSA public verification key from PKCS#1 DER format.
    ///
    /// This format is defined in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.1)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub fn from_pkcs1_der(bytes: &[u8]) -> Result<Self, Error> {
        let _ = Entry::new_public();
        let decoded = pkix::RSAPublicKey::from_bytes(bytes).map_err(Error::Asn1Error)?;

        if decoded.modulus.is_negative() {
            return Err(Error::OutOfRange);
        }

        let n = PosInt::from_bytes(decoded.modulus.as_ref())?;
        let e = decoded
            .publicExponent
            .as_usize()
            .map_err(Error::Asn1Error)?;
        let e = e.try_into().map_err(|_| Error::OutOfRange)?;

        let pub_key = rsa_pub::RsaPublicKey::new(n, e)?;

        Ok(Self(pub_key))
    }

    /// Verifies `signature`, using RSASSA-PKCS1-v1_5 with SHA-256.
    ///
    /// `message` is the (unhashed) signed message.  It is hashed
    /// using SHA-256 by this function.
    ///
    /// [`Error::BadSignature`] is returned if the signature is invalid.
    pub fn verify_pkcs1_sha256(&self, signature: &[u8], message: &[u8]) -> Result<(), Error> {
        let _ = Entry::new_public();
        let hash = hash::Sha256::hash(message);
        self._verify_pkcs1(signature, pkcs1::DIGESTINFO_SHA256, hash.as_ref())
    }

    /// Verifies `signature`, using RSASSA-PKCS1-v1_5 with SHA-384.
    ///
    /// `message` is the (unhashed) signed message.  It is hashed
    /// using SHA-384 by this function.
    ///
    /// [`Error::BadSignature`] is returned if the signature is invalid.
    pub fn verify_pkcs1_sha384(&self, signature: &[u8], message: &[u8]) -> Result<(), Error> {
        let _ = Entry::new_public();
        let hash = hash::Sha384::hash(message);
        self._verify_pkcs1(signature, pkcs1::DIGESTINFO_SHA384, hash.as_ref())
    }

    /// Verifies `signature`, using RSASSA-PKCS1-v1_5 with SHA-512.
    ///
    /// `message` is the (unhashed) signed message.  It is hashed
    /// using SHA-512 by this function.
    ///
    /// [`Error::BadSignature`] is returned if the signature is invalid.
    pub fn verify_pkcs1_sha512(&self, signature: &[u8], message: &[u8]) -> Result<(), Error> {
        let _ = Entry::new_public();
        let hash = hash::Sha512::hash(message);
        self._verify_pkcs1(signature, pkcs1::DIGESTINFO_SHA512, hash.as_ref())
    }

    fn _verify_pkcs1(
        &self,
        signature: &[u8],
        digest_info: &[u8],
        hash: &[u8],
    ) -> Result<(), Error> {
        let c = PosInt::from_bytes(signature).map_err(|_| Error::BadSignature)?;
        let m = self.0.public_op(c).map_err(|_| Error::BadSignature)?;

        let mut m_bytes = [0u8; rsa_pub::MAX_PUBLIC_MODULUS_BYTES];
        let m_bytes = m.to_bytes(&mut m_bytes)?;

        let mut actual_m = [0u8; rsa_pub::MAX_PUBLIC_MODULUS_BYTES];
        let actual_m = &mut actual_m[..self.0.modulus_len_bytes()];
        pkcs1::encode_pkcs1_sig(actual_m, digest_info, hash);

        match actual_m == m_bytes {
            true => Ok(()),
            false => Err(Error::BadSignature),
        }
    }

    /// Verifies `signature`, using RSASSA-PSS with SHA-256.
    ///
    /// `saltLength` is fixed as 32 bytes; this is the most common
    /// option when used with SHA-256.
    ///
    /// `message` is the (unhashed) signed message.  It is hashed
    /// using SHA-256 by this function.
    ///
    /// [`Error::BadSignature`] is returned if the signature is invalid.
    ///
    /// RSASSA-PSS is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub fn verify_pss_sha256(&self, signature: &[u8], message: &[u8]) -> Result<(), Error> {
        let _ = Entry::new_public();
        self._verify_pss::<hash::Sha256>(signature, message)
    }

    /// Verifies `signature`, using RSASSA-PSS with SHA-384.
    ///
    /// `saltLength` is fixed as 48 bytes; this is the most common
    /// option when used with SHA-384.
    ///
    /// `message` is the (unhashed) signed message.  It is hashed
    /// using SHA-384 by this function.
    ///
    /// [`Error::BadSignature`] is returned if the signature is invalid.
    ///
    /// RSASSA-PSS is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub fn verify_pss_sha384(&self, signature: &[u8], message: &[u8]) -> Result<(), Error> {
        let _ = Entry::new_public();
        self._verify_pss::<hash::Sha384>(signature, message)
    }

    /// Verifies `signature`, using RSASSA-PSS with SHA-512.
    ///
    /// `saltLength` is fixed as 64 bytes; this is the most common
    /// option when used with SHA-512.
    ///
    /// `message` is the (unhashed) signed message.  It is hashed
    /// using SHA-512 by this function.
    ///
    /// [`Error::BadSignature`] is returned if the signature is invalid.
    ///
    /// RSASSA-PSS is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub fn verify_pss_sha512(&self, signature: &[u8], message: &[u8]) -> Result<(), Error> {
        let _ = Entry::new_public();
        self._verify_pss::<hash::Sha512>(signature, message)
    }

    fn _verify_pss<H: Hash>(&self, signature: &[u8], message: &[u8]) -> Result<(), Error> {
        let hash = H::hash(message);

        if signature.len() > self.0.modulus_len_bytes() {
            return Err(Error::BadSignature);
        }
        let c = PosInt::from_bytes(signature).map_err(|_| Error::BadSignature)?;
        let m = self.0.public_op(c).map_err(|_| Error::BadSignature)?;

        let mut m_bytes = [0u8; rsa_pub::MAX_PUBLIC_MODULUS_BYTES];
        let m_bytes_len = m.to_bytes(&mut m_bytes)?.len();

        pkcs1::verify_pss_sig::<H>(&mut m_bytes[..m_bytes_len], hash.as_ref())
    }
}

/// An RSA signing private key.
///
/// Keys supported by this library have public moduli between
/// 2048- and 8192-bits.  Only two-prime RSA keys are supported.
pub struct SigningKey(rsa_priv::RsaPrivateKey);

impl SigningKey {
    /// Decodes an RSA signing key from PKCS#1 DER format.
    ///
    /// This format is defined in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.2)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub fn from_pkcs1_der(bytes: &[u8]) -> Result<Self, Error> {
        let _ = Entry::new_secret();
        let decoded = pkix::RSAPrivateKey::from_bytes(bytes).map_err(Error::Asn1Error)?;

        if !matches!(decoded.version, pkix::Version::two_prime) {
            return Err(Error::OutOfRange);
        }

        if decoded.modulus.is_negative() {
            return Err(Error::OutOfRange);
        }

        let n = PosInt::from_bytes(decoded.modulus.as_ref())?;
        let e = decoded
            .publicExponent
            .as_usize()
            .map_err(Error::Asn1Error)?;
        let e = e.try_into().map_err(|_| Error::OutOfRange)?;

        let p = PosInt::from_bytes(decoded.prime1.as_ref())?.into();
        let q = PosInt::from_bytes(decoded.prime2.as_ref())?.into();
        let d = PosInt::from_bytes(decoded.privateExponent.as_ref())?.into();
        let dp = PosInt::from_bytes(decoded.exponent1.as_ref())?.into();
        let dq = PosInt::from_bytes(decoded.exponent2.as_ref())?.into();
        let iqmp = PosInt::from_bytes(decoded.coefficient.as_ref())?.into();

        let priv_key = rsa_priv::RsaPrivateKey::new(p, q, d, dp, dq, iqmp, n, e)?;
        Ok(Self(priv_key))
    }

    /// Decodes an RSA signing key from PKCS#8 DER format.
    ///
    /// This format is defined in
    /// [RFC5208](https://datatracker.ietf.org/doc/html/rfc5208#section-5)
    /// (and earlier standards, including the original PKCS#8 standard).
    ///
    /// `privateKeyAlgorithm` inside this encoding must be `rsaEncryption`.
    pub fn from_pkcs8_der(bytes: &[u8]) -> Result<Self, Error> {
        let _ = Entry::new_secret();
        pkcs8::decode_pkcs8(
            bytes,
            &asn1::oid::rsaEncryption,
            Some(asn1::Any::Null(asn1::Null)),
        )
        .and_then(Self::from_pkcs1_der)
    }

    /// Returns the matching public key.
    pub fn public_key(&self) -> VerifyingKey {
        let _ = Entry::new_public();
        VerifyingKey(self.0.public_key())
    }

    /// Returns the public modulus length, in bytes.
    pub fn modulus_len_bytes(&self) -> usize {
        let _ = Entry::new_public();
        self.0.public_key().modulus_len_bytes()
    }

    /// Signs `message`, using RSASSA-PKCS1-v1_5 with SHA-256.
    ///
    /// The signature is written to the front of `signature`, is
    /// precisely [`Self::modulus_len_bytes()`] in length, and
    /// then the written-to slice is returned.
    ///
    /// RSASSA-PKCS1-v1_5 is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.2)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub fn sign_pkcs1_sha256<'a>(
        &self,
        signature: &'a mut [u8],
        message: &[u8],
    ) -> Result<&'a [u8], Error> {
        let _ = Entry::new_secret();
        let hash = hash::Sha256::hash(message);
        self._sign_pkcs1(signature, pkcs1::DIGESTINFO_SHA256, hash.as_ref())
    }

    /// Signs `message`, using RSASSA-PKCS1-v1_5 with SHA-384.
    ///
    /// The signature is written to the front of `signature`, is
    /// precisely [`Self::modulus_len_bytes()`] in length, and
    /// then the written-to slice is returned.
    ///
    /// RSASSA-PKCS1-v1_5 is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.2)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub fn sign_pkcs1_sha384<'a>(
        &self,
        signature: &'a mut [u8],
        message: &[u8],
    ) -> Result<&'a [u8], Error> {
        let _ = Entry::new_secret();
        let hash = hash::Sha384::hash(message);
        self._sign_pkcs1(signature, pkcs1::DIGESTINFO_SHA384, hash.as_ref())
    }

    /// Signs `message`, using RSASSA-PKCS1-v1_5 with SHA-512.
    ///
    /// The signature is written to the front of `signature`, is
    /// precisely [`Self::modulus_len_bytes()`] in length, and
    /// then the written-to slice is returned.
    ///
    /// RSASSA-PKCS1-v1_5 is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.2)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub fn sign_pkcs1_sha512<'a>(
        &self,
        signature: &'a mut [u8],
        message: &[u8],
    ) -> Result<&'a [u8], Error> {
        let _ = Entry::new_secret();
        let hash = hash::Sha512::hash(message);
        self._sign_pkcs1(signature, pkcs1::DIGESTINFO_SHA512, hash.as_ref())
    }

    /// Signs `message`, using RSASSA-PSS with SHA-256.
    ///
    /// `saltLength` is fixed as 32 bytes; this is the most common
    /// option when used with SHA-256.
    ///
    /// The signature is written to the front of `signature`, is
    /// precisely [`Self::modulus_len_bytes()`] in length, and
    /// then the written-to slice is returned.
    ///
    /// RSASSA-PSS is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub fn sign_pss_sha256<'a>(
        &self,
        signature: &'a mut [u8],
        message: &[u8],
    ) -> Result<&'a [u8], Error> {
        let _ = Entry::new_secret();
        self._sign_pss::<hash::Sha256>(signature, message)
    }

    /// Signs `message`, using RSASSA-PSS with SHA-384.
    ///
    /// `saltLength` is fixed as 48 bytes; this is the most common
    /// option when used with SHA-384.
    ///
    /// The signature is written to the front of `signature`, is
    /// precisely [`Self::modulus_len_bytes()`] in length, and
    /// then the written-to slice is returned.
    ///
    /// RSASSA-PSS is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub fn sign_pss_sha384<'a>(
        &self,
        signature: &'a mut [u8],
        message: &[u8],
    ) -> Result<&'a [u8], Error> {
        let _ = Entry::new_secret();
        self._sign_pss::<hash::Sha384>(signature, message)
    }

    /// Signs `message`, using RSASSA-PSS with SHA-512.
    ///
    /// `saltLength` is fixed as 64 bytes; this is the most common
    /// option when used with SHA-512.
    ///
    /// The signature is written to the front of `signature`, is
    /// precisely [`Self::modulus_len_bytes()`] in length, and
    /// then the written-to slice is returned.
    ///
    /// RSASSA-PSS is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub fn sign_pss_sha512<'a>(
        &self,
        signature: &'a mut [u8],
        message: &[u8],
    ) -> Result<&'a [u8], Error> {
        let _ = Entry::new_secret();
        self._sign_pss::<hash::Sha512>(signature, message)
    }

    fn _sign_pkcs1<'a>(
        &self,
        signature: &'a mut [u8],
        digest_info: &[u8],
        hash: &[u8],
    ) -> Result<&'a [u8], Error> {
        if signature.len() < self.0.modulus_len_bytes() {
            return Err(Error::OutOfRange);
        }

        let mut m = [0u8; rsa_pub::MAX_PUBLIC_MODULUS_BYTES];
        let m = &mut m[..self.0.modulus_len_bytes()];
        pkcs1::encode_pkcs1_sig(m, digest_info, hash);

        let m = PosInt::from_bytes(m)?;
        let c = self.0.private_op(&m).map_err(|_| Error::BadSignature)?;
        c.to_bytes(signature)
    }

    fn _sign_pss<'a, H: Hash>(
        &self,
        signature: &'a mut [u8],
        message: &[u8],
    ) -> Result<&'a [u8], Error> {
        if signature.len() < self.0.modulus_len_bytes() {
            return Err(Error::OutOfRange);
        }

        let hash = H::hash(message);

        let mut m = [0u8; rsa_pub::MAX_PUBLIC_MODULUS_BYTES];
        let m = &mut m[..self.0.modulus_len_bytes()];

        pkcs1::encode_pss_sig::<H>(m, &mut SystemRandom, hash.as_ref())?;
        let m = PosInt::from_bytes(m)?;
        let c = self.0.private_op(&m).map_err(|_| Error::BadSignature)?;
        c.to_bytes(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_all_algs(buf: &mut [u8], private: &SigningKey, public: &VerifyingKey) {
        let sig = private.sign_pkcs1_sha256(buf, b"hello").unwrap();
        public.verify_pkcs1_sha256(sig, b"hello").unwrap();

        let sig = private.sign_pkcs1_sha384(buf, b"hello").unwrap();
        public.verify_pkcs1_sha384(sig, b"hello").unwrap();

        let sig = private.sign_pkcs1_sha512(buf, b"hello").unwrap();
        public.verify_pkcs1_sha512(sig, b"hello").unwrap();

        let sig = private.sign_pss_sha256(buf, b"hello").unwrap();
        public.verify_pss_sha256(sig, b"hello").unwrap();

        let sig = private.sign_pss_sha384(buf, b"hello").unwrap();
        public.verify_pss_sha384(sig, b"hello").unwrap();

        let sig = private.sign_pss_sha512(buf, b"hello").unwrap();
        public.verify_pss_sha512(sig, b"hello").unwrap();
    }

    #[test]
    fn pairwise_rsa2048_sign_verify() {
        let private_key = SigningKey::from_pkcs1_der(include_bytes!("rsa/rsa2048.der")).unwrap();

        check_all_algs(&mut [0u8; 256], &private_key, &private_key.public_key());
    }

    #[test]
    fn pairwise_rsa2048_sign_verify_pkcs8() {
        let private_key =
            SigningKey::from_pkcs8_der(include_bytes!("rsa/rsa2048.pkcs8.der")).unwrap();

        check_all_algs(&mut [0u8; 256], &private_key, &private_key.public_key());
    }

    #[test]
    fn pairwise_rsa3072_sign_verify() {
        let private_key = SigningKey::from_pkcs1_der(include_bytes!("rsa/rsa3072.der")).unwrap();

        check_all_algs(&mut [0u8; 384], &private_key, &private_key.public_key());
    }

    #[test]
    fn pairwise_rsa4096_sign_verify() {
        let private_key = SigningKey::from_pkcs1_der(include_bytes!("rsa/rsa4096.der")).unwrap();

        check_all_algs(&mut [0u8; 512], &private_key, &private_key.public_key());
    }

    #[test]
    fn pairwise_rsa6144_sign_verify() {
        let private_key = SigningKey::from_pkcs1_der(include_bytes!("rsa/rsa6144.der")).unwrap();

        check_all_algs(&mut [0u8; 768], &private_key, &private_key.public_key());
    }

    #[test]
    fn pairwise_rsa8192_sign_verify() {
        let private_key = SigningKey::from_pkcs1_der(include_bytes!("rsa/rsa8192.der")).unwrap();

        check_all_algs(&mut [0u8; 1024], &private_key, &private_key.public_key());
    }
}
