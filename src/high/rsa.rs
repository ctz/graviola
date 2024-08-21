use crate::high::asn1::{pkix, Type};
use crate::high::hash::{self, Hash};
use crate::high::pkcs1;
use crate::low::PosInt;
use crate::mid::{rsa_priv, rsa_pub};
use crate::Error;

#[derive(Debug)]
pub struct RsaPublicVerificationKey(rsa_pub::RsaPublicKey);

impl RsaPublicVerificationKey {
    pub fn from_pkcs1_der(bytes: &[u8]) -> Result<Self, Error> {
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

    pub fn verify_pkcs1_sha256(&self, signature: &[u8], message: &[u8]) -> Result<(), Error> {
        let hash = hash::Sha256::hash(message);
        self._verify_pkcs1(signature, pkcs1::DIGESTINFO_SHA256, hash.as_ref())
    }

    pub fn verify_pkcs1_sha384(&self, signature: &[u8], message: &[u8]) -> Result<(), Error> {
        let hash = hash::Sha384::hash(message);
        self._verify_pkcs1(signature, pkcs1::DIGESTINFO_SHA384, hash.as_ref())
    }

    pub fn verify_pkcs1_sha512(&self, signature: &[u8], message: &[u8]) -> Result<(), Error> {
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
        let m = self.0.public_op(&c).map_err(|_| Error::BadSignature)?;

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
}

pub struct RsaPrivateSigningKey(rsa_priv::RsaPrivateKey);

impl RsaPrivateSigningKey {
    pub fn from_pkcs1_der(bytes: &[u8]) -> Result<Self, Error> {
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

        let p = PosInt::from_bytes(decoded.prime1.as_ref())?;
        let q = PosInt::from_bytes(decoded.prime2.as_ref())?;
        let dp = PosInt::from_bytes(decoded.exponent1.as_ref())?;
        let dq = PosInt::from_bytes(decoded.exponent2.as_ref())?;
        let iqmp = PosInt::from_bytes(decoded.coefficient.as_ref())?;

        let priv_key = rsa_priv::RsaPrivateKey::new(p, q, dp, dq, iqmp, n, e)?;
        Ok(Self(priv_key))
    }

    pub fn public_key(&self) -> RsaPublicVerificationKey {
        RsaPublicVerificationKey(self.0.public_key())
    }

    pub fn sign_pkcs1_sha256<'a>(
        &self,
        signature: &'a mut [u8],
        message: &[u8],
    ) -> Result<&'a [u8], Error> {
        let hash = hash::Sha256::hash(message);
        self._sign_pkcs1(signature, pkcs1::DIGESTINFO_SHA256, hash.as_ref())
    }

    pub fn sign_pkcs1_sha384<'a>(
        &self,
        signature: &'a mut [u8],
        message: &[u8],
    ) -> Result<&'a [u8], Error> {
        let hash = hash::Sha384::hash(message);
        self._sign_pkcs1(signature, pkcs1::DIGESTINFO_SHA384, hash.as_ref())
    }

    pub fn sign_pkcs1_sha512<'a>(
        &self,
        signature: &'a mut [u8],
        message: &[u8],
    ) -> Result<&'a [u8], Error> {
        let hash = hash::Sha512::hash(message);
        self._sign_pkcs1(signature, pkcs1::DIGESTINFO_SHA512, hash.as_ref())
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairwise_rsa2048_sign_verify() {
        let mut buf = [0u8; 256];
        let private_key =
            RsaPrivateSigningKey::from_pkcs1_der(include_bytes!("rsa/rsa2048.der")).unwrap();

        let pub_key = private_key.public_key();

        let sig = private_key.sign_pkcs1_sha256(&mut buf, b"hello").unwrap();
        pub_key.verify_pkcs1_sha256(sig, b"hello").unwrap();

        let sig = private_key.sign_pkcs1_sha384(&mut buf, b"hello").unwrap();
        pub_key.verify_pkcs1_sha384(sig, b"hello").unwrap();

        let sig = private_key.sign_pkcs1_sha512(&mut buf, b"hello").unwrap();
        pub_key.verify_pkcs1_sha512(sig, b"hello").unwrap();
    }

    #[test]
    fn pairwise_rsa3072_sign_verify() {
        let mut buf = [0u8; 384];
        let private_key =
            RsaPrivateSigningKey::from_pkcs1_der(include_bytes!("rsa/rsa3072.der")).unwrap();

        let pub_key = private_key.public_key();

        let sig = private_key.sign_pkcs1_sha256(&mut buf, b"hello").unwrap();
        pub_key.verify_pkcs1_sha256(sig, b"hello").unwrap();

        let sig = private_key.sign_pkcs1_sha384(&mut buf, b"hello").unwrap();
        pub_key.verify_pkcs1_sha384(sig, b"hello").unwrap();

        let sig = private_key.sign_pkcs1_sha512(&mut buf, b"hello").unwrap();
        pub_key.verify_pkcs1_sha512(sig, b"hello").unwrap();
    }

    #[test]
    fn pairwise_rsa4096_sign_verify() {
        let mut buf = [0u8; 512];
        let private_key =
            RsaPrivateSigningKey::from_pkcs1_der(include_bytes!("rsa/rsa4096.der")).unwrap();

        let pub_key = private_key.public_key();

        let sig = private_key.sign_pkcs1_sha256(&mut buf, b"hello").unwrap();
        pub_key.verify_pkcs1_sha256(sig, b"hello").unwrap();

        let sig = private_key.sign_pkcs1_sha384(&mut buf, b"hello").unwrap();
        pub_key.verify_pkcs1_sha384(sig, b"hello").unwrap();

        let sig = private_key.sign_pkcs1_sha512(&mut buf, b"hello").unwrap();
        pub_key.verify_pkcs1_sha512(sig, b"hello").unwrap();
    }

    #[test]
    fn pairwise_rsa6144_sign_verify() {
        let mut buf = [0u8; 768];
        let private_key =
            RsaPrivateSigningKey::from_pkcs1_der(include_bytes!("rsa/rsa6144.der")).unwrap();

        let pub_key = private_key.public_key();

        let sig = private_key.sign_pkcs1_sha256(&mut buf, b"hello").unwrap();
        pub_key.verify_pkcs1_sha256(sig, b"hello").unwrap();

        let sig = private_key.sign_pkcs1_sha384(&mut buf, b"hello").unwrap();
        pub_key.verify_pkcs1_sha384(sig, b"hello").unwrap();

        let sig = private_key.sign_pkcs1_sha512(&mut buf, b"hello").unwrap();
        pub_key.verify_pkcs1_sha512(sig, b"hello").unwrap();
    }

    #[test]
    fn pairwise_rsa8192_sign_verify() {
        let mut buf = [0u8; 1024];
        let private_key =
            RsaPrivateSigningKey::from_pkcs1_der(include_bytes!("rsa/rsa8192.der")).unwrap();

        let pub_key = private_key.public_key();

        let sig = private_key.sign_pkcs1_sha256(&mut buf, b"hello").unwrap();
        pub_key.verify_pkcs1_sha256(sig, b"hello").unwrap();

        let sig = private_key.sign_pkcs1_sha384(&mut buf, b"hello").unwrap();
        pub_key.verify_pkcs1_sha384(sig, b"hello").unwrap();

        let sig = private_key.sign_pkcs1_sha512(&mut buf, b"hello").unwrap();
        pub_key.verify_pkcs1_sha512(sig, b"hello").unwrap();
    }
}
