// Written for Graviola by Joe Birr-Pixton, 2025.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::Error;
use crate::error::KeyFormatError;
use crate::high::asn1::{self, Type, pkix};
use crate::high::pkcs8;
use crate::low::Entry;
use crate::low::zeroise;
use crate::mid::ed25519;
use crate::mid::rng::{RandomSource, SystemRandom};

/// An Ed25519 verification public key.
#[derive(Debug)]
pub struct Ed25519VerifyingKey(ed25519::VerifyingKey);

impl Ed25519VerifyingKey {
    /// Decode from `SubjectPublicKeyInfo` DER format.
    pub fn from_spki_der(bytes: &[u8]) -> Result<Self, Error> {
        let _entry = Entry::new_public();
        let decoded = pkix::SubjectPublicKeyInfo::from_bytes(bytes).map_err(Error::Asn1Error)?;

        if decoded.algorithm.algorithm != asn1::oid::id_ed25519 {
            return Err(KeyFormatError::MismatchedSpkiAlgorithm.into());
        }

        Self::from_bytes(decoded.subjectPublicKey.as_octets())
    }

    /// Encode in `SubjectPublicKeyInfo` DER format.
    ///
    /// The encoding is written to the start of `output`, and the used span is
    /// returned.  [`Error::WrongLength`] is returned if `output` is not sufficient
    /// to contain the full encoding.
    pub fn to_spki_der<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let pub_key_buffer = self.as_bytes();

        let spki = pkix::SubjectPublicKeyInfo {
            algorithm: pkix::AlgorithmIdentifier {
                algorithm: asn1::oid::id_ed25519.clone(),
                parameters: None,
            },
            subjectPublicKey: asn1::BitString::new(&pub_key_buffer[..]),
        };

        let len = spki
            .encode(&mut asn1::Encoder::new(output))
            .map_err(Error::Asn1Error)?;
        Ok(&output[..len])
    }

    /// Decode from compressed point encoding, in bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        ed25519::VerifyingKey::from_bytes(bytes).map(Self)
    }

    /// Encode using compressed point encoding.
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.as_bytes()
    }

    /// Verify a `signature` against the given `message`.
    ///
    /// Returns `Error::BadSignature` if the signature is invalid.
    pub fn verify(&self, signature: &[u8], message: &[u8]) -> Result<(), Error> {
        let _entry = Entry::new_public();

        self.0.verify(
            signature.try_into().map_err(|_| Error::BadSignature)?,
            message,
        )
    }
}

/// An Ed25519 signing private key.
pub struct Ed25519SigningKey(ed25519::SigningKey);

impl Ed25519SigningKey {
    /// Generate a new signing key.
    pub fn generate() -> Result<Self, Error> {
        let _entry = Entry::new_secret();
        let mut seed = [0u8; 32];
        SystemRandom.fill(&mut seed)?;
        let r = Ok(Self(ed25519::SigningKey::from_seed(&seed)));
        zeroise(&mut seed);
        r
    }

    /// Load an Ed25519 private key in PKCS#8 format.
    ///
    /// This supports keys in both PKCS#8 v1 and v2 format.
    pub fn from_pkcs8_der(bytes: &[u8]) -> Result<Self, Error> {
        let _entry = Entry::new_secret();

        pkcs8::Key::decode(bytes, &asn1::oid::id_ed25519, None)
            .and_then(|k| asn1::OctetString::from_bytes(k.private_key()).map_err(Error::Asn1Error))
            .and_then(|pk| Self::from_bytes(pk.as_octets()))
    }

    /// Encode this private key in PKCS#8 DER format.
    ///
    /// This produces an RFC5958 PKCS#8 "v2" format.
    ///
    /// The encoding is written to the start of `output`, and the used span is
    /// returned.  [`Error::WrongLength`] is returned if `output` is not sufficient
    /// to contain the full encoding.
    pub fn to_pkcs8_der<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let _entry = Entry::new_secret();

        let mut private_key_buf = [0u8; 34];
        let private_key_len = asn1::OctetString::new(self.0.as_bytes())
            .encode(&mut asn1::Encoder::new(&mut private_key_buf))
            .map_err(Error::Asn1Error)?;
        assert_eq!(private_key_len, private_key_buf.len());

        let public_key = self.public_key().as_bytes();

        pkcs8::Key::construct(
            &private_key_buf[..],
            Some(&public_key[..]),
            asn1::oid::id_ed25519.clone(),
            None,
        )
        .encode(output)
    }

    /// Load an Ed25519 private key from a 32-byte seed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let _entry = Entry::new_secret();
        bytes
            .try_into()
            .map(|seed| Self(ed25519::SigningKey::from_seed(&seed)))
            .map_err(|_| Error::WrongLength)
    }

    /// Sign `message`.
    ///
    /// The signature is returned.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let _entry = Entry::new_secret();
        self.0.sign(message)
    }

    /// Return the corresponding public key.
    pub fn public_key(&self) -> Ed25519VerifyingKey {
        let _entry = Entry::new_secret();
        Ed25519VerifyingKey(self.0.verifying_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairwise() {
        for _ in 0..100 {
            let k = Ed25519SigningKey::generate().unwrap();
            let pk = k.public_key();
            let mut msg = [0u8; 128];
            SystemRandom.fill(&mut msg).unwrap();
            let sig = k.sign(&msg);

            pk.verify(&sig, &msg).unwrap();
        }
    }

    #[test]
    fn round_trip_pkcs8_v2() {
        let bytes = include_bytes!("asn1/testdata/ed25519-p8v2.bin");
        let key = Ed25519SigningKey::from_pkcs8_der(bytes).unwrap();

        let mut buf = vec![0; bytes.len()];
        let buf = key.to_pkcs8_der(&mut buf).unwrap();
        assert_eq!(bytes, buf);
    }
}
