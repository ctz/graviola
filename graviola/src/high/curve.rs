// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::high::asn1;
use crate::mid::p256;
use crate::mid::p384;
use crate::mid::rng::RandomSource;
use crate::Error;

pub trait Curve {
    type PrivateKey: PrivateKey<Self>;
    type PublicKey: PublicKey<Self>;
    type Scalar: Scalar<Self>;

    fn oid() -> asn1::ObjectId;
    fn generate_random_key(rng: &mut dyn RandomSource) -> Result<Self::PrivateKey, Error>;
}

pub trait PrivateKey<C: Curve + ?Sized> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;
    fn encode<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8], Error>;
    fn public_key_x_scalar(&self) -> C::Scalar;
    fn public_key_encode_uncompressed<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8], Error>;
    fn raw_ecdsa_sign(&self, k: &Self, e: &C::Scalar, r: &C::Scalar) -> C::Scalar;
}

pub trait PublicKey<C: Curve + ?Sized> {
    const LEN_BYTES: usize; // uncompressed

    fn from_x962_uncompressed(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;
    fn raw_ecdsa_verify(&self, r: &C::Scalar, s: &C::Scalar, e: &C::Scalar) -> Result<(), Error>;
}

pub trait Scalar<C: Curve + ?Sized> {
    const LEN_BYTES: usize;

    fn from_bytes_checked(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;
    fn from_bytes_reduced(bytes: &[u8]) -> Self;
    fn is_zero(&self) -> bool;
    fn write_bytes(&self, target: &mut [u8]);
}

// enough for P521
pub const MAX_SCALAR_LEN: usize = 66;

pub struct P256;

impl Curve for P256 {
    type PrivateKey = p256::PrivateKey;
    type PublicKey = p256::PublicKey;
    type Scalar = p256::Scalar;

    fn oid() -> asn1::ObjectId {
        asn1::oid::id_prime256v1.clone()
    }

    fn generate_random_key(rng: &mut dyn RandomSource) -> Result<p256::PrivateKey, Error> {
        p256::PrivateKey::generate(rng)
    }
}

impl PrivateKey<P256> for p256::PrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes)
    }

    fn encode<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8], Error> {
        if let Some(out) = out.get_mut(0..32) {
            out.copy_from_slice(&self.as_bytes());
            Ok(out)
        } else {
            Err(Error::OutOfRange)
        }
    }

    fn public_key_x_scalar(&self) -> p256::Scalar {
        self.public_key_x_scalar()
    }

    fn public_key_encode_uncompressed<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8], Error> {
        if let Some(out) = out.get_mut(0..65) {
            out.copy_from_slice(&self.public_key_uncompressed());
            Ok(out)
        } else {
            Err(Error::OutOfRange)
        }
    }

    fn raw_ecdsa_sign(&self, k: &Self, e: &p256::Scalar, r: &p256::Scalar) -> p256::Scalar {
        self.raw_ecdsa_sign(k, e, r)
    }
}

impl PublicKey<P256> for p256::PublicKey {
    const LEN_BYTES: usize = 65;

    fn from_x962_uncompressed(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_x962_uncompressed(bytes)
    }

    fn raw_ecdsa_verify(
        &self,
        r: &p256::Scalar,
        s: &p256::Scalar,
        e: &p256::Scalar,
    ) -> Result<(), Error> {
        self.raw_ecdsa_verify(r, s, e)
    }
}

impl Scalar<P256> for p256::Scalar {
    const LEN_BYTES: usize = 32;

    fn from_bytes_checked(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes_checked(bytes)
    }

    fn from_bytes_reduced(bytes: &[u8]) -> Self {
        Self::from_bytes_reduced(bytes).unwrap()
    }

    fn is_zero(&self) -> bool {
        self.is_zero()
    }

    fn write_bytes(&self, target: &mut [u8]) {
        target.copy_from_slice(&self.as_bytes());
    }
}

pub struct P384;

impl Curve for P384 {
    type PrivateKey = p384::PrivateKey;
    type PublicKey = p384::PublicKey;
    type Scalar = p384::Scalar;

    fn oid() -> asn1::ObjectId {
        asn1::oid::secp384r1.clone()
    }

    fn generate_random_key(rng: &mut dyn RandomSource) -> Result<p384::PrivateKey, Error> {
        p384::PrivateKey::generate(rng)
    }
}

impl PrivateKey<P384> for p384::PrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes)
    }

    fn encode<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8], Error> {
        if let Some(out) = out.get_mut(0..48) {
            out.copy_from_slice(&self.as_bytes());
            Ok(out)
        } else {
            Err(Error::OutOfRange)
        }
    }

    fn public_key_x_scalar(&self) -> p384::Scalar {
        self.public_key_x_scalar()
    }

    fn public_key_encode_uncompressed<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8], Error> {
        if let Some(out) = out.get_mut(0..97) {
            out.copy_from_slice(&self.public_key_uncompressed());
            Ok(out)
        } else {
            Err(Error::OutOfRange)
        }
    }

    fn raw_ecdsa_sign(&self, k: &Self, e: &p384::Scalar, r: &p384::Scalar) -> p384::Scalar {
        self.raw_ecdsa_sign(k, e, r)
    }
}

impl PublicKey<P384> for p384::PublicKey {
    const LEN_BYTES: usize = 97;

    fn from_x962_uncompressed(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_x962_uncompressed(bytes)
    }

    fn raw_ecdsa_verify(
        &self,
        r: &p384::Scalar,
        s: &p384::Scalar,
        e: &p384::Scalar,
    ) -> Result<(), Error> {
        self.raw_ecdsa_verify(r, s, e)
    }
}

impl Scalar<P384> for p384::Scalar {
    const LEN_BYTES: usize = 48;

    fn from_bytes_checked(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes_checked(bytes)
    }

    fn from_bytes_reduced(bytes: &[u8]) -> Self {
        Self::from_bytes_reduced(bytes).unwrap()
    }

    fn is_zero(&self) -> bool {
        self.is_zero()
    }

    fn write_bytes(&self, target: &mut [u8]) {
        target.copy_from_slice(&self.as_bytes());
    }
}
