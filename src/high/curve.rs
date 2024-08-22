// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::mid::p256;
use crate::Error;
use crate::RandomSource;

pub trait Curve {
    type PrivateKey: PrivateKey<Self>;
    type PublicKey: PublicKey<Self>;
    type Scalar: Scalar<Self>;

    fn generate_random_key(rng: &mut dyn RandomSource) -> Result<Self::PrivateKey, Error>;
}

pub trait PrivateKey<C: Curve + ?Sized> {
    fn encode<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8], Error>;
    fn public_key(&self) -> C::PublicKey;
    fn raw_ecdsa_sign(&self, k: &Self, e: &C::Scalar, r: &C::Scalar) -> C::Scalar;
}

pub trait PublicKey<C: Curve + ?Sized> {
    fn from_x962_uncompressed(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;
    fn x_scalar(&self) -> C::Scalar;
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

    fn generate_random_key(rng: &mut dyn RandomSource) -> Result<p256::PrivateKey, Error> {
        p256::PrivateKey::generate(rng)
    }
}

impl PrivateKey<P256> for p256::PrivateKey {
    fn encode<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8], Error> {
        if let Some(out) = out.get_mut(0..32) {
            out.copy_from_slice(&self.as_bytes());
            Ok(out)
        } else {
            Err(Error::OutOfRange)
        }
    }

    fn public_key(&self) -> p256::PublicKey {
        self.public_key()
    }

    fn raw_ecdsa_sign(&self, k: &Self, e: &p256::Scalar, r: &p256::Scalar) -> p256::Scalar {
        self.raw_ecdsa_sign(k, e, r)
    }
}

impl PublicKey<P256> for p256::PublicKey {
    fn from_x962_uncompressed(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_x962_uncompressed(bytes)
    }

    fn x_scalar(&self) -> p256::Scalar {
        self.x_scalar()
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
