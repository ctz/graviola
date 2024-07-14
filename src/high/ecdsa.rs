use super::curve::{Curve, PrivateKey, PublicKey, Scalar, MAX_SCALAR_LEN};
use super::hash::{Hash, HashContext};
use super::hmac_drbg::HmacDrbg;
use crate::Error;

#[cfg(test)]
mod tests;

pub struct SigningKey<C: Curve> {
    pub private_key: C::PrivateKey,
}

impl<C: Curve> SigningKey<C> {
    pub fn sign<H: Hash>(&self, message: &[&[u8]], signature: &mut [u8]) -> Result<(), Error> {
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

        let mut rng = HmacDrbg::<H>::new(&encoded_private_key, hash.as_ref());

        let (k, r) = loop {
            let k = C::generate_random_key(&mut rng)?;
            let x = k.public_key().x_scalar();
            if !x.is_zero() {
                break (k, x);
            }
        };
        let e = hash_to_scalar::<C>(hash.as_ref())?;
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
    pub fn from_x962_uncompressed(encoded: &[u8]) -> Result<Self, Error> {
        C::PublicKey::from_x962_uncompressed(encoded).map(|public_key| Self { public_key })
    }

    pub fn verify(&self, hash: &[u8], signature: &[u8]) -> Result<(), Error> {
        if signature.len() != C::Scalar::LEN_BYTES * 2 {
            return Err(Error::WrongLength);
        }

        // 1. If r and s are not both integers in the interval [1, n − 1], output “invalid” and stop.
        let r = C::Scalar::from_bytes_checked(&signature[..C::Scalar::LEN_BYTES])
            .map_err(|_| Error::BadSignature)?;
        let s = C::Scalar::from_bytes_checked(&signature[C::Scalar::LEN_BYTES..])
            .map_err(|_| Error::BadSignature)?;

        // 2. Use the hash function established during the setup procedure to compute the hash value:
        // (done by caller)

        // 3. Derive an integer e from H as follows: (...)
        let e = hash_to_scalar::<C>(hash)?;

        // 4. - 8. in `raw_ecdsa_verify`
        self.public_key.raw_ecdsa_verify(&r, &s, &e)
    }
}

fn hash_to_scalar<C: Curve>(hash: &[u8]) -> Result<C::Scalar, Error> {
    if hash.len() > C::Scalar::LEN_BYTES {
        todo!("reduction of |H| into scalar");
    }

    Ok(C::Scalar::from_bytes_reduced(hash))
}
