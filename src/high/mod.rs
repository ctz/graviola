#![deny(unsafe_code)]

pub mod curve;
pub mod ecdsa;
pub mod hash;
pub mod hmac;
pub mod hmac_drbg;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SystemRandom;
    use curve::Curve;

    #[test]
    fn smoke() {
        let k = curve::P256::generate_random_key(&mut SystemRandom).unwrap();
        println!("public key {:?}", k.public_key().as_bytes_uncompressed());
        let k = ecdsa::SigningKey::<curve::P256> { private_key: k };
        let mut signature = [0u8; 64];
        k.sign::<hash::Sha256>(&[b"hello"], &mut signature).unwrap();
        println!("sig {:?}", signature);
    }
}
