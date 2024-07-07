#![deny(unsafe_code)]

pub mod curve;
pub mod ecdsa;

#[cfg(test)]
mod tests {
    use super::*;
    use curve::Curve;

    #[test]
    fn smoke() {
        let k = curve::P256::generate_random_key(&mut rand_core::OsRng).unwrap();
        println!("public key {:?}", k.public_key().as_bytes_uncompressed());
        let k = ecdsa::SigningKey::<curve::P256> { private_key: k };
        let mut signature = [0u8; 64];
        k.sign(b"\x2c\xf2\x4d\xba\x5f\xb0\xa3\x0e\x26\xe8\x3b\x2a\xc5\xb9\xe2\x9e\x1b\x16\x1e\x5c\x1f\xa7\x42\x5e\x73\x04\x33\x62\x93\x8b\x98\x24", &mut rand_core::OsRng, &mut signature)
            .unwrap();
        println!("sig {:?}", signature);
    }
}
