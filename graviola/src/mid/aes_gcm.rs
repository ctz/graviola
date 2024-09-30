// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::low::ghash::{Ghash, GhashTable};
use crate::low::{aes_gcm, ct_equal, AesKey, Entry};
use crate::Error;

pub struct AesGcm {
    key: AesKey,
    gh: GhashTable,
}

impl AesGcm {
    pub fn new(key: &[u8]) -> Self {
        let _ = Entry::new_secret();
        let key = AesKey::new(key);
        let mut h = [0u8; 16];
        key.encrypt_block(&mut h);

        let h = u128::from_be_bytes(h);
        let gh = GhashTable::new(h);

        Self { key, gh }
    }

    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        cipher_inout: &mut [u8],
        tag_out: &mut [u8; 16],
    ) {
        let _ = Entry::new_secret();
        let mut ghash = Ghash::new(&self.gh);

        let counter = self.nonce_to_y0(nonce);

        let mut e_y0 = counter;
        self.key.encrypt_block(&mut e_y0);

        // give low-level code opportunity to stitch gf128 and aes
        // computations. see low::generic::aes_gcm for model version.
        aes_gcm::encrypt(&self.key, &mut ghash, &counter, aad, cipher_inout);

        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&((aad.len() * 8) as u64).to_be_bytes());
        lengths[8..].copy_from_slice(&((cipher_inout.len() * 8) as u64).to_be_bytes());
        ghash.add(&lengths);

        let final_xi = ghash.into_bytes();

        for ((out, x), e) in tag_out.iter_mut().zip(final_xi.iter()).zip(e_y0.iter()) {
            *out = *x ^ *e;
        }
    }

    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        cipher_inout: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        let _ = Entry::new_secret();
        let mut ghash = Ghash::new(&self.gh);

        let counter = self.nonce_to_y0(nonce);

        let mut e_y0 = counter;
        self.key.encrypt_block(&mut e_y0);

        aes_gcm::decrypt(&self.key, &mut ghash, &counter, aad, cipher_inout);

        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&((aad.len() * 8) as u64).to_be_bytes());
        lengths[8..].copy_from_slice(&((cipher_inout.len() * 8) as u64).to_be_bytes());
        ghash.add(&lengths);

        let mut actual_tag = ghash.into_bytes();
        for (out, e) in actual_tag.iter_mut().zip(e_y0.iter()) {
            *out ^= *e;
        }

        if ct_equal(&actual_tag, tag) {
            Ok(())
        } else {
            // avoid unauthenticated plaintext leak
            cipher_inout.fill(0x00);
            Err(Error::DecryptFailed)
        }
    }

    fn nonce_to_y0(&self, nonce: &[u8; 12]) -> [u8; 16] {
        let mut y0 = [0u8; 16];
        y0[..12].copy_from_slice(nonce);
        y0[15] = 0x01;
        y0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn smoketest() {
        let t = AesGcm::new(&[0; 16]);
        let mut tag = [0u8; 16];
        t.encrypt(&[0u8; 12], &[], &mut [], &mut tag);
        assert_eq!(
            &tag,
            b"\x58\xe2\xfc\xce\xfa\x7e\x30\x61\x36\x7f\x1d\x57\xa4\xe7\x45\x5a"
        );
    }

    #[test]
    fn long_encrypt_test() {
        let t = AesGcm::new(&[b'k'; 16]);
        let mut tag = [0u8; 16];
        // not divisible by 128, 64, 16 to cover by-8, by-4, and trailing cases
        let mut cipher = [b'p'; 4164];
        t.encrypt(b"noncenonceno", b"aad", &mut cipher, &mut tag);

        let expected = include_bytes!("../testdata/aes-gcm-ciphertext.bin");
        let (expected_cipher, expected_tag) = expected.split_at(expected.len() - 16);
        assert_eq!(expected_cipher, cipher);
        assert_eq!(expected_tag, tag);
    }

    #[test]
    fn long_decrypt_test() {
        let t = AesGcm::new(&[b'k'; 16]);
        let expected = include_bytes!("../testdata/aes-gcm-ciphertext.bin");
        let (cipher, tag) = expected.split_at(expected.len() - 16);
        let mut plain = cipher.to_vec();

        t.decrypt(b"noncenonceno", b"aad", &mut plain, &tag)
            .unwrap();

        assert_eq!(plain, &[b'p'; 4164]);
    }
}
