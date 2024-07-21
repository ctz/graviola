use crate::low::{aes_expand_key, ct_equal};
use crate::low::{gf128, AesKey, BlockwisePadded, GcmTable};
use crate::Error;

pub struct AesGcm {
    key: AesKey,
    gcm: GcmTable,
}

impl AesGcm {
    pub fn new(key: &[u8]) -> Self {
        let key = aes_expand_key(key);
        let mut h = [0u8; 16];
        key.encrypt_block(&mut h);

        let h = u128::from_be_bytes(h);
        let mut h_table = [0; 9];
        h_table[0] = gf128::mul(h, h);
        h_table[1] = gf128::mul(h_table[0], h);
        h_table[2] = gf128::mul(h_table[1], h);
        h_table[3] = gf128::mul(h_table[2], h);
        h_table[4] = gf128::mul(h_table[3], h);
        h_table[5] = gf128::mul(h_table[4], h);
        h_table[6] = gf128::mul(h_table[5], h);
        h_table[7] = gf128::mul(h_table[6], h);
        h_table[8] = gf128::mul(h_table[7], h);

        let gcm = GcmTable { h, h_table };

        Self { key, gcm }
    }

    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        cipher_inout: &mut [u8],
        tag_out: &mut [u8; 16],
    ) {
        let mut ghash = Ghash::new(self.gcm.h);
        ghash.add(aad);

        self.cipher(nonce, cipher_inout);
        ghash.add(cipher_inout);

        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&((aad.len() * 8) as u64).to_be_bytes());
        lengths[8..].copy_from_slice(&((cipher_inout.len() * 8) as u64).to_be_bytes());
        ghash.add(&lengths);

        let mut e_y0 = self.nonce_to_y0(nonce);
        self.key.encrypt_block(&mut e_y0);

        let final_xi = ghash.into_bytes();

        xor(tag_out, &final_xi, &e_y0);
    }

    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        cipher_inout: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        let mut ghash = Ghash::new(self.gcm.h);
        ghash.add(aad);

        ghash.add(cipher_inout);
        self.cipher(nonce, cipher_inout);

        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&((aad.len() * 8) as u64).to_be_bytes());
        lengths[8..].copy_from_slice(&((cipher_inout.len() * 8) as u64).to_be_bytes());
        ghash.add(&lengths);

        let mut e_y0 = self.nonce_to_y0(nonce);
        self.key.encrypt_block(&mut e_y0);

        let mut actual_tag = ghash.into_bytes();
        xor_in_place(&mut actual_tag, &e_y0);

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

    fn cipher(&self, nonce: &[u8; 12], cipher_inout: &mut [u8]) {
        let mut counter = self.nonce_to_y0(nonce);

        for chunk in cipher_inout.chunks_mut(16) {
            increment32(&mut counter);
            let mut block = counter;
            self.key.encrypt_block(&mut block);

            xor_in_place(chunk, &block);
        }
    }
}

struct Ghash {
    current: u128,
    h: u128,
}

impl Ghash {
    fn new(h: u128) -> Self {
        Self { current: 0, h }
    }

    fn add(&mut self, bytes: &[u8]) {
        for block in BlockwisePadded::<16>::new(bytes, 0x00) {
            self.current ^= u128::from_be_bytes(block);
            self.current = gf128::mul(self.current, self.h);
        }
    }

    fn into_bytes(self) -> [u8; 16] {
        self.current.to_be_bytes()
    }
}

fn xor<const N: usize>(out: &mut [u8; N], a: &[u8; N], b: &[u8; N]) {
    for i in 0..N {
        out[i] = a[i] ^ b[i];
    }
}

fn xor_in_place(inout: &mut [u8], offset: &[u8]) {
    assert!(inout.len() <= offset.len());
    for (a, b) in inout.iter_mut().zip(offset.iter()) {
        *a ^= *b;
    }
}

fn increment32(block: &mut [u8; 16]) {
    let mut counter = u32::from_be_bytes(block[12..].try_into().unwrap());
    counter = counter.wrapping_add(1);
    block[12..].copy_from_slice(&counter.to_be_bytes());
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
}
