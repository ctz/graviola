// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::Error;
use crate::low::ghash::{Ghash, GhashTable};
use crate::low::{AesKey, Blockwise, Entry, aes_gcm, ct_equal};

/// An AES-GCM key.
///
/// Making one of these is relatively expensive due to key
/// expansion and precomputation.
///
/// This implementation is limited to that which is commonly
/// used:
///
/// - AES-192 is not supported, as it is rarely used.
/// - Only nonces that are 12-bytes/96-bits are supported.
pub struct AesGcm {
    key: AesKey,
    gh: GhashTable,
}

impl AesGcm {
    /// Create a new `AesGcm` object.
    ///
    /// `key` must be 16 or 32 bytes, corresponding
    /// to AES-128 or AES-256.  This function panics otherwise.
    ///
    /// (Note: this crate does not support AES-192).
    pub fn new(key: &[u8]) -> Self {
        let _entry = Entry::new_secret();
        let key = AesKey::new(key);
        let mut h = [0u8; 16];
        key.encrypt_block(&mut h);

        let h = u128::from_be_bytes(h);
        let gh = GhashTable::new(h);

        Self { key, gh }
    }

    /// Encrypts the given message.
    ///
    /// On entry, `cipher_inout` contains the plaintext of the message.
    /// `nonce` contains the nonce, which must be unique for a given key.
    /// `aad` is the additionally-authenticated data.  It may be empty.
    ///
    /// On exit, `cipher_inout` contains the ciphertext of the message,
    /// and `tag_out` contains the authentication tag.
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        cipher_inout: &mut [u8],
        tag_out: &mut [u8; 16],
    ) {
        let _entry = Entry::new_secret();
        let mut ghash = Ghash::new(&self.gh);

        let counter = self.nonce_to_y0(nonce);

        let mut e_y0 = counter;
        self.key.encrypt_block(&mut e_y0);

        // give low-level code opportunity to stitch gf128 and aes
        // computations. see low::generic::aes_gcm for model version.
        aes_gcm::encrypt_in_place(&self.key, &mut ghash, &counter, aad, cipher_inout);

        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&((aad.len() * 8) as u64).to_be_bytes());
        lengths[8..].copy_from_slice(&((cipher_inout.len() * 8) as u64).to_be_bytes());
        ghash.add(&lengths);

        let final_xi = ghash.into_bytes();

        for ((out, x), e) in tag_out.iter_mut().zip(final_xi.iter()).zip(e_y0.iter()) {
            *out = *x ^ *e;
        }
    }

    /// Encrypts a message gathered from several slices, appending it to `cipher_out`.
    ///
    /// On entry, the plaintext of the message is the concatenation of the
    /// slices yielded by `plain_chunks`.  Chunks may have any length,
    /// including zero.
    /// `nonce` contains the nonce, which must be unique for a given key.
    /// `aad` is the additionally-authenticated data.  It may be empty.
    ///
    /// On exit, the ciphertext of the message followed by the tag has
    /// been appended to `cipher_out`.
    ///
    /// The plaintext is copied into `cipher_out` as a side effect of
    /// encrypting it, rather than in a separate pass.  (A partial block
    /// at a chunk boundary is first gathered into a 16-byte buffer.
    /// On aarch64, a separate copy pass is still made.)
    pub fn encrypt_copy<'a>(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        plain_chunks: impl IntoIterator<Item = &'a [u8]>,
        cipher_out: &mut Vec<u8>,
    ) {
        let _entry = Entry::new_secret();
        let mut ghash = Ghash::new(&self.gh);

        let y0 = self.nonce_to_y0(nonce);

        let mut e_y0 = y0;
        self.key.encrypt_block(&mut e_y0);

        // The low-level code processes a contiguous run of plaintext,
        // starting with `ghash.add(aad)`.  Because GHASH state carries across
        // calls, and its only padding is of the final partial block, we
        // can call it repeatedly provided every run except the last is a
        // whole number of blocks, `aad` is supplied only to the first,
        // and each run starts with the counter advanced by the
        // number of blocks already processed.
        let mut aad_pending = aad;
        let mut blocks_done = 0u32;
        let mut plain_len = 0usize;
        let mut carry = Blockwise::<16>::new();

        // `input` must be a whole number of blocks, except for the final run.
        let mut process = |input: &[u8]| {
            let counter = counter_add(&y0, blocks_done);
            aes_gcm::encrypt_copy(
                &self.key,
                &mut ghash,
                &counter,
                aad_pending,
                input,
                cipher_out,
            );
            aad_pending = &[];
            blocks_done = blocks_done.wrapping_add((input.len() / 16) as u32);
        };

        for chunk in plain_chunks {
            plain_len += chunk.len();

            let chunk = carry.add_leading(chunk);
            if let Some(block) = carry.take() {
                process(&block);
            }

            let (blocks, tail) = chunk.split_at(chunk.len() & !15);
            if !blocks.is_empty() {
                process(blocks);
            }
            carry.add_trailing(tail);
        }

        // final run: the partial block, if any.  this also covers
        // the case of a message with aad but no plaintext (which is
        // the only case where no earlier run has absorbed the aad).
        match carry.peek_remaining() {
            Some(partial) => process(partial),
            None if plain_len == 0 && !aad.is_empty() => process(&[]),
            None => {}
        }

        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&((aad.len() * 8) as u64).to_be_bytes());
        lengths[8..].copy_from_slice(&((plain_len * 8) as u64).to_be_bytes());
        ghash.add(&lengths);

        let final_xi = ghash.into_bytes();

        let mut tag_out = [0; 16];
        for ((out, x), e) in tag_out.iter_mut().zip(final_xi.iter()).zip(e_y0.iter()) {
            *out = *x ^ *e;
        }
        cipher_out.extend_from_slice(&tag_out);
    }

    /// Decrypts and verifies the given message.
    ///
    /// On entry, `cipher_inout` contains the ciphertext of the message.
    /// `nonce` contains the nonce, which must match what was supplied
    /// when encrypting this message.
    /// `aad` is the additionally-authenticated data.  It may be empty.
    /// `tag` is the purported authentication tag.
    ///
    /// On success, `cipher_inout` contains the plaintext of the message,
    /// and `Ok(())` is returned.
    /// Otherwise, `Err(Error::DecryptFailed)` is returned and `cipher_inout`
    /// is cleared.
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        cipher_inout: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        let _entry = Entry::new_secret();
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

/// Returns `counter` with its low 32 bits (big-endian) advanced by `blocks`.
///
/// This matches GCM's `inc32` function, applied `blocks` times.
fn counter_add(counter: &[u8; 16], blocks: u32) -> [u8; 16] {
    let mut r = *counter;
    let low = u32::from_be_bytes(counter[12..].try_into().unwrap()).wrapping_add(blocks);
    r[12..].copy_from_slice(&low.to_be_bytes());
    r
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::test::*;

    #[test]
    fn encrypt_copy_matches_encrypt() {
        let t = AesGcm::new(&[0x42; 16]);
        let nonce = [0x11; 12];

        // a selection of splits that hit: empty chunks, chunks
        // that fill the carry block exactly, chunks smaller than
        // the carry gap, chunks spanning many blocks, and the
        // TLS1.3 shape of payload + 1-byte trailer.
        let split_patterns: &[&[usize]] = &[
            &[],
            &[0],
            &[1],
            &[15],
            &[16],
            &[17],
            &[0, 0, 0],
            &[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
            &[3, 13],
            &[5, 5, 5, 5],
            &[7, 0, 9, 0],
            &[15, 1, 15, 1],
            &[16, 16],
            &[17, 15],
            &[100],
            &[129],
            &[256, 1],
            &[300, 4, 1],
        ];

        for aad in [&b""[..], b"aad", &[0xaa; 17]] {
            for len in [
                0, 1, 15, 16, 17, 31, 32, 33, 127, 128, 129, 255, 256, 257, 300, 1023, 1024, 1029,
            ] {
                let plain: Vec<u8> = (0..len).map(|i| i as u8).collect();

                let mut expect = plain.clone();
                let mut tag = [0u8; 16];
                t.encrypt(&nonce, aad, &mut expect, &mut tag);
                expect.extend_from_slice(&tag);

                for pattern in split_patterns {
                    // split `plain` per `pattern`, with the remainder as the final chunk
                    let mut chunks = vec![];
                    let mut rest = &plain[..];
                    for &n in pattern.iter() {
                        let (head, tail) = rest.split_at(n.min(rest.len()));
                        chunks.push(head);
                        rest = tail;
                    }
                    chunks.push(rest);

                    let mut out = vec![0xff; 3];
                    t.encrypt_copy(&nonce, aad, chunks.iter().copied(), &mut out);
                    assert_eq!(&out[..3], &[0xff; 3], "prefix clobbered");
                    assert_eq!(
                        &out[3..],
                        &expect[..],
                        "mismatch at aad={aad:?} len={len} pattern={pattern:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn counter_add_wraps_low_32_bits() {
        let c = [0xff; 16];
        let mut expect = [0xff; 16];
        expect[12..].copy_from_slice(&[0, 0, 0, 1]);
        assert_eq!(counter_add(&c, 2), expect);
        assert_eq!(counter_add(&c, 0), c);
    }

    #[test]
    fn out_of_place_encrypt_matches_in_place() {
        let t = AesGcm::new(&[0x42; 16]);
        let counter = t.nonce_to_y0(&[0x11; 12]);
        let aad = b"aad";

        // covers the 256-, 128- and 16-byte chunk paths, and partial tails
        for len in [
            0, 1, 15, 16, 17, 127, 128, 129, 255, 256, 257, 300, 1023, 1024, 1029,
        ] {
            let plain: Vec<u8> = (0..len).map(|i| i as u8).collect();

            let mut in_place = plain.clone();
            let mut gh_in = Ghash::new(&t.gh);
            aes_gcm::encrypt_in_place(&t.key, &mut gh_in, &counter, aad, &mut in_place);

            let mut out_of_place = vec![];
            let mut gh_out = Ghash::new(&t.gh);
            aes_gcm::encrypt_copy(
                &t.key,
                &mut gh_out,
                &counter,
                aad,
                &plain,
                &mut out_of_place,
            );

            assert_eq!(in_place, out_of_place, "ciphertext differs at len {len}");
            assert_eq!(
                gh_in.into_bytes(),
                gh_out.into_bytes(),
                "ghash differs at len {len}"
            );
        }
    }

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

        t.decrypt(b"noncenonceno", b"aad", &mut plain, tag).unwrap();

        assert_eq!(plain, &[b'p'; 4164]);
    }

    #[test]
    fn cavp() {
        #[derive(Default)]
        struct State {
            encrypt: bool,
            key: Option<AesGcm>,
            nonce: Vec<u8>,
            ct: Vec<u8>,
            aad: Vec<u8>,
            pt: Vec<u8>,
            tag: Vec<u8>,
        }

        impl CavpSink for State {
            fn on_meta(&mut self, _meta: &str) {}

            fn on_value(&mut self, name: &str, value: Value<'_>) {
                match name {
                    "Count" => println!("  test {}", value.int()),
                    "Key" => self.key = Some(AesGcm::new(&value.bytes())),
                    "IV" => self.nonce = value.bytes(),
                    "CT" => self.ct = value.bytes(),
                    "AAD" => self.aad = value.bytes(),
                    "Tag" if !self.encrypt => self.tag = value.bytes(),
                    "Tag" if self.encrypt => {
                        if self.nonce.len() != 12 {
                            println!("skip unhandled nonce len");
                            return;
                        }
                        let mut got_tag = [0u8; 16];
                        self.key.as_ref().unwrap().encrypt(
                            &self.nonce[..].try_into().unwrap(),
                            &self.aad,
                            &mut self.pt,
                            &mut got_tag,
                        );
                        assert_eq!(self.pt, self.ct);
                        let tag = value.bytes();
                        assert_eq!(&got_tag[..tag.len()], &tag[..]);
                    }
                    "FAIL" => {
                        assert!(!self.encrypt);
                        if self.nonce.len() != 12 {
                            println!("skip unhandled nonce len");
                            return;
                        }
                        assert_eq!(
                            self.key
                                .as_ref()
                                .unwrap()
                                .decrypt(
                                    &self.nonce[..].try_into().unwrap(),
                                    &self.aad,
                                    &mut self.ct,
                                    &self.tag,
                                )
                                .unwrap_err(),
                            Error::DecryptFailed,
                        );
                    }
                    "PT" if !self.encrypt => {
                        if self.nonce.len() != 12 || self.tag.len() != 16 {
                            println!("skip unhandled nonce/tag len");
                            return;
                        }
                        self.key
                            .as_ref()
                            .unwrap()
                            .decrypt(
                                &self.nonce[..].try_into().expect("only 96-bit nonce"),
                                &self.aad,
                                &mut self.ct,
                                &self.tag,
                            )
                            .unwrap();
                        assert_eq!(self.ct, value.bytes());
                    }
                    "PT" if self.encrypt => self.pt = value.bytes(),
                    _ => {
                        todo!("unhandled value {name} = {value:?}");
                    }
                }
            }
        }

        process_cavp(
            "../thirdparty/cavp/gcm/gcmDecrypt128.rsp",
            &mut State::default(),
        );
        process_cavp(
            "../thirdparty/cavp/gcm/gcmDecrypt256.rsp",
            &mut State::default(),
        );

        let mut state = State {
            encrypt: true,
            ..Default::default()
        };
        process_cavp("../thirdparty/cavp/gcm/gcmEncryptExtIV128.rsp", &mut state);
        process_cavp("../thirdparty/cavp/gcm/gcmEncryptExtIV256.rsp", &mut state);
    }
}
