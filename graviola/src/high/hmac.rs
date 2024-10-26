// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! HMAC (Hash Message Authentication Code).
//!
//! HMAC is standardized in [FIPS 198](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf).

use super::hash::{Hash, HashContext, HashOutput};
use crate::Error;

/// An in-progress HMAC computation, using hash function `H`.
#[derive(Clone)]
pub struct Hmac<H: Hash> {
    inner: H::Context,
    outer: H::Context,
}

impl<H: Hash> Hmac<H> {
    /// Create a new [`Hmac<H>`] using the given key material.
    pub fn new(key: impl AsRef<[u8]>) -> Self {
        let mut key_block = H::zeroed_block();

        let key = key.as_ref();
        // shorten long keys
        if key.len() > key_block.len() {
            let h_key = H::hash(key);
            key_block[..h_key.as_ref().len()].copy_from_slice(h_key.as_ref());
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        // compute inner
        let mut block = key_block;
        for byte in block.iter_mut() {
            *byte ^= 0x36;
        }
        let mut inner = H::new();
        inner.update(&block);

        // and outer
        let mut block = key_block;
        for byte in block.iter_mut() {
            *byte ^= 0x5c;
        }
        let mut outer = H::new();
        outer.update(&block);

        Self { inner, outer }
    }

    /// Add data to be signed.
    pub fn update(&mut self, bytes: impl AsRef<[u8]>) {
        self.inner.update(bytes.as_ref());
    }

    /// Complete the HMAC signing operation, consuming it.
    ///
    /// The HMAC output (sometimes called a "signature", or "tag") is returned.
    pub fn finish(mut self) -> HashOutput {
        let inner_output = self.inner.finish();
        self.outer.update(inner_output.as_ref());
        self.outer.finish()
    }

    /// Complete the HMAC signing operation and compare the result against `expected_tag`.
    ///
    /// This is done in constant-time.  `expected_tag` may not be truncated.
    pub fn verify(self, expected_tag: &[u8]) -> Result<(), Error> {
        let got = self.finish();
        match got.ct_equal(expected_tag) {
            true => Ok(()),
            false => Err(Error::BadSignature),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::high::hash::{Sha256, Sha384, Sha512};
    use crate::test::*;

    #[test]
    fn smoke() {
        let mut h = Hmac::<Sha256>::new(b"hello");
        h.update(b"world");
        assert_eq!(h.finish(),
                   HashOutput::Sha256(*b"\xf1\xac\x97\x02\xeb\x5f\xaf\x23\xca\x29\x1a\x4d\xc4\x6d\xed\xde\xee\x2a\x78\xcc\xda\xf0\xa4\x12\xbe\xd7\x71\x4c\xff\xfb\x1c\xc4"));
    }

    #[test]
    fn cavp() {
        #[derive(Debug)]
        enum Kind {
            None,
            Sha256,
            Sha384,
            Sha512,
        }

        #[derive(Debug)]
        struct Cavp {
            kind: Kind,
            key: Vec<u8>,
            message: Vec<u8>,
        }

        impl Default for Cavp {
            fn default() -> Self {
                Self {
                    kind: Kind::None,
                    key: Vec::new(),
                    message: Vec::new(),
                }
            }
        }

        impl CavpSink for Cavp {
            fn on_meta(&mut self, meta: &str) {
                self.kind = match meta {
                    "L=20" | "L=28" => Kind::None,
                    "L=32" => Kind::Sha256,
                    "L=48" => Kind::Sha384,
                    "L=64" => Kind::Sha512,
                    _ => panic!("unhandled {meta:?}"),
                };
            }

            fn on_value(&mut self, name: &str, value: Value<'_>) {
                match name {
                    "Klen" | "Tlen" => {}
                    "Count" => println!("  test {}", value.int()),
                    "Key" => self.key = value.bytes(),
                    "Msg" => self.message = value.bytes(),
                    "Mac" => match self.kind {
                        Kind::None => {}
                        Kind::Sha256 => {
                            let mut h = Hmac::<Sha256>::new(&self.key);
                            h.update(&self.message);
                            let tag = h.finish();

                            let wanted = value.bytes();

                            match wanted.len() {
                                32 => assert!(tag.ct_equal(&wanted)),
                                24 => assert!(tag.truncated_ct_equal::<24>(&wanted)),
                                16 => assert!(tag.truncated_ct_equal::<16>(&wanted)),
                                len => todo!("unhandled tag len {len}"),
                            }
                        }
                        Kind::Sha384 => {
                            let mut h = Hmac::<Sha384>::new(&self.key);
                            h.update(&self.message);
                            let tag = h.finish();

                            let wanted = value.bytes();

                            match wanted.len() {
                                48 => assert!(tag.ct_equal(&wanted)),
                                40 => assert!(tag.truncated_ct_equal::<40>(&wanted)),
                                32 => assert!(tag.truncated_ct_equal::<32>(&wanted)),
                                24 => assert!(tag.truncated_ct_equal::<24>(&wanted)),
                                len => todo!("unhandled tag len {len}"),
                            }
                        }
                        Kind::Sha512 => {
                            let mut h = Hmac::<Sha512>::new(&self.key);
                            h.update(&self.message);
                            let tag = h.finish();

                            let wanted = value.bytes();

                            match wanted.len() {
                                64 => assert!(tag.ct_equal(&wanted)),
                                56 => assert!(tag.truncated_ct_equal::<56>(&wanted)),
                                48 => assert!(tag.truncated_ct_equal::<48>(&wanted)),
                                40 => assert!(tag.truncated_ct_equal::<40>(&wanted)),
                                32 => assert!(tag.truncated_ct_equal::<32>(&wanted)),
                                len => todo!("unhandled tag len {len}"),
                            }
                        }
                    },
                    _ => {
                        todo!("{self:?} value {name} = {value:?}");
                    }
                }
            }
        }

        process_cavp("../thirdparty/cavp/hmac/HMAC.rsp", &mut Cavp::default());
    }
}
