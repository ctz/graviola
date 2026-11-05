// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::marker::PhantomData;

use super::hash::{Hash, HashOutput};
use super::hmac::Hmac;
use crate::Error;
use crate::mid::rng::RandomSource;

/// A limited implementation of SP800-90A -- enough for RFC6979 ECDSA.
pub(crate) struct HmacDrbg<H: Hash> {
    k: HashOutput,
    v: HashOutput,
    reseed_counter: usize,
    _h: PhantomData<H>,
}

impl<H: Hash> HmacDrbg<H> {
    pub(crate) fn new(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self {
        // 1. seed_material = entropy_input || nonce || personalization_string.
        let seed_material = &[entropy_input, nonce, personalization_string];

        // 2. Key = 0x00 00...00. Comment: outlen bits.
        let k = H::zeroed_output();
        // 3. V = 0x01 01...01. Comment: outlen bits.
        let mut v = H::zeroed_output();
        v.as_mut().fill(1u8);

        // 4. (Key, V) = HMAC_DRBG_Update (seed_material, Key, V).
        // 5. reseed_counter = 1.
        // (nb. `update()` increments `reseed_counter` to 1)
        let mut r = Self {
            k,
            v,
            reseed_counter: 0,
            _h: PhantomData,
        };
        r.update(seed_material);
        r
    }

    fn update(&mut self, additional_input: &[&[u8]]) {
        // 1. K = HMAC (K, V || 0x00 || provided_data).
        let mut ctx = Hmac::<H>::new(self.k.as_ref());
        ctx.update(self.v.as_ref());
        ctx.update([0u8]);

        for item in additional_input {
            ctx.update(item);
        }

        self.k = ctx.finish();

        // 2. V = HMAC (K, V).
        let mut ctx = Hmac::<H>::new(self.k.as_ref());
        ctx.update(self.v.as_ref());
        self.v = ctx.finish();

        self.reseed_counter += 1;

        // 3. If (provided_data = Null), then return K and V.
        if additional_input.is_empty() {
            return;
        }

        // 4. K = HMAC (K, V || 0x01 || provided_data).
        let mut ctx = Hmac::<H>::new(self.k.as_ref());
        ctx.update(self.v.as_ref());
        ctx.update([1u8]);

        for item in additional_input {
            ctx.update(item);
        }

        self.k = ctx.finish();

        // 5. V = HMAC (K, V).
        let mut ctx = Hmac::<H>::new(self.k.as_ref());
        ctx.update(self.v.as_ref());
        self.v = ctx.finish();
    }

    fn generate_block(&mut self) {
        // V = HMAC (Key, V).
        let mut ctx = Hmac::<H>::new(self.k.as_ref());
        ctx.update(self.v.as_ref());
        self.v = ctx.finish();
    }
}

impl<H: Hash> RandomSource for HmacDrbg<H> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        let hashlen = self.v.as_ref().len();

        // 1. If reseed_counter > reseed_interval, then
        //    return an indication that a reseed is required.
        // nb. in practice, does not happen in our uses
        assert!(self.reseed_counter < 0x1_0000_0000_0000);

        // 2. If additional_input ≠ Null, then (Key, V) =
        //    HMAC_DRBG_Update (additional_input, Key, V).
        // nb: we don't accept additional_input here.

        // 3. - 5. this is a different formulation, but
        // ends up with all `V` terms being written to `out`.
        for chunk in out.chunks_mut(hashlen) {
            self.generate_block();
            chunk.copy_from_slice(&self.v.as_ref()[..chunk.len()]);
        }

        // 6. (Key, V) = HMAC_DRBG_Update (additional_input, Key, V).
        // 7. reseed_counter = reseed_counter + 1.
        self.update(&[]);

        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::high::hash::{Sha1, Sha256, Sha384, Sha512};

    #[test]
    fn rfc6979_example() {
        let x =
            b"\x00\x9A\x4D\x67\x92\x29\x5A\x7F\x73\x0F\xC3\xF2\xB4\x9C\xBC\x0F\x62\xE8\x62\x27\x2F";
        let h1 =
            b"\x01\x79\x5E\xDF\x0D\x54\xDB\x76\x0F\x15\x6D\x0D\xAC\x04\xC0\x32\x2B\x3A\x20\x42\x24";

        let mut ctx = HmacDrbg::<Sha256>::new(x, h1, &[]);
        let mut t1 = [0u8; 32];
        ctx.fill(&mut t1).unwrap();
        assert_eq!(&t1, b"\x93\x05\xA4\x6D\xE7\xFF\x8E\xB1\x07\x19\x4D\xEB\xD3\xFD\x48\xAA\x20\xD5\xE7\x65\x6C\xBE\x0E\xA6\x9D\x2A\x8D\x4E\x7C\x67\x31\x4A");

        let mut t2 = [0u8; 32];
        ctx.fill(&mut t2).unwrap();
        assert_eq!(&t2, b"\xC7\x0C\x78\x60\x8A\x3B\x5B\xE9\x28\x9B\xE9\x0E\xF6\xE8\x1A\x9E\x2C\x15\x16\xD5\x75\x1D\x2F\x75\xF5\x00\x33\xE4\x5F\x73\xBD\xEB");
    }

    #[test]
    fn vectors() {
        // Generated independently with python.
        fn check<H: Hash>(first: &[u8; 70], second: &[u8; 30]) {
            let entropy: [u8; 32] = core::array::from_fn(|i| i as u8);
            let nonce: [u8; 16] = core::array::from_fn(|i| 0x40 + i as u8);
            let perso = b"graviola hmac-drbg";

            let mut ctx = HmacDrbg::<H>::new(&entropy, &nonce, perso);

            let mut o1 = [0u8; 70];
            ctx.fill(&mut o1).unwrap();
            assert_eq!(&o1, first);

            let mut o2 = [0u8; 30];
            ctx.fill(&mut o2).unwrap();
            assert_eq!(&o2, second);
        }

        check::<Sha1>(
            b"\x8d\x1b\xb7\x15\xf8\xdb\x72\x42\x65\x10\xd5\x2e\xac\x76\x59\x53\x5c\xf6\xb9\x1c\x3a\x6b\xf3\x4d\x73\x38\xc9\xf9\x7f\xe2\
              \xdb\x77\xcc\x4b\xa9\xb6\x8a\xec\x28\x85\xf0\xa9\x5c\x65\x96\x63\x73\x0a\xd0\x2e\x88\x7c\x55\xc0\x25\xb5\xd3\xe8\xbb\x93\
              \x9f\x8a\xb7\x62\x75\x18\x2b\xbb\x6f\x9b",
            b"\x05\x6d\x9e\xdb\x14\x7b\x7f\x07\x13\xa7\x0f\xc9\xb1\xdd\x3d\xb2\x4a\x57\x55\x0f\xe5\xb2\x05\xb7\x0d\x90\x34\x13\x1d\xa9",
        );
        check::<Sha256>(
            b"\xc5\xc1\x25\x25\xc2\x09\xb9\x25\x91\x57\xc8\x31\x76\xd2\xd0\xd5\x88\x5e\x5e\xaf\x29\xd9\x22\x86\xec\xe7\x6a\x94\x27\x0c\
              \x79\x9a\x57\x1d\xb2\x31\xb5\x87\xe1\x7c\x3b\x64\x2e\x26\x62\xac\x5d\x62\x16\x8d\xc5\xbe\x78\x0f\xde\xa8\x76\x6e\x03\x8a\
              \xc3\xd7\xb5\x15\x3b\x33\xbc\x21\x21\xab",
            b"\x7d\xbb\x59\xe0\x36\x7a\x1c\x0a\xc3\x1a\xbd\x60\xfc\x42\xba\x3c\x4c\x2b\x0a\xf2\x5c\xf8\xe1\x65\x00\x62\x7c\x82\x14\x21",
        );
        check::<Sha384>(
            b"\x93\xb3\x8c\xe3\x14\x37\x84\x75\x2a\x48\x20\xd6\x87\xda\x6c\xc8\xc6\x1a\x2c\x54\xc1\x64\x7b\xff\x4c\x81\x16\x43\x57\xdf\
              \x65\x02\x1c\xee\x99\x71\x77\xa3\x31\x04\x63\x67\x60\xa1\xb3\x5e\x35\x9d\x55\xa6\x5f\x48\xce\x79\x45\x3b\x54\x44\x19\x21\
              \xd8\xae\x2e\xaa\x84\xc8\x73\x69\xa4\xef",
            b"\xca\xd6\x29\x26\x73\x0e\x38\xad\x07\xaf\x3a\x06\xe4\xfa\x48\xc5\x9e\x50\xbe\x2e\x71\x20\x6d\x1e\x0f\xee\x4a\x3e\x95\x4f",
        );
        check::<Sha512>(
            b"\x41\x86\x6a\x14\x61\x21\x70\x57\xab\x66\xde\x78\xb7\x05\x9c\xbc\x87\x4e\x05\xe7\x49\xde\x57\xbd\x17\xff\x5e\x44\xaf\x88\
              \x16\xd2\x72\x4e\x5a\xa3\xf5\x41\x61\x47\xc2\x18\x1f\xdd\x39\x8d\xed\xc6\xa2\xb6\x79\x9e\x2d\xa3\xf2\x22\x72\x7e\xaa\xaa\
              \xd8\x7e\x68\xc3\x7a\x2e\xee\x9e\x1b\xa3",
            b"\xb2\x6d\x4e\xf0\x66\x27\x45\xc1\xa3\x80\x51\xf6\x18\x3d\x22\x0c\x94\xd7\x3a\xaf\xa4\x00\xc7\x2a\xee\x47\xf3\x74\x1c\x55",
        );
    }
}
