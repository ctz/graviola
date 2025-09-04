// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! HMAC-based Key Derivation Function (HKDF).
//!
//! HKDF is defined in [RFC 5869].
//!
//! # Examples
//!
//! ```
//! use graviola::{
//!     hashing::{Sha256, hkdf},
//!     random,
//! };
//!
//! // Generate non-secret salt.
//! let mut salt = [0u8; 32];
//! random::fill(&mut salt).unwrap();
//!
//! // Secret initial keying material.
//! let mut ikm = b"\x00\x01\x02\x03"; // i.e., NOT this.
//!
//! // Extract a pseudorandom key from IKM.
//! let prk = hkdf::extract::<Sha256>(Some(&salt), ikm);
//!
//! // Non-secret optional context and application specific information.
//! let info = b"client key";
//!
//! let mut key = [0u8; 32];
//! // Expand IKM into an OKM.
//! hkdf::expand::<Sha256>(&prk, info, &mut key);
//!
//! // Use the derived key...
//! ```
//!
//! [RFC 5869]: https://datatracker.ietf.org/doc/html/rfc5869

#![warn(clippy::cast_possible_truncation)]

use core::cmp;

use crate::{
    hashing::{Hash, HashOutput},
    high::hmac::Hmac,
};

/// The [HKDF-Extract] step.
///
/// Extracts a fixed-length [pseudorandom key](Prk) from the input keying
/// material `ikm`.
///
/// If `salt` is not provided, it is set to a string of hash-length zeroes.
///
/// [HKDF-Extract]: https://datatracker.ietf.org/doc/html/rfc5869#section-2.2
pub fn extract<H: Hash>(salt: Option<&[u8]>, ikm: &[u8]) -> Prk<'static> {
    let mut hmac = match salt {
        Some(salt) => Hmac::<H>::new(salt),
        None => Hmac::<H>::new(H::zeroed_output()),
    };
    hmac.update(ikm);
    let output = hmac.finish();
    Prk::Extracted(output)
}

/// The [HKDF-Expand] step.
///
/// Expands the pseudorandom key `prk` into an output keying material `okm`.
///
/// # Panics
///
/// This function will panic if the length of `okm` is greater than 255 times
/// the length of the hash function output.
///
/// ```should_panic
/// # use graviola::{hashing::{Hash, hkdf, sha2, Sha256}};
/// #
/// # const SHA256_OUTPUT_LEN: usize = sha2::Sha256Context::OUTPUT_SZ;
/// # let salt = b"\x70\x1d\xfb\xe3\xf2\x2c\x13\x26\x8a\x04\x87\x1d\xbb\x97\x11\xf3\x71\xbd\x70\x2b\x2b\xb4\x1d\xba\x24\x40\x95\x78\xe6\x48\x1b\xc1";
/// # let ikm = b"\xfe\xba\xf0\xce\x3a\x45\x2b\xda\xd4\x83\x38\xae\x25\x87\x75\xdb";
/// # let prk = hkdf::extract::<Sha256>(Some(salt), ikm);
/// #
/// # let info = b"\x57\x2d\x90\xbc\x31\xfc\x1e\xdd";
/// let mut okm = [0u8; 8161];
/// assert!(okm.len() > 255 * SHA256_OUTPUT_LEN);
/// let _ = hkdf::expand::<Sha256>(&prk, info, &mut okm);
/// ```
///
/// [HKDF-Expand]: https://datatracker.ietf.org/doc/html/rfc5869#section-2.3
pub fn expand<H: Hash>(prk: &Prk<'_>, info: &[u8], mut okm: &mut [u8]) {
    let prk = match prk {
        Prk::Extracted(hash_output) => hash_output.as_ref(),
        Prk::Provided(slice) => slice,
    };
    let l = okm.len();
    let hash_len = H::zeroed_output().as_ref().len();
    assert!(
        l <= 255 * hash_len,
        "length of output keying material must be less than or equal to 255 times the length of the hash function output"
    );
    #[expect(
        clippy::cast_possible_truncation,
        reason = "l <= 255 * hash_len <=> l / hash_len <= 255"
    )]
    let n = l.div_ceil(hash_len) as u8;

    let mut hmac = Hmac::<H>::new(prk);
    for i in 1..=n {
        hmac.update(info);
        hmac.update([i]);
        let t = hmac.finish();
        let t = t.as_ref();
        let len = cmp::min(okm.len(), t.len());
        let (chunk, rest) = okm.split_at_mut(len);
        chunk.copy_from_slice(&t[..len]);
        okm = rest;
        if okm.is_empty() {
            return;
        }

        hmac = Hmac::<H>::new(prk);
        hmac.update(t);
    }
}

/// A pseudorandom key (usually, the output from the [extract step](extract)).
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
#[non_exhaustive]
pub enum Prk<'a> {
    #[doc(hidden)]
    Extracted(HashOutput),
    #[doc(hidden)]
    Provided(&'a [u8]),
}

impl<'a> Prk<'a> {
    /// Constructs a new pseudorandom key from a uniformly random or
    /// pseudorandom cryptographically strong key.
    ///
    /// <div class="warning">
    ///
    /// Read [Section 3.3 of RFC 5869] before using! Most common scenarios will
    /// want to use [`hkdf::extract`] instead.
    ///
    /// </div>
    ///
    /// [Section 3.3 of RFC 5869]: https://datatracker.ietf.org/doc/html/rfc5869#section-3.3
    /// [`hkdf::extract`]: extract
    pub fn new_less_safe(value: &'a [u8]) -> Self {
        Self::Provided(value)
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::hashing::Sha256;

    use super::*;

    #[derive(Debug)]
    struct TestParameters {
        ikm: &'static [u8],
        salt: &'static [u8],
        info: &'static [u8],
        expected_prk: HashOutput,
        expected_okm: &'static [u8],
    }

    fn t<H: Hash, const L: usize>(params: TestParameters) {
        let TestParameters {
            ikm,
            salt,
            info,
            expected_prk,
            expected_okm,
        } = params;

        let prk = extract::<H>(Some(salt), ikm);
        assert_eq!(prk, Prk::Extracted(expected_prk.clone()));
        let mut okm = [0; L];
        expand::<H>(&prk, info, &mut okm);
        assert_eq!(okm.as_ref(), expected_okm);

        let prk = Prk::new_less_safe(expected_prk.as_ref());
        let mut okm = [0; L];
        expand::<H>(&prk, info, &mut okm);
        assert_eq!(okm.as_ref(), expected_okm);
    }

    /// Test case 1 from [RFC 5869].
    ///
    /// [RFC 5869]: https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.1
    #[test]
    fn basic_with_sha256() {
        type Hash = Sha256;
        const L: usize = 42;
        let ikm = &hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = &hex!("000102030405060708090a0b0c");
        let info = &hex!("f0f1f2f3f4f5f6f7f8f9");

        let expected_prk = HashOutput::Sha256(hex!(
            "077709362c2e32df0ddc3f0dc47bba63"
            "90b6c73bb50f9c3122ec844ad7c2b3e5"
        ));
        let expected_okm = &hex!(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        );

        t::<Hash, L>(TestParameters {
            ikm,
            salt,
            info,
            expected_prk,
            expected_okm,
        });
    }

    /// Test case 2 from [RFC 5869].
    ///
    /// [RFC 5869]: https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.2
    #[test]
    fn sha256_with_long_inputs_and_outputs() {
        type Hash = Sha256;
        const L: usize = 82;
        let ikm = &hex!(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f"
            "303132333435363738393a3b3c3d3e3f"
            "404142434445464748494a4b4c4d4e4f"
        );
        let salt = &hex!(
            "606162636465666768696a6b6c6d6e6f"
            "707172737475767778797a7b7c7d7e7f"
            "808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9f"
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        );
        let info = &hex!(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
            "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
            "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
            "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        );

        let expected_prk = HashOutput::Sha256(hex!(
            "06a6b88c5853361a06104c9ceb35b45c"
            "ef760014904671014a193f40c15fc244"
        ));
        let expected_okm = &hex!(
            "b11e398dc80327a1c8e7f78c596a4934"
            "4f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09"
            "da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f"
            "1d87"
        );

        t::<Hash, L>(TestParameters {
            ikm,
            salt,
            info,
            expected_prk,
            expected_okm,
        });
    }

    /// Test case 3 from [RFC 5869].
    ///
    /// [RFC 5869]: https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.3
    #[test]
    fn sha256_with_empty_salt_and_info() {
        type Hash = Sha256;
        const L: usize = 42;
        let ikm = &hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = &[];
        let info = &[];

        let expected_prk = HashOutput::Sha256(hex!(
            "19ef24a32c717b167f33a91d6f648bdf"
            "96596776afdb6377ac434c1c293ccb04"
        ));
        let expected_okm = &hex!(
            "8da4e775a563c18f715f802a063c5a31"
            "b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8"
        );

        t::<Hash, L>(TestParameters {
            ikm,
            salt,
            info,
            expected_prk,
            expected_okm,
        });
    }
}
