// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! HMAC-based Key Derivation Function (HKDF).
//!
//! HKDF is defined in [RFC 5869].
//!
//! # Examples
//!
//! ```
//! use graviola::hashing::{Sha256, hkdf};
//! use graviola::random;
//!
//! // Generate a random salt.
//! let mut salt = [0u8; 32];
//! random::fill(&mut salt).unwrap();
//!
//! // Secret initial keying material.
//! let ikm = b"\x00\x01\x02\x03"; // i.e., NOT this.
//!
//! // Extract a pseudorandom key from IKM.
//! let prk = hkdf::ExtractedPrk::<Sha256>::extract(Some(&salt), ikm);
//!
//! let expander = prk.into_expander();
//!
//! // Expand the PRK into an OKM for each key. The non-secret optional
//! // context and application specific information (`info`) differ
//! // between keys.
//! let mut client_key = [0u8; 32];
//! expander.expand(&[b"client key"], &mut client_key).unwrap();
//!
//! let mut server_key = [0u8; 32];
//! expander.expand(&[b"server key"], &mut server_key).unwrap();
//!
//! // Use the derived keys...
//! ```
//!
//! [RFC 5869]: https://datatracker.ietf.org/doc/html/rfc5869

use core::error::Error;
use core::fmt;
use core::marker::PhantomData;

use crate::hashing::{Hash, HashOutput};
use crate::high::hmac::Hmac;
use crate::low::{Entry, zeroise};

/// A pseudorandom key (the output from the [extract step]).
///
/// [extract step]: ExtractedPrk::extract
pub struct ExtractedPrk<H: Hash> {
    key: HashOutput,
    phantom: PhantomData<fn() -> H>,
}

impl<H: Hash> fmt::Debug for ExtractedPrk<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtractedPrk").finish_non_exhaustive()
    }
}

impl<H: Hash> Drop for ExtractedPrk<H> {
    fn drop(&mut self) {
        zeroise(self.key.as_mut());
    }
}

impl<H: Hash> ExtractedPrk<H> {
    /// The [HKDF-Extract] step.
    ///
    /// Extracts a fixed-length pseudorandom key from the input keying
    /// material `ikm`.
    ///
    /// If `salt` is not provided, it is set to a string of hash-length zeroes.
    ///
    /// [HKDF-Extract]: https://datatracker.ietf.org/doc/html/rfc5869#section-2.2
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        let _entry = Entry::new_secret();

        let mut hmac = match salt {
            Some(salt) => Hmac::<H>::new(salt),
            None => Hmac::<H>::new(H::zeroed_output()),
        };
        hmac.update(ikm);
        let key = hmac.finish();
        Self {
            key,
            phantom: PhantomData,
        }
    }

    /// The raw bytes of the pseudorandom key.
    ///
    /// <div class="warning">
    ///
    /// Read [Section 3.3 of RFC 5869] before using! It is not
    /// recommended to use the PRK directly as the OKM. Most common
    /// scenarios will want to turn the [`ExtractedPrk`] into an
    /// [`Expander`] using [`into_expander()`] and then [expand].
    ///
    /// </div>
    ///
    /// [Section 3.3 of RFC 5869]: https://datatracker.ietf.org/doc/html/rfc5869#section-3.3
    /// [`into_expander()`]: Self::into_expander
    /// [expand]: Expander::expand
    pub fn as_bytes(&self) -> &[u8] {
        self.key.as_ref()
    }

    /// Turns the [`ExtractedPrk`] into an [`Expander`] that can be used
    /// to [expand] the PRK repeatedly into OKMs.
    ///
    /// [expand]: Expander::expand
    pub fn into_expander(self) -> Expander<H> {
        let _entry = Entry::new_secret();

        let hmac = Hmac::<H>::new(&self.key);
        Expander { hmac }
    }
}

/// An [`Expander`] can be used to expand a pseudorandom key into
/// several keys.
///
/// Each call to [expand] is independent: the same `info` always gives the
/// same output, and a shorter output is a prefix of a longer one.
///
/// [expand]: Expander::expand
pub struct Expander<H: Hash> {
    hmac: Hmac<H>,
}

impl<H: Hash> fmt::Debug for Expander<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Expander").finish_non_exhaustive()
    }
}

impl<H: Hash> Expander<H> {
    /// Constructs an [`Expander`] from a uniformly random or
    /// pseudorandom cryptographically strong key.
    ///
    /// <div class="warning">
    ///
    /// Read [Section 3.3 of RFC 5869] before using! Most common
    /// scenarios will want to [extract] a PRK
    /// then call [`ExtractedPrk::into_expander`] instead.
    ///
    /// </div>
    ///
    /// # Errors
    ///
    /// Returns [`PrkTooShortError`] if `prk` is shorter than the length of
    /// the hash function output.
    ///
    /// [Section 3.3 of RFC 5869]: https://datatracker.ietf.org/doc/html/rfc5869#section-3.3
    /// [extract]: ExtractedPrk::extract
    pub fn new_less_safe(prk: impl AsRef<[u8]>) -> Result<Self, PrkTooShortError> {
        let _entry = Entry::new_secret();

        let prk = prk.as_ref();
        if prk.len() < H::OUTPUT_SZ {
            return Err(PrkTooShortError);
        }
        let hmac = Hmac::<H>::new(prk);
        Ok(Self { hmac })
    }

    /// The [HKDF-Expand] step.
    ///
    /// Expands the pseudorandom key into an output keying material `okm`.
    ///
    /// The `info` slices are concatenated to form the single `info` string,
    /// so `&[b"AB", b"CD"]` and `&[b"ABC", b"D"]` are equivalent.
    ///
    /// # Errors
    ///
    /// Returns [`OkmTooLongError`] if `okm` is longer than 255 times the
    /// length of the hash function output.
    ///
    /// [HKDF-Expand]: https://datatracker.ietf.org/doc/html/rfc5869#section-2.3
    pub fn expand(&self, info: &[&[u8]], okm: &mut [u8]) -> Result<(), OkmTooLongError> {
        let _entry = Entry::new_secret();

        if okm.len() > const { 255 * H::OUTPUT_SZ } {
            return Err(OkmTooLongError);
        }

        let mut t: Option<HashOutput> = None;
        for (chunk, i) in okm.chunks_mut(H::OUTPUT_SZ).zip(1..=u8::MAX) {
            let mut hmac = self.hmac.clone();
            if let Some(t) = t.as_mut() {
                hmac.update(t.as_ref());
                zeroise(t.as_mut());
            }
            for info in info {
                hmac.update(info);
            }
            hmac.update([i]);
            let t = t.insert(hmac.finish());
            chunk.copy_from_slice(&t.as_ref()[..chunk.len()]);
        }
        if let Some(t) = t.as_mut() {
            zeroise(t.as_mut());
        }

        Ok(())
    }
}

/// Error returned when the OKM buffer used in the expand step is
/// longer than 255 times the length of the hash function output.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct OkmTooLongError;

impl fmt::Display for OkmTooLongError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("output keying material is longer than 255 times the length of the hash function output")
    }
}

impl Error for OkmTooLongError {}

/// Error returned when a PRK buffer that would be used in the expand step is
/// shorter than the length of the hash function output.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct PrkTooShortError;

impl fmt::Display for PrkTooShortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("pseudorandom key is shorter than the length of the hash function output")
    }
}

impl Error for PrkTooShortError {}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::hashing::Sha256;

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

        let prk = ExtractedPrk::<H>::extract(Some(salt), ikm);
        assert!(expected_prk.ct_equal(prk.as_bytes()));
        let mut okm = [0; L];
        prk.into_expander().expand(&[info], &mut okm).unwrap();
        assert_eq!(okm.as_ref(), expected_okm);

        let expander = Expander::<H>::new_less_safe(expected_prk.as_ref()).unwrap();
        let mut okm = [0; L];
        expander.expand(&[info], &mut okm).unwrap();
        assert_eq!(okm.as_ref(), expected_okm);
    }

    /// Test case 1 from [RFC 5869].
    ///
    /// [RFC 5869]: https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.1
    #[test]
    fn basic_with_sha256() {
        type Hash = Sha256;
        const L: usize = 42;
        let ikm = &[
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ];
        let salt = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let expected_prk = HashOutput::Sha256([
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ]);
        let expected_okm = &[
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

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
        let ikm = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
            0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        ];
        let salt = &[
            0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
            0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b,
            0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
            0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
            0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        ];
        let info = &[
            0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
            0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
            0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9,
            0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
            0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
            0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
        ];

        let expected_prk = HashOutput::Sha256([
            0x06, 0xa6, 0xb8, 0x8c, 0x58, 0x53, 0x36, 0x1a, 0x06, 0x10, 0x4c, 0x9c, 0xeb, 0x35,
            0xb4, 0x5c, 0xef, 0x76, 0x00, 0x14, 0x90, 0x46, 0x71, 0x01, 0x4a, 0x19, 0x3f, 0x40,
            0xc1, 0x5f, 0xc2, 0x44,
        ]);
        let expected_okm = &[
            0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a,
            0x49, 0x34, 0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c,
            0x19, 0xaf, 0xa9, 0x7c, 0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb,
            0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09, 0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
            0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71, 0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec,
            0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f, 0x1d, 0x87,
        ];

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
        let ikm = &[
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ];
        let salt = &[];
        let info = &[];

        let expected_prk = HashOutput::Sha256([
            0x19, 0xef, 0x24, 0xa3, 0x2c, 0x71, 0x7b, 0x16, 0x7f, 0x33, 0xa9, 0x1d, 0x6f, 0x64,
            0x8b, 0xdf, 0x96, 0x59, 0x67, 0x76, 0xaf, 0xdb, 0x63, 0x77, 0xac, 0x43, 0x4c, 0x1c,
            0x29, 0x3c, 0xcb, 0x04,
        ]);
        let expected_okm = &[
            0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c,
            0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f,
            0x3c, 0x73, 0x8d, 0x2d, 0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8,
        ];

        t::<Hash, L>(TestParameters {
            ikm,
            salt,
            info,
            expected_prk,
            expected_okm,
        });
    }

    #[test]
    fn sha256_with_empty_okm() {
        type Hash = Sha256;
        const L: usize = 0;
        let ikm = &[
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ];
        let salt = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let expected_prk = HashOutput::Sha256([
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ]);
        let expected_okm = &[];

        t::<Hash, L>(TestParameters {
            ikm,
            salt,
            info,
            expected_prk,
            expected_okm,
        });
    }
}
