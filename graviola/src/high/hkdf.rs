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
    use super::*;
    use crate::hashing::Sha256;

    /// Test case 1 from [RFC 5869].
    ///
    /// [RFC 5869]: https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.1
    #[test]
    fn basic_with_sha256() {
        type Hash = Sha256;
        const L: usize = 42;
        let ikm: &[u8] = &[0x0b; 22];
        let salt: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c";
        let info: &[u8] = b"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9";

        let expected_prk = b"\x07\x77\x09\x36\x2c\x2e\x32\xdf\x0d\xdc\x3f\x0d\xc4\x7b\xba\x63\x90\xb6\xc7\x3b\xb5\x0f\x9c\x31\x22\xec\x84\x4a\xd7\xc2\xb3\xe5";
        let expected_okm = b"\x3c\xb2\x5f\x25\xfa\xac\xd5\x7a\x90\x43\x4f\x64\xd0\x36\x2f\x2a\x2d\x2d\x0a\x90\xcf\x1a\x5a\x4c\x5d\xb0\x2d\x56\xec\xc4\xc5\xbf\x34\x00\x72\x08\xd5\xb8\x87\x18\x58\x65";

        let prk = extract::<Hash>(Some(salt), ikm);
        assert_eq!(prk, Prk::Extracted(HashOutput::Sha256(*expected_prk)));
        let mut okm = [0; L];
        expand::<Hash>(&prk, info, &mut okm);
        assert_eq!(okm.as_ref(), expected_okm);
    }
}
