// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

/// All errors that may happen in this crate.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Error {
    /// Some slice was the wrong length.
    WrongLength,

    /// An compressed elliptic curve point encoding was encountered.
    NotUncompressed,

    /// A public key was invalid.
    NotOnCurve,

    /// A value was too small or large.
    OutOfRange,

    /// A random number generator returned an error or fixed values.
    RngFailed,

    /// Presented signature is invalid.
    BadSignature,

    /// Presented AEAD tag/aad/ciphertext/nonce was wrong
    DecryptFailed,

    /// An ASN.1 encoding/decoding error.
    Asn1Error(crate::high::asn1::Error),
}
