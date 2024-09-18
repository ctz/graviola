// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use super::asn1::pkix;
use super::asn1::{self, Integer, Type};
use crate::error::{Error, KeyFormatError};

/// Helper for decoding PKCS#8 key encodings.
///
/// This decodes the given slice as a whole `PrivateKeyInfo`, and then:
///
/// - ensures the version is 0,
/// - ensures the key algorithm is `algorithm`,
/// - ensures the parameters are `parameters`.
///
/// Then returns the slice that covers the `privateKey` `OCTET STRING` body,
/// that can be decoded by the caller as the correct asn1 type.
pub(crate) fn decode_pkcs8<'a>(
    slice: &'a [u8],
    algorithm: &asn1::ObjectId,
    parameters: Option<asn1::Any<'_>>,
) -> Result<&'a [u8], Error> {
    let pki =
        pkix::PrivateKeyInfo::parse(&mut asn1::Parser::new(slice)).map_err(Error::Asn1Error)?;

    if pki.version != Integer::new(&[0]) {
        return Err(KeyFormatError::UnsupportedPkcs8Version.into());
    }

    if pki.privateKeyAlgorithm.algorithm != *algorithm {
        return Err(KeyFormatError::MismatchedPkcs8Algorithm.into());
    }

    if pki.privateKeyAlgorithm.parameters != parameters {
        return Err(KeyFormatError::MismatchedPkcs8Parameters.into());
    }

    Ok(pki.privateKey.into_octets())
}
