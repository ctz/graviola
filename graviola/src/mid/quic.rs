// Written for Graviola by Joe Birr-Pixton, 2025.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! QUIC-specific cryptography.
//!
//! Do not use this except to implement QUIC.

use crate::low::chacha20::ChaCha20;
use crate::low::zeroise;
use crate::low::AesKey;

/// QUIC Header Protection, using AES-128 or AES-256.
///
/// See RFC9001 section 5.4.3
pub struct AesHeaderProtection(AesKey);

impl AesHeaderProtection {
    /// Create a new `AesHeaderProtection`, given a key of 128 or 256 bits.
    pub fn new(key: &[u8]) -> Self {
        Self(AesKey::new(key))
    }

    /// Encrypt `packet_0` and a prefix of `packet_number`.
    ///
    /// `sample` is the header protection sample.
    ///
    /// The number of bytes altered in `packet_number` is given by the bottom 2 bits
    /// of `packet_0`.
    pub fn encrypt_in_place(&self, sample: &[u8; 16], packet_0: &mut u8, packet_number: &mut [u8]) {
        let mut mask = *sample;
        self.0.encrypt_block(&mut mask);
        let mask = mask[..5].try_into().unwrap_or_else(|_| unreachable!());

        cipher_in_place::<true>(mask, packet_0, packet_number);
    }

    /// Decrypt `packet_0` and a prefix of `packet_number`.
    ///
    /// `sample` is the header protection sample.
    ///
    /// The number of bytes altered in `packet_number` is given by the bottom 2 bits
    /// of `packet_0`.
    pub fn decrypt_in_place(&self, sample: &[u8; 16], packet_0: &mut u8, packet_number: &mut [u8]) {
        let mut mask = *sample;
        self.0.encrypt_block(&mut mask);
        let mask = mask[..5].try_into().unwrap_or_else(|_| unreachable!());

        cipher_in_place::<false>(mask, packet_0, packet_number);
    }
}

/// QUIC Header Protection, using ChaCha20.
///
/// See RFC9001 section 5.4.4
pub struct ChaCha20HeaderProtection([u8; 32]);

impl ChaCha20HeaderProtection {
    /// Create a new `ChaCha20HeaderProtection`, given a key of 256 bits.
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
    /// Encrypt `packet_0` and a prefix of `packet_number`.
    ///
    /// `sample` is the header protection sample.
    ///
    /// The number of bytes altered in `packet_number` is given by the bottom 2 bits
    /// of `packet_0`.
    pub fn encrypt_in_place(&self, sample: &[u8; 16], packet_0: &mut u8, packet_number: &mut [u8]) {
        let mut mask = [0u8; 5];
        ChaCha20::new(&self.0, sample).cipher(&mut mask);
        cipher_in_place::<true>(mask, packet_0, packet_number);
    }

    /// Decrypt `packet_0` and a prefix of `packet_number`.
    ///
    /// `sample` is the header protection sample.
    ///
    /// The number of bytes altered in `packet_number` is given by the bottom 2 bits
    /// of `packet_0`.
    pub fn decrypt_in_place(&self, sample: &[u8; 16], packet_0: &mut u8, packet_number: &mut [u8]) {
        let mut mask = [0u8; 5];
        ChaCha20::new(&self.0, sample).cipher(&mut mask);
        cipher_in_place::<false>(mask, packet_0, packet_number);
    }
}

impl Drop for ChaCha20HeaderProtection {
    fn drop(&mut self) {
        zeroise(&mut self.0);
    }
}

fn cipher_in_place<const ENC: bool>(mask: [u8; 5], packet_0: &mut u8, packet_number: &mut [u8]) {
    let (mask_0, mask) = mask.split_first().unwrap_or_else(|| unreachable!());

    let mask_0 = match *packet_0 & HEADER_FORM_LONG == HEADER_FORM_LONG {
        true => mask_0 & 0x0f,
        false => mask_0 & 0x1f,
    };

    let pn_length = if ENC {
        let len = (*packet_0 & 0x03) as usize + 1;
        *packet_0 ^= mask_0;
        len
    } else {
        *packet_0 ^= mask_0;
        (*packet_0 & 0x03) as usize + 1
    };

    for (pn, m) in packet_number.iter_mut().zip(mask.iter()).take(pn_length) {
        *pn ^= m;
    }
}

const HEADER_FORM_LONG: u8 = 0x80u8;

#[cfg(test)]
mod tests {
    use super::*;

    // all known-answer tests from RFC9001 appendix A

    #[test]
    fn client_initial() {
        let k = AesHeaderProtection::new(
            b"\x9f\x50\x44\x9e\x04\xa0\xe8\x10\x28\x3a\x1e\x99\x33\xad\xed\xd2",
        );

        let mut packet_0 = 0xc3;
        let mut packet_number = [0x00, 0x00, 0x00, 0x02];
        let sample = &[
            0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8, 0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23,
            0xdc, 0x9b,
        ];

        k.encrypt_in_place(sample, &mut packet_0, &mut packet_number);
        assert_eq!(packet_0, 0xc0);
        assert_eq!(packet_number, [0x7b, 0x9a, 0xec, 0x34]);

        k.decrypt_in_place(sample, &mut packet_0, &mut packet_number);
        assert_eq!(packet_0, 0xc3);
        assert_eq!(packet_number, [0x00, 0x00, 0x00, 0x02]);
    }

    #[test]
    fn server_initial() {
        let k = AesHeaderProtection::new(
            b"\xc2\x06\xb8\xd9\xb9\xf0\xf3\x76\x44\x43\x0b\x49\x0e\xea\xa3\x14",
        );

        let mut packet_0 = 0xc1;
        let mut packet_number = [0x00, 0x01];
        let sample = &[
            0x2c, 0xd0, 0x99, 0x1c, 0xd2, 0x5b, 0x0a, 0xac, 0x40, 0x6a, 0x58, 0x16, 0xb6, 0x39,
            0x41, 0x00,
        ];

        k.encrypt_in_place(sample, &mut packet_0, &mut packet_number);
        assert_eq!(packet_0, 0xcf);
        assert_eq!(packet_number, [0xc0, 0xd9]);

        k.decrypt_in_place(sample, &mut packet_0, &mut packet_number);
        assert_eq!(packet_0, 0xc1);
        assert_eq!(packet_number, [0x00, 0x01]);
    }

    #[test]
    fn chacha20_short_header() {
        let k = ChaCha20HeaderProtection::new(
            *b"\x25\xa2\x82\xb9\xe8\x2f\x06\xf2\x1f\x48\x89\x17\xa4\xfc\x8f\x1b\
               \x73\x57\x36\x85\x60\x85\x97\xd0\xef\xcb\x07\x6b\x0a\xb7\xa7\xa4",
        );

        let mut packet_0 = 0x42;
        let mut packet_number = [0x00, 0xbf, 0xf4];
        let sample = &[
            0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80, 0x57, 0x5d, 0x79, 0x99, 0xc2, 0x5a,
            0x5b, 0xfb,
        ];

        k.encrypt_in_place(sample, &mut packet_0, &mut packet_number);
        assert_eq!(packet_0, 0x4c);
        assert_eq!(packet_number, [0xfe, 0x41, 0x89]);

        k.decrypt_in_place(sample, &mut packet_0, &mut packet_number);
        assert_eq!(packet_0, 0x42);
        assert_eq!(packet_number, [0x00, 0xbf, 0xf4]);
    }
}
