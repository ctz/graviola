// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! RSA key generation routines.

use crate::low::{zeroise, PosInt};
use crate::mid::rng::RandomSource;
use crate::Error;

/// Supported RSA key sizes for key generation.
///
/// This refers to the public modulus size.
#[derive(Clone, Copy, Debug)]
pub(crate) enum RsaSize {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Rsa6144,
    Rsa8192,
}

impl RsaSize {
    fn public_modulus_size_bits(&self) -> usize {
        match self {
            Self::Rsa2048 => 2048,
            Self::Rsa3072 => 3072,
            Self::Rsa4096 => 4096,
            Self::Rsa6144 => 6144,
            Self::Rsa8192 => 8192,
        }
    }

    fn private_prime_size_bits(&self) -> usize {
        self.public_modulus_size_bits() / 2
    }
}

pub(super) fn generate_key(
    size: RsaSize,
    random: &mut dyn RandomSource,
) -> Result<super::RsaPrivateKey, Error> {
    loop {
        let p = random_prime(size, random)?;
        let q = random_prime(size, random)?;

        let n: super::RsaPosIntModN = PosInt::mul(&p, &q);

        let one = PosInt::word(1);

        let p_1 = p.sub(&one);
        let q_1 = q.sub(&one);

        let phi = PosInt::mul(&p_1, &q_1);

        let e = PosInt::word(PUBLIC_EXPONENT.into());
        e.debug("e");
        phi.debug("phi");

        if !phi.is_coprime(&e) {
            continue;
        }

        let d = e.mod_inverse(&phi);
        d.debug("d");

        let iqmp = q.mod_inverse(&p);
        iqmp.debug("iqmp");
        let dp = d.reduce(&p, &p.montifier());
        let dq = d.reduce(&q, &q.montifier());

        return super::RsaPrivateKey::new(
            p,
            q,
            d.into(),
            dp.into(),
            dq.into(),
            iqmp.into(),
            n,
            PUBLIC_EXPONENT,
        );
    }
}

const PUBLIC_EXPONENT: u32 = 0x10001;

fn random_prime(
    size: RsaSize,
    random: &mut dyn RandomSource,
) -> Result<super::RsaPosIntModP, Error> {
    let bytes = size.private_prime_size_bits() / 8;

    loop {
        let mut buffer = [0u8; super::MAX_PRIVATE_MODULUS_BYTES];
        random.fill(&mut buffer[..bytes])?;

        // set top two bits to ensure the product of two primes, n, is the right size.
        buffer[0] |= 0b1100_0000;

        // set bottom bit: an even number (of size bounded by RsaSize) is never prime
        buffer[bytes - 1] |= 0b0000_0001;

        let candidate = PosInt::from_bytes(&buffer[..bytes])?;

        if is_prime(&candidate) {
            // this is the one we'll use, so it becomes sensitive on return.
            zeroise(&mut buffer[..bytes]);

            return Ok(candidate.into());
        }
    }
}

fn is_prime(candidate: &PosInt<{ super::MAX_PRIVATE_MODULUS_WORDS }>) -> bool {
    let small_primes = PosInt::from_bytes(PRODUCT_OF_SMALL_PRIMES).unwrap();

    if !candidate.is_coprime(&small_primes) {
        println!("small primes fail");
        return false;
    }

    // TODO: Rabin-Miller, with rounds chosen from `RsaSize` or size of candidate
    true
}

/// Product of the primes from 3..743, such that the product fits in 1024-bits
/// -- our smallest allowed prime.
const PRODUCT_OF_SMALL_PRIMES: &[u8] = &[
    0x02, 0xc8, 0x5f, 0xf8, 0x70, 0xf2, 0x4b, 0xe8, 0x0f, 0x62, 0xb1, 0xba, 0x6c, 0x20, 0xbd, 0x72,
    0xb8, 0x37, 0xef, 0xdf, 0x12, 0x12, 0x06, 0xd8, 0x7d, 0xb5, 0x6b, 0x7d, 0x69, 0xfa, 0x4c, 0x02,
    0x1c, 0x10, 0x7c, 0x3c, 0xa2, 0x06, 0xfe, 0x8f, 0xa7, 0x08, 0x0e, 0xf5, 0x76, 0xef, 0xfc, 0x82,
    0xf9, 0xb1, 0x0f, 0x57, 0x50, 0x65, 0x6b, 0x77, 0x94, 0xb1, 0x6a, 0xfd, 0x70, 0x99, 0x6e, 0x91,
    0xae, 0xf6, 0xe0, 0xad, 0x15, 0xe9, 0x1b, 0x07, 0x1a, 0xc9, 0xb2, 0x4d, 0x98, 0xb2, 0x33, 0xad,
    0x86, 0xee, 0x05, 0x55, 0x18, 0xe5, 0x8e, 0x56, 0x63, 0x8e, 0xf1, 0x8b, 0xac, 0x5c, 0x74, 0xcb,
    0x35, 0xbb, 0xb6, 0xe5, 0xda, 0xe2, 0x78, 0x3d, 0xd1, 0xc0, 0xce, 0x7d, 0xec, 0x4f, 0xc7, 0x0e,
    0x51, 0x86, 0xd4, 0x11, 0xdf, 0x36, 0x36, 0x8f, 0x06, 0x1a, 0xa3, 0x60, 0x11, 0xf3, 0x01, 0x79,
];
