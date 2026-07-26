// Written for Graviola by Joe Birr-Pixton, 2026.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::{low, mid::sha3};

pub(super) fn sample_ntt(rho: &[u8; 32]) -> [i16; K * K * N] {
    _sample_ntt::<false>(rho)
}

pub(super) fn sample_ntt_transposed(rho: &[u8; 32]) -> [i16; K * K * N] {
    _sample_ntt::<true>(rho)
}

fn _sample_ntt<const TRANSPOSED: bool>(rho: &[u8; 32]) -> [i16; K * K * N] {
    let mut r = [0; _];

    // We have K * K polynomials to generate.  In this case, K := 3, so 9.
    // We attack this as one block of 8, followed by a stragger.

    let (output_8, output_tail) = r.split_at_mut(N * 8);

    let inputs = match TRANSPOSED {
        false => &[
            [0, 0],
            [1, 0],
            [2, 0],
            [0, 1],
            [1, 1],
            [2, 1],
            [0, 2],
            [1, 2],
        ],
        true => &[
            [0, 0],
            [0, 1],
            [0, 2],
            [1, 0],
            [1, 1],
            [1, 2],
            [2, 0],
            [2, 1],
        ],
    };

    _sample_poly_ntt_8x(rho, inputs, output_8.try_into().unwrap());

    Shake128ForMlKem::new(&[rho, &[2, 2]]).sample_into(output_tail.try_into().unwrap());

    r
}

fn _sample_poly_ntt_8x(rho: &[u8; 32], inputs: &[[u8; 2]; 8], outputs: &mut [i16; N * 8]) {
    let mut buf = [0; 40];
    buf[..32].copy_from_slice(rho);
    buf[34] = sha3::SHAKE_PAD_BYTE;

    // Expand the indices `inputs` into the prefix of SHAKE inputs, by prepending `rho` and
    // appending `SHAKE_PAD_BYTE`.
    let inputs = inputs.map(|ij| {
        let mut buf_ij = buf;
        buf_ij[32..34].clone_from_slice(&ij);
        buf_ij
    });

    for (inputs, outputs) in inputs.chunks_exact(4).zip(outputs.chunks_exact_mut(N * 4)) {
        let sponge_4x = sha3::SqueezingSponge4xShake128::new(&inputs.try_into().unwrap());

        let mut samples = [[0; sha3::SHAKE_128_R_BYTES * 3]; 4];
        let tail_sponges = sponge_4x.squeeze(&mut samples);

        for ((output, samples), tail_sponge) in outputs
            .chunks_exact_mut(N)
            .zip(samples.iter())
            .zip(tail_sponges)
        {
            let tail = Shake128ForMlKem::sample(samples, output.try_into().unwrap());
            if !tail.is_empty() {
                Shake128ForMlKem {
                    sponge: tail_sponge.restitute(),
                }
                .tail_case(tail);
            }
        }
    }
}

/// SHAKE128, but oriented at use in ML-KEM's `SampleNTT()`
struct Shake128ForMlKem {
    sponge: sha3::Shake128SqueezingSponge,
}

impl Shake128ForMlKem {
    fn new(message: &[&[u8]]) -> Self {
        Self {
            sponge: sha3::Shake128Sponge::new_for_message(message),
        }
    }

    /// Extract 256 coefficients that are < Q by rejection sampling.
    ///
    /// Refer to FIPS-203 `SampleNTT()`.  This function is the inner rejection loop.
    fn sample_into(mut self, output: &mut [i16; 256]) {
        // First, we squeeze three blocks.  Each block contributes up to 112 coefficients,
        // so we get 336 candidate coefficients.
        let mut initial_bytes = [0; sha3::SHAKE_128_R_BYTES * 3];
        self.sponge.squeeze(&mut initial_bytes);

        let tail = Self::sample(&initial_bytes, output);

        // If we were unlucky, 336 candidate coeffients weren't enough.  That
        // happens with low but not negligible probability (1 in ~120).
        if !tail.is_empty() {
            self.tail_case(tail);
        }
    }

    /// Sample into `output` using the bytes `samples`
    ///
    /// Returns the _unwritten_ items in output.  Call `tail_case()` with this value if
    /// non-empty.
    #[must_use]
    fn sample<'a>(
        samples: &'_ [u8; sha3::SHAKE_128_R_BYTES * 3],
        output: &'a mut [i16; 256],
    ) -> &'a mut [i16] {
        let used = low::mlkem_rej_uniform_vartime(output, samples) as usize;
        output.split_at_mut(used).1
    }

    fn tail_case(self, output: &mut [i16]) {
        let tail_iterator = Shake128TwelveBitIterator::new(self.sponge).filter(|f| *f < Q);

        for (out, coeff) in output.iter_mut().zip(tail_iterator) {
            *out = coeff;
        }
    }
}

/// Iterates over 12-bit samples drawn from `sponge`.
struct Shake128TwelveBitIterator {
    sponge: sha3::Shake128SqueezingSponge,
    samples: [i16; Self::SAMPLE_COUNT],
    used: usize,
}

impl Shake128TwelveBitIterator {
    fn new(sponge: sha3::Shake128SqueezingSponge) -> Self {
        Self {
            sponge,
            samples: [0; Self::SAMPLE_COUNT],
            used: Self::SAMPLE_COUNT,
        }
    }

    /// Each three bytes of SHAKE output yields two coefficients.
    const SAMPLE_COUNT: usize = sha3::SHAKE_128_R_BYTES / 3 * 2;
}

impl Iterator for Shake128TwelveBitIterator {
    type Item = i16;

    #[cold]
    fn next(&mut self) -> Option<Self::Item> {
        if self.used == self.samples.len() {
            let mut bytes = [0u8; sha3::SHAKE_128_R_BYTES];
            self.sponge.squeeze(&mut bytes);

            for (buf, d) in bytes.chunks_exact(3).zip(self.samples.chunks_exact_mut(2)) {
                d[0] = (u16::from_le_bytes([buf[0], buf[1]]) & 0xfff) as i16;
                d[1] = (u16::from_le_bytes([buf[1], buf[2]]) >> 4) as i16;
            }
            self.used = 0;
        }

        let item = self.samples[self.used];
        self.used += 1;
        Some(item)
    }
}
