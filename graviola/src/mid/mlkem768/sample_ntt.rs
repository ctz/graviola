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
    // We have a by-4 keccak, so we can attack the problem in two
    // sets of four, followed by one straggler.

    let mut work_iter = SAMPLE_POLY_WORK.chunks_exact(4);

    for c4 in work_iter.by_ref() {
        let inputs = match TRANSPOSED {
            false => &[
                &[c4[0].1, c4[0].0],
                &[c4[1].1, c4[1].0],
                &[c4[2].1, c4[2].0],
                &[c4[3].1, c4[3].0],
            ],
            true => &[
                &[c4[0].0, c4[0].1],
                &[c4[1].0, c4[1].1],
                &[c4[2].0, c4[2].1],
                &[c4[3].0, c4[3].1],
            ],
        };

        _sample_poly_ntt_quad(
            rho,
            inputs,
            (&mut r[c4[0].2..c4[3].2 + N]).try_into().unwrap(),
        );
    }

    for (i, j, offs) in work_iter.remainder() {
        let input = match TRANSPOSED {
            false => &[*j, *i],
            true => &[*i, *j],
        };
        Shake128ForMlKem::new(&[rho, input])
            .sample_into((&mut r[*offs..*offs + N]).try_into().unwrap());
    }

    r
}

fn _sample_poly_ntt_quad(rho: &[u8; 32], inputs: &[&[u8; 2]; 4], outputs: &mut [i16; N * 4]) {
    let mut buf = [0; 40];
    buf[..32].copy_from_slice(rho);
    buf[34] = sha3::SHAKE_PAD_BYTE;

    let mut buf0 = buf;
    buf0[32..34].clone_from_slice(inputs[0]);
    let mut buf1 = buf;
    buf1[32..34].clone_from_slice(inputs[1]);
    let mut buf2 = buf;
    buf2[32..34].clone_from_slice(inputs[2]);
    let mut buf3 = buf;
    buf3[32..34].clone_from_slice(inputs[3]);

    let sponge_4x = sha3::SqueezingSponge4xShake128::new(&[&buf0, &buf1, &buf2, &buf3]);
    let (output0, outputs) = outputs.split_at_mut(N);
    let (output1, outputs) = outputs.split_at_mut(N);
    let (output2, output3) = outputs.split_at_mut(N);

    let mut samples = [[0; sha3::SHAKE_128_R_BYTES * 3]; 4];
    let [tsponge0, tsponge1, tsponge2, tsponge3] = sponge_4x.squeeze(&mut samples);

    let tail0 = Shake128ForMlKem::sample(&samples[0], output0.try_into().unwrap());
    let tail1 = Shake128ForMlKem::sample(&samples[1], output1.try_into().unwrap());
    let tail2 = Shake128ForMlKem::sample(&samples[2], output2.try_into().unwrap());
    let tail3 = Shake128ForMlKem::sample(&samples[3], output3.try_into().unwrap());

    if !tail0.is_empty() {
        Shake128ForMlKem {
            sponge: tsponge0.restitute(),
        }
        .tail_case(tail0);
    }

    if !tail1.is_empty() {
        Shake128ForMlKem {
            sponge: tsponge1.restitute(),
        }
        .tail_case(tail1);
    }

    if !tail2.is_empty() {
        Shake128ForMlKem {
            sponge: tsponge2.restitute(),
        }
        .tail_case(tail2);
    }

    if !tail3.is_empty() {
        Shake128ForMlKem {
            sponge: tsponge3.restitute(),
        }
        .tail_case(tail3);
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

/// Values for i and j (pre-transpose) plus start offset of N coefficients within
/// a K * K * N matrix.
const SAMPLE_POLY_WORK: &[(u8, u8, usize)] = &[
    (0, 0, 0), //
    (0, 1, N),
    (0, 2, N * 2),
    (1, 0, K * N),
    (1, 1, N + K * N),
    (1, 2, N * 2 + K * N),
    (2, 0, K * N * 2),
    (2, 1, N + K * N * 2),
    (2, 2, N * 2 + K * N * 2),
];
