// Written for Graviola by Joe Birr-Pixton, 2026.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use super::{K, N, Q};
use crate::{low, mid::sha3};

/// Sample A^ from `rho`.
///
/// `ninth` optionally supplies the ninth polynomial's bytes, squeezed ahead of time.
pub(super) fn sample_ntt(rho: &[u8; 32], ninth: Option<NinthPoly>) -> [i16; K * K * N] {
    sample_ntt_internal::<false>(rho, ninth)
}

/// Sample transpose(A^) from `rho`.
///
/// `ninth` optionally supplies the ninth polynomial's bytes, squeezed ahead of time.
pub(super) fn sample_ntt_transposed(rho: &[u8; 32], ninth: Option<NinthPoly>) -> [i16; K * K * N] {
    sample_ntt_internal::<true>(rho, ninth)
}

/// The ninth polynomial of A^, `A[2][2]`, with its SHAKE128 output squeezed ahead of time.
///
/// It is the same in A^ and transpose(A^).  Its three squeezes depend only on `rho`,
/// so they can share keccak-f permutations with other work.
pub(super) struct NinthPoly {
    sponge: sha3::Shake128SqueezingSponge,
    bytes: [u8; sha3::SHAKE_128_R_BYTES * 3],
}

impl NinthPoly {
    /// Squeeze the ninth polynomial's bytes from `rho`, while `other` absorbs `other_blocks`.
    ///
    /// `other` must be at a block boundary.
    pub(super) fn squeeze_alongside<const R: usize, const PAD: u8>(
        rho: &[u8; 32],
        other: &mut sha3::Sponge<R, PAD>,
        other_blocks: &[[u8; R]; 3],
    ) -> Self {
        let mut sponge = sha3::Shake128Sponge::new_for_message(&[rho, &[2, 2]]);
        let mut bytes = [0; _];
        for (block, out) in other_blocks.iter().zip(bytes.as_chunks_mut().0) {
            other.absorb_block_and_squeeze(block, &mut sponge, out);
        }
        Self { sponge, bytes }
    }
}

fn sample_ntt_internal<const TRANSPOSED: bool>(
    rho: &[u8; 32],
    ninth: Option<NinthPoly>,
) -> [i16; K * K * N] {
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

    sample_poly_ntt_8x(rho, inputs, output_8.try_into().unwrap());

    let output_tail = output_tail.try_into().unwrap();
    match ninth {
        Some(NinthPoly { sponge, bytes }) => {
            Shake128ForMlKem { sponge }.sample_from(&bytes, output_tail)
        }
        None => Shake128ForMlKem::new(&[rho, &[2, 2]]).sample_into(output_tail),
    }

    r
}

fn sample_poly_ntt_8x(rho: &[u8; 32], inputs: &[[u8; 2]; 8], outputs: &mut [i16; N * 8]) {
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

    low::mlkem768_sample_poly_ntt_8x(
        &inputs,
        outputs,
        sample_poly_ntt_8x_fallback,
        sample_poly_ntt_tail,
    )
}

fn sample_poly_ntt_8x_fallback(inputs: &[[u8; 40]; 8], outputs: &mut [i16; N * 8]) {
    let (input_quads, _) = inputs.as_chunks::<4>();
    let (output_quads, _) = outputs.as_chunks_mut::<{ N * 4 }>();
    for (inputs, outputs) in input_quads.iter().zip(output_quads.iter_mut()) {
        let sponge_4x = sha3::SqueezingSponge4xShake128::new(inputs);

        let mut samples = [[0; sha3::SHAKE_128_R_BYTES * 3]; 4];
        let tail_sponges = sponge_4x.squeeze(&mut samples);

        for ((output, samples), tail_sponge) in outputs
            .as_chunks_mut::<N>()
            .0
            .iter_mut()
            .zip(samples.iter())
            .zip(tail_sponges)
        {
            let tail = Shake128ForMlKem::sample(samples, output);
            if !tail.is_empty() {
                Shake128ForMlKem {
                    sponge: tail_sponge,
                }
                .tail_case(tail);
            }
        }
    }
}

fn sample_poly_ntt_tail(tail_sponge: &mut [u64; 25], tail: &mut [i16]) {
    Shake128ForMlKem {
        sponge: sha3::Shake128SqueezingSponge::from_owed_state(*tail_sponge),
    }
    .tail_case(tail);
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
        self.sample_from(&initial_bytes, output);
    }

    /// As [`Self::sample_into`], but with the first three blocks already squeezed into `bytes`.
    fn sample_from(self, bytes: &[u8; sha3::SHAKE_128_R_BYTES * 3], output: &mut [i16; 256]) {
        let tail = Self::sample(bytes, output);

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

            let (chunks, _) = bytes.as_chunks::<3>();
            for (buf, d) in chunks
                .iter()
                .zip(self.samples.as_chunks_mut::<2>().0.iter_mut())
            {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_poly_ntt_8x_matches_fallback() {
        // About 1 in 120 polynomials needs the tail case, so this covers
        // a good number of those, across every output position.
        let mut seed = [0u8; 32];
        for iter in 0..2000u32 {
            seed[..4].copy_from_slice(&iter.to_le_bytes());
            let mut rho = sha3::Shake128Sponge::new_for_message(&[&seed]);
            let mut rho_bytes = [0u8; 32];
            rho.squeeze(&mut rho_bytes);

            let inputs: [[u8; 2]; 8] = core::array::from_fn(|i| [i as u8, (iter % 3) as u8]);
            let mut got = [0i16; N * 8];
            sample_poly_ntt_8x(&rho_bytes, &inputs, &mut got);

            let mut expected = [0i16; N * 8];
            for (ij, out) in inputs
                .iter()
                .zip(expected.as_chunks_mut::<N>().0.iter_mut())
            {
                Shake128ForMlKem::new(&[&rho_bytes, ij]).sample_into(out);
            }

            assert_eq!(got, expected, "mismatch for iteration {iter}");
        }
    }

    #[test]
    fn ninth_poly_matches_unpaired() {
        // About 1 in 120 ninth polynomials needs the tail case, which is
        // sampled from the sponge left in `NinthPoly`.
        let blocks = [[0x5a; sha3::SHA3_256_R_BYTES]; 3];
        let mut tail_cases = 0;
        for iter in 0..2000u32 {
            let mut rho = [0u8; 32];
            rho[..4].copy_from_slice(&iter.to_le_bytes());

            let expect = sample_ntt(&rho, None);

            let mut other = sha3::Sha3_256Sponge::new();
            let ninth = NinthPoly::squeeze_alongside(&rho, &mut other, &blocks);
            if (low::mlkem_rej_uniform_vartime(&mut [0; N], &ninth.bytes) as usize) < N {
                tail_cases += 1;
            }
            assert_eq!(
                sample_ntt(&rho, Some(ninth)),
                expect,
                "mismatch for iteration {iter}"
            );
        }
        assert!(tail_cases > 0);
    }
}
