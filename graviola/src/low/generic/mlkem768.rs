/// This does `SampleNTT()` for MLKEM768, yielding 8 polynomials worth of coefficients.
///
/// `inputs` are eight pre-formatted SHAKE inputs (already containing the domain separation bits.
///
/// `outputs` are where to write the coefficients.
///
/// `fallback_fn` is a complete fallback implementation of the whole function, reading `inputs` and
/// writing `outputs`.  It does not require `tail_fn`.
///
/// `tail_fn` takes a keccak state (which requires an immedate permutation prior to use) and a set
/// of "tail" coefficients which need to be filled via sampling the SHAKE output in the usual way.
/// This is called in uncommon situations.
pub(crate) fn mlkem768_sample_poly_ntt_8x(
    inputs: &[[u8; 40]; 8],
    outputs: &mut [i16; 256 * 8],
    fallback_fn: fn(&[[u8; 40]; 8], &mut [i16; 256 * 8]),
    _tail_fn: fn(&mut [u64; 25], &mut [i16]),
) {
    fallback_fn(inputs, outputs)
}
