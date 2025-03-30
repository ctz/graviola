# from: aws-lc/crypto/fipsmodule/curve25519/curve25519_s2n_bignum_asm.c
#
# ```c
# # curve25519_s2n_bignum_asm.c
# void ed25519_public_key_from_hashed_seed_s2n_bignum(
#   uint8_t out_public_key[ED25519_PUBLIC_KEY_LEN],
#   uint8_t az[SHA512_DIGEST_LENGTH],
# );
# void ed25519_sha512(
#   uint8_t out[SHA512_DIGEST_LENGTH],
#   const void *input1, size_t len1,
#   const void *input2, size_t len2,
#   const void *input3, size_t len3,
#   const void *input4, size_t len4,
# );
# void ed25519_sign_s2n_bignum(
#   uint8_t out_sig[ED25519_SIGNATURE_LEN],
#   uint8_t r[SHA512_DIGEST_LENGTH],
#   const uint8_t *s,
#   const uint8_t *A,
#   const void *message, size_t message_len,
#   const uint8_t *dom2, size_t dom2_len,
# );
# int ed25519_verify_s2n_bignum(
#   uint8_t R_computed_encoded[32],
#   const uint8_t public_key[ED25519_PUBLIC_KEY_LEN],
#   uint8_t R_expected[32],
#   uint8_t S[32],
#   const uint8_t *message, size_t message_len,
#   const uint8_t *dom2, size_t dom2_len,
# );
#
# # s2n-bignum
# void bignum_madd_n25519(uint64_t out_z[4], uint64_t x[4], uint64_t y[4], uint64_t c[4]);
# void bignum_mod_n25519(uint64_t out_z[4], uint64_t k, uint64_t *x);
# void bignum_neg_p25519(uint64_t out_z[4], uint64_t x[4]);
# uint64_t edwards25519_decode(uint64_t out_z[8], const uint8_t c[32]);
# void edwards25519_encode(uint8_t out_z[static 32], uint64_t p[static 8]);
# void edwards25519_scalarmulbase(uint64_t out_res[8], uint64_t scalar[4]);
# void edwards25519_scalarmuldouble(uint64_t out_res[8], uint64_t scalar[4], uint64_t point[8], uint64_t bscalar[4]);
# ```

from parse import parse_file
from driver import (
    Architecture_aarch64,
    Architecture_amd64,
    RustDriver,
)

if __name__ == "__main__":
    with open(
        "../../thirdparty/s2n-bignum/x86/curve25519/edwards25519_decode.S"
    ) as input, open(
        "../../graviola/src/low/x86_64/edwards25519_decode.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "edwards25519_decode",
            parameter_map=[
                ("inout", "z.as_mut_ptr() => _"),
                ("inout", "c.as_ptr() => _"),
            ],
            return_value=("u64", "ret", "ret == 0"),
            return_map=("out", "ret"),
            hoist=["proc", "edwards25519_decode_loop", "ret"],
            rust_decl="fn edwards25519_decode(z: &mut [u64; 8], c: &[u8; 32]) -> bool",
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/arm/curve25519/edwards25519_decode_alt.S"
    ) as input, open(
        "../../graviola/src/low/aarch64/edwards25519_decode.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "edwards25519_decode_alt",
            parameter_map=[
                ("inout", "z.as_mut_ptr() => ret"),
                ("inout", "c.as_ptr() => _"),
            ],
            return_value=("u64", "ret", "ret == 0"),
            hoist=["proc", "edwards25519_decode_alt_loop", "ret"],
            rust_decl="fn edwards25519_decode(z: &mut [u64; 8], c: &[u8; 32]) -> bool",
        )
        parse_file(input, d)
