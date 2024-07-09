mod macros;

#[cfg(test)]
mod tests;

#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::{
    bignum_add_p256::bignum_add_p256, bignum_copy_row_from_table::bignum_copy_row_from_table,
    bignum_demont::bignum_demont, bignum_demont_p256::bignum_demont_p256, bignum_eq::bignum_eq,
    bignum_inv_p256::bignum_inv_p256, bignum_mod_n256::bignum_mod_n256,
    bignum_modadd::bignum_modadd, bignum_modinv::bignum_modinv, bignum_montifier::bignum_montifier,
    bignum_montmul::bignum_montmul, bignum_montmul_p256::bignum_montmul_p256,
    bignum_montsqr_p256::bignum_montsqr_p256, bignum_mux::bignum_mux,
    bignum_neg_p256::bignum_neg_p256, bignum_tomont_p256::bignum_tomont_p256,
    curve25519_x25519::curve25519_x25519, curve25519_x25519base::curve25519_x25519base,
    p256_montjadd::p256_montjadd, p256_montjdouble::p256_montjdouble,
    p256_montjmixadd::p256_montjmixadd, sha256_mux::sha256_compress_blocks,
    sha512_mux::sha512_compress_blocks,
};

#[cfg(target_arch = "aarch64")]
mod aarch64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::{
    bignum_add_p256::bignum_add_p256, bignum_copy_row_from_table::bignum_copy_row_from_table,
    bignum_demont_p256::bignum_demont_p256, bignum_eq::bignum_eq, bignum_inv_p256::bignum_inv_p256,
    bignum_mod_n256::bignum_mod_n256, bignum_montmul_p256::bignum_montmul_p256,
    bignum_montsqr_p256::bignum_montsqr_p256, bignum_mux::bignum_mux,
    bignum_neg_p256::bignum_neg_p256, bignum_tomont_p256::bignum_tomont_p256,
    curve25519_x25519::curve25519_x25519, curve25519_x25519base::curve25519_x25519base,
    p256_montjadd::p256_montjadd, p256_montjdouble::p256_montjdouble,
    p256_montjmixadd::p256_montjmixadd,
};

mod generic;
