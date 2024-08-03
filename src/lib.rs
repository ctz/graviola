#![allow(
    clippy::new_without_default,
    clippy::result_unit_err,
    clippy::too_many_arguments
)]
#![forbid(unused_must_use)]
#![warn(
    clippy::alloc_instead_of_core,
    clippy::clone_on_ref_ptr,
    clippy::std_instead_of_core,
    clippy::use_self,
    clippy::upper_case_acronyms,
    elided_lifetimes_in_paths,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_extern_crates,
    unused_qualifications
)]
// XXX: development: remove these
#![allow(missing_docs, unreachable_pub, dead_code)]

/// Low level operations.
///
/// `unsafe` is allowed only here.
///
/// Examples: elliptic curve field operations,
/// bignum arithmetic.
mod low;

/// Mid-level APIs.
///
/// Examples: elliptic curve group operations.
mod mid;

/// High-level APIs.
///
/// Examples: key encodings, high-level constructions.
pub mod high;

/// Errors.  Common to all layers.
mod error;

// vvv Public API

pub mod x25519 {
    pub use super::mid::x25519::{PrivateKey, PublicKey, SharedSecret};
}

pub mod p256 {
    pub use super::mid::p256::{PrivateKey, PublicKey, SharedSecret};
}

pub mod ecdsa {
    pub use super::high::ecdsa::{SigningKey, VerifyingKey};
}

pub mod ec {
    pub use super::high::curve::{Curve, P256};
}

pub mod sha2 {
    pub use super::mid::sha2::{Sha256Context, Sha384Context, Sha512Context};
}

pub mod hash {
    pub use super::high::hash::{Hash, HashContext, HashOutput, Sha256, Sha384, Sha512};
}

pub use error::Error;
pub use mid::aes_gcm;
pub use mid::rng::{RandomSource, SystemRandom};
