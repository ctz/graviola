// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
#![doc = include_str!("../README.md")]

//! # Yo, where are the API docs?
//! At the moment, this crate doesn't have a public API.
//! It is coming soon.
//!
//! The cryptography here is available for use with rustls
//! via [rustls-graviola](https://crates.io/crates/rustls-graviola).

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
    trivial_numeric_casts,
    unused_import_braces,
    unused_extern_crates,
    unused_qualifications
)]
// XXX: development: remove these
#![allow(missing_docs, unreachable_pub)]

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
mod high;

/// Errors.  Common to all layers.
mod error;

// vvv Internal API

#[cfg(feature = "__internal_08eaf2eb")]
pub mod x25519 {
    pub use super::mid::x25519::{PrivateKey, PublicKey, SharedSecret};
}

#[cfg(feature = "__internal_08eaf2eb")]
pub mod p256 {
    pub use super::mid::p256::{PrivateKey, PublicKey, SharedSecret};
}

#[cfg(feature = "__internal_08eaf2eb")]
pub mod p384 {
    pub use super::mid::p384::{PrivateKey, PublicKey, SharedSecret};
}

#[cfg(feature = "__internal_08eaf2eb")]
pub mod rsa {
    pub use super::high::rsa::{RsaPrivateSigningKey, RsaPublicVerificationKey};
}

#[cfg(feature = "__internal_08eaf2eb")]
pub mod ecdsa {
    pub use super::high::curve::{Curve, P256, P384};
    pub use super::high::ecdsa::{SigningKey, VerifyingKey};
}

#[cfg(feature = "__internal_08eaf2eb")]
pub mod hash {
    pub use super::high::hash::{Hash, HashContext, HashOutput, Sha256, Sha384, Sha512};
    pub use super::high::hmac;
    pub use super::mid::sha2;
}

#[cfg(feature = "__internal_08eaf2eb")]
pub mod aead {
    pub use super::mid::aes_gcm::AesGcm;
    pub use super::mid::chacha20poly1305::ChaCha20Poly1305;
}

#[cfg(feature = "__internal_08eaf2eb")]
pub mod rng {
    pub use super::mid::rng::{RandomSource, SystemRandom};
}

// vvv Public API
pub use error::Error;
