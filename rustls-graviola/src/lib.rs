//! <h1 align="center">Graviola</h1>
//! <img width="40%" align="right" src="https://raw.githubusercontent.com/ctz/graviola/main/admin/picture.png">
//!
//! This crate provides an integration between [rustls](https://github.com/rustls/rustls) and [Graviola](https://github.com/ctz/graviola/).
//!
//! Use it like:
//!
//! ```rust
//! rustls_graviola::default_provider()
//!     .install_default()
//!     .unwrap();
//! ```
//!
//! And then use rustls as normal.

use rustls::crypto::CryptoProvider;

mod aead;
mod hash;
mod hmac;
mod sign;
mod verify;

/// Supported key exchange algorithms.
pub mod kx;

/// Supported cipher suites.
pub mod suites;

mod ticketer;
pub use ticketer::Ticketer;

/// This is a rustls [`CryptoProvider`] using cryptography from Graviola.
///
/// This provides the same algorithms as the rustls *ring*-based
/// provider, which are interoperable and safe defaults for modern TLS.
pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: suites::ALL_CIPHER_SUITES.to_vec(),
        kx_groups: kx::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &RngProvider,
        key_provider: &sign::Provider,
    }
}

#[derive(Debug)]
struct RngProvider;

impl rustls::crypto::SecureRandom for RngProvider {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        graviola::random::fill(bytes).map_err(|_| rustls::crypto::GetRandomFailed)
    }
}
