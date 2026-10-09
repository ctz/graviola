//! <h1 align="center">Graviola</h1>
//! <img width="40%" align="right" src="https://raw.githubusercontent.com/ctz/graviola/main/admin/picture.png">
//!
//! This crate provides an integration between [rustls](https://github.com/rustls/rustls) and [Graviola](https://github.com/ctz/graviola/).
//!
//! Use it like:
//!
//! ```rust
//! use std::sync::Arc;
//!
//! let provider = Arc::new(rustls_graviola::default_provider());
//! let config_builder = rustls::ClientConfig::builder(provider);
//! ```
//!
//! And then use rustls as normal.

use std::borrow::Cow;
use std::sync::Arc;

use rustls::crypto::{CryptoProvider, TicketProducer, TicketerFactory};

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
        tls12_cipher_suites: Cow::Borrowed(suites::ALL_TLS12_CIPHER_SUITES),
        tls13_cipher_suites: Cow::Borrowed(suites::ALL_TLS13_CIPHER_SUITES),
        kx_groups: Cow::Borrowed(kx::ALL_KX_GROUPS),
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &RngProvider,
        key_provider: &sign::Provider,
        ticketer_factory: &TicketerProvider,
    }
}

#[derive(Debug)]
struct RngProvider;

impl rustls::crypto::SecureRandom for RngProvider {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        graviola::random::fill(bytes).map_err(|_| rustls::crypto::GetRandomFailed)
    }
}

#[derive(Debug)]
struct TicketerProvider;

impl TicketerFactory for TicketerProvider {
    fn ticketer(&self) -> Result<Arc<dyn TicketProducer>, rustls::Error> {
        Ticketer::new()
    }
}
