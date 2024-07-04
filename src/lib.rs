#![allow(clippy::result_unit_err, dead_code)]

mod low;
mod mid;

// vvv Public API

pub mod x25519 {
    pub use super::mid::x25519::{PrivateKey, PublicKey, SharedSecret};
}

pub mod p256 {
    pub use super::mid::p256::{PrivateKey, PublicKey, SharedSecret};
}
