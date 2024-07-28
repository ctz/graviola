#![deny(unsafe_code)]

#[cfg(target_arch = "x86_64")]
pub mod aes_gcm;
pub mod p256;
pub mod rng;
pub mod sha2;
pub mod util;
pub mod x25519;
