mod macros;

#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::{
    curve25519_x25519::curve25519_x25519, curve25519_x25519base::curve25519_x25519base,
};

#[cfg(target_arch = "aarch64")]
mod aarch64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::{
    curve25519_x25519::curve25519_x25519, curve25519_x25519base::curve25519_x25519base,
};
