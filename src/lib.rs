//#![allow(clippy::result_unit_err, dead_code)]
//#![forbid(unused_must_use)]
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
// development: remove these
#![allow(missing_docs, unreachable_pub)]

mod low;
mod mid;

// vvv Public API

pub mod x25519 {
    pub use super::mid::x25519::{PrivateKey, PublicKey, SharedSecret};
}

pub mod p256 {
    pub use super::mid::p256::{PrivateKey, PublicKey, SharedSecret};
}
