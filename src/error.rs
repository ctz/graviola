/// All errors that may happen in this crate.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Error {
    /// Some slice was the wrong length.
    WrongLength,

    /// An compressed elliptic curve point encoding was encountered.
    NotUncompressed,

    /// A public key was invalid.
    NotOnCurve,

    /// A value was too small or large.
    OutOfRange,

    /// A random number generator returned an error or fixed values.
    RngFailed,

    /// Presented signature is invalid.
    BadSignature,
}
