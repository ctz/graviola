// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

/// Check whether the full Graviola API works on the current CPU.
///
/// For applications using only specific algorithms, see [`is_cpu_feature_supported`].
pub fn is_cpu_supported() -> bool {
    crate::low::is_cpu_supported()
}

/// Cryptographic capabilities whose CPU support can be queried.
///
/// Combine capabilities with `|` to require support for all of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuFeature(u8);

impl CpuFeature {
    /// AES-128-GCM and AES-256-GCM.
    ///
    /// Requires `aes`, `ssse3`, `pclmulqdq`, `avx`, and `avx2` on x86_64,
    /// or `aes`, `pmull`, and `neon` on aarch64. ADX is not required.
    #[allow(non_upper_case_globals)]
    pub const AesGcm: Self = Self(1);

    /// X25519 key agreement.
    ///
    /// This currently uses the full library's CPU requirements, as checked
    /// by [`is_cpu_supported`].
    pub const X25519: Self = Self(2);

    fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for CpuFeature {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Check whether all the requested cryptographic capabilities work on this CPU.
///
/// These checks match the CPU guards used by the corresponding algorithms.
/// Optional accelerations such as AVX-512 are detected separately at runtime.
///
/// ```
/// use graviola::util::{CpuFeature, is_cpu_feature_supported};
///
/// let aes_gcm_supported = is_cpu_feature_supported(CpuFeature::AesGcm);
/// let both_supported =
///     is_cpu_feature_supported(CpuFeature::AesGcm | CpuFeature::X25519);
/// assert!(!both_supported || aes_gcm_supported);
/// ```
pub fn is_cpu_feature_supported(features: CpuFeature) -> bool {
    (!features.contains(CpuFeature::AesGcm) || crate::low::is_aes_gcm_cpu_supported())
        && (!features.contains(CpuFeature::X25519) || crate::low::is_cpu_supported())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatible_cpu() {
        // This assumes that Graviola is being built on a host that also supports
        // the minimum required runtime features.
        assert!(is_cpu_supported());
    }
}
