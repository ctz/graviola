// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

/// Check whether Graviola works on the current CPU.
pub fn is_cpu_supported() -> bool {
    crate::low::is_cpu_supported()
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
