// Written for Graviola by Joe Birr-Pixton, 2025.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

cfg_if::cfg_if! {
    if #[cfg(all(test, target_os = "linux", target_arch = "x86_64"))] {
        use crabgrind as cg;
        use core::mem::size_of_val;

        #[inline]
        pub(crate) fn secret_slice<T>(v: &[T]) {
            cg::monitor_command(format!(
                "make_memory undefined {:p} {}",
                v.as_ptr(),
                size_of_val(v)
            ))
            .unwrap();
        }

        #[inline]
        pub(crate) fn public_slice<T>(v: &[T]) {
            cg::monitor_command(format!(
                "make_memory defined {:p} {}",
                v.as_ptr(),
                size_of_val(v)
            ))
            .unwrap();
        }

        #[inline]
        #[must_use]
        pub(crate) fn into_secret<T>(v: T) -> T {
            cg::monitor_command(format!(
                "make_memory undefined {:p} {}",
                &v as *const T,
                size_of_val(&v)
            ))
            .unwrap();
            v
        }

        #[inline]
        #[must_use]
        pub(crate) fn into_public<T>(v: T) -> T {
            cg::monitor_command(format!(
                "make_memory defined {:p} {}",
                &v as *const T,
                size_of_val(&v)
            ))
            .unwrap();
            v
        }
    } else {
        #[inline]
        pub(crate) fn secret_slice<T>(_v: &[T]) {}

        #[inline]
        pub(crate) fn public_slice<T>(_v: &[T]) {}

        #[inline]
        #[must_use]
        pub(crate) fn into_secret<T>(v: T) -> T { v }

        #[inline]
        #[must_use]
        pub(crate) fn into_public<T>(v: T) -> T { v }
    }
}
