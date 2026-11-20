// Written for Graviola by Joe Birr-Pixton, 2025.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::ops::{Deref, DerefMut};

cfg_if::cfg_if! {
    if #[cfg(all(test, feature = "__ctgrind"))] {
        use crabgrind::{memcheck, valgrind};
        use core::mem::size_of_val;

        #[inline]
        pub(crate) fn secret_slice<T>(v: &[T]) {
            if let valgrind::RunningMode::Valgrind = valgrind::running_mode() {
                memcheck::mark_memory(
                    v.as_ptr().cast(),
                    size_of_val(v),
                    memcheck::MemState::Undefined,
                )
                .unwrap();
            }
        }

        #[inline]
        pub(crate) fn public_slice<T>(v: &[T]) {
            if let valgrind::RunningMode::Valgrind = valgrind::running_mode() {
                memcheck::mark_memory(
                    v.as_ptr().cast(),
                    size_of_val(v),
                    memcheck::MemState::Defined,
                )
                .unwrap();
            }
        }

        #[inline]
        #[must_use]
        pub(crate) fn into_secret<T>(v: T) -> T {
            mark_secret(&v);
            v
        }

        #[inline]
        #[must_use]
        pub(crate) fn into_public<T>(v: T) -> T {
            mark_public(&v);
            v
        }

        #[inline]
        fn mark_secret<T>(v: &T) {
            if let valgrind::RunningMode::Valgrind = valgrind::running_mode() {
                memcheck::mark_memory(
                    (v as *const T).cast(),
                    size_of_val(v),
                    memcheck::MemState::Undefined,
                )
                .unwrap();
            }
        }

        #[inline]
        fn mark_public<T>(v: &T) {
            if let valgrind::RunningMode::Valgrind = valgrind::running_mode() {
                memcheck::mark_memory(
                    (v as *const T).cast(),
                    size_of_val(v),
                    memcheck::MemState::Defined,
                )
                .unwrap();
            }
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

        #[inline]
        fn mark_secret<T>(_v: &T) {}

        #[inline]
        fn mark_public<T>(_v: &T) {}
    }
}

// Wrapper that holds a reference to an object and asks ctgrind to ensure that no
// non-constant-time operations are done on the object during the wrapper's lifetime
pub(crate) struct CT<'a, T> {
    inner: &'a T
}

impl<'a, T> CT<'a, T> {
    pub(crate) fn new(inner: &'a T) -> Self {
        mark_secret(inner);
        Self { inner }
    }
}

impl <'a, T> Drop for CT<'a, T> {
    fn drop(&mut self) {
        mark_public(self.inner);
    }
}

impl<'a, T> Deref for CT<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}


// `CT` for mutable objects
pub(crate) struct CTMut<'a, T> {
    inner: &'a mut T
}

impl<'a, T> CTMut<'a, T> {
    pub(crate) fn new(inner: &'a mut T) -> Self {
        mark_secret(inner);
        Self { inner }
    }
}

impl <'a, T> Drop for CTMut<'a, T> {
    fn drop(&mut self) {
        mark_public(self.inner);
    }
}

impl<'a, T> Deref for CTMut<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

impl<'a, T>  DerefMut for CTMut<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner
    }
}

// `CT` for variable-size slices
pub(crate) struct CTSlice<'a, T> {
    inner: &'a [T],
}

impl<'a, T> CTSlice<'a, T> {
    pub(crate) fn new(inner: &'a [T]) -> Self {
        secret_slice(inner);
        Self { inner }
    }
}

impl<'a, T> Drop for CTSlice<'a, T> {
    fn drop(&mut self) {
        public_slice(self.inner);
    }
}

impl<'a, T> Deref for CTSlice<'a, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

// `CT` for mutable, variable-size slices
pub(crate) struct CTSliceMut<'a, T> {
    inner: &'a mut [T],
}

impl<'a, T> CTSliceMut<'a, T> {
    pub(crate) fn new(inner: &'a mut [T]) -> Self {
        secret_slice(inner);
        Self { inner }
    }
}

impl<'a, T> Drop for CTSliceMut<'a, T> {
    fn drop(&mut self) {
        public_slice(self.inner);
    }
}

impl<'a, T> Deref for CTSliceMut<'a, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

impl<'a, T> DerefMut for CTSliceMut<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner
    }
}
