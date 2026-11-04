// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

/// takes a sequence of expressions (not separated by commas),
/// and feeds them into concat!() to form a single string
///
/// named after perl's q operator.
macro_rules! Q {
    ($($e:expr)*) => {
        concat!($($e ,)*)
    };
}

/// Label macro, which just resolves to the id as a string,
/// but keeps the name close to it in the code.
///
/// See the warnings about labels in the rust guide, this
/// means we use local labels without compromising so much
/// on readability.
macro_rules! Label {
    // declaration form
    ($name:literal, $id:literal) => {
        stringify!($id)
    };

    // reference form (downwards)
    ($name:literal, $id:literal, After) => {
        stringify!($id f)
    };

    // reference form (upwards)
    ($name:literal, $id:literal, Before) => {
        stringify!($id b)
    }
}

/// Plasters over the difference between ELF and Mach-O relocation
/// syntax, for page-aligned items.  (Only makes sense on aarch64).
#[cfg(target_vendor = "apple")]
macro_rules! PageRef {
    ($sym:literal) => { Q!( "{" $sym "}@PAGE" ) }
}

#[cfg(target_vendor = "apple")]
macro_rules! PageOffRef {
    ($sym:literal) => { Q!( "{" $sym "}@PAGEOFF" ) }
}

#[allow(unused_macros)]
#[cfg(not(target_vendor = "apple"))]
macro_rules! PageRef {
    ($sym:literal) => { Q!( "{" $sym "}" ) }
}

#[allow(unused_macros)]
#[cfg(not(target_vendor = "apple"))]
macro_rules! PageOffRef {
    ($sym:literal) => { Q!( ":lo12:" "{" $sym "}" ) }
}

/// Macro to declare and implement a token type that can be instantiated if and only if
/// a set of CPU features are all available
///
/// A value of this token type is proof that the CPU dynamic feature check has happened.
#[allow(unused_macros)]
macro_rules! cpu_feature_token {
    ($type:ident, $($feature:tt),+) => {
        #[derive(Clone, Copy, Debug)]
        pub(crate) struct $type(());
        impl $type {
            pub(crate) fn check() -> Option<Self> {
                $(
                   if !have_cpu_feature!($feature) {
                       return None;
                   }
                )*
                Some(Self(()))
            }
        }
    }
}
