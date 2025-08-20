// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::arch::x86_64::*;

pub(crate) fn enter_cpu_state() -> u32 {
    // DOIT: "Data Operand Independent Timing" -- turning this on
    // is under kernel control, because MSRs are privileged.
    // <https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/data-operand-independent-timing-isa-guidance.html>
    0
}

pub(crate) fn leave_cpu_state(_old: u32) {
    // zeroise simd registers

    // SAFETY: this crate requires the `avx` cpu feature.
    // SAFETY: all registers written by `vzeroall` are listed as clobbers.
    unsafe {
        core::arch::asm!(
            // clear z/y/xmm0-15
            "   vzeroall",

            // TODO: add zmm16-31 here if/when we use AVX512
            out("ymm0") _,
            out("ymm1") _,
            out("ymm2") _,
            out("ymm3") _,
            out("ymm4") _,
            out("ymm5") _,
            out("ymm6") _,
            out("ymm7") _,
            out("ymm8") _,
            out("ymm9") _,
            out("ymm10") _,
            out("ymm11") _,
            out("ymm12") _,
            out("ymm13") _,
            out("ymm14") _,
            out("ymm15") _,
        )
    }
}

/// Effectively memset(ptr, 0, len), but not visible to optimiser
///
/// # Safety
/// The caller must ensure that there are `len` bytes writable at `ptr`,
/// and that the pointed-to object has a safe all-zeroes representation.
/// (see `low::generic::zeroise` which expresses this within the type system).
pub(in crate::low) fn zero_bytes(ptr: *mut u8, len: usize) {
    // SAFETY: this crate requires the `avx` cpu feature
    unsafe { _zero_bytes(ptr, len) }
}

#[target_feature(enable = "avx")]
unsafe fn _zero_bytes(ptr: *mut u8, len: usize) {
    // SAFETY: writes to `len` bytes at `ptr`, which the caller guarantees
    unsafe {
        core::arch::asm!(
            "       vpxor   {zero}, {zero}, {zero}",
            // by-32 loop
            "   2:  cmp {len}, 32",
            "       jl  3f",
            "       vmovdqu [{ptr}], {zero}",
            "       add {ptr}, 32",
            "       sub {len}, 32",
            "       jmp 2b",
            // by-1 loop
            "   3:  sub {len}, 1",
            "       jl  4f",
            "       mov byte ptr [{ptr}], 0",
            "       add {ptr}, 1",
            "       jmp 3b",
            "   4:  ",

            ptr = inout(reg) ptr => _,
            len = inout(reg) len => _,

            // clobbers
            zero = out(ymm_reg) _,
        )
    }
}

/// Effectively memcmp(a, b, len), but guaranteed to visit every element
/// of a and b.
///
/// The return value does not follow memcmp semantics: it is zero if
/// `a == b`, otherwise it is non-zero.
///
/// # Safety
/// The caller must ensure that there are `len` bytes readable at `a` and `b`,
pub(in crate::low) unsafe fn ct_compare_bytes(a: *const u8, b: *const u8, len: usize) -> u8 {
    let mut acc = 0u8;
    // SAFETY: reads `len` bytes from `a` and `b`, which the caller guarantees
    unsafe {
        core::arch::asm!(
            "   2: cmp {len}, 0",
            "      je  3f",
            "      mov {tmp}, [{a}]",
            "      xor {tmp}, [{b}]",
            "      or  {acc}, {tmp}",
            "      add {a}, 1",
            "      add {b}, 1",
            "      sub {len}, 1",
            "      jmp 2b",
            "   3:  ",
            a = inout(reg) a => _,
            b = inout(reg) b => _,
            len = inout(reg) len => _,
            tmp = inout(reg_byte) 0u8 => _,
            acc = inout(reg_byte) acc,
        );
    }
    acc
}

/// This macro interdicts is_x86_feature_detected to
/// allow testability.
macro_rules! have_cpu_feature {
    ("aes") => {
        crate::low::x86_64::cpu::test_toggle("aes", is_x86_feature_detected!("aes"))
    };
    ("vaes") => {
        crate::low::x86_64::cpu::test_toggle("vaes", is_x86_feature_detected!("vaes"))
    };
    ("pclmulqdq") => {
        crate::low::x86_64::cpu::test_toggle("pclmulqdq", is_x86_feature_detected!("pclmulqdq"))
    };
    ("vpclmulqdq") => {
        crate::low::x86_64::cpu::test_toggle("vpclmulqdq", is_x86_feature_detected!("vpclmulqdq"))
    };
    ("bmi1") => {
        crate::low::x86_64::cpu::test_toggle("bmi1", is_x86_feature_detected!("bmi1"))
    };
    ("bmi2") => {
        crate::low::x86_64::cpu::test_toggle("bmi2", is_x86_feature_detected!("bmi2"))
    };
    ("adx") => {
        crate::low::x86_64::cpu::test_toggle("adx", is_x86_feature_detected!("adx"))
    };
    ("avx") => {
        crate::low::x86_64::cpu::test_toggle("avx", is_x86_feature_detected!("avx"))
    };
    ("avx2") => {
        crate::low::x86_64::cpu::test_toggle("avx2", is_x86_feature_detected!("avx2"))
    };
    ("avx512f") => {
        crate::low::x86_64::cpu::test_toggle("avx512f", is_x86_feature_detected!("avx512f"))
    };
    ("avx512bw") => {
        crate::low::x86_64::cpu::test_toggle("avx512bw", is_x86_feature_detected!("avx512bw"))
    };
    ("avx512vl") => {
        crate::low::x86_64::cpu::test_toggle("avx512vl", is_x86_feature_detected!("avx512vl"))
    };
    ("sha") => {
        crate::low::x86_64::cpu::test_toggle("sha", is_x86_feature_detected!("sha"))
    };
}

/// Token type reflecting the check for CPU features needed for AVX512-AES-GCM
///
/// A value of this type is proof that the CPU dynamic feature check has happened.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HaveAvx512ForAesGcm(());

impl HaveAvx512ForAesGcm {
    pub(crate) fn check() -> Option<Self> {
        match have_cpu_feature!("avx512f")
            && have_cpu_feature!("avx512bw")
            && have_cpu_feature!("avx512vl")
            && have_cpu_feature!("vpclmulqdq")
            && have_cpu_feature!("vaes")
        {
            true => Some(Self(())),
            false => None,
        }
    }
}

/// Token type reflecting the check for CPU features needed for SHA256 using SHA-NI
///
/// A value of this type is proof that the CPU dynamic feature check has happened.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HaveSha256(());

impl HaveSha256 {
    pub(crate) fn check() -> Option<Self> {
        match have_cpu_feature!("sha") {
            true => Some(Self(())),
            false => None,
        }
    }
}

/// Token type reflecting the check for the BMI2 CPU feature
///
/// A value of this type is proof that the CPU dynamic feature check has happened.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HaveBmi2(());

impl HaveBmi2 {
    pub(crate) fn check() -> Option<Self> {
        match have_cpu_feature!("bmi2") {
            true => Some(Self(())),
            false => None,
        }
    }
}
#[cfg(not(debug_assertions))]
pub(crate) fn test_toggle(_id: &str, detected: bool) -> bool {
    detected
}

#[cfg(debug_assertions)]
pub(crate) fn test_toggle(id: &str, detected: bool) -> bool {
    if std::env::var(format!("GRAVIOLA_CPU_DISABLE_{id}")).is_ok() {
        println!("DEBUG: denying cpuid {id:?}");
        false
    } else {
        detected
    }
}

pub(crate) fn verify_cpu_features() {
    // these are the cpu features we require unconditionally.
    // this limits the library to x86_64 processors released after approx 2013.

    // mandatory feature requirements
    // our aes-gcm
    assert!(
        have_cpu_feature!("aes"),
        "graviola requires aes CPU support"
    );
    assert!(
        have_cpu_feature!("pclmulqdq"),
        "graviola requires pclmulqdq CPU support"
    );

    // s2n-bignum non _alt versions
    assert!(
        have_cpu_feature!("bmi1"),
        "graviola requires bmi1 CPU support"
    );

    // see this valgrind bug: https://bugs.kde.org/show_bug.cgi?id=494162
    assert!(
        have_cpu_feature!("adx") || option_env!("VALGRIND_BUG_494162").is_some(),
        "graviola requires adx CPU support (rebuild with VALGRIND_BUG_494162 for valgrind compatibility)"
    );

    // assorted intrinsic code
    assert!(
        is_x86_feature_detected!("avx"),
        "graviola requires avx CPU support"
    );
    assert!(
        have_cpu_feature!("avx2"),
        "graviola requires avx2 CPU support"
    );

    // there are more features required, but (eg)
    // ssse3 is implied by avx.
}

// --- Safe abstractions over common intrinsics operations ---

/// Prefetch both `table` and `table[stride]`
///
/// `table[stride]` is not range checked, as prefetching doesn't need a valid
/// pointer.
#[target_feature(enable = "sse")]
#[inline]
pub(crate) fn prefetch<T>(table: &[T], stride: usize) {
    // SAFETY: prefetches do not fault and are not architecturally visible
    unsafe {
        _mm_prefetch(table.as_ptr().cast(), _MM_HINT_T0);
        _mm_prefetch(table.as_ptr().add(stride).cast(), _MM_HINT_T0);
    }
}

/// Load 8 64-bit words from an array.
#[target_feature(enable = "avx")]
#[inline]
pub(crate) fn load_8x_u64(x: &[u64; 8]) -> (__m256i, __m256i) {
    // SAFETY: `x` is exactly 8 elements and readable due to it coming from a reference.
    unsafe {
        (
            _mm256_loadu_si256(x.as_ptr().add(0).cast()),
            _mm256_loadu_si256(x.as_ptr().add(4).cast()),
        )
    }
}

/// Load 8 64-bit words from a slice of exactly 8 items.
#[target_feature(enable = "avx")]
#[inline]
pub(crate) fn load_8x_u64_slice(slice: &[u64]) -> (__m256i, __m256i) {
    assert_eq!(slice.len(), 8);

    // SAFETY: `slice` is exactly 8 elements and readable due to it coming from a reference.
    unsafe {
        (
            _mm256_loadu_si256(slice.as_ptr().add(0).cast()),
            _mm256_loadu_si256(slice.as_ptr().add(4).cast()),
        )
    }
}

/// Store 8 64-bit words into an array of 8 items.
#[target_feature(enable = "avx")]
#[inline]
pub(crate) fn store_8x_u64(out: &mut [u64; 8], a: __m256i, b: __m256i) {
    // SAFETY: `out` is writable as it comes from a mut ref, and 8 items
    unsafe {
        _mm256_storeu_si256(out.as_mut_ptr().add(0).cast(), a);
        _mm256_storeu_si256(out.as_mut_ptr().add(4).cast(), b);
    }
}

/// Store 8 64-bit words into an slice of exactly 8 items.
#[target_feature(enable = "avx")]
#[inline]
pub(crate) fn store_8x_u64_slice(out: &mut [u64], a: __m256i, b: __m256i) {
    assert_eq!(out.len(), 8);

    // SAFETY: `out` is writable as it comes from a mut ref, and 8 items
    unsafe {
        _mm256_storeu_si256(out.as_mut_ptr().add(0).cast(), a);
        _mm256_storeu_si256(out.as_mut_ptr().add(4).cast(), b);
    }
}

/// Load 12 64-bit words from a slice of exactly 12 items.
#[target_feature(enable = "avx")]
#[inline]
pub(crate) fn load_12x_u64_slice(slice: &[u64]) -> (__m256i, __m256i, __m256i) {
    assert_eq!(slice.len(), 12);

    // SAFETY: `slice` is exactly 12 elements and readable due to it coming from a reference.
    unsafe {
        (
            _mm256_loadu_si256(slice.as_ptr().add(0).cast()),
            _mm256_loadu_si256(slice.as_ptr().add(4).cast()),
            _mm256_loadu_si256(slice.as_ptr().add(8).cast()),
        )
    }
}

/// Store 12 64-bit words into an array of 12 items.
#[target_feature(enable = "avx")]
#[inline]
pub(crate) fn store_12x_u64(out: &mut [u64; 12], a: __m256i, b: __m256i, c: __m256i) {
    // SAFETY: `out` is writable as it comes from a mut ref, and 12 items
    unsafe {
        _mm256_storeu_si256(out.as_mut_ptr().add(0).cast(), a);
        _mm256_storeu_si256(out.as_mut_ptr().add(4).cast(), b);
        _mm256_storeu_si256(out.as_mut_ptr().add(8).cast(), c);
    }
}

/// Load 16 64-bit words from a slice of exactly 16 items.
#[target_feature(enable = "avx")]
#[inline]
pub(crate) fn load_16x_u64_slice(slice: &[u64]) -> (__m256i, __m256i, __m256i, __m256i) {
    assert_eq!(slice.len(), 16);

    // SAFETY: `slice` is exactly 16 elements and readable due to it coming from a reference.
    unsafe {
        (
            _mm256_loadu_si256(slice.as_ptr().add(0).cast()),
            _mm256_loadu_si256(slice.as_ptr().add(4).cast()),
            _mm256_loadu_si256(slice.as_ptr().add(8).cast()),
            _mm256_loadu_si256(slice.as_ptr().add(12).cast()),
        )
    }
}

/// Store 16 64-bit words into a slice of exactly 16 items.
#[target_feature(enable = "avx")]
#[inline]
pub(crate) fn store_16x_u64_slice(out: &mut [u64], a: __m256i, b: __m256i, c: __m256i, d: __m256i) {
    assert_eq!(out.len(), 16);

    // SAFETY: `out` is writable as it comes from a mut ref, and 16 items
    unsafe {
        _mm256_storeu_si256(out.as_mut_ptr().add(0).cast(), a);
        _mm256_storeu_si256(out.as_mut_ptr().add(4).cast(), b);
        _mm256_storeu_si256(out.as_mut_ptr().add(8).cast(), c);
        _mm256_storeu_si256(out.as_mut_ptr().add(12).cast(), d);
    }
}
