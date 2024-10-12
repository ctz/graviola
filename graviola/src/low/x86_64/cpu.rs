// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

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

/// This macro interdicts is_x86_feature_detected to
/// allow testability.
macro_rules! have_cpu_feature {
    ("aes") => {
        crate::low::x86_64::cpu::test_toggle("aes", is_x86_feature_detected!("aes"))
    };
    ("pclmulqdq") => {
        crate::low::x86_64::cpu::test_toggle("pclmulqdq", is_x86_feature_detected!("pclmulqdq"))
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
    ("sha") => {
        crate::low::x86_64::cpu::test_toggle("sha", is_x86_feature_detected!("sha"))
    };
}

pub(crate) use have_cpu_feature;

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

    // we should have here:
    //
    // assert!(
    //    have_cpu_feature!("adx"),
    //    "graviola requires adx CPU support"
    // );
    //
    // however, valgrind is buggy (https://bugs.kde.org/show_bug.cgi?id=494162)
    // -- therefore rely on the expectation that `adx` support is implied by
    // `bmi1` support.

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
