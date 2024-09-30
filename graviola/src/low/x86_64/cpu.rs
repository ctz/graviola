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

pub(crate) fn verify_cpu_features() {
    // these are the cpu features we require unconditionally.
    // this limits the library to x86_64 processors released after approx 2013.

    // mandatory feature requirements
    // our aes-gcm
    assert!(
        is_x86_feature_detected!("aes"),
        "graviola requires aes CPU support"
    );
    assert!(
        is_x86_feature_detected!("pclmulqdq"),
        "graviola requires pclmulqdq CPU support"
    );

    // s2n-bignum non _alt versions
    assert!(
        is_x86_feature_detected!("bmi1"),
        "graviola requires bmi1 CPU support"
    );
    assert!(
        is_x86_feature_detected!("adx"),
        "graviola requires adx CPU support"
    );

    // assorted intrinsic code
    assert!(
        is_x86_feature_detected!("avx"),
        "graviola requires avx CPU support"
    );
    assert!(
        is_x86_feature_detected!("avx2"),
        "graviola requires avx2 CPU support"
    );

    // there are more features required, but (eg)
    // ssse3 is implied by avx.
}
