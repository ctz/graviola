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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn leave_cpu_state_clears_vector_regs() {
        #[target_feature(enable = "avx2")]
        #[inline]
        fn fill_regs() {
            // SAFETY: test code
            unsafe {
                core::arch::asm!(
                    "   vpcmpeqd ymm0, ymm0, ymm0",
                    "   vpcmpeqd ymm1, ymm1, ymm1",
                    "   vpcmpeqd ymm2, ymm2, ymm2",
                    "   vpcmpeqd ymm3, ymm3, ymm3",
                    "   vpcmpeqd ymm4, ymm4, ymm4",
                    "   vpcmpeqd ymm5, ymm5, ymm5",
                    "   vpcmpeqd ymm6, ymm6, ymm6",
                    "   vpcmpeqd ymm7, ymm7, ymm7",
                    "   vpcmpeqd ymm8, ymm8, ymm8",
                    "   vpcmpeqd ymm9, ymm9, ymm9",
                    "   vpcmpeqd ymm10, ymm10, ymm10",
                    "   vpcmpeqd ymm11, ymm11, ymm11",
                    "   vpcmpeqd ymm12, ymm12, ymm12",
                    "   vpcmpeqd ymm13, ymm13, ymm13",
                    "   vpcmpeqd ymm14, ymm14, ymm14",
                    "   vpcmpeqd ymm15, ymm15, ymm15",
                )
            }
        }

        #[target_feature(enable = "avx2")]
        #[inline]
        fn which_regs_are_zero() -> u64 {
            let mut out: u64;

            macro_rules! check_reg {
                ($reg:literal) => { Q!(
                    "   shl {out}, 1;\n"
                    "   mov {tmp}, {out};\n"
                    "   inc {tmp};\n"
                    "   vptest " $reg "," $reg ";\n"
                    "   cmovz {out}, {tmp};\n"
                )}
            }

            // SAFETY: test code
            unsafe {
                core::arch::asm!(
                    "   mov {out}, 0",
                    check_reg!("ymm15"),
                    check_reg!("ymm14"),
                    check_reg!("ymm13"),
                    check_reg!("ymm12"),
                    check_reg!("ymm11"),
                    check_reg!("ymm10"),
                    check_reg!("ymm9"),
                    check_reg!("ymm8"),
                    check_reg!("ymm7"),
                    check_reg!("ymm6"),
                    check_reg!("ymm5"),
                    check_reg!("ymm4"),
                    check_reg!("ymm3"),
                    check_reg!("ymm2"),
                    check_reg!("ymm1"),
                    check_reg!("ymm0"),

                    out = out(reg) out,
                    tmp = out(reg) _,
                )
            }
            out
        }

        // SAFETY: test code
        unsafe {
            fill_regs();
            assert_eq!(which_regs_are_zero(), 0);
            leave_cpu_state(0);
            assert!(matches!(
                which_regs_are_zero(),
                ALL_CALLER_SAVE_YMM_REGISTERS | ALL_CALLER_SAVE_YMM_REGISTERS_WINDOWS
            ));
        }
    }

    // see https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170
    // XMM0-XMM5 inclusive are caller-save.  both of these are possible, depending on whether
    // `leave_cpu_state` is inlined.
    const ALL_CALLER_SAVE_YMM_REGISTERS_WINDOWS: u64 = 0b0000_0000_0011_1111;
    const ALL_CALLER_SAVE_YMM_REGISTERS: u64 = 0b1111_1111_1111_1111;
}
