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
    static HAVE_AVX512F: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *HAVE_AVX512F.get_or_init(|| test_toggle("avx512f", is_x86_feature_detected!("avx512f"))) {
        // SAFETY: the feature check confirms AVX-512F is available.
        unsafe { clear_avx512_registers() };
    }

    // zeroise simd registers

    // SAFETY: this crate requires the `avx` cpu feature.
    // SAFETY: all registers written by `vzeroall` are listed as clobbers.
    unsafe {
        core::arch::asm!(
            // clear z/y/xmm0-15
            "   vzeroall",

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

#[target_feature(enable = "avx512f")]
unsafe fn clear_avx512_registers() {
    // SAFETY: all registers written by the instructions are listed as clobbers.
    unsafe {
        core::arch::asm!(
            "vpxord zmm16, zmm16, zmm16",
            "vpxord zmm17, zmm17, zmm17",
            "vpxord zmm18, zmm18, zmm18",
            "vpxord zmm19, zmm19, zmm19",
            "vpxord zmm20, zmm20, zmm20",
            "vpxord zmm21, zmm21, zmm21",
            "vpxord zmm22, zmm22, zmm22",
            "vpxord zmm23, zmm23, zmm23",
            "vpxord zmm24, zmm24, zmm24",
            "vpxord zmm25, zmm25, zmm25",
            "vpxord zmm26, zmm26, zmm26",
            "vpxord zmm27, zmm27, zmm27",
            "vpxord zmm28, zmm28, zmm28",
            "vpxord zmm29, zmm29, zmm29",
            "vpxord zmm30, zmm30, zmm30",
            "vpxord zmm31, zmm31, zmm31",
            out("zmm16") _,
            out("zmm17") _,
            out("zmm18") _,
            out("zmm19") _,
            out("zmm20") _,
            out("zmm21") _,
            out("zmm22") _,
            out("zmm23") _,
            out("zmm24") _,
            out("zmm25") _,
            out("zmm26") _,
            out("zmm27") _,
            out("zmm28") _,
            out("zmm29") _,
            out("zmm30") _,
            out("zmm31") _,
        );
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

#[target_feature(enable = "avx,avx2")]
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
    let acc: u64;
    // SAFETY: reads `len` bytes from `a` and `b`, which the caller guarantees
    unsafe {
        core::arch::asm!(
            // by-8 loop
            "   2: cmp {len}, 8",
            "      jb  3f",
            "      mov {tmp}, [{a}]",
            "      xor {tmp}, [{b}]",
            "      or  {acc}, {tmp}",
            "      add {a}, 8",
            "      add {b}, 8",
            "      sub {len}, 8",
            "      jmp 2b",
            // by-1 loop
            "   3: test {len}, {len}",
            "      jz  4f",
            "      movzx {tmp:e}, byte ptr [{a}]",
            "      xor {tmp:l}, byte ptr [{b}]",
            "      or  {acc}, {tmp}",
            "      add {a}, 1",
            "      add {b}, 1",
            "      sub {len}, 1",
            "      jmp 3b",
            // acc = (acc != 0) ? !0 : 0
            "   4: neg {acc}",
            "      sbb {acc}, {acc}",
            a = inout(reg) a => _,
            b = inout(reg) b => _,
            len = inout(reg) len => _,
            tmp = out(reg) _,
            acc = inout(reg) 0u64 => acc,
        );
    }
    acc as u8
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
    ("avx512vbmi") => {
        crate::low::x86_64::cpu::test_toggle("avx512vbmi", is_x86_feature_detected!("avx512vbmi"))
    };
    ("avx512vbmi2") => {
        crate::low::x86_64::cpu::test_toggle("avx512vbmi2", is_x86_feature_detected!("avx512vbmi2"))
    };
    ("sha") => {
        crate::low::x86_64::cpu::test_toggle("sha", is_x86_feature_detected!("sha"))
    };
}

// Token types reflecting the checks for CPU features needed for various functions
// An instance of one of these types is proof that the CPU dynamic feature check
// has happened successfully.

// AVX512-AES-GCM
cpu_feature_token!(
    HaveAvx512ForAesGcm,
    "avx512f",
    "avx512bw",
    "avx512vl",
    "vpclmulqdq",
    "vaes"
);

// AVX512-ML-KEM
cpu_feature_token!(
    HaveAvx512ForMlKem,
    "avx512f",
    "avx512bw",
    "avx512vbmi",
    "avx512vbmi2"
);

// AVX512 Keccak-f1600
cpu_feature_token!(HaveAvx512ForSha3, "avx512f", "avx512vl");

// SHA256 using SHA-NI
cpu_feature_token!(HaveSha256, "sha");

// BMI2, useful for accelerating SHA-512
cpu_feature_token!(HaveBmi2, "bmi2");

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
    assert!(
        is_cpu_supported(),
        "graviola requires adx, aes, avx, avx2, bmi1, and pclmulqdq CPU support. \
        (rebuild with VALGRIND_BUG_494162 for valgrind compatibility)"
    );
}

pub(crate) fn is_cpu_supported() -> bool {
    // these are the cpu features we require unconditionally.
    // this limits the library to x86_64 processors released after approx 2013.
    // there are more features required, but (eg)
    // ssse3 is implied by avx.
    have_cpu_feature!("aes")
        && have_cpu_feature!("pclmulqdq")
        && have_cpu_feature!("bmi1")
        && (have_cpu_feature!("adx") || option_env!("VALGRIND_BUG_494162").is_some())
        && is_x86_feature_detected!("avx")
        && have_cpu_feature!("avx2")
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn leave_clears_high_zmm_registers() {
        if !is_x86_feature_detected!("avx512f") {
            return;
        }
        // SAFETY: AVX-512F was detected above.
        unsafe { check_high_zmm_registers() };
    }

    #[inline(never)]
    extern "C" fn leave_for_test() {
        leave_cpu_state(0);
    }

    #[target_feature(enable = "avx512f")]
    unsafe fn check_high_zmm_registers() {
        let mut registers = [[0xffu8; 64]; 16];
        // SAFETY: the buffer is writable, the called function follows the C register
        // convention on this platform, and all caller-saved registers are clobbered.
        unsafe {
            core::arch::asm!(
                "vpternlogd zmm16, zmm16, zmm16, 0xff",
                "vpternlogd zmm17, zmm17, zmm17, 0xff",
                "vpternlogd zmm18, zmm18, zmm18, 0xff",
                "vpternlogd zmm19, zmm19, zmm19, 0xff",
                "vpternlogd zmm20, zmm20, zmm20, 0xff",
                "vpternlogd zmm21, zmm21, zmm21, 0xff",
                "vpternlogd zmm22, zmm22, zmm22, 0xff",
                "vpternlogd zmm23, zmm23, zmm23, 0xff",
                "vpternlogd zmm24, zmm24, zmm24, 0xff",
                "vpternlogd zmm25, zmm25, zmm25, 0xff",
                "vpternlogd zmm26, zmm26, zmm26, 0xff",
                "vpternlogd zmm27, zmm27, zmm27, 0xff",
                "vpternlogd zmm28, zmm28, zmm28, 0xff",
                "vpternlogd zmm29, zmm29, zmm29, 0xff",
                "vpternlogd zmm30, zmm30, zmm30, 0xff",
                "vpternlogd zmm31, zmm31, zmm31, 0xff",
                "xor edi, edi",
                "call {leave}",
                "vmovdqu64 [r12 + 0], zmm16",
                "vmovdqu64 [r12 + 64], zmm17",
                "vmovdqu64 [r12 + 128], zmm18",
                "vmovdqu64 [r12 + 192], zmm19",
                "vmovdqu64 [r12 + 256], zmm20",
                "vmovdqu64 [r12 + 320], zmm21",
                "vmovdqu64 [r12 + 384], zmm22",
                "vmovdqu64 [r12 + 448], zmm23",
                "vmovdqu64 [r12 + 512], zmm24",
                "vmovdqu64 [r12 + 576], zmm25",
                "vmovdqu64 [r12 + 640], zmm26",
                "vmovdqu64 [r12 + 704], zmm27",
                "vmovdqu64 [r12 + 768], zmm28",
                "vmovdqu64 [r12 + 832], zmm29",
                "vmovdqu64 [r12 + 896], zmm30",
                "vmovdqu64 [r12 + 960], zmm31",
                leave = sym leave_for_test,
                in("r12") registers.as_mut_ptr(),
                clobber_abi("C"),
            );
        }
        assert_eq!(registers, [[0u8; 64]; 16]);
    }
}
