// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use std::arch::is_aarch64_feature_detected;

pub(crate) fn enter_cpu_state() -> u32 {
    dit::maybe_enable()
}

pub(crate) fn leave_cpu_state(old: u32) {
    dit::maybe_disable(old);
}

/// Effectively memset(ptr, 0, len), but not visible to optimiser
///
/// # Safety:
/// There must be `len` writable bytes at `ptr`; with no alignment
/// requirement.
pub(in crate::low) fn zero_bytes(ptr: *mut u8, len: usize) {
    // SAFETY: inline assembly.
    unsafe {
        core::arch::asm!(
            "       eor {zero}.16b, {zero}.16b, {zero}.16b",
            // by-16 loop
            "   2:  cmp {len}, #16",
            "       blt 3f",
            "       st1 {{{zero}.16b}}, [{ptr}]",
            "       add {ptr}, {ptr}, #16",
            "       sub {len}, {len}, #16",
            "       b 2b",
            // by-1 loop
            "   3:  subs {len}, {len}, #1",
            "       blt 4f",
            "       strb wzr, [{ptr}], #1",
            "       b 3b",
            "   4:  ",

            ptr = inout(reg) ptr => _,
            len = inout(reg) len => _,

            // clobbers
            zero = out(vreg) _,
        )
    }
}

pub(crate) fn verify_cpu_features() {
    assert!(
        is_aarch64_feature_detected!("neon"),
        "graviola requires neon CPU support"
    );
    assert!(
        is_aarch64_feature_detected!("aes"),
        "graviola requires aes CPU support"
    );
    assert!(
        is_aarch64_feature_detected!("pmull"),
        "graviola requires pmull CPU support"
    );
    assert!(
        is_aarch64_feature_detected!("sha2"),
        "graviola requires sha2 CPU support"
    );
}

mod dit {
    pub(super) fn maybe_enable() -> u32 {
        if super::is_aarch64_feature_detected!("dit") {
            // SAFETY: in this branch, we verified `dit` cpu feature is supported
            match unsafe { read() } {
                0 => {
                    // SAFETY: in this branch, we verified `dit` cpu feature is supported
                    unsafe {
                        write(1);
                    };
                    1
                }
                _ => 0,
            }
        } else {
            0
        }
    }

    pub(super) fn maybe_disable(we_enabled: u32) {
        if we_enabled > 0 {
            // SAFETY: `we_enabled > 0` implies `dit` cpu feature was supported earlier
            unsafe { write(0) }
        }
    }

    #[target_feature(enable = "dit")]
    unsafe fn read() -> u32 {
        let mut out: u64;
        // SAFETY: `mrs _, DIT` is defined only if `dit` cpu feature is supported
        core::arch::asm!(
            "mrs {r}, DIT",
            r = out(reg) out,
        );

        const DIT: u64 = 0x01000000;
        (out & DIT == DIT) as u32
    }

    #[target_feature(enable = "dit")]
    unsafe fn write(on: u32) {
        if on > 0 {
            // SAFETY: `msr DIT, _` is defined only if `dit` cpu feature is supported
            core::arch::asm!("msr DIT, #1");
        } else {
            // SAFETY: `msr DIT, _` is defined only if `dit` cpu feature is supported
            core::arch::asm!("msr DIT, #0")
        }
    }
}
