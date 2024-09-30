// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use std::arch::is_aarch64_feature_detected;

pub(crate) fn enter_cpu_state() -> u32 {
    dit::maybe_enable()
}

pub(crate) fn leave_cpu_state(old: u32) {
    dit::maybe_disable(old);
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
            match unsafe { read() } {
                0 => {
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
            unsafe { write(0) }
        }
    }

    #[target_feature(enable = "dit")]
    unsafe fn read() -> u32 {
        let mut out: u64;
        unsafe {
            core::arch::asm!(
                "mrs {r}, DIT",
                r = out(reg) out,
            )
        };

        const DIT: u64 = 0x01000000;
        (out & DIT == DIT) as u32
    }

    #[target_feature(enable = "dit")]
    unsafe fn write(on: u32) {
        unsafe {
            if on > 0 {
                core::arch::asm!("msr DIT, #1");
            } else {
                core::arch::asm!("msr DIT, #0")
            }
        }
    }
}
