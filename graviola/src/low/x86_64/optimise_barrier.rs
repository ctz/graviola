// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

pub(crate) fn optimise_barrier_u8(v: u8) -> u8 {
    let ret: u8;
    // SAFETY: inline assembly, which does nothing but block the optimiser
    // from seeing the data dependency between `v` and `ret`.
    unsafe {
        core::arch::asm!(
            "/* {v} */",
            v = inout(reg_byte) v => ret,
        )
    };
    ret
}
