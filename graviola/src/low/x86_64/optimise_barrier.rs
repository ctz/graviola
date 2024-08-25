// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

pub fn optimise_barrier_u8(v: u8) -> u8 {
    let ret: u8;
    unsafe {
        core::arch::asm!(
            "/* {v} */",
            v = inout(reg_byte) v => ret,
        )
    };
    ret
}
