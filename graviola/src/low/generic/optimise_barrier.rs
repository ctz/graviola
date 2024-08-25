// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::ptr::read_volatile;

pub fn optimise_barrier_u8(v: u8) -> u8 {
    unsafe { read_volatile(&v) }
}
