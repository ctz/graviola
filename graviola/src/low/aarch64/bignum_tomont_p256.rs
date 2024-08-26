#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Convert to Montgomery form z := (2^256 * x) mod p_256
// Input x[4]; output z[4]
//
//    extern void bignum_tomont_p256
//     (uint64_t z[static 4], uint64_t x[static 4]);
//
// Standard ARM ABI: X0 = z, X1 = x
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Core "x |-> (2^64 * x) mod p_256" macro, with x assumed to be < p_256.
// Input is in [d4;d3;d2;d1] and output in [d3;d2;d1;d0]
// using d4 as well as t1, t2, t3 as temporaries.
// ----------------------------------------------------------------------------

macro_rules! modstep_p256 {
    ($d4:expr, $d3:expr, $d2:expr, $d1:expr, $d0:expr, $t1:expr, $t2:expr, $t3:expr) => { Q!(
        /* Writing the input as z = 2^256 * h + 2^192 * l + t = 2^192 * hl + t,  */ /* our quotient approximation is MIN ((hl + hl>>32 + 1)>>64) (2^64 - 1). */ "subs xzr, xzr, xzr;"
        /* Set carry flag for +1 */ "extr " $t3 ", " $d4 ", " $d3 ", #32;"
        "adcs xzr, " $d3 ", " $t3 ";"
        "lsr " $t3 ", " $d4 ", #32;"
        "adcs " $t3 ", " $d4 ", " $t3 ";"
        "csetm " $d0 ", cs;"
        "orr " $t3 ", " $t3 ", " $d0 ";"
        /* First do [t2;t1] = 2^32 * q, which we use twice                       */ "lsl " $t1 ", " $t3 ", #32;"
        "lsr " $t2 ", " $t3 ", #32;"
        /* Add 2^224 * q to sum                                                  */ "adds " $d3 ", " $d3 ", " $t1 ";"
        "adc " $d4 ", " $d4 ", " $t2 ";"
        /* Accumulate [t2;t1;d0] = (2^96 - 1) * q                                */ "subs " $d0 ", xzr, " $t3 ";"
        "sbcs " $t1 ", " $t1 ", xzr;"
        "sbc " $t2 ", " $t2 ", xzr;"
        /* Subtract (2^256 + 2^192 + 2^96 - 1) * q                               */ "subs " $d0 ", xzr, " $d0 ";"
        "sbcs " $d1 ", " $d1 ", " $t1 ";"
        "sbcs " $d2 ", " $d2 ", " $t2 ";"
        "sbcs " $d3 ", " $d3 ", " $t3 ";"
        "sbcs " $d4 ", " $d4 ", " $t3 ";"
        /* Use top word as mask to correct                                       */ "adds " $d0 ", " $d0 ", " $d4 ";"
        "mov " $t1 ", #0x00000000ffffffff;"
        "and " $t1 ", " $t1 ", " $d4 ";"
        "adcs " $d1 ", " $d1 ", " $t1 ";"
        "adcs " $d2 ", " $d2 ", xzr;"
        "mov " $t1 ", #0xffffffff00000001;"
        "and " $t1 ", " $t1 ", " $d4 ";"
        "adc " $d3 ", " $d3 ", " $t1
    )}
}

macro_rules! d0 {
    () => {
        Q!("x2")
    };
}
macro_rules! d1 {
    () => {
        Q!("x3")
    };
}
macro_rules! d2 {
    () => {
        Q!("x4")
    };
}
macro_rules! d3 {
    () => {
        Q!("x5")
    };
}
macro_rules! d4 {
    () => {
        Q!("x6")
    };
}

macro_rules! t0 {
    () => {
        Q!("x1")
    };
}
macro_rules! t1 {
    () => {
        Q!("x7")
    };
}
macro_rules! t2 {
    () => {
        Q!("x8")
    };
}
macro_rules! t3 {
    () => {
        Q!("x9")
    };
}

pub fn bignum_tomont_p256(z: &mut [u64; 4], x: &[u64; 4]) {
    unsafe {
        core::arch::asm!(



        // Load the input

        Q!("    ldp             " d0!() ", " d1!() ", [x1]"),
        Q!("    ldp             " d2!() ", " d3!() ", [x1, #16]"),

        // Do an initial reduction to make sure this is < p_256, using just
        // a copy of the bignum_mod_p256_4 code. This is needed to set up the
        // invariant "input < p_256" for the main modular reduction steps.

        Q!("    mov             " t0!() ", #0xffffffffffffffff"),
        Q!("    mov             " t1!() ", #0x00000000ffffffff"),
        Q!("    mov             " t3!() ", #0xffffffff00000001"),
        Q!("    subs            " t0!() ", " d0!() ", " t0!()),
        Q!("    sbcs            " t1!() ", " d1!() ", " t1!()),
        Q!("    sbcs            " t2!() ", " d2!() ", xzr"),
        Q!("    sbcs            " t3!() ", " d3!() ", " t3!()),
        Q!("    csel            " d0!() ", " d0!() ", " t0!() ", cc"),
        Q!("    csel            " d1!() ", " d1!() ", " t1!() ", cc"),
        Q!("    csel            " d2!() ", " d2!() ", " t2!() ", cc"),
        Q!("    csel            " d3!() ", " d3!() ", " t3!() ", cc"),

        // Successively multiply by 2^64 and reduce

        modstep_p256!(d3!(), d2!(), d1!(), d0!(), d4!(), t1!(), t2!(), t3!()),
        modstep_p256!(d2!(), d1!(), d0!(), d4!(), d3!(), t1!(), t2!(), t3!()),
        modstep_p256!(d1!(), d0!(), d4!(), d3!(), d2!(), t1!(), t2!(), t3!()),
        modstep_p256!(d0!(), d4!(), d3!(), d2!(), d1!(), t1!(), t2!(), t3!()),

        // Store the result and return

        Q!("    stp             " d1!() ", " d2!() ", [x0]"),
        Q!("    stp             " d3!() ", " d4!() ", [x0, #16]"),

        inout("x0") z.as_mut_ptr() => _,
        inout("x1") x.as_ptr() => _,
        // clobbers
        out("v0") _,
        out("v1") _,
        out("v2") _,
        out("v3") _,
        out("v4") _,
        out("x2") _,
        out("x3") _,
        out("x4") _,
        out("x5") _,
        out("x6") _,
        out("x7") _,
        out("x8") _,
        out("x9") _,
            )
    };
}
