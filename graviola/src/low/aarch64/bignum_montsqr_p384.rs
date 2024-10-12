#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Montgomery square, z := (x^2 / 2^384) mod p_384
// Input x[6]; output z[6]
//
//    extern void bignum_montsqr_p384_alt
//     (uint64_t z[static 6], uint64_t x[static 6]);
//
// Does z := (x^2 / 2^384) mod p_384, assuming x^2 <= 2^384 * p_384, which is
// guaranteed in particular if x < p_384 initially (the "intended" case).
//
// Standard ARM ABI: X0 = z, X1 = x
// ----------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Core one-step "short" Montgomery reduction macro. Takes input in
// [d5;d4;d3;d2;d1;d0] and returns result in [d6;d5;d4;d3;d2;d1],
// adding to the existing contents of [d5;d4;d3;d2;d1]. It is fine
// for d6 to be the same register as d0.
//
// We want to add (2^384 - 2^128 - 2^96 + 2^32 - 1) * w
// where w = [d0 + (d0<<32)] mod 2^64
// ---------------------------------------------------------------------------

macro_rules! montreds {
    ($d6:expr, $d5:expr, $d4:expr, $d3:expr, $d2:expr, $d1:expr, $d0:expr, $t3:expr, $t2:expr, $t1:expr) => { Q!(
        /* Our correction multiplier is w = [d0 + (d0<<32)] mod 2^64            */
        /* Store it in d6 to make the 2^384 * w contribution already            */
        "lsl " $t1 ", " $d0 ", #32;\n"
        "add " $d6 ", " $t1 ", " $d0 ";\n"
        /* Now let [t3;t2;t1;-] = (2^384 - p_384) * w                    */
        /* We know the lowest word will cancel d0 so we don't need it    */
        "mov " $t1 ", #0xffffffff00000001;\n"
        "umulh " $t1 ", " $t1 ", " $d6 ";\n"
        "mov " $t2 ", #0x00000000ffffffff;\n"
        "mul " $t3 ", " $t2 ", " $d6 ";\n"
        "umulh " $t2 ", " $t2 ", " $d6 ";\n"
        "adds " $t1 ", " $t1 ", " $t3 ";\n"
        "adcs " $t2 ", " $t2 ", " $d6 ";\n"
        "adc " $t3 ", xzr, xzr;\n"
        /* Now add it, by subtracting from 2^384 * w + x */
        "subs " $d1 ", " $d1 ", " $t1 ";\n"
        "sbcs " $d2 ", " $d2 ", " $t2 ";\n"
        "sbcs " $d3 ", " $d3 ", " $t3 ";\n"
        "sbcs " $d4 ", " $d4 ", xzr;\n"
        "sbcs " $d5 ", " $d5 ", xzr;\n"
        "sbc " $d6 ", " $d6 ", xzr"
    )}
}

macro_rules! z {
    () => {
        Q!("x0")
    };
}
macro_rules! x {
    () => {
        Q!("x1")
    };
}

macro_rules! a0 {
    () => {
        Q!("x2")
    };
}
macro_rules! a1 {
    () => {
        Q!("x3")
    };
}
macro_rules! a2 {
    () => {
        Q!("x4")
    };
}
macro_rules! a3 {
    () => {
        Q!("x5")
    };
}
macro_rules! a4 {
    () => {
        Q!("x6")
    };
}
macro_rules! a5 {
    () => {
        Q!("x7")
    };
}

macro_rules! l {
    () => {
        Q!("x8")
    };
}

macro_rules! u0 {
    () => {
        Q!("x2")
    };
}
macro_rules! u1 {
    () => {
        Q!("x9")
    };
}
macro_rules! u2 {
    () => {
        Q!("x10")
    };
}
macro_rules! u3 {
    () => {
        Q!("x11")
    };
}
macro_rules! u4 {
    () => {
        Q!("x12")
    };
}
macro_rules! u5 {
    () => {
        Q!("x13")
    };
}
macro_rules! u6 {
    () => {
        Q!("x14")
    };
}
macro_rules! u7 {
    () => {
        Q!("x15")
    };
}
macro_rules! u8 {
    () => {
        Q!("x16")
    };
}
macro_rules! u9 {
    () => {
        Q!("x17")
    };
}
macro_rules! u10 {
    () => {
        Q!("x19")
    };
}
macro_rules! u11 {
    () => {
        Q!("x20")
    };
}
macro_rules! h {
    () => {
        Q!("x6")
    };
}

pub fn bignum_montsqr_p384(z: &mut [u64; 6], x: &[u64; 6]) {
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(


        // It's convenient to have two more registers to play with

        Q!("    stp             " "x19, x20, [sp, #-16] !"),

        // Load all the elements as [a5;a4;a3;a2;a1;a0], set up an initial
        // window [u8;u7; u6;u5; u4;u3; u2;u1] = [34;05;03;01], and then
        // chain in the addition of 02 + 12 + 13 + 14 + 15 to that window
        // (no carry-out possible since we add it to the top of a product).

        Q!("    ldp             " a0!() ", " a1!() ", [" x!() "]"),

        Q!("    mul             " u1!() ", " a0!() ", " a1!()),
        Q!("    umulh           " u2!() ", " a0!() ", " a1!()),

        Q!("    ldp             " a2!() ", " a3!() ", [" x!() ", #16]"),

        Q!("    mul             " l!() ", " a0!() ", " a2!()),
        Q!("    adds            " u2!() ", " u2!() ", " l!()),

        Q!("    mul             " u3!() ", " a0!() ", " a3!()),
        Q!("    mul             " l!() ", " a1!() ", " a2!()),
        Q!("    adcs            " u3!() ", " u3!() ", " l!()),

        Q!("    umulh           " u4!() ", " a0!() ", " a3!()),
        Q!("    mul             " l!() ", " a1!() ", " a3!()),
        Q!("    adcs            " u4!() ", " u4!() ", " l!()),

        Q!("    ldp             " a4!() ", " a5!() ", [" x!() ", #32]"),

        Q!("    mul             " u5!() ", " a0!() ", " a5!()),
        Q!("    mul             " l!() ", " a1!() ", " a4!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),

        Q!("    umulh           " u6!() ", " a0!() ", " a5!()),
        Q!("    mul             " l!() ", " a1!() ", " a5!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),

        Q!("    mul             " u7!() ", " a3!() ", " a4!()),
        Q!("    adcs            " u7!() ", " u7!() ", xzr"),

        Q!("    umulh           " u8!() ", " a3!() ", " a4!()),
        Q!("    adc             " u8!() ", " u8!() ", xzr"),

        Q!("    umulh           " l!() ", " a0!() ", " a2!()),
        Q!("    adds            " u3!() ", " u3!() ", " l!()),
        Q!("    umulh           " l!() ", " a1!() ", " a2!()),
        Q!("    adcs            " u4!() ", " u4!() ", " l!()),
        Q!("    umulh           " l!() ", " a1!() ", " a3!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),
        Q!("    umulh           " l!() ", " a1!() ", " a4!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    umulh           " l!() ", " a1!() ", " a5!()),
        Q!("    adcs            " u7!() ", " u7!() ", " l!()),
        Q!("    adc             " u8!() ", " u8!() ", xzr"),

        // Now chain in the 04 + 23 + 24 + 25 + 35 + 45 terms

        Q!("    mul             " l!() ", " a0!() ", " a4!()),
        Q!("    adds            " u4!() ", " u4!() ", " l!()),
        Q!("    mul             " l!() ", " a2!() ", " a3!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),
        Q!("    mul             " l!() ", " a2!() ", " a4!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    mul             " l!() ", " a2!() ", " a5!()),
        Q!("    adcs            " u7!() ", " u7!() ", " l!()),
        Q!("    mul             " l!() ", " a3!() ", " a5!()),
        Q!("    adcs            " u8!() ", " u8!() ", " l!()),
        Q!("    mul             " u9!() ", " a4!() ", " a5!()),
        Q!("    adcs            " u9!() ", " u9!() ", xzr"),
        Q!("    umulh           " u10!() ", " a4!() ", " a5!()),
        Q!("    adc             " u10!() ", " u10!() ", xzr"),

        Q!("    umulh           " l!() ", " a0!() ", " a4!()),
        Q!("    adds            " u5!() ", " u5!() ", " l!()),
        Q!("    umulh           " l!() ", " a2!() ", " a3!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    umulh           " l!() ", " a2!() ", " a4!()),
        Q!("    adcs            " u7!() ", " u7!() ", " l!()),
        Q!("    umulh           " l!() ", " a2!() ", " a5!()),
        Q!("    adcs            " u8!() ", " u8!() ", " l!()),
        Q!("    umulh           " l!() ", " a3!() ", " a5!()),
        Q!("    adcs            " u9!() ", " u9!() ", " l!()),
        Q!("    adc             " u10!() ", " u10!() ", xzr"),

        // Double that, with u11 holding the top carry

        Q!("    adds            " u1!() ", " u1!() ", " u1!()),
        Q!("    adcs            " u2!() ", " u2!() ", " u2!()),
        Q!("    adcs            " u3!() ", " u3!() ", " u3!()),
        Q!("    adcs            " u4!() ", " u4!() ", " u4!()),
        Q!("    adcs            " u5!() ", " u5!() ", " u5!()),
        Q!("    adcs            " u6!() ", " u6!() ", " u6!()),
        Q!("    adcs            " u7!() ", " u7!() ", " u7!()),
        Q!("    adcs            " u8!() ", " u8!() ", " u8!()),
        Q!("    adcs            " u9!() ", " u9!() ", " u9!()),
        Q!("    adcs            " u10!() ", " u10!() ", " u10!()),
        Q!("    cset            " u11!() ", cs"),

        // Add the homogeneous terms 00 + 11 + 22 + 33 + 44 + 55

        Q!("    umulh           " l!() ", " a0!() ", " a0!()),
        Q!("    mul             " u0!() ", " a0!() ", " a0!()),
        Q!("    adds            " u1!() ", " u1!() ", " l!()),

        Q!("    mul             " l!() ", " a1!() ", " a1!()),
        Q!("    adcs            " u2!() ", " u2!() ", " l!()),
        Q!("    umulh           " l!() ", " a1!() ", " a1!()),
        Q!("    adcs            " u3!() ", " u3!() ", " l!()),

        Q!("    mul             " l!() ", " a2!() ", " a2!()),
        Q!("    adcs            " u4!() ", " u4!() ", " l!()),
        Q!("    umulh           " l!() ", " a2!() ", " a2!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),

        Q!("    mul             " l!() ", " a3!() ", " a3!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    umulh           " l!() ", " a3!() ", " a3!()),
        Q!("    adcs            " u7!() ", " u7!() ", " l!()),

        Q!("    mul             " l!() ", " a4!() ", " a4!()),
        Q!("    adcs            " u8!() ", " u8!() ", " l!()),
        Q!("    umulh           " l!() ", " a4!() ", " a4!()),
        Q!("    adcs            " u9!() ", " u9!() ", " l!()),

        Q!("    mul             " l!() ", " a5!() ", " a5!()),
        Q!("    adcs            " u10!() ", " u10!() ", " l!()),
        Q!("    umulh           " l!() ", " a5!() ", " a5!()),
        Q!("    adc             " u11!() ", " u11!() ", " l!()),

        // Montgomery rotate the low half

        montreds!(u0!(), u5!(), u4!(), u3!(), u2!(), u1!(), u0!(), a1!(), a2!(), a3!()),
        montreds!(u1!(), u0!(), u5!(), u4!(), u3!(), u2!(), u1!(), a1!(), a2!(), a3!()),
        montreds!(u2!(), u1!(), u0!(), u5!(), u4!(), u3!(), u2!(), a1!(), a2!(), a3!()),
        montreds!(u3!(), u2!(), u1!(), u0!(), u5!(), u4!(), u3!(), a1!(), a2!(), a3!()),
        montreds!(u4!(), u3!(), u2!(), u1!(), u0!(), u5!(), u4!(), a1!(), a2!(), a3!()),
        montreds!(u5!(), u4!(), u3!(), u2!(), u1!(), u0!(), u5!(), a1!(), a2!(), a3!()),

        // Add up the high and low parts as [h; u5;u4;u3;u2;u1;u0] = z

        Q!("    adds            " u0!() ", " u0!() ", " u6!()),
        Q!("    adcs            " u1!() ", " u1!() ", " u7!()),
        Q!("    adcs            " u2!() ", " u2!() ", " u8!()),
        Q!("    adcs            " u3!() ", " u3!() ", " u9!()),
        Q!("    adcs            " u4!() ", " u4!() ", " u10!()),
        Q!("    adcs            " u5!() ", " u5!() ", " u11!()),
        Q!("    adc             " h!() ", xzr, xzr"),

        // Now add [h; u11;u10;u9;u8;u7;u6] = z + (2^384 - p_384)

        Q!("    mov             " l!() ", #0xffffffff00000001"),
        Q!("    adds            " u6!() ", " u0!() ", " l!()),
        Q!("    mov             " l!() ", #0x00000000ffffffff"),
        Q!("    adcs            " u7!() ", " u1!() ", " l!()),
        Q!("    mov             " l!() ", #0x0000000000000001"),
        Q!("    adcs            " u8!() ", " u2!() ", " l!()),
        Q!("    adcs            " u9!() ", " u3!() ", xzr"),
        Q!("    adcs            " u10!() ", " u4!() ", xzr"),
        Q!("    adcs            " u11!() ", " u5!() ", xzr"),
        Q!("    adcs            " h!() ", " h!() ", xzr"),

        // Now z >= p_384 iff h is nonzero, so select accordingly

        Q!("    csel            " u0!() ", " u0!() ", " u6!() ", eq"),
        Q!("    csel            " u1!() ", " u1!() ", " u7!() ", eq"),
        Q!("    csel            " u2!() ", " u2!() ", " u8!() ", eq"),
        Q!("    csel            " u3!() ", " u3!() ", " u9!() ", eq"),
        Q!("    csel            " u4!() ", " u4!() ", " u10!() ", eq"),
        Q!("    csel            " u5!() ", " u5!() ", " u11!() ", eq"),

        // Store back final result

        Q!("    stp             " u0!() ", " u1!() ", [" z!() "]"),
        Q!("    stp             " u2!() ", " u3!() ", [" z!() ", #16]"),
        Q!("    stp             " u4!() ", " u5!() ", [" z!() ", #32]"),

        // Restore registers

        Q!("    ldp             " "x19, x20, [sp], #16"),

        inout("x0") z.as_mut_ptr() => _,
        inout("x1") x.as_ptr() => _,
        // clobbers
        out("v0") _,
        out("v1") _,
        out("v2") _,
        out("v3") _,
        out("v4") _,
        out("v5") _,
        out("v6") _,
        out("x10") _,
        out("x11") _,
        out("x12") _,
        out("x13") _,
        out("x14") _,
        out("x15") _,
        out("x16") _,
        out("x17") _,
        out("x2") _,
        out("x20") _,
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
