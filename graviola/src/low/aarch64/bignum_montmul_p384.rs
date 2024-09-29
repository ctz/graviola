#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Montgomery multiply, z := (x * y / 2^384) mod p_384
// Inputs x[6], y[6]; output z[6]
//
//    extern void bignum_montmul_p384_alt
//     (uint64_t z[static 6], uint64_t x[static 6], uint64_t y[static 6]);
//
// Does z := (2^{-384} * x * y) mod p_384, assuming that the inputs x and y
// satisfy x * y <= 2^384 * p_384 (in particular this is true if we are in
// the "usual" case x < p_384 and y < p_384).
//
// Standard ARM ABI: X0 = z, X1 = x, X2 = y
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
macro_rules! y {
    () => {
        Q!("x2")
    };
}

// These are repeated mod 2 as we load pairs of inputs

macro_rules! a0 {
    () => {
        Q!("x3")
    };
}
macro_rules! a1 {
    () => {
        Q!("x4")
    };
}
macro_rules! a2 {
    () => {
        Q!("x3")
    };
}
macro_rules! a3 {
    () => {
        Q!("x4")
    };
}
macro_rules! a4 {
    () => {
        Q!("x3")
    };
}
macro_rules! a5 {
    () => {
        Q!("x4")
    };
}

macro_rules! b0 {
    () => {
        Q!("x5")
    };
}
macro_rules! b1 {
    () => {
        Q!("x6")
    };
}
macro_rules! b2 {
    () => {
        Q!("x7")
    };
}
macro_rules! b3 {
    () => {
        Q!("x8")
    };
}
macro_rules! b4 {
    () => {
        Q!("x9")
    };
}
macro_rules! b5 {
    () => {
        Q!("x10")
    };
}

macro_rules! l {
    () => {
        Q!("x11")
    };
}

macro_rules! u0 {
    () => {
        Q!("x12")
    };
}
macro_rules! u1 {
    () => {
        Q!("x13")
    };
}
macro_rules! u2 {
    () => {
        Q!("x14")
    };
}
macro_rules! u3 {
    () => {
        Q!("x15")
    };
}
macro_rules! u4 {
    () => {
        Q!("x16")
    };
}
macro_rules! u5 {
    () => {
        Q!("x17")
    };
}
macro_rules! u6 {
    () => {
        Q!("x19")
    };
}
macro_rules! u7 {
    () => {
        Q!("x20")
    };
}
macro_rules! u8 {
    () => {
        Q!("x21")
    };
}
macro_rules! u9 {
    () => {
        Q!("x22")
    };
}
macro_rules! u10 {
    () => {
        Q!("x2")
    };
}
macro_rules! u11 {
    () => {
        Q!("x1")
    };
}
macro_rules! h {
    () => {
        Q!(b5!())
    };
}

pub fn bignum_montmul_p384(z: &mut [u64; 6], x: &[u64; 6], y: &[u64; 6]) {
    unsafe {
        core::arch::asm!(


        // Save more registers

        Q!("    stp             " "x19, x20, [sp, #-16] !"),
        Q!("    stp             " "x21, x22, [sp, #-16] !"),

        // Load operands and set up row 0 = [u6;...;u0] = a0 * [b5;...;b0]

        Q!("    ldp             " a0!() ", " a1!() ", [" x!() "]"),
        Q!("    ldp             " b0!() ", " b1!() ", [" y!() "]"),

        Q!("    mul             " u0!() ", " a0!() ", " b0!()),
        Q!("    umulh           " u1!() ", " a0!() ", " b0!()),
        Q!("    mul             " l!() ", " a0!() ", " b1!()),
        Q!("    umulh           " u2!() ", " a0!() ", " b1!()),
        Q!("    adds            " u1!() ", " u1!() ", " l!()),

        Q!("    ldp             " b2!() ", " b3!() ", [" y!() ", #16]"),

        Q!("    mul             " l!() ", " a0!() ", " b2!()),
        Q!("    umulh           " u3!() ", " a0!() ", " b2!()),
        Q!("    adcs            " u2!() ", " u2!() ", " l!()),

        Q!("    mul             " l!() ", " a0!() ", " b3!()),
        Q!("    umulh           " u4!() ", " a0!() ", " b3!()),
        Q!("    adcs            " u3!() ", " u3!() ", " l!()),

        Q!("    ldp             " b4!() ", " b5!() ", [" y!() ", #32]"),

        Q!("    mul             " l!() ", " a0!() ", " b4!()),
        Q!("    umulh           " u5!() ", " a0!() ", " b4!()),
        Q!("    adcs            " u4!() ", " u4!() ", " l!()),

        Q!("    mul             " l!() ", " a0!() ", " b5!()),
        Q!("    umulh           " u6!() ", " a0!() ", " b5!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),

        Q!("    adc             " u6!() ", " u6!() ", xzr"),

        // Row 1 = [u7;...;u0] = [a1;a0] * [b5;...;b0]

        Q!("    mul             " l!() ", " a1!() ", " b0!()),
        Q!("    adds            " u1!() ", " u1!() ", " l!()),
        Q!("    mul             " l!() ", " a1!() ", " b1!()),
        Q!("    adcs            " u2!() ", " u2!() ", " l!()),
        Q!("    mul             " l!() ", " a1!() ", " b2!()),
        Q!("    adcs            " u3!() ", " u3!() ", " l!()),
        Q!("    mul             " l!() ", " a1!() ", " b3!()),
        Q!("    adcs            " u4!() ", " u4!() ", " l!()),
        Q!("    mul             " l!() ", " a1!() ", " b4!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),
        Q!("    mul             " l!() ", " a1!() ", " b5!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    cset            " u7!() ", cs"),

        Q!("    umulh           " l!() ", " a1!() ", " b0!()),
        Q!("    adds            " u2!() ", " u2!() ", " l!()),
        Q!("    umulh           " l!() ", " a1!() ", " b1!()),
        Q!("    adcs            " u3!() ", " u3!() ", " l!()),
        Q!("    umulh           " l!() ", " a1!() ", " b2!()),
        Q!("    adcs            " u4!() ", " u4!() ", " l!()),
        Q!("    umulh           " l!() ", " a1!() ", " b3!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),
        Q!("    umulh           " l!() ", " a1!() ", " b4!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    umulh           " l!() ", " a1!() ", " b5!()),
        Q!("    adc             " u7!() ", " u7!() ", " l!()),

        // Row 2 = [u8;...;u0] = [a2;a1;a0] * [b5;...;b0]

        Q!("    ldp             " a2!() ", " a3!() ", [" x!() ", #16]"),

        Q!("    mul             " l!() ", " a2!() ", " b0!()),
        Q!("    adds            " u2!() ", " u2!() ", " l!()),
        Q!("    mul             " l!() ", " a2!() ", " b1!()),
        Q!("    adcs            " u3!() ", " u3!() ", " l!()),
        Q!("    mul             " l!() ", " a2!() ", " b2!()),
        Q!("    adcs            " u4!() ", " u4!() ", " l!()),
        Q!("    mul             " l!() ", " a2!() ", " b3!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),
        Q!("    mul             " l!() ", " a2!() ", " b4!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    mul             " l!() ", " a2!() ", " b5!()),
        Q!("    adcs            " u7!() ", " u7!() ", " l!()),
        Q!("    cset            " u8!() ", cs"),

        Q!("    umulh           " l!() ", " a2!() ", " b0!()),
        Q!("    adds            " u3!() ", " u3!() ", " l!()),
        Q!("    umulh           " l!() ", " a2!() ", " b1!()),
        Q!("    adcs            " u4!() ", " u4!() ", " l!()),
        Q!("    umulh           " l!() ", " a2!() ", " b2!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),
        Q!("    umulh           " l!() ", " a2!() ", " b3!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    umulh           " l!() ", " a2!() ", " b4!()),
        Q!("    adcs            " u7!() ", " u7!() ", " l!()),
        Q!("    umulh           " l!() ", " a2!() ", " b5!()),
        Q!("    adc             " u8!() ", " u8!() ", " l!()),

        // Row 3 = [u9;...;u0] = [a3;a2;a1;a0] * [b5;...;b0]

        Q!("    mul             " l!() ", " a3!() ", " b0!()),
        Q!("    adds            " u3!() ", " u3!() ", " l!()),
        Q!("    mul             " l!() ", " a3!() ", " b1!()),
        Q!("    adcs            " u4!() ", " u4!() ", " l!()),
        Q!("    mul             " l!() ", " a3!() ", " b2!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),
        Q!("    mul             " l!() ", " a3!() ", " b3!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    mul             " l!() ", " a3!() ", " b4!()),
        Q!("    adcs            " u7!() ", " u7!() ", " l!()),
        Q!("    mul             " l!() ", " a3!() ", " b5!()),
        Q!("    adcs            " u8!() ", " u8!() ", " l!()),
        Q!("    cset            " u9!() ", cs"),

        Q!("    umulh           " l!() ", " a3!() ", " b0!()),
        Q!("    adds            " u4!() ", " u4!() ", " l!()),
        Q!("    umulh           " l!() ", " a3!() ", " b1!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),
        Q!("    umulh           " l!() ", " a3!() ", " b2!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    umulh           " l!() ", " a3!() ", " b3!()),
        Q!("    adcs            " u7!() ", " u7!() ", " l!()),
        Q!("    umulh           " l!() ", " a3!() ", " b4!()),
        Q!("    adcs            " u8!() ", " u8!() ", " l!()),
        Q!("    umulh           " l!() ", " a3!() ", " b5!()),
        Q!("    adc             " u9!() ", " u9!() ", " l!()),

        // Row 4 = [u10;...;u0] = [a4;a3;a2;a1;a0] * [b5;...;b0]

        Q!("    ldp             " a4!() ", " a5!() ", [" x!() ", #32]"),

        Q!("    mul             " l!() ", " a4!() ", " b0!()),
        Q!("    adds            " u4!() ", " u4!() ", " l!()),
        Q!("    mul             " l!() ", " a4!() ", " b1!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),
        Q!("    mul             " l!() ", " a4!() ", " b2!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    mul             " l!() ", " a4!() ", " b3!()),
        Q!("    adcs            " u7!() ", " u7!() ", " l!()),
        Q!("    mul             " l!() ", " a4!() ", " b4!()),
        Q!("    adcs            " u8!() ", " u8!() ", " l!()),
        Q!("    mul             " l!() ", " a4!() ", " b5!()),
        Q!("    adcs            " u9!() ", " u9!() ", " l!()),
        Q!("    cset            " u10!() ", cs"),

        Q!("    umulh           " l!() ", " a4!() ", " b0!()),
        Q!("    adds            " u5!() ", " u5!() ", " l!()),
        Q!("    umulh           " l!() ", " a4!() ", " b1!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    umulh           " l!() ", " a4!() ", " b2!()),
        Q!("    adcs            " u7!() ", " u7!() ", " l!()),
        Q!("    umulh           " l!() ", " a4!() ", " b3!()),
        Q!("    adcs            " u8!() ", " u8!() ", " l!()),
        Q!("    umulh           " l!() ", " a4!() ", " b4!()),
        Q!("    adcs            " u9!() ", " u9!() ", " l!()),
        Q!("    umulh           " l!() ", " a4!() ", " b5!()),
        Q!("    adc             " u10!() ", " u10!() ", " l!()),

        // Row 5 = [u11;...;u0] = [a5;a4;a3;a2;a1;a0] * [b5;...;b0]

        Q!("    mul             " l!() ", " a5!() ", " b0!()),
        Q!("    adds            " u5!() ", " u5!() ", " l!()),
        Q!("    mul             " l!() ", " a5!() ", " b1!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    mul             " l!() ", " a5!() ", " b2!()),
        Q!("    adcs            " u7!() ", " u7!() ", " l!()),
        Q!("    mul             " l!() ", " a5!() ", " b3!()),
        Q!("    adcs            " u8!() ", " u8!() ", " l!()),
        Q!("    mul             " l!() ", " a5!() ", " b4!()),
        Q!("    adcs            " u9!() ", " u9!() ", " l!()),
        Q!("    mul             " l!() ", " a5!() ", " b5!()),
        Q!("    adcs            " u10!() ", " u10!() ", " l!()),
        Q!("    cset            " u11!() ", cs"),

        Q!("    umulh           " l!() ", " a5!() ", " b0!()),
        Q!("    adds            " u6!() ", " u6!() ", " l!()),
        Q!("    umulh           " l!() ", " a5!() ", " b1!()),
        Q!("    adcs            " u7!() ", " u7!() ", " l!()),
        Q!("    umulh           " l!() ", " a5!() ", " b2!()),
        Q!("    adcs            " u8!() ", " u8!() ", " l!()),
        Q!("    umulh           " l!() ", " a5!() ", " b3!()),
        Q!("    adcs            " u9!() ", " u9!() ", " l!()),
        Q!("    umulh           " l!() ", " a5!() ", " b4!()),
        Q!("    adcs            " u10!() ", " u10!() ", " l!()),
        Q!("    umulh           " l!() ", " a5!() ", " b5!()),
        Q!("    adc             " u11!() ", " u11!() ", " l!()),

        // Montgomery rotate the low half

        montreds!(u0!(), u5!(), u4!(), u3!(), u2!(), u1!(), u0!(), b0!(), b1!(), b2!()),
        montreds!(u1!(), u0!(), u5!(), u4!(), u3!(), u2!(), u1!(), b0!(), b1!(), b2!()),
        montreds!(u2!(), u1!(), u0!(), u5!(), u4!(), u3!(), u2!(), b0!(), b1!(), b2!()),
        montreds!(u3!(), u2!(), u1!(), u0!(), u5!(), u4!(), u3!(), b0!(), b1!(), b2!()),
        montreds!(u4!(), u3!(), u2!(), u1!(), u0!(), u5!(), u4!(), b0!(), b1!(), b2!()),
        montreds!(u5!(), u4!(), u3!(), u2!(), u1!(), u0!(), u5!(), b0!(), b1!(), b2!()),

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

        Q!("    ldp             " "x21, x22, [sp], #16"),
        Q!("    ldp             " "x19, x20, [sp], #16"),

        inout("x0") z.as_mut_ptr() => _,
        inout("x1") x.as_ptr() => _,
        inout("x2") y.as_ptr() => _,
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
        out("x20") _,
        out("x21") _,
        out("x22") _,
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
