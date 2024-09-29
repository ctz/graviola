#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Montgomery multiply, z := (x * y / 2^256) mod p_256
// Inputs x[4], y[4]; output z[4]
//
//    extern void bignum_montmul_p256_alt
//     (uint64_t z[static 4], uint64_t x[static 4], uint64_t y[static 4]);
//
// Does z := (2^{-256} * x * y) mod p_256, assuming that the inputs x and y
// satisfy x * y <= 2^256 * p_256 (in particular this is true if we are in
// the "usual" case x < p_256 and y < p_256).
//
// Standard ARM ABI: X0 = z, X1 = x, X2 = y
// ----------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Core one-step "short" Montgomery reduction macro. Takes input in
// [d3;d2;d1;d0] and returns result in [d4;d3;d2;d1], adding to the
// existing contents of [d3;d2;d1] and generating d4 from zero, re-using
// d0 as a temporary internally together with tmp. The "mc" parameter is
// assumed to be a register whose value is 0xFFFFFFFF00000001.
// It is fine for d4 to be the same register as d0, and it often is.
// ---------------------------------------------------------------------------

macro_rules! montreds {
    ($d4:expr, $d3:expr, $d2:expr, $d1:expr, $d0:expr, $tmp:expr, $mc:expr) => { Q!(
        "adds " $d1 ", " $d1 ", " $d0 ", lsl #32;\n"
        "lsr " $tmp ", " $d0 ", #32;\n"
        "adcs " $d2 ", " $d2 ", " $tmp ";\n"
        "mul " $tmp ", " $d0 ", " $mc ";\n"
        "umulh " $d4 ", " $d0 ", " $mc ";\n"
        "adcs " $d3 ", " $d3 ", " $tmp ";\n"
        "adc " $d4 ", " $d4 ", xzr"
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
        Q!("x5")
    };
}
macro_rules! a3 {
    () => {
        Q!("x6")
    };
}
macro_rules! b0 {
    () => {
        Q!("x7")
    };
}
macro_rules! b1 {
    () => {
        Q!("x8")
    };
}
macro_rules! b2 {
    () => {
        Q!("x9")
    };
}
macro_rules! b3 {
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

// These alias to the input arguments when no longer needed

macro_rules! u5 {
    () => {
        Q!(a0!())
    };
}
macro_rules! u6 {
    () => {
        Q!(a1!())
    };
}
macro_rules! u7 {
    () => {
        Q!(a2!())
    };
}
macro_rules! h {
    () => {
        Q!(a3!())
    };
}
macro_rules! mc {
    () => {
        Q!(b3!())
    };
}

pub fn bignum_montmul_p256(z: &mut [u64; 4], x: &[u64; 4], y: &[u64; 4]) {
    unsafe {
        core::arch::asm!(


        // Load operands and set up row 0 = [u4;...;u0] = a0 * [b3;...;b0]

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
        Q!("    adc             " u4!() ", " u4!() ", xzr"),

        Q!("    ldp             " a2!() ", " a3!() ", [" x!() ", #16]"),

        // Row 1 = [u5;...;u0] = [a1;a0] * [b3;...;b0]

        Q!("    mul             " l!() ", " a1!() ", " b0!()),
        Q!("    adds            " u1!() ", " u1!() ", " l!()),
        Q!("    mul             " l!() ", " a1!() ", " b1!()),
        Q!("    adcs            " u2!() ", " u2!() ", " l!()),
        Q!("    mul             " l!() ", " a1!() ", " b2!()),
        Q!("    adcs            " u3!() ", " u3!() ", " l!()),
        Q!("    mul             " l!() ", " a1!() ", " b3!()),
        Q!("    adcs            " u4!() ", " u4!() ", " l!()),
        Q!("    umulh           " u5!() ", " a1!() ", " b3!()),
        Q!("    adc             " u5!() ", " u5!() ", xzr"),

        Q!("    umulh           " l!() ", " a1!() ", " b0!()),
        Q!("    adds            " u2!() ", " u2!() ", " l!()),
        Q!("    umulh           " l!() ", " a1!() ", " b1!()),
        Q!("    adcs            " u3!() ", " u3!() ", " l!()),
        Q!("    umulh           " l!() ", " a1!() ", " b2!()),
        Q!("    adcs            " u4!() ", " u4!() ", " l!()),
        Q!("    adc             " u5!() ", " u5!() ", xzr"),

        // Row 2 = [u6;...;u0] = [a2;a1;a0] * [b3;...;b0]

        Q!("    mul             " l!() ", " a2!() ", " b0!()),
        Q!("    adds            " u2!() ", " u2!() ", " l!()),
        Q!("    mul             " l!() ", " a2!() ", " b1!()),
        Q!("    adcs            " u3!() ", " u3!() ", " l!()),
        Q!("    mul             " l!() ", " a2!() ", " b2!()),
        Q!("    adcs            " u4!() ", " u4!() ", " l!()),
        Q!("    mul             " l!() ", " a2!() ", " b3!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),
        Q!("    umulh           " u6!() ", " a2!() ", " b3!()),
        Q!("    adc             " u6!() ", " u6!() ", xzr"),

        Q!("    umulh           " l!() ", " a2!() ", " b0!()),
        Q!("    adds            " u3!() ", " u3!() ", " l!()),
        Q!("    umulh           " l!() ", " a2!() ", " b1!()),
        Q!("    adcs            " u4!() ", " u4!() ", " l!()),
        Q!("    umulh           " l!() ", " a2!() ", " b2!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),
        Q!("    adc             " u6!() ", " u6!() ", xzr"),

        // Row 3 = [u7;...;u0] = [a3;...a0] * [b3;...;b0]
        // Interleave the first Montgomery rotation of the low half

        Q!("    mul             " l!() ", " a3!() ", " b0!()),
        Q!("    adds            " u3!() ", " u3!() ", " l!()),
        Q!("    mul             " l!() ", " a3!() ", " b1!()),
        Q!("    adcs            " u4!() ", " u4!() ", " l!()),
        Q!("    mul             " l!() ", " a3!() ", " b2!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),
        Q!("    mul             " l!() ", " a3!() ", " b3!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    umulh           " u7!() ", " a3!() ", " b3!()),
        Q!("    adc             " u7!() ", " u7!() ", xzr"),

        Q!("    mov             " mc!() ", 0xFFFFFFFF00000001"),
        montreds!(u0!(), u3!(), u2!(), u1!(), u0!(), l!(), mc!()),

        Q!("    umulh           " l!() ", " a3!() ", " b0!()),
        Q!("    adds            " u4!() ", " u4!() ", " l!()),
        Q!("    umulh           " l!() ", " a3!() ", " b1!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),
        Q!("    umulh           " l!() ", " a3!() ", " b2!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    adc             " u7!() ", " u7!() ", xzr"),

        // Perform 3 further Montgomery steps to rotate the lower half

        montreds!(u1!(), u0!(), u3!(), u2!(), u1!(), l!(), mc!()),
        montreds!(u2!(), u1!(), u0!(), u3!(), u2!(), l!(), mc!()),
        montreds!(u3!(), u2!(), u1!(), u0!(), u3!(), l!(), mc!()),

        // Add high and low parts, catching carry in b1

        Q!("    adds            " u0!() ", " u0!() ", " u4!()),
        Q!("    adcs            " u1!() ", " u1!() ", " u5!()),
        Q!("    adcs            " u2!() ", " u2!() ", " u6!()),
        Q!("    adcs            " u3!() ", " u3!() ", " u7!()),
        Q!("    cset            " b1!() ", cs"),

        // Set [mc;0;l;-1] = p_256 and form [u7,u6,u5,u4] = [b1;u3;u2;u1;u0] - p_256

        Q!("    mov             " l!() ", #0x00000000ffffffff"),

        Q!("    subs            " u4!() ", " u0!() ", #-1"),
        Q!("    sbcs            " u5!() ", " u1!() ", " l!()),
        Q!("    sbcs            " u6!() ", " u2!() ", xzr"),
        Q!("    sbcs            " u7!() ", " u3!() ", " mc!()),
        Q!("    sbcs            " "xzr, " b1!() ", xzr"),

        // Now CF is clear if the comparison carried so the original was fine
        // Otherwise take the form with p_256 subtracted.

        Q!("    csel            " u0!() ", " u0!() ", " u4!() ", cc"),
        Q!("    csel            " u1!() ", " u1!() ", " u5!() ", cc"),
        Q!("    csel            " u2!() ", " u2!() ", " u6!() ", cc"),
        Q!("    csel            " u3!() ", " u3!() ", " u7!() ", cc"),

        // Store back final result

        Q!("    stp             " u0!() ", " u1!() ", [" z!() "]"),
        Q!("    stp             " u2!() ", " u3!() ", [" z!() ", #16]"),

        inout("x0") z.as_mut_ptr() => _,
        inout("x1") x.as_ptr() => _,
        inout("x2") y.as_ptr() => _,
        // clobbers
        out("v0") _,
        out("v1") _,
        out("v2") _,
        out("v3") _,
        out("v4") _,
        out("x10") _,
        out("x11") _,
        out("x12") _,
        out("x13") _,
        out("x14") _,
        out("x15") _,
        out("x16") _,
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
