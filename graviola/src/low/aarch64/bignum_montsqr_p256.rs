#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Montgomery square, z := (x^2 / 2^256) mod p_256
// Input x[4]; output z[4]
//
//    extern void bignum_montsqr_p256_alt
//     (uint64_t z[static 4], uint64_t x[static 4]);
//
// Does z := (x^2 / 2^256) mod p_256, assuming x^2 <= 2^256 * p_256, which is
// guaranteed in particular if x < p_256 initially (the "intended" case).
//
// Standard ARM ABI: X0 = z, X1 = x
// ----------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Core one-step "short" Montgomery reduction macro. Takes input in
// [d3;d2;d1;d0] and returns result in [d4;d3;d2;d1], adding to the
// existing contents of [d3;d2;d1] and generating d4 from zero, re-using
// d0 as a temporary internally together with "tmp". The "mc" parameter is
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

macro_rules! l {
    () => {
        Q!("x6")
    };
}
macro_rules! h {
    () => {
        Q!("x7")
    };
}

macro_rules! u0 {
    () => {
        Q!("x8")
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

// This one is the same as h, which is safe with this computation sequence

macro_rules! u7 {
    () => {
        Q!(h!())
    };
}

// This one is the same as a3, and is used for the Montgomery constant
// 0xFFFFFFFF00000001

macro_rules! mc {
    () => {
        Q!("x5")
    };
}

pub(crate) fn bignum_montsqr_p256(z: &mut [u64; 4], x: &[u64; 4]) {
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(


        // Load all the elements, set up an initial window [u6;...u1] = [23;03;01]
        // and chain in the addition of 02 + 12 + 13 (no carry-out is possible).
        // This gives all the "heterogeneous" terms of the squaring ready to double

        Q!("    ldp             " a0!() ", " a1!() ", [" x!() "]"),

        Q!("    mul             " u1!() ", " a0!() ", " a1!()),
        Q!("    umulh           " u2!() ", " a0!() ", " a1!()),

        Q!("    ldp             " a2!() ", " a3!() ", [" x!() ", #16]"),

        Q!("    mul             " u3!() ", " a0!() ", " a3!()),
        Q!("    umulh           " u4!() ", " a0!() ", " a3!()),

        Q!("    mul             " l!() ", " a0!() ", " a2!()),
        Q!("    umulh           " h!() ", " a0!() ", " a2!()),
        Q!("    adds            " u2!() ", " u2!() ", " l!()),

        Q!("    adcs            " u3!() ", " u3!() ", " h!()),
        Q!("    mul             " l!() ", " a1!() ", " a2!()),
        Q!("    umulh           " h!() ", " a1!() ", " a2!()),
        Q!("    adc             " h!() ", " h!() ", xzr"),
        Q!("    adds            " u3!() ", " u3!() ", " l!()),

        Q!("    mul             " u5!() ", " a2!() ", " a3!()),
        Q!("    umulh           " u6!() ", " a2!() ", " a3!()),

        Q!("    adcs            " u4!() ", " u4!() ", " h!()),
        Q!("    mul             " l!() ", " a1!() ", " a3!()),
        Q!("    umulh           " h!() ", " a1!() ", " a3!()),
        Q!("    adc             " h!() ", " h!() ", xzr"),
        Q!("    adds            " u4!() ", " u4!() ", " l!()),

        Q!("    adcs            " u5!() ", " u5!() ", " h!()),
        Q!("    adc             " u6!() ", " u6!() ", xzr"),

        // Now just double it; this simple approach seems to work better than extr

        Q!("    adds            " u1!() ", " u1!() ", " u1!()),
        Q!("    adcs            " u2!() ", " u2!() ", " u2!()),
        Q!("    adcs            " u3!() ", " u3!() ", " u3!()),
        Q!("    adcs            " u4!() ", " u4!() ", " u4!()),
        Q!("    adcs            " u5!() ", " u5!() ", " u5!()),
        Q!("    adcs            " u6!() ", " u6!() ", " u6!()),
        Q!("    cset            " u7!() ", cs"),

        // Add the homogeneous terms 00 + 11 + 22 + 33

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
        Q!("    adc             " u7!() ", " u7!() ", " l!()),

        // Squaring complete. Perform 4 Montgomery steps to rotate the lower half

        Q!("    mov             " mc!() ", #0xFFFFFFFF00000001"),
        montreds!(u0!(), u3!(), u2!(), u1!(), u0!(), a0!(), mc!()),
        montreds!(u1!(), u0!(), u3!(), u2!(), u1!(), a0!(), mc!()),
        montreds!(u2!(), u1!(), u0!(), u3!(), u2!(), a0!(), mc!()),
        montreds!(u3!(), u2!(), u1!(), u0!(), u3!(), a0!(), mc!()),

        // Add high and low parts, catching carry in a0

        Q!("    adds            " u0!() ", " u0!() ", " u4!()),
        Q!("    adcs            " u1!() ", " u1!() ", " u5!()),
        Q!("    adcs            " u2!() ", " u2!() ", " u6!()),
        Q!("    adcs            " u3!() ", " u3!() ", " u7!()),
        Q!("    cset            " a0!() ", cs"),

        // Set [a3;0;a1;-1] = p_256 and form [u7,u6,u5,u4] = [a0;u3;u2;u1;u0] - p_256
        // Note that a3 == mc was already set above

        Q!("    mov             " a1!() ", #0x00000000ffffffff"),

        Q!("    subs            " u4!() ", " u0!() ", #-1"),
        Q!("    sbcs            " u5!() ", " u1!() ", " a1!()),
        Q!("    sbcs            " u6!() ", " u2!() ", xzr"),
        Q!("    sbcs            " u7!() ", " u3!() ", " mc!()),
        Q!("    sbcs            " "xzr, " a0!() ", xzr"),

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
