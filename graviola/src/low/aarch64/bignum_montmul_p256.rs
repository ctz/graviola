#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Montgomery multiply, z := (x * y / 2^256) mod p_256
// Inputs x[4], y[4]; output z[4]
//
//    extern void bignum_montmul_p256
//     (uint64_t z[static 4], uint64_t x[static 4], uint64_t y[static 4]);
//
// Does z := (2^{-256} * x * y) mod p_256, assuming that the inputs x and y
// satisfy x * y <= 2^256 * p_256 (in particular this is true if we are in
// the "usual" case x < p_256 and y < p_256).
//
// Standard ARM ABI: X0 = z, X1 = x, X2 = y
// ----------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Macro returning (c,h,l) = 3-word 1s complement (x - y) * (w - z)
// c,h,l,t should all be different
// t,h should not overlap w,z
// ---------------------------------------------------------------------------

macro_rules! muldiffn {
    ($c:expr, $h:expr, $l:expr, $t:expr, $x:expr, $y:expr, $w:expr, $z:expr) => { Q!(
        "subs " $t ", " $x ", " $y ";\n"
        "cneg " $t ", " $t ", cc;\n"
        "csetm " $c ", cc;\n"
        "subs " $h ", " $w ", " $z ";\n"
        "cneg " $h ", " $h ", cc;\n"
        "mul " $l ", " $t ", " $h ";\n"
        "umulh " $h ", " $t ", " $h ";\n"
        "cinv " $c ", " $c ", cc;\n"
        "eor " $l ", " $l ", " $c ";\n"
        "eor " $h ", " $h ", " $c
    )}
}

// ---------------------------------------------------------------------------
// Core one-step "short" Montgomery reduction macro. Takes input in
// [d3;d2;d1;d0] and returns result in [d4;d3;d2;d1], adding to the
// existing contents of [d3;d2;d1] and generating d4 from zero, re-using
// d0 as a temporary internally together with t0, t1 and t2.
// It is fine for d4 to be the same register as d0, and it often is.
// ---------------------------------------------------------------------------

macro_rules! montreds {
    ($d4:expr, $d3:expr, $d2:expr, $d1:expr, $d0:expr, $t2:expr, $t1:expr, $t0:expr) => { Q!(
        /* Let w = d0, the original word we use as offset; d0 gets recycled      */
        /* First let [t2;t1] = 2^32 * w                                          */
        /* then let [d0;t0] = (2^64 - 2^32 + 1) * w (overwrite old d0)           */
        "lsl " $t1 ", " $d0 ", #32;\n"
        "subs " $t0 ", " $d0 ", " $t1 ";\n"
        "lsr " $t2 ", " $d0 ", #32;\n"
        "sbc " $d0 ", " $d0 ", " $t2 ";\n"
        /* Hence [d4;..;d1] := [d3;d2;d1;0] + (2^256 - 2^224 + 2^192 + 2^96) * w */
        "adds " $d1 ", " $d1 ", " $t1 ";\n"
        "adcs " $d2 ", " $d2 ", " $t2 ";\n"
        "adcs " $d3 ", " $d3 ", " $t0 ";\n"
        "adc " $d4 ", " $d0 ", xzr"
    )}
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

macro_rules! s0 {
    () => {
        Q!("x11")
    };
}
macro_rules! s1 {
    () => {
        Q!("x12")
    };
}
macro_rules! s2 {
    () => {
        Q!("x13")
    };
}
macro_rules! s3 {
    () => {
        Q!("x14")
    };
}
macro_rules! t0 {
    () => {
        Q!("x15")
    };
}
macro_rules! t1 {
    () => {
        Q!("x16")
    };
}
macro_rules! t2 {
    () => {
        Q!("x17")
    };
}
macro_rules! t3 {
    () => {
        Q!("x1")
    };
}
macro_rules! s4 {
    () => {
        Q!("x2")
    };
}

macro_rules! d0 {
    () => {
        Q!(s2!())
    };
}
macro_rules! d1 {
    () => {
        Q!(s3!())
    };
}
macro_rules! d2 {
    () => {
        Q!(a0!())
    };
}
macro_rules! d3 {
    () => {
        Q!(a1!())
    };
}
macro_rules! h {
    () => {
        Q!(b3!())
    };
}
macro_rules! q {
    () => {
        Q!(s4!())
    };
}
macro_rules! c {
    () => {
        Q!(b0!())
    };
}

pub fn bignum_montmul_p256(z: &mut [u64; 4], x: &[u64; 4], y: &[u64; 4]) {
    unsafe {
        core::arch::asm!(


        // Load in all words of both inputs

        Q!("    ldp             " a0!() ", " a1!() ", [x1]"),
        Q!("    ldp             " a2!() ", " a3!() ", [x1, #16]"),
        Q!("    ldp             " b0!() ", " b1!() ", [x2]"),
        Q!("    ldp             " b2!() ", " b3!() ", [x2, #16]"),

        // Multiply low halves with a 2x2->4 ADK multiplier as L = [s3;s2;s1;s0]

        Q!("    mul             " s0!() ", " a0!() ", " b0!()),
        Q!("    mul             " s2!() ", " a1!() ", " b1!()),
        Q!("    umulh           " s1!() ", " a0!() ", " b0!()),
        Q!("    adds            " t1!() ", " s0!() ", " s2!()),
        Q!("    umulh           " s3!() ", " a1!() ", " b1!()),
        Q!("    adcs            " t2!() ", " s1!() ", " s3!()),
        Q!("    adcs            " s3!() ", " s3!() ", xzr"),
        Q!("    adds            " s1!() ", " s1!() ", " t1!()),
        Q!("    adcs            " s2!() ", " s2!() ", " t2!()),
        Q!("    adcs            " s3!() ", " s3!() ", xzr"),
        muldiffn!(t3!(), t2!(), t1!(), t0!(), a0!(), a1!(), b1!(), b0!()),
        Q!("    adds            " "xzr, " t3!() ", #1"),
        Q!("    adcs            " s1!() ", " s1!() ", " t1!()),
        Q!("    adcs            " s2!() ", " s2!() ", " t2!()),
        Q!("    adc             " s3!() ", " s3!() ", " t3!()),

        // Perform two "short" Montgomery steps on the low product to
        // get a modified low result L' = [s1;s0;s3;s2]
        // This shifts it to an offset compatible with middle terms
        // Stash the result L' temporarily in the output buffer to avoid
        // using additional registers.

        montreds!(s0!(), s3!(), s2!(), s1!(), s0!(), t1!(), t2!(), t3!()),
        montreds!(s1!(), s0!(), s3!(), s2!(), s1!(), t1!(), t2!(), t3!()),

        Q!("    stp             " s2!() ", " s3!() ", [x0]"),
        Q!("    stp             " s0!() ", " s1!() ", [x0, #16]"),

        // Multiply high halves with a 2x2->4 ADK multiplier as H = [s3;s2;s1;s0]

        Q!("    mul             " s0!() ", " a2!() ", " b2!()),
        Q!("    mul             " s2!() ", " a3!() ", " b3!()),
        Q!("    umulh           " s1!() ", " a2!() ", " b2!()),
        Q!("    adds            " t1!() ", " s0!() ", " s2!()),
        Q!("    umulh           " s3!() ", " a3!() ", " b3!()),
        Q!("    adcs            " t2!() ", " s1!() ", " s3!()),
        Q!("    adcs            " s3!() ", " s3!() ", xzr"),
        Q!("    adds            " s1!() ", " s1!() ", " t1!()),
        Q!("    adcs            " s2!() ", " s2!() ", " t2!()),
        Q!("    adcs            " s3!() ", " s3!() ", xzr"),
        muldiffn!(t3!(), t2!(), t1!(), t0!(), a2!(), a3!(), b3!(), b2!()),
        Q!("    adds            " "xzr, " t3!() ", #1"),
        Q!("    adcs            " s1!() ", " s1!() ", " t1!()),
        Q!("    adcs            " s2!() ", " s2!() ", " t2!()),
        Q!("    adc             " s3!() ", " s3!() ", " t3!()),

        // Compute sign-magnitude a2,[a1,a0] = x_hi - x_lo

        Q!("    subs            " a0!() ", " a2!() ", " a0!()),
        Q!("    sbcs            " a1!() ", " a3!() ", " a1!()),
        Q!("    sbc             " a2!() ", xzr, xzr"),
        Q!("    adds            " "xzr, " a2!() ", #1"),
        Q!("    eor             " a0!() ", " a0!() ", " a2!()),
        Q!("    adcs            " a0!() ", " a0!() ", xzr"),
        Q!("    eor             " a1!() ", " a1!() ", " a2!()),
        Q!("    adcs            " a1!() ", " a1!() ", xzr"),

        // Compute sign-magnitude b2,[b1,b0] = y_lo - y_hi

        Q!("    subs            " b0!() ", " b0!() ", " b2!()),
        Q!("    sbcs            " b1!() ", " b1!() ", " b3!()),
        Q!("    sbc             " b2!() ", xzr, xzr"),
        Q!("    adds            " "xzr, " b2!() ", #1"),
        Q!("    eor             " b0!() ", " b0!() ", " b2!()),
        Q!("    adcs            " b0!() ", " b0!() ", xzr"),
        Q!("    eor             " b1!() ", " b1!() ", " b2!()),
        Q!("    adcs            " b1!() ", " b1!() ", xzr"),

        // Save the correct sign for the sub-product in b3

        Q!("    eor             " b3!() ", " a2!() ", " b2!()),

        // Add the high H to the modified low term L' as H + L' = [s4;b2;a2;t3;t0]

        Q!("    ldp             " t0!() ", " t3!() ", [x0]"),
        Q!("    adds            " t0!() ", " s0!() ", " t0!()),
        Q!("    adcs            " t3!() ", " s1!() ", " t3!()),
        Q!("    ldp             " a2!() ", " b2!() ", [x0, #16]"),
        Q!("    adcs            " a2!() ", " s2!() ", " a2!()),
        Q!("    adcs            " b2!() ", " s3!() ", " b2!()),
        Q!("    adc             " s4!() ", xzr, xzr"),

        // Multiply with yet a third 2x2->4 ADK multiplier for complex mid-term M

        Q!("    mul             " s0!() ", " a0!() ", " b0!()),
        Q!("    mul             " s2!() ", " a1!() ", " b1!()),
        Q!("    umulh           " s1!() ", " a0!() ", " b0!()),
        Q!("    adds            " t1!() ", " s0!() ", " s2!()),
        Q!("    umulh           " s3!() ", " a1!() ", " b1!()),
        Q!("    adcs            " t2!() ", " s1!() ", " s3!()),
        Q!("    adcs            " s3!() ", " s3!() ", xzr"),
        Q!("    adds            " s1!() ", " s1!() ", " t1!()),
        Q!("    adcs            " s2!() ", " s2!() ", " t2!()),
        Q!("    adcs            " s3!() ", " s3!() ", xzr"),
        muldiffn!(a1!(), t2!(), t1!(), a0!(), a0!(), a1!(), b1!(), b0!()),
        Q!("    adds            " "xzr, " a1!() ", #1"),
        Q!("    adcs            " s1!() ", " s1!() ", " t1!()),
        Q!("    adcs            " s2!() ", " s2!() ", " t2!()),
        Q!("    adc             " s3!() ", " s3!() ", " a1!()),

        // Set up a sign-modified version of the mid-product in a long accumulator
        // as [b3;a1;a0;s3;s2;s1;s0], adding in the H + L' term once with
        // zero offset as this signed value is created

        Q!("    adds            " "xzr, " b3!() ", #1"),
        Q!("    eor             " s0!() ", " s0!() ", " b3!()),
        Q!("    adcs            " s0!() ", " s0!() ", " t0!()),
        Q!("    eor             " s1!() ", " s1!() ", " b3!()),
        Q!("    adcs            " s1!() ", " s1!() ", " t3!()),
        Q!("    eor             " s2!() ", " s2!() ", " b3!()),
        Q!("    adcs            " s2!() ", " s2!() ", " a2!()),
        Q!("    eor             " s3!() ", " s3!() ", " b3!()),
        Q!("    adcs            " s3!() ", " s3!() ", " b2!()),
        Q!("    adcs            " a0!() ", " s4!() ", " b3!()),
        Q!("    adcs            " a1!() ", " b3!() ", xzr"),
        Q!("    adc             " b3!() ", " b3!() ", xzr"),

        // Add in the stashed H + L' term an offset of 2 words as well

        Q!("    adds            " s2!() ", " s2!() ", " t0!()),
        Q!("    adcs            " s3!() ", " s3!() ", " t3!()),
        Q!("    adcs            " a0!() ", " a0!() ", " a2!()),
        Q!("    adcs            " a1!() ", " a1!() ", " b2!()),
        Q!("    adc             " b3!() ", " b3!() ", " s4!()),

        // Do two more Montgomery steps on the composed term
        // Net pre-reduct is in [b3;a1;a0;s3;s2]

        montreds!(s0!(), s3!(), s2!(), s1!(), s0!(), t1!(), t2!(), t3!()),
        montreds!(s1!(), s0!(), s3!(), s2!(), s1!(), t1!(), t2!(), t3!()),

        Q!("    adds            " a0!() ", " a0!() ", " s0!()),
        Q!("    adcs            " a1!() ", " a1!() ", " s1!()),
        Q!("    adc             " b3!() ", " b3!() ", xzr"),

        // Because of the way we added L' in two places, we can overspill by
        // more than usual in Montgomery, with the result being only known to
        // be < 3 * p_256, not the usual < 2 * p_256. So now we do a more
        // elaborate final correction in the style of bignum_cmul_p256, though
        // we can use much simpler quotient estimation logic (q = h + 1) and
        // slightly more direct accumulation of p_256 * q.

        // <macro definition d0 hoisted upwards>
        // <macro definition d1 hoisted upwards>
        // <macro definition d2 hoisted upwards>
        // <macro definition d3 hoisted upwards>
        // <macro definition h hoisted upwards>

        // <macro definition q hoisted upwards>
        // <macro definition c hoisted upwards>

        Q!("    add             " q!() ", " h!() ", #1"),
        Q!("    lsl             " t1!() ", " q!() ", #32"),

        Q!("    adds            " d3!() ", " d3!() ", " t1!()),
        Q!("    adc             " h!() ", " h!() ", xzr"),
        Q!("    sub             " t0!() ", xzr, " q!()),
        Q!("    sub             " t1!() ", " t1!() ", #1"),
        Q!("    subs            " d0!() ", " d0!() ", " t0!()),
        Q!("    sbcs            " d1!() ", " d1!() ", " t1!()),
        Q!("    sbcs            " d2!() ", " d2!() ", xzr"),
        Q!("    sbcs            " d3!() ", " d3!() ", " q!()),
        Q!("    sbcs            " c!() ", " h!() ", " q!()),
        Q!("    adds            " d0!() ", " d0!() ", " c!()),
        Q!("    mov             " h!() ", #0x00000000ffffffff"),
        Q!("    and             " h!() ", " h!() ", " c!()),
        Q!("    adcs            " d1!() ", " d1!() ", " h!()),
        Q!("    adcs            " d2!() ", " d2!() ", xzr"),
        Q!("    mov             " h!() ", #0xffffffff00000001"),
        Q!("    and             " h!() ", " h!() ", " c!()),
        Q!("    adc             " d3!() ", " d3!() ", " h!()),

        // Finally store the result

        Q!("    stp             " d0!() ", " d1!() ", [x0]"),
        Q!("    stp             " d2!() ", " d3!() ", [x0, #16]"),

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
        out("x17") _,
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
