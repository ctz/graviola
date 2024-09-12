#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Montgomery multiply, z := (x * y / 2^384) mod p_384
// Inputs x[6], y[6]; output z[6]
//
//    extern void bignum_montmul_p384
//     (uint64_t z[static 6], uint64_t x[static 6], uint64_t y[static 6]);
//
// Does z := (2^{-384} * x * y) mod p_384, assuming that the inputs x and y
// satisfy x * y <= 2^384 * p_384 (in particular this is true if we are in
// the "usual" case x < p_384 and y < p_384).
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
        /* Recycle d0 (which we know gets implicitly cancelled) to store it     */
        "lsl " $t1 ", " $d0 ", #32;\n"
        "add " $d0 ", " $t1 ", " $d0 ";\n"
        /* Now let [t2;t1] = 2^64 * w - w + w_hi where w_hi = floor(w/2^32)     */
        /* We need to subtract 2^32 * this, and we can ignore its lower 32      */
        /* bits since by design it will cancel anyway; we only need the w_hi    */
        /* part to get the carry propagation going.                             */
        "lsr " $t1 ", " $d0 ", #32;\n"
        "subs " $t1 ", " $t1 ", " $d0 ";\n"
        "sbc " $t2 ", " $d0 ", xzr;\n"
        /* Now select in t1 the field to subtract from d1                       */
        "extr " $t1 ", " $t2 ", " $t1 ", #32;\n"
        /* And now get the terms to subtract from d2 and d3                     */
        "lsr " $t2 ", " $t2 ", #32;\n"
        "adds " $t2 ", " $t2 ", " $d0 ";\n"
        "adc " $t3 ", xzr, xzr;\n"
        /* Do the subtraction of that portion                                   */
        "subs " $d1 ", " $d1 ", " $t1 ";\n"
        "sbcs " $d2 ", " $d2 ", " $t2 ";\n"
        "sbcs " $d3 ", " $d3 ", " $t3 ";\n"
        "sbcs " $d4 ", " $d4 ", xzr;\n"
        "sbcs " $d5 ", " $d5 ", xzr;\n"
        /* Now effectively add 2^384 * w by taking d0 as the input for last sbc */
        "sbc " $d6 ", " $d0 ", xzr"
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
macro_rules! a4 {
    () => {
        Q!("x7")
    };
}
macro_rules! a5 {
    () => {
        Q!("x8")
    };
}
macro_rules! b0 {
    () => {
        Q!("x9")
    };
}
macro_rules! b1 {
    () => {
        Q!("x10")
    };
}
macro_rules! b2 {
    () => {
        Q!("x11")
    };
}
macro_rules! b3 {
    () => {
        Q!("x12")
    };
}
macro_rules! b4 {
    () => {
        Q!("x13")
    };
}
macro_rules! b5 {
    () => {
        Q!("x14")
    };
}

macro_rules! s0 {
    () => {
        Q!("x15")
    };
}
macro_rules! s1 {
    () => {
        Q!("x16")
    };
}
macro_rules! s2 {
    () => {
        Q!("x17")
    };
}
macro_rules! s3 {
    () => {
        Q!("x19")
    };
}
macro_rules! s4 {
    () => {
        Q!("x20")
    };
}
macro_rules! s5 {
    () => {
        Q!("x1")
    };
}
macro_rules! s6 {
    () => {
        Q!("x2")
    };
}

macro_rules! t1 {
    () => {
        Q!("x21")
    };
}
macro_rules! t2 {
    () => {
        Q!("x22")
    };
}
macro_rules! t3 {
    () => {
        Q!("x23")
    };
}
macro_rules! t4 {
    () => {
        Q!("x24")
    };
}

pub fn bignum_montmul_p384(z: &mut [u64; 6], x: &[u64; 6], y: &[u64; 6]) {
    unsafe {
        core::arch::asm!(


        // Save some registers

        Q!("    stp             " "x19, x20, [sp, -16] !"),
        Q!("    stp             " "x21, x22, [sp, -16] !"),
        Q!("    stp             " "x23, x24, [sp, -16] !"),

        // Load in all words of both inputs

        Q!("    ldp             " a0!() ", " a1!() ", [x1]"),
        Q!("    ldp             " a2!() ", " a3!() ", [x1, #16]"),
        Q!("    ldp             " a4!() ", " a5!() ", [x1, #32]"),
        Q!("    ldp             " b0!() ", " b1!() ", [x2]"),
        Q!("    ldp             " b2!() ", " b3!() ", [x2, #16]"),
        Q!("    ldp             " b4!() ", " b5!() ", [x2, #32]"),

        // Multiply low halves with a 3x3->6 ADK multiplier as [s5;s4;s3;s2;s1;s0]

        Q!("    mul             " s0!() ", " a0!() ", " b0!()),
        Q!("    mul             " t1!() ", " a1!() ", " b1!()),
        Q!("    mul             " t2!() ", " a2!() ", " b2!()),
        Q!("    umulh           " t3!() ", " a0!() ", " b0!()),
        Q!("    umulh           " t4!() ", " a1!() ", " b1!()),
        Q!("    umulh           " s5!() ", " a2!() ", " b2!()),

        Q!("    adds            " t3!() ", " t3!() ", " t1!()),
        Q!("    adcs            " t4!() ", " t4!() ", " t2!()),
        Q!("    adc             " s5!() ", " s5!() ", xzr"),

        Q!("    adds            " s1!() ", " t3!() ", " s0!()),
        Q!("    adcs            " s2!() ", " t4!() ", " t3!()),
        Q!("    adcs            " s3!() ", " s5!() ", " t4!()),
        Q!("    adc             " s4!() ", " s5!() ", xzr"),

        Q!("    adds            " s2!() ", " s2!() ", " s0!()),
        Q!("    adcs            " s3!() ", " s3!() ", " t3!()),
        Q!("    adcs            " s4!() ", " s4!() ", " t4!()),
        Q!("    adc             " s5!() ", " s5!() ", xzr"),

        muldiffn!(t3!(), t2!(), t1!(), t4!(), a0!(), a1!(), b1!(), b0!()),
        Q!("    adds            " "xzr, " t3!() ", #1"),
        Q!("    adcs            " s1!() ", " s1!() ", " t1!()),
        Q!("    adcs            " s2!() ", " s2!() ", " t2!()),
        Q!("    adcs            " s3!() ", " s3!() ", " t3!()),
        Q!("    adcs            " s4!() ", " s4!() ", " t3!()),
        Q!("    adc             " s5!() ", " s5!() ", " t3!()),

        muldiffn!(t3!(), t2!(), t1!(), t4!(), a0!(), a2!(), b2!(), b0!()),
        Q!("    adds            " "xzr, " t3!() ", #1"),
        Q!("    adcs            " s2!() ", " s2!() ", " t1!()),
        Q!("    adcs            " s3!() ", " s3!() ", " t2!()),
        Q!("    adcs            " s4!() ", " s4!() ", " t3!()),
        Q!("    adc             " s5!() ", " s5!() ", " t3!()),

        muldiffn!(t3!(), t2!(), t1!(), t4!(), a1!(), a2!(), b2!(), b1!()),
        Q!("    adds            " "xzr, " t3!() ", #1"),
        Q!("    adcs            " s3!() ", " s3!() ", " t1!()),
        Q!("    adcs            " s4!() ", " s4!() ", " t2!()),
        Q!("    adc             " s5!() ", " s5!() ", " t3!()),

        // Perform three "short" Montgomery steps on the low product
        // This shifts it to an offset compatible with middle terms
        // Stash the result temporarily in the output buffer
        // We could keep this in registers by directly adding to it in the next
        // ADK block, but if anything that seems to be slightly slower

        montreds!(s0!(), s5!(), s4!(), s3!(), s2!(), s1!(), s0!(), t1!(), t2!(), t3!()),

        montreds!(s1!(), s0!(), s5!(), s4!(), s3!(), s2!(), s1!(), t1!(), t2!(), t3!()),

        montreds!(s2!(), s1!(), s0!(), s5!(), s4!(), s3!(), s2!(), t1!(), t2!(), t3!()),

        Q!("    stp             " s3!() ", " s4!() ", [x0]"),
        Q!("    stp             " s5!() ", " s0!() ", [x0, #16]"),
        Q!("    stp             " s1!() ", " s2!() ", [x0, #32]"),

        // Multiply high halves with a 3x3->6 ADK multiplier as [s5;s4;s3;s2;s1;s0]

        Q!("    mul             " s0!() ", " a3!() ", " b3!()),
        Q!("    mul             " t1!() ", " a4!() ", " b4!()),
        Q!("    mul             " t2!() ", " a5!() ", " b5!()),
        Q!("    umulh           " t3!() ", " a3!() ", " b3!()),
        Q!("    umulh           " t4!() ", " a4!() ", " b4!()),
        Q!("    umulh           " s5!() ", " a5!() ", " b5!()),

        Q!("    adds            " t3!() ", " t3!() ", " t1!()),
        Q!("    adcs            " t4!() ", " t4!() ", " t2!()),
        Q!("    adc             " s5!() ", " s5!() ", xzr"),

        Q!("    adds            " s1!() ", " t3!() ", " s0!()),
        Q!("    adcs            " s2!() ", " t4!() ", " t3!()),
        Q!("    adcs            " s3!() ", " s5!() ", " t4!()),
        Q!("    adc             " s4!() ", " s5!() ", xzr"),

        Q!("    adds            " s2!() ", " s2!() ", " s0!()),
        Q!("    adcs            " s3!() ", " s3!() ", " t3!()),
        Q!("    adcs            " s4!() ", " s4!() ", " t4!()),
        Q!("    adc             " s5!() ", " s5!() ", xzr"),

        muldiffn!(t3!(), t2!(), t1!(), t4!(), a3!(), a4!(), b4!(), b3!()),
        Q!("    adds            " "xzr, " t3!() ", #1"),
        Q!("    adcs            " s1!() ", " s1!() ", " t1!()),
        Q!("    adcs            " s2!() ", " s2!() ", " t2!()),
        Q!("    adcs            " s3!() ", " s3!() ", " t3!()),
        Q!("    adcs            " s4!() ", " s4!() ", " t3!()),
        Q!("    adc             " s5!() ", " s5!() ", " t3!()),

        muldiffn!(t3!(), t2!(), t1!(), t4!(), a3!(), a5!(), b5!(), b3!()),
        Q!("    adds            " "xzr, " t3!() ", #1"),
        Q!("    adcs            " s2!() ", " s2!() ", " t1!()),
        Q!("    adcs            " s3!() ", " s3!() ", " t2!()),
        Q!("    adcs            " s4!() ", " s4!() ", " t3!()),
        Q!("    adc             " s5!() ", " s5!() ", " t3!()),

        muldiffn!(t3!(), t2!(), t1!(), t4!(), a4!(), a5!(), b5!(), b4!()),
        Q!("    adds            " "xzr, " t3!() ", #1"),
        Q!("    adcs            " s3!() ", " s3!() ", " t1!()),
        Q!("    adcs            " s4!() ", " s4!() ", " t2!()),
        Q!("    adc             " s5!() ", " s5!() ", " t3!()),

        // Compute sign-magnitude a0,[a5,a4,a3] = x_hi - x_lo

        Q!("    subs            " a3!() ", " a3!() ", " a0!()),
        Q!("    sbcs            " a4!() ", " a4!() ", " a1!()),
        Q!("    sbcs            " a5!() ", " a5!() ", " a2!()),
        Q!("    sbc             " a0!() ", xzr, xzr"),
        Q!("    adds            " "xzr, " a0!() ", #1"),
        Q!("    eor             " a3!() ", " a3!() ", " a0!()),
        Q!("    adcs            " a3!() ", " a3!() ", xzr"),
        Q!("    eor             " a4!() ", " a4!() ", " a0!()),
        Q!("    adcs            " a4!() ", " a4!() ", xzr"),
        Q!("    eor             " a5!() ", " a5!() ", " a0!()),
        Q!("    adc             " a5!() ", " a5!() ", xzr"),

        // Compute sign-magnitude b5,[b2,b1,b0] = y_lo - y_hi

        Q!("    subs            " b0!() ", " b0!() ", " b3!()),
        Q!("    sbcs            " b1!() ", " b1!() ", " b4!()),
        Q!("    sbcs            " b2!() ", " b2!() ", " b5!()),
        Q!("    sbc             " b5!() ", xzr, xzr"),

        Q!("    adds            " "xzr, " b5!() ", #1"),
        Q!("    eor             " b0!() ", " b0!() ", " b5!()),
        Q!("    adcs            " b0!() ", " b0!() ", xzr"),
        Q!("    eor             " b1!() ", " b1!() ", " b5!()),
        Q!("    adcs            " b1!() ", " b1!() ", xzr"),
        Q!("    eor             " b2!() ", " b2!() ", " b5!()),
        Q!("    adc             " b2!() ", " b2!() ", xzr"),

        // Save the correct sign for the sub-product in b5

        Q!("    eor             " b5!() ", " a0!() ", " b5!()),

        // Add the high H to the modified low term L' and re-stash 6 words,
        // keeping top word in s6

        Q!("    ldp             " t1!() ", " t2!() ", [x0]"),
        Q!("    adds            " s0!() ", " s0!() ", " t1!()),
        Q!("    adcs            " s1!() ", " s1!() ", " t2!()),
        Q!("    ldp             " t1!() ", " t2!() ", [x0, #16]"),
        Q!("    adcs            " s2!() ", " s2!() ", " t1!()),
        Q!("    adcs            " s3!() ", " s3!() ", " t2!()),
        Q!("    ldp             " t1!() ", " t2!() ", [x0, #32]"),
        Q!("    adcs            " s4!() ", " s4!() ", " t1!()),
        Q!("    adcs            " s5!() ", " s5!() ", " t2!()),
        Q!("    adc             " s6!() ", xzr, xzr"),
        Q!("    stp             " s0!() ", " s1!() ", [x0]"),
        Q!("    stp             " s2!() ", " s3!() ", [x0, #16]"),
        Q!("    stp             " s4!() ", " s5!() ", [x0, #32]"),

        // Multiply with yet a third 3x3 ADK for the complex mid-term

        Q!("    mul             " s0!() ", " a3!() ", " b0!()),
        Q!("    mul             " t1!() ", " a4!() ", " b1!()),
        Q!("    mul             " t2!() ", " a5!() ", " b2!()),
        Q!("    umulh           " t3!() ", " a3!() ", " b0!()),
        Q!("    umulh           " t4!() ", " a4!() ", " b1!()),
        Q!("    umulh           " s5!() ", " a5!() ", " b2!()),

        Q!("    adds            " t3!() ", " t3!() ", " t1!()),
        Q!("    adcs            " t4!() ", " t4!() ", " t2!()),
        Q!("    adc             " s5!() ", " s5!() ", xzr"),

        Q!("    adds            " s1!() ", " t3!() ", " s0!()),
        Q!("    adcs            " s2!() ", " t4!() ", " t3!()),
        Q!("    adcs            " s3!() ", " s5!() ", " t4!()),
        Q!("    adc             " s4!() ", " s5!() ", xzr"),

        Q!("    adds            " s2!() ", " s2!() ", " s0!()),
        Q!("    adcs            " s3!() ", " s3!() ", " t3!()),
        Q!("    adcs            " s4!() ", " s4!() ", " t4!()),
        Q!("    adc             " s5!() ", " s5!() ", xzr"),

        muldiffn!(t3!(), t2!(), t1!(), t4!(), a3!(), a4!(), b1!(), b0!()),
        Q!("    adds            " "xzr, " t3!() ", #1"),
        Q!("    adcs            " s1!() ", " s1!() ", " t1!()),
        Q!("    adcs            " s2!() ", " s2!() ", " t2!()),
        Q!("    adcs            " s3!() ", " s3!() ", " t3!()),
        Q!("    adcs            " s4!() ", " s4!() ", " t3!()),
        Q!("    adc             " s5!() ", " s5!() ", " t3!()),

        muldiffn!(t3!(), t2!(), t1!(), t4!(), a3!(), a5!(), b2!(), b0!()),
        Q!("    adds            " "xzr, " t3!() ", #1"),
        Q!("    adcs            " s2!() ", " s2!() ", " t1!()),
        Q!("    adcs            " s3!() ", " s3!() ", " t2!()),
        Q!("    adcs            " s4!() ", " s4!() ", " t3!()),
        Q!("    adc             " s5!() ", " s5!() ", " t3!()),

        muldiffn!(t3!(), t2!(), t1!(), t4!(), a4!(), a5!(), b2!(), b1!()),
        Q!("    adds            " "xzr, " t3!() ", #1"),
        Q!("    adcs            " s3!() ", " s3!() ", " t1!()),
        Q!("    adcs            " s4!() ", " s4!() ", " t2!()),
        Q!("    adc             " s5!() ", " s5!() ", " t3!()),

        // Unstash the H + L' sum to add in twice

        Q!("    ldp             " a0!() ", " a1!() ", [x0]"),
        Q!("    ldp             " a2!() ", " a3!() ", [x0, #16]"),
        Q!("    ldp             " a4!() ", " a5!() ", [x0, #32]"),

        // Set up a sign-modified version of the mid-product in a long accumulator
        // as [b3;b2;b1;b0;s5;s4;s3;s2;s1;s0], adding in the H + L' term once with
        // zero offset as this signed value is created

        Q!("    adds            " "xzr, " b5!() ", #1"),
        Q!("    eor             " s0!() ", " s0!() ", " b5!()),
        Q!("    adcs            " s0!() ", " s0!() ", " a0!()),
        Q!("    eor             " s1!() ", " s1!() ", " b5!()),
        Q!("    adcs            " s1!() ", " s1!() ", " a1!()),
        Q!("    eor             " s2!() ", " s2!() ", " b5!()),
        Q!("    adcs            " s2!() ", " s2!() ", " a2!()),
        Q!("    eor             " s3!() ", " s3!() ", " b5!()),
        Q!("    adcs            " s3!() ", " s3!() ", " a3!()),
        Q!("    eor             " s4!() ", " s4!() ", " b5!()),
        Q!("    adcs            " s4!() ", " s4!() ", " a4!()),
        Q!("    eor             " s5!() ", " s5!() ", " b5!()),
        Q!("    adcs            " s5!() ", " s5!() ", " a5!()),
        Q!("    adcs            " b0!() ", " b5!() ", " s6!()),
        Q!("    adcs            " b1!() ", " b5!() ", xzr"),
        Q!("    adcs            " b2!() ", " b5!() ", xzr"),
        Q!("    adc             " b3!() ", " b5!() ", xzr"),

        // Add in the stashed H + L' term an offset of 3 words as well

        Q!("    adds            " s3!() ", " s3!() ", " a0!()),
        Q!("    adcs            " s4!() ", " s4!() ", " a1!()),
        Q!("    adcs            " s5!() ", " s5!() ", " a2!()),
        Q!("    adcs            " b0!() ", " b0!() ", " a3!()),
        Q!("    adcs            " b1!() ", " b1!() ", " a4!()),
        Q!("    adcs            " b2!() ", " b2!() ", " a5!()),
        Q!("    adc             " b3!() ", " b3!() ", " s6!()),

        // Do three more Montgomery steps on the composed term

        montreds!(s0!(), s5!(), s4!(), s3!(), s2!(), s1!(), s0!(), t1!(), t2!(), t3!()),
        montreds!(s1!(), s0!(), s5!(), s4!(), s3!(), s2!(), s1!(), t1!(), t2!(), t3!()),
        montreds!(s2!(), s1!(), s0!(), s5!(), s4!(), s3!(), s2!(), t1!(), t2!(), t3!()),

        Q!("    adds            " b0!() ", " b0!() ", " s0!()),
        Q!("    adcs            " b1!() ", " b1!() ", " s1!()),
        Q!("    adcs            " b2!() ", " b2!() ", " s2!()),
        Q!("    adc             " b3!() ", " b3!() ", xzr"),

        // Because of the way we added L' in two places, we can overspill by
        // more than usual in Montgomery, with the result being only known to
        // be < 3 * p_384, not the usual < 2 * p_384. So now we do a more
        // elaborate final correction in the style of bignum_cmul_p384, just
        // a little bit simpler because we know q is small.

        Q!("    add             " t2!() ", " b3!() ", #1"),
        Q!("    lsl             " t1!() ", " t2!() ", #32"),
        Q!("    subs            " t4!() ", " t2!() ", " t1!()),
        Q!("    sbc             " t1!() ", " t1!() ", xzr"),

        Q!("    adds            " s3!() ", " s3!() ", " t4!()),
        Q!("    adcs            " s4!() ", " s4!() ", " t1!()),
        Q!("    adcs            " s5!() ", " s5!() ", " t2!()),
        Q!("    adcs            " b0!() ", " b0!() ", xzr"),
        Q!("    adcs            " b1!() ", " b1!() ", xzr"),
        Q!("    adcs            " b2!() ", " b2!() ", xzr"),

        Q!("    csetm           " t2!() ", cc"),

        Q!("    mov             " t3!() ", #0x00000000ffffffff"),
        Q!("    and             " t3!() ", " t3!() ", " t2!()),
        Q!("    adds            " s3!() ", " s3!() ", " t3!()),
        Q!("    eor             " t3!() ", " t3!() ", " t2!()),
        Q!("    adcs            " s4!() ", " s4!() ", " t3!()),
        Q!("    mov             " t3!() ", #0xfffffffffffffffe"),
        Q!("    and             " t3!() ", " t3!() ", " t2!()),
        Q!("    adcs            " s5!() ", " s5!() ", " t3!()),
        Q!("    adcs            " b0!() ", " b0!() ", " t2!()),
        Q!("    adcs            " b1!() ", " b1!() ", " t2!()),
        Q!("    adc             " b2!() ", " b2!() ", " t2!()),

        // Write back the result

        Q!("    stp             " s3!() ", " s4!() ", [x0]"),
        Q!("    stp             " s5!() ", " b0!() ", [x0, #16]"),
        Q!("    stp             " b1!() ", " b2!() ", [x0, #32]"),

        // Restore registers and return

        Q!("    ldp             " "x23, x24, [sp], #16"),
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
        out("x23") _,
        out("x24") _,
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
