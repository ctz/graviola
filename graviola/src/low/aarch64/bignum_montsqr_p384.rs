#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Montgomery square, z := (x^2 / 2^384) mod p_384
// Input x[6]; output z[6]
//
//    extern void bignum_montsqr_p384
//     (uint64_t z[static 6], uint64_t x[static 6]);
//
// Does z := (x^2 / 2^384) mod p_384, assuming x^2 <= 2^384 * p_384, which is
// guaranteed in particular if x < p_384 initially (the "intended" case).
//
// Standard ARM ABI: X0 = z, X1 = x
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

macro_rules! c0 {
    () => {
        Q!("x8")
    };
}
macro_rules! c1 {
    () => {
        Q!("x9")
    };
}
macro_rules! c2 {
    () => {
        Q!("x10")
    };
}
macro_rules! c3 {
    () => {
        Q!("x11")
    };
}
macro_rules! c4 {
    () => {
        Q!("x12")
    };
}
macro_rules! c5 {
    () => {
        Q!("x13")
    };
}
macro_rules! d1 {
    () => {
        Q!("x14")
    };
}
macro_rules! d2 {
    () => {
        Q!("x15")
    };
}
macro_rules! d3 {
    () => {
        Q!("x16")
    };
}
macro_rules! d4 {
    () => {
        Q!("x17")
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
macro_rules! s0 {
    () => {
        Q!("x8")
    };
}
macro_rules! s1 {
    () => {
        Q!("x9")
    };
}
macro_rules! s2 {
    () => {
        Q!("x10")
    };
}
macro_rules! s3 {
    () => {
        Q!("x11")
    };
}
macro_rules! s4 {
    () => {
        Q!("x12")
    };
}
macro_rules! s5 {
    () => {
        Q!("x13")
    };
}
macro_rules! l1 {
    () => {
        Q!("x14")
    };
}
macro_rules! l2 {
    () => {
        Q!("x15")
    };
}
macro_rules! h0 {
    () => {
        Q!("x16")
    };
}
macro_rules! h1 {
    () => {
        Q!("x17")
    };
}
macro_rules! h2 {
    () => {
        Q!("x1")
    };
}
macro_rules! s6 {
    () => {
        Q!(h1!())
    };
}
macro_rules! c {
    () => {
        Q!(l1!())
    };
}
macro_rules! h {
    () => {
        Q!(l2!())
    };
}
macro_rules! l {
    () => {
        Q!(h0!())
    };
}
macro_rules! t {
    () => {
        Q!(h1!())
    };
}
macro_rules! r0 {
    () => {
        Q!("x11")
    };
}
macro_rules! r1 {
    () => {
        Q!("x12")
    };
}
macro_rules! r2 {
    () => {
        Q!("x13")
    };
}
macro_rules! r3 {
    () => {
        Q!("x17")
    };
}
macro_rules! r4 {
    () => {
        Q!("x8")
    };
}
macro_rules! r5 {
    () => {
        Q!("x9")
    };
}
macro_rules! r6 {
    () => {
        Q!("x10")
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
macro_rules! t1 {
    () => {
        Q!("x1")
    };
}
macro_rules! t2 {
    () => {
        Q!("x14")
    };
}
macro_rules! t3 {
    () => {
        Q!("x15")
    };
}
macro_rules! t4 {
    () => {
        Q!("x16")
    };
}
macro_rules! t5 {
    () => {
        Q!("x5")
    };
}

pub fn bignum_montsqr_p384(z: &mut [u64; 6], x: &[u64; 6]) {
    unsafe {
        core::arch::asm!(


        // Load in all words of the input

        Q!("    ldp             " a0!() ", " a1!() ", [x1]"),
        Q!("    ldp             " a2!() ", " a3!() ", [x1, #16]"),
        Q!("    ldp             " a4!() ", " a5!() ", [x1, #32]"),

        // Square the low half getting a result in [c5;c4;c3;c2;c1;c0]

        Q!("    mul             " d1!() ", " a0!() ", " a1!()),
        Q!("    mul             " d2!() ", " a0!() ", " a2!()),
        Q!("    mul             " d3!() ", " a1!() ", " a2!()),
        Q!("    mul             " c0!() ", " a0!() ", " a0!()),
        Q!("    mul             " c2!() ", " a1!() ", " a1!()),
        Q!("    mul             " c4!() ", " a2!() ", " a2!()),

        Q!("    umulh           " d4!() ", " a0!() ", " a1!()),
        Q!("    adds            " d2!() ", " d2!() ", " d4!()),
        Q!("    umulh           " d4!() ", " a0!() ", " a2!()),
        Q!("    adcs            " d3!() ", " d3!() ", " d4!()),
        Q!("    umulh           " d4!() ", " a1!() ", " a2!()),
        Q!("    adcs            " d4!() ", " d4!() ", xzr"),

        Q!("    umulh           " c1!() ", " a0!() ", " a0!()),
        Q!("    umulh           " c3!() ", " a1!() ", " a1!()),
        Q!("    umulh           " c5!() ", " a2!() ", " a2!()),

        Q!("    adds            " d1!() ", " d1!() ", " d1!()),
        Q!("    adcs            " d2!() ", " d2!() ", " d2!()),
        Q!("    adcs            " d3!() ", " d3!() ", " d3!()),
        Q!("    adcs            " d4!() ", " d4!() ", " d4!()),
        Q!("    adc             " c5!() ", " c5!() ", xzr"),

        Q!("    adds            " c1!() ", " c1!() ", " d1!()),
        Q!("    adcs            " c2!() ", " c2!() ", " d2!()),
        Q!("    adcs            " c3!() ", " c3!() ", " d3!()),
        Q!("    adcs            " c4!() ", " c4!() ", " d4!()),
        Q!("    adc             " c5!() ", " c5!() ", xzr"),

        // Perform three "short" Montgomery steps on the low square
        // This shifts it to an offset compatible with middle product
        // Stash the result temporarily in the output buffer (to avoid more registers)

        montreds!(c0!(), c5!(), c4!(), c3!(), c2!(), c1!(), c0!(), d1!(), d2!(), d3!()),

        montreds!(c1!(), c0!(), c5!(), c4!(), c3!(), c2!(), c1!(), d1!(), d2!(), d3!()),

        montreds!(c2!(), c1!(), c0!(), c5!(), c4!(), c3!(), c2!(), d1!(), d2!(), d3!()),

        Q!("    stp             " c3!() ", " c4!() ", [x0]"),
        Q!("    stp             " c5!() ", " c0!() ", [x0, #16]"),
        Q!("    stp             " c1!() ", " c2!() ", [x0, #32]"),

        // Compute product of the cross-term with ADK 3x3->6 multiplier

        // <macro definition a0 hoisted upwards>
        // <macro definition a1 hoisted upwards>
        // <macro definition a2 hoisted upwards>
        // <macro definition a3 hoisted upwards>
        // <macro definition a4 hoisted upwards>
        // <macro definition a5 hoisted upwards>
        // <macro definition s0 hoisted upwards>
        // <macro definition s1 hoisted upwards>
        // <macro definition s2 hoisted upwards>
        // <macro definition s3 hoisted upwards>
        // <macro definition s4 hoisted upwards>
        // <macro definition s5 hoisted upwards>

        // <macro definition l1 hoisted upwards>
        // <macro definition l2 hoisted upwards>
        // <macro definition h0 hoisted upwards>
        // <macro definition h1 hoisted upwards>
        // <macro definition h2 hoisted upwards>

        // <macro definition s6 hoisted upwards>
        // <macro definition c hoisted upwards>
        // <macro definition h hoisted upwards>
        // <macro definition l hoisted upwards>
        // <macro definition t hoisted upwards>

        Q!("    mul             " s0!() ", " a0!() ", " a3!()),
        Q!("    mul             " l1!() ", " a1!() ", " a4!()),
        Q!("    mul             " l2!() ", " a2!() ", " a5!()),
        Q!("    umulh           " h0!() ", " a0!() ", " a3!()),
        Q!("    umulh           " h1!() ", " a1!() ", " a4!()),
        Q!("    umulh           " h2!() ", " a2!() ", " a5!()),

        Q!("    adds            " h0!() ", " h0!() ", " l1!()),
        Q!("    adcs            " h1!() ", " h1!() ", " l2!()),
        Q!("    adc             " h2!() ", " h2!() ", xzr"),

        Q!("    adds            " s1!() ", " h0!() ", " s0!()),
        Q!("    adcs            " s2!() ", " h1!() ", " h0!()),
        Q!("    adcs            " s3!() ", " h2!() ", " h1!()),
        Q!("    adc             " s4!() ", " h2!() ", xzr"),

        Q!("    adds            " s2!() ", " s2!() ", " s0!()),
        Q!("    adcs            " s3!() ", " s3!() ", " h0!()),
        Q!("    adcs            " s4!() ", " s4!() ", " h1!()),
        Q!("    adc             " s5!() ", " h2!() ", xzr"),

        muldiffn!(c!(), h!(), l!(), t!(), a0!(), a1!(), a4!(), a3!()),
        Q!("    adds            " "xzr, " c!() ", #1"),
        Q!("    adcs            " s1!() ", " s1!() ", " l!()),
        Q!("    adcs            " s2!() ", " s2!() ", " h!()),
        Q!("    adcs            " s3!() ", " s3!() ", " c!()),
        Q!("    adcs            " s4!() ", " s4!() ", " c!()),
        Q!("    adc             " s5!() ", " s5!() ", " c!()),

        muldiffn!(c!(), h!(), l!(), t!(), a0!(), a2!(), a5!(), a3!()),
        Q!("    adds            " "xzr, " c!() ", #1"),
        Q!("    adcs            " s2!() ", " s2!() ", " l!()),
        Q!("    adcs            " s3!() ", " s3!() ", " h!()),
        Q!("    adcs            " s4!() ", " s4!() ", " c!()),
        Q!("    adc             " s5!() ", " s5!() ", " c!()),

        muldiffn!(c!(), h!(), l!(), t!(), a1!(), a2!(), a5!(), a4!()),
        Q!("    adds            " "xzr, " c!() ", #1"),
        Q!("    adcs            " s3!() ", " s3!() ", " l!()),
        Q!("    adcs            " s4!() ", " s4!() ", " h!()),
        Q!("    adc             " s5!() ", " s5!() ", " c!()),

        // Double it and add the stashed Montgomerified low square

        Q!("    adds            " s0!() ", " s0!() ", " s0!()),
        Q!("    adcs            " s1!() ", " s1!() ", " s1!()),
        Q!("    adcs            " s2!() ", " s2!() ", " s2!()),
        Q!("    adcs            " s3!() ", " s3!() ", " s3!()),
        Q!("    adcs            " s4!() ", " s4!() ", " s4!()),
        Q!("    adcs            " s5!() ", " s5!() ", " s5!()),
        Q!("    adc             " s6!() ", xzr, xzr"),

        Q!("    ldp             " a0!() ", " a1!() ", [x0]"),
        Q!("    adds            " s0!() ", " s0!() ", " a0!()),
        Q!("    adcs            " s1!() ", " s1!() ", " a1!()),
        Q!("    ldp             " a0!() ", " a1!() ", [x0, #16]"),
        Q!("    adcs            " s2!() ", " s2!() ", " a0!()),
        Q!("    adcs            " s3!() ", " s3!() ", " a1!()),
        Q!("    ldp             " a0!() ", " a1!() ", [x0, #32]"),
        Q!("    adcs            " s4!() ", " s4!() ", " a0!()),
        Q!("    adcs            " s5!() ", " s5!() ", " a1!()),
        Q!("    adc             " s6!() ", " s6!() ", xzr"),

        // Montgomery-reduce the combined low and middle term another thrice

        montreds!(s0!(), s5!(), s4!(), s3!(), s2!(), s1!(), s0!(), a0!(), a1!(), a2!()),

        montreds!(s1!(), s0!(), s5!(), s4!(), s3!(), s2!(), s1!(), a0!(), a1!(), a2!()),

        montreds!(s2!(), s1!(), s0!(), s5!(), s4!(), s3!(), s2!(), a0!(), a1!(), a2!()),

        Q!("    adds            " s6!() ", " s6!() ", " s0!()),
        Q!("    adcs            " s0!() ", " s1!() ", xzr"),
        Q!("    adcs            " s1!() ", " s2!() ", xzr"),
        Q!("    adcs            " s2!() ", xzr, xzr"),

        // Our sum so far is in [s2;s1;s0;s6;s5;s4;s3]
        // Choose more intuitive names

        // <macro definition r0 hoisted upwards>
        // <macro definition r1 hoisted upwards>
        // <macro definition r2 hoisted upwards>
        // <macro definition r3 hoisted upwards>
        // <macro definition r4 hoisted upwards>
        // <macro definition r5 hoisted upwards>
        // <macro definition r6 hoisted upwards>

        // Remind ourselves what else we can't destroy

        // <macro definition a3 hoisted upwards>
        // <macro definition a4 hoisted upwards>
        // <macro definition a5 hoisted upwards>

        // So we can have these as temps

        // <macro definition t1 hoisted upwards>
        // <macro definition t2 hoisted upwards>
        // <macro definition t3 hoisted upwards>
        // <macro definition t4 hoisted upwards>

        // Add in all the pure squares 33 + 44 + 55

        Q!("    mul             " t1!() ", " a3!() ", " a3!()),
        Q!("    adds            " r0!() ", " r0!() ", " t1!()),
        Q!("    mul             " t2!() ", " a4!() ", " a4!()),
        Q!("    mul             " t3!() ", " a5!() ", " a5!()),
        Q!("    umulh           " t1!() ", " a3!() ", " a3!()),
        Q!("    adcs            " r1!() ", " r1!() ", " t1!()),
        Q!("    umulh           " t1!() ", " a4!() ", " a4!()),
        Q!("    adcs            " r2!() ", " r2!() ", " t2!()),
        Q!("    adcs            " r3!() ", " r3!() ", " t1!()),
        Q!("    umulh           " t1!() ", " a5!() ", " a5!()),
        Q!("    adcs            " r4!() ", " r4!() ", " t3!()),
        Q!("    adcs            " r5!() ", " r5!() ", " t1!()),
        Q!("    adc             " r6!() ", " r6!() ", xzr"),

        // Now compose the 34 + 35 + 45 terms, which need doubling

        Q!("    mul             " t1!() ", " a3!() ", " a4!()),
        Q!("    mul             " t2!() ", " a3!() ", " a5!()),
        Q!("    mul             " t3!() ", " a4!() ", " a5!()),
        Q!("    umulh           " t4!() ", " a3!() ", " a4!()),
        Q!("    adds            " t2!() ", " t2!() ", " t4!()),
        Q!("    umulh           " t4!() ", " a3!() ", " a5!()),
        Q!("    adcs            " t3!() ", " t3!() ", " t4!()),
        Q!("    umulh           " t4!() ", " a4!() ", " a5!()),
        Q!("    adc             " t4!() ", " t4!() ", xzr"),

        // Double and add. Recycle one of the no-longer-needed inputs as a temp

        // <macro definition t5 hoisted upwards>

        Q!("    adds            " t1!() ", " t1!() ", " t1!()),
        Q!("    adcs            " t2!() ", " t2!() ", " t2!()),
        Q!("    adcs            " t3!() ", " t3!() ", " t3!()),
        Q!("    adcs            " t4!() ", " t4!() ", " t4!()),
        Q!("    adc             " t5!() ", xzr, xzr"),

        Q!("    adds            " r1!() ", " r1!() ", " t1!()),
        Q!("    adcs            " r2!() ", " r2!() ", " t2!()),
        Q!("    adcs            " r3!() ", " r3!() ", " t3!()),
        Q!("    adcs            " r4!() ", " r4!() ", " t4!()),
        Q!("    adcs            " r5!() ", " r5!() ", " t5!()),
        Q!("    adc             " r6!() ", " r6!() ", xzr"),

        // We know, writing B = 2^{6*64} that the full implicit result is
        // B^2 c <= z + (B - 1) * p < B * p + (B - 1) * p < 2 * B * p,
        // so the top half is certainly < 2 * p. If c = 1 already, we know
        // subtracting p will give the reduced modulus. But now we do a
        // comparison to catch cases where the residue is >= p.
        // First set [0;0;0;t3;t2;t1] = 2^384 - p_384

        Q!("    mov             " t1!() ", #0xffffffff00000001"),
        Q!("    mov             " t2!() ", #0x00000000ffffffff"),
        Q!("    mov             " t3!() ", #0x0000000000000001"),

        // Let dd = [] be the 6-word intermediate result.
        // Set CF if the addition dd + (2^384 - p_384) >= 2^384, hence iff dd >= p_384.

        Q!("    adds            " "xzr, " r0!() ", " t1!()),
        Q!("    adcs            " "xzr, " r1!() ", " t2!()),
        Q!("    adcs            " "xzr, " r2!() ", " t3!()),
        Q!("    adcs            " "xzr, " r3!() ", xzr"),
        Q!("    adcs            " "xzr, " r4!() ", xzr"),
        Q!("    adcs            " "xzr, " r5!() ", xzr"),

        // Now just add this new carry into the existing r6. It's easy to see they
        // can't both be 1 by our range assumptions, so this gives us a {0,1} flag

        Q!("    adc             " r6!() ", " r6!() ", xzr"),

        // Now convert it into a bitmask

        Q!("    sub             " r6!() ", xzr, " r6!()),

        // Masked addition of 2^384 - p_384, hence subtraction of p_384

        Q!("    and             " t1!() ", " t1!() ", " r6!()),
        Q!("    adds            " r0!() ", " r0!() ", " t1!()),
        Q!("    and             " t2!() ", " t2!() ", " r6!()),
        Q!("    adcs            " r1!() ", " r1!() ", " t2!()),
        Q!("    and             " t3!() ", " t3!() ", " r6!()),
        Q!("    adcs            " r2!() ", " r2!() ", " t3!()),
        Q!("    adcs            " r3!() ", " r3!() ", xzr"),
        Q!("    adcs            " r4!() ", " r4!() ", xzr"),
        Q!("    adc             " r5!() ", " r5!() ", xzr"),

        // Store it back

        Q!("    stp             " r0!() ", " r1!() ", [x0]"),
        Q!("    stp             " r2!() ", " r3!() ", [x0, #16]"),
        Q!("    stp             " r4!() ", " r5!() ", [x0, #32]"),

        inout("x0") z.as_mut_ptr() => _,
        inout("x1") x.as_ptr() => _,
        // clobbers
        out("v0") _,
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
