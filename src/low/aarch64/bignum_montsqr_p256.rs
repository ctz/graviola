#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::{Label, Q};

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Montgomery square, z := (x^2 / 2^256) mod p_256
// Input x[4]; output z[4]
//
//    extern void bignum_montsqr_p256
//     (uint64_t z[static 4], uint64_t x[static 4]);
//
// Does z := (x^2 / 2^256) mod p_256, assuming x^2 <= 2^256 * p_256, which is
// guaranteed in particular if x < p_256 initially (the "intended" case).
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
        "subs " $t ", " $x ", " $y ";"
        "cneg " $t ", " $t ", cc;"
        "csetm " $c ", cc;"
        "subs " $h ", " $w ", " $z ";"
        "cneg " $h ", " $h ", cc;"
        "mul " $l ", " $t ", " $h ";"
        "umulh " $h ", " $t ", " $h ";"
        "cinv " $c ", " $c ", cc;"
        "eor " $l ", " $l ", " $c ";"
        "eor " $h ", " $h ", " $c
    )}
}

// ---------------------------------------------------------------------------
// Core one-step "end" Montgomery reduction macro. Takes input in
// [d5;d4;d3;d2;d1;d0] and returns result in [d5;d4;d3;d2;d1], adding to
// the existing [d4;d3;d2;d1], re-using d0 as a temporary internally as well
// as t1, t2, t3, and initializing d5 from zero (hence "end").
// ---------------------------------------------------------------------------

macro_rules! montrede {
    ($d5:expr, $d4:expr, $d3:expr, $d2:expr, $d1:expr, $d0:expr, $t2:expr, $t1:expr, $t0:expr) => { Q!(
        /* Let w = d0, the original word we use as offset; d0 gets recycled */ /* First let [t2;t1] = 2^32 * w                                     */ /* then let [d0;t0] = (2^64 - 2^32 + 1) * w (overwrite old d0)      */ "lsl " $t1 ", " $d0 ", # 32;"
        "subs " $t0 ", " $d0 ", " $t1 ";"
        "lsr " $t2 ", " $d0 ", # 32;"
        "sbc " $d0 ", " $d0 ", " $t2 ";"
        /* Hence basic [d4;d3;d2;d1] += (2^256 - 2^224 + 2^192 + 2^96) * w  */ "adds " $d1 ", " $d1 ", " $t1 ";"
        "adcs " $d2 ", " $d2 ", " $t2 ";"
        "adcs " $d3 ", " $d3 ", " $t0 ";"
        "adcs " $d4 ", " $d4 ", " $d0 ";"
        "adc " $d5 ", xzr, xzr"
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
        /* Let w = d0, the original word we use as offset; d0 gets recycled      */ /* First let [t2;t1] = 2^32 * w                                          */ /* then let [d0;t0] = (2^64 - 2^32 + 1) * w (overwrite old d0)           */ "lsl " $t1 ", " $d0 ", # 32;"
        "subs " $t0 ", " $d0 ", " $t1 ";"
        "lsr " $t2 ", " $d0 ", # 32;"
        "sbc " $d0 ", " $d0 ", " $t2 ";"
        /* Hence [d4;..;d1] := [d3;d2;d1;0] + (2^256 - 2^224 + 2^192 + 2^96) * w */ "adds " $d1 ", " $d1 ", " $t1 ";"
        "adcs " $d2 ", " $d2 ", " $t2 ";"
        "adcs " $d3 ", " $d3 ", " $t0 ";"
        "adc " $d4 ", " $d0 ", xzr"
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

macro_rules! c0 {
    () => {
        Q!("x6")
    };
}
macro_rules! c1 {
    () => {
        Q!("x7")
    };
}
macro_rules! c2 {
    () => {
        Q!("x8")
    };
}
macro_rules! c3 {
    () => {
        Q!("x9")
    };
}
macro_rules! c4 {
    () => {
        Q!("x10")
    };
}
macro_rules! d1 {
    () => {
        Q!("x11")
    };
}
macro_rules! d2 {
    () => {
        Q!("x12")
    };
}
macro_rules! d3 {
    () => {
        Q!("x13")
    };
}
macro_rules! d4 {
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
        Q!("x1")
    };
}

macro_rules! a0short {
    () => {
        Q!("w2")
    };
}
macro_rules! a1short {
    () => {
        Q!("w3")
    };
}
macro_rules! d1short {
    () => {
        Q!("w11")
    };
}

macro_rules! r0 {
    () => {
        Q!("x8")
    };
}
macro_rules! r1 {
    () => {
        Q!("x9")
    };
}
macro_rules! r2 {
    () => {
        Q!("x10")
    };
}
macro_rules! r3 {
    () => {
        Q!("x6")
    };
}
macro_rules! c {
    () => {
        Q!("x7")
    };
}
macro_rules! t1 {
    () => {
        Q!("x11")
    };
}
macro_rules! t2 {
    () => {
        Q!("x12")
    };
}
macro_rules! t3 {
    () => {
        Q!("x13")
    };
}
macro_rules! t0 {
    () => {
        Q!("x5")
    };
}

pub fn bignum_montsqr_p256(z: &mut [u64; 4], x: &[u64; 4]) {
    unsafe {
        core::arch::asm!(


        // Load in all words of the input

        Q!("    ldp       " a0!() ", " a1!() ", [x1]"),
        Q!("    ldp       " a2!() ", " a3!() ", [x1, # 16]"),

        // Square the low half, getting a result in [s3;s2;s1;s0]
        // This uses 32x32->64 multiplications to reduce the number of UMULHs

        Q!("    umull     " s0!() ", " a0short!() ", " a0short!()),
        Q!("    lsr       " d1!() ", " a0!() ", # 32"),
        Q!("    umull     " s1!() ", " d1short!() ", " d1short!()),
        Q!("    umull     " d1!() ", " a0short!() ", " d1short!()),
        Q!("    adds      " s0!() ", " s0!() ", " d1!() ", lsl # 33"),
        Q!("    lsr       " d1!() ", " d1!() ", # 31"),
        Q!("    adc       " s1!() ", " s1!() ", " d1!()),
        Q!("    umull     " s2!() ", " a1short!() ", " a1short!()),
        Q!("    lsr       " d1!() ", " a1!() ", # 32"),
        Q!("    umull     " s3!() ", " d1short!() ", " d1short!()),
        Q!("    umull     " d1!() ", " a1short!() ", " d1short!()),
        Q!("    mul       " d2!() ", " a0!() ", " a1!()),
        Q!("    umulh     " d3!() ", " a0!() ", " a1!()),
        Q!("    adds      " s2!() ", " s2!() ", " d1!() ", lsl # 33"),
        Q!("    lsr       " d1!() ", " d1!() ", # 31"),
        Q!("    adc       " s3!() ", " s3!() ", " d1!()),
        Q!("    adds      " d2!() ", " d2!() ", " d2!()),
        Q!("    adcs      " d3!() ", " d3!() ", " d3!()),
        Q!("    adc       " s3!() ", " s3!() ", xzr"),
        Q!("    adds      " s1!() ", " s1!() ", " d2!()),
        Q!("    adcs      " s2!() ", " s2!() ", " d3!()),
        Q!("    adc       " s3!() ", " s3!() ", xzr"),

        // Perform two "short" Montgomery steps on the low square
        // This shifts it to an offset compatible with middle product

        montreds!(s0!(), s3!(), s2!(), s1!(), s0!(), d1!(), d2!(), d3!()),

        montreds!(s1!(), s0!(), s3!(), s2!(), s1!(), d1!(), d2!(), d3!()),

        // Compute cross-product with ADK 2x2->4 multiplier as [c3;c2;c1;c0]

        Q!("    mul       " c0!() ", " a0!() ", " a2!()),
        Q!("    mul       " d4!() ", " a1!() ", " a3!()),
        Q!("    umulh     " c2!() ", " a0!() ", " a2!()),
        muldiffn!(d3!(), d2!(), d1!(), c4!(), a0!(), a1!(), a3!(), a2!()),

        Q!("    adds      " c1!() ", " c0!() ", " c2!()),
        Q!("    adc       " c2!() ", " c2!() ", xzr"),

        Q!("    umulh     " c3!() ", " a1!() ", " a3!()),

        Q!("    adds      " c1!() ", " c1!() ", " d4!()),
        Q!("    adcs      " c2!() ", " c2!() ", " c3!()),
        Q!("    adc       " c3!() ", " c3!() ", xzr"),
        Q!("    adds      " c2!() ", " c2!() ", " d4!()),
        Q!("    adc       " c3!() ", " c3!() ", xzr"),

        Q!("    adds      " "xzr, " d3!() ", # 1"),
        Q!("    adcs      " c1!() ", " c1!() ", " d1!()),
        Q!("    adcs      " c2!() ", " c2!() ", " d2!()),
        Q!("    adc       " c3!() ", " c3!() ", " d3!()),

        // Double it and add the Montgomerified low square

        Q!("    adds      " c0!() ", " c0!() ", " c0!()),
        Q!("    adcs      " c1!() ", " c1!() ", " c1!()),
        Q!("    adcs      " c2!() ", " c2!() ", " c2!()),
        Q!("    adcs      " c3!() ", " c3!() ", " c3!()),
        Q!("    adc       " c4!() ", xzr, xzr"),

        Q!("    adds      " c0!() ", " c0!() ", " s2!()),
        Q!("    adcs      " c1!() ", " c1!() ", " s3!()),
        Q!("    adcs      " c2!() ", " c2!() ", " s0!()),
        Q!("    adcs      " c3!() ", " c3!() ", " s1!()),
        Q!("    adc       " c4!() ", " c4!() ", xzr"),

        // Montgomery-reduce the combined low and middle term another twice

        montrede!(c0!(), c4!(), c3!(), c2!(), c1!(), c0!(), d1!(), d2!(), d3!()),

        montrede!(c1!(), c0!(), c4!(), c3!(), c2!(), c1!(), d1!(), d2!(), d3!()),

        // Our sum so far is in [c1,c0,c4,c3,c2]; choose more intuitive names

        // <macro definition r0 hoisted upwards>
        // <macro definition r1 hoisted upwards>
        // <macro definition r2 hoisted upwards>
        // <macro definition r3 hoisted upwards>
        // <macro definition c hoisted upwards>

        // So we can have these as temps

        // <macro definition t1 hoisted upwards>
        // <macro definition t2 hoisted upwards>
        // <macro definition t3 hoisted upwards>

        // Add in the pure squares 22 + 33

        Q!("    mul       " t1!() ", " a2!() ", " a2!()),
        Q!("    adds      " r0!() ", " r0!() ", " t1!()),
        Q!("    mul       " t2!() ", " a3!() ", " a3!()),
        Q!("    umulh     " t1!() ", " a2!() ", " a2!()),
        Q!("    adcs      " r1!() ", " r1!() ", " t1!()),
        Q!("    adcs      " r2!() ", " r2!() ", " t2!()),
        Q!("    umulh     " t2!() ", " a3!() ", " a3!()),
        Q!("    adcs      " r3!() ", " r3!() ", " t2!()),
        Q!("    adc       " c!() ", " c!() ", xzr"),

        // Construct the 23 term, double and add it in

        Q!("    mul       " t1!() ", " a2!() ", " a3!()),
        Q!("    umulh     " t2!() ", " a2!() ", " a3!()),
        Q!("    adds      " t1!() ", " t1!() ", " t1!()),
        Q!("    adcs      " t2!() ", " t2!() ", " t2!()),
        Q!("    adc       " t3!() ", xzr, xzr"),

        Q!("    adds      " r1!() ", " r1!() ", " t1!()),
        Q!("    adcs      " r2!() ", " r2!() ", " t2!()),
        Q!("    adcs      " r3!() ", " r3!() ", " t3!()),
        Q!("    adcs      " c!() ", " c!() ", xzr"),

        // We know, writing B = 2^{4*64} that the full implicit result is
        // B^2 c <= z + (B - 1) * p < B * p + (B - 1) * p < 2 * B * p,
        // so the top half is certainly < 2 * p. If c = 1 already, we know
        // subtracting p will give the reduced modulus. But now we do a
        // subtraction-comparison to catch cases where the residue is >= p.
        // The constants are such that [t3;0;t1;-1] = p_256.

        // <macro definition t0 hoisted upwards>

        // Set CF (because of inversion) iff (0,p_256) <= (c,r3,r2,r1,r0)

        Q!("    mov       " t1!() ", #0x00000000ffffffff"),
        Q!("    subs      " t0!() ", " r0!() ", # - 1"),
        Q!("    sbcs      " t1!() ", " r1!() ", " t1!()),
        Q!("    mov       " t3!() ", #0xffffffff00000001"),
        Q!("    sbcs      " t2!() ", " r2!() ", xzr"),
        Q!("    sbcs      " t3!() ", " r3!() ", " t3!()),
        Q!("    sbcs      " "xzr, " c!() ", xzr"),

        // Select final output accordingly

        Q!("    csel      " r0!() ", " t0!() ", " r0!() ", cs"),
        Q!("    csel      " r1!() ", " t1!() ", " r1!() ", cs"),
        Q!("    csel      " r2!() ", " t2!() ", " r2!() ", cs"),
        Q!("    csel      " r3!() ", " t3!() ", " r3!() ", cs"),

        // Store things back in place

        Q!("    stp       " r0!() ", " r1!() ", [x0]"),
        Q!("    stp       " r2!() ", " r3!() ", [x0, # 16]"),

        inout("x0") z.as_mut_ptr() => _,
        inout("x1") x.as_ptr() => _,
        // clobbers
        out("v0") _,
        out("v1") _,
        out("v2") _,
        out("v3") _,
        out("v4") _,
        out("v5") _,
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
