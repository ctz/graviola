#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Point mixed addition on NIST curve P-256 in Montgomery-Jacobian coordinates
//
//    extern void p256_montjmixadd
//      (uint64_t p3[static 12],uint64_t p1[static 12],uint64_t p2[static 8]);
//
// Does p3 := p1 + p2 where all points are regarded as Jacobian triples with
// each coordinate in the Montgomery domain, i.e. x' = (2^256 * x) mod p_256.
// A Jacobian triple (x',y',z') represents affine point (x/z^2,y/z^3).
// The "mixed" part means that p2 only has x and y coordinates, with the
// implicit z coordinate assumed to be the identity.
//
// Standard ARM ABI: X0 = p3, X1 = p1, X2 = p2
// ----------------------------------------------------------------------------

// Size of individual field elements

macro_rules! NUMSIZE {
    () => {
        Q!("32")
    };
}

// Stable homes for input arguments during main code sequence

macro_rules! input_z {
    () => {
        Q!("x17")
    };
}
macro_rules! input_x {
    () => {
        Q!("x19")
    };
}
macro_rules! input_y {
    () => {
        Q!("x20")
    };
}

// Pointer-offset pairs for inputs and outputs

macro_rules! x_1 { () => { Q!(input_x!() ", #0") } }
macro_rules! y_1 { () => { Q!(input_x!() ", # " NUMSIZE!()) } }
macro_rules! z_1 { () => { Q!(input_x!() ", # (2 * " NUMSIZE!() ")") } }

macro_rules! x_2 { () => { Q!(input_y!() ", #0") } }
macro_rules! y_2 { () => { Q!(input_y!() ", # " NUMSIZE!()) } }

macro_rules! x_3 { () => { Q!(input_z!() ", #0") } }
macro_rules! y_3 { () => { Q!(input_z!() ", # " NUMSIZE!()) } }
macro_rules! z_3 { () => { Q!(input_z!() ", # (2 * " NUMSIZE!() ")") } }

// Pointer-offset pairs for temporaries, with some aliasing
// NSPACE is the total stack needed for these temporaries

macro_rules! zp2 { () => { Q!("sp, # (" NUMSIZE!() "* 0)") } }
macro_rules! ww { () => { Q!("sp, # (" NUMSIZE!() "* 0)") } }
macro_rules! resx { () => { Q!("sp, # (" NUMSIZE!() "* 0)") } }

macro_rules! yd { () => { Q!("sp, # (" NUMSIZE!() "* 1)") } }
macro_rules! y2a { () => { Q!("sp, # (" NUMSIZE!() "* 1)") } }

macro_rules! x2a { () => { Q!("sp, # (" NUMSIZE!() "* 2)") } }
macro_rules! zzx2 { () => { Q!("sp, # (" NUMSIZE!() "* 2)") } }

macro_rules! zz { () => { Q!("sp, # (" NUMSIZE!() "* 3)") } }
macro_rules! t1 { () => { Q!("sp, # (" NUMSIZE!() "* 3)") } }

macro_rules! t2 { () => { Q!("sp, # (" NUMSIZE!() "* 4)") } }
macro_rules! zzx1 { () => { Q!("sp, # (" NUMSIZE!() "* 4)") } }
macro_rules! resy { () => { Q!("sp, # (" NUMSIZE!() "* 4)") } }

macro_rules! xd { () => { Q!("sp, # (" NUMSIZE!() "* 5)") } }
macro_rules! resz { () => { Q!("sp, # (" NUMSIZE!() "* 5)") } }

macro_rules! NSPACE { () => { Q!("(" NUMSIZE!() "* 6)") } }

// Corresponds to bignum_montmul_p256 but uses x0 in place of x17

macro_rules! montmul_p256 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "ldp x3, x4, [" $P1 "];\n"
        "ldp x5, x6, [" $P1 "+ 16];\n"
        "ldp x7, x8, [" $P2 "];\n"
        "ldp x9, x10, [" $P2 "+ 16];\n"
        "mul x11, x3, x7;\n"
        "mul x13, x4, x8;\n"
        "umulh x12, x3, x7;\n"
        "adds x16, x11, x13;\n"
        "umulh x14, x4, x8;\n"
        "adcs x0, x12, x14;\n"
        "adcs x14, x14, xzr;\n"
        "adds x12, x12, x16;\n"
        "adcs x13, x13, x0;\n"
        "adcs x14, x14, xzr;\n"
        "subs x15, x3, x4;\n"
        "cneg x15, x15, lo;\n"
        "csetm x1, lo;\n"
        "subs x0, x8, x7;\n"
        "cneg x0, x0, lo;\n"
        "mul x16, x15, x0;\n"
        "umulh x0, x15, x0;\n"
        "cinv x1, x1, lo;\n"
        "eor x16, x16, x1;\n"
        "eor x0, x0, x1;\n"
        "cmn x1, #1;\n"
        "adcs x12, x12, x16;\n"
        "adcs x13, x13, x0;\n"
        "adc x14, x14, x1;\n"
        "lsl x0, x11, #32;\n"
        "subs x1, x11, x0;\n"
        "lsr x16, x11, #32;\n"
        "sbc x11, x11, x16;\n"
        "adds x12, x12, x0;\n"
        "adcs x13, x13, x16;\n"
        "adcs x14, x14, x1;\n"
        "adc x11, x11, xzr;\n"
        "lsl x0, x12, #32;\n"
        "subs x1, x12, x0;\n"
        "lsr x16, x12, #32;\n"
        "sbc x12, x12, x16;\n"
        "adds x13, x13, x0;\n"
        "adcs x14, x14, x16;\n"
        "adcs x11, x11, x1;\n"
        "adc x12, x12, xzr;\n"
        "stp x13, x14, [" $P0 "];\n"
        "stp x11, x12, [" $P0 "+ 16];\n"
        "mul x11, x5, x9;\n"
        "mul x13, x6, x10;\n"
        "umulh x12, x5, x9;\n"
        "adds x16, x11, x13;\n"
        "umulh x14, x6, x10;\n"
        "adcs x0, x12, x14;\n"
        "adcs x14, x14, xzr;\n"
        "adds x12, x12, x16;\n"
        "adcs x13, x13, x0;\n"
        "adcs x14, x14, xzr;\n"
        "subs x15, x5, x6;\n"
        "cneg x15, x15, lo;\n"
        "csetm x1, lo;\n"
        "subs x0, x10, x9;\n"
        "cneg x0, x0, lo;\n"
        "mul x16, x15, x0;\n"
        "umulh x0, x15, x0;\n"
        "cinv x1, x1, lo;\n"
        "eor x16, x16, x1;\n"
        "eor x0, x0, x1;\n"
        "cmn x1, #1;\n"
        "adcs x12, x12, x16;\n"
        "adcs x13, x13, x0;\n"
        "adc x14, x14, x1;\n"
        "subs x3, x5, x3;\n"
        "sbcs x4, x6, x4;\n"
        "ngc x5, xzr;\n"
        "cmn x5, #1;\n"
        "eor x3, x3, x5;\n"
        "adcs x3, x3, xzr;\n"
        "eor x4, x4, x5;\n"
        "adcs x4, x4, xzr;\n"
        "subs x7, x7, x9;\n"
        "sbcs x8, x8, x10;\n"
        "ngc x9, xzr;\n"
        "cmn x9, #1;\n"
        "eor x7, x7, x9;\n"
        "adcs x7, x7, xzr;\n"
        "eor x8, x8, x9;\n"
        "adcs x8, x8, xzr;\n"
        "eor x10, x5, x9;\n"
        "ldp x15, x1, [" $P0 "];\n"
        "adds x15, x11, x15;\n"
        "adcs x1, x12, x1;\n"
        "ldp x5, x9, [" $P0 "+ 16];\n"
        "adcs x5, x13, x5;\n"
        "adcs x9, x14, x9;\n"
        "adc x2, xzr, xzr;\n"
        "mul x11, x3, x7;\n"
        "mul x13, x4, x8;\n"
        "umulh x12, x3, x7;\n"
        "adds x16, x11, x13;\n"
        "umulh x14, x4, x8;\n"
        "adcs x0, x12, x14;\n"
        "adcs x14, x14, xzr;\n"
        "adds x12, x12, x16;\n"
        "adcs x13, x13, x0;\n"
        "adcs x14, x14, xzr;\n"
        "subs x3, x3, x4;\n"
        "cneg x3, x3, lo;\n"
        "csetm x4, lo;\n"
        "subs x0, x8, x7;\n"
        "cneg x0, x0, lo;\n"
        "mul x16, x3, x0;\n"
        "umulh x0, x3, x0;\n"
        "cinv x4, x4, lo;\n"
        "eor x16, x16, x4;\n"
        "eor x0, x0, x4;\n"
        "cmn x4, #1;\n"
        "adcs x12, x12, x16;\n"
        "adcs x13, x13, x0;\n"
        "adc x14, x14, x4;\n"
        "cmn x10, #1;\n"
        "eor x11, x11, x10;\n"
        "adcs x11, x11, x15;\n"
        "eor x12, x12, x10;\n"
        "adcs x12, x12, x1;\n"
        "eor x13, x13, x10;\n"
        "adcs x13, x13, x5;\n"
        "eor x14, x14, x10;\n"
        "adcs x14, x14, x9;\n"
        "adcs x3, x2, x10;\n"
        "adcs x4, x10, xzr;\n"
        "adc x10, x10, xzr;\n"
        "adds x13, x13, x15;\n"
        "adcs x14, x14, x1;\n"
        "adcs x3, x3, x5;\n"
        "adcs x4, x4, x9;\n"
        "adc x10, x10, x2;\n"
        "lsl x0, x11, #32;\n"
        "subs x1, x11, x0;\n"
        "lsr x16, x11, #32;\n"
        "sbc x11, x11, x16;\n"
        "adds x12, x12, x0;\n"
        "adcs x13, x13, x16;\n"
        "adcs x14, x14, x1;\n"
        "adc x11, x11, xzr;\n"
        "lsl x0, x12, #32;\n"
        "subs x1, x12, x0;\n"
        "lsr x16, x12, #32;\n"
        "sbc x12, x12, x16;\n"
        "adds x13, x13, x0;\n"
        "adcs x14, x14, x16;\n"
        "adcs x11, x11, x1;\n"
        "adc x12, x12, xzr;\n"
        "adds x3, x3, x11;\n"
        "adcs x4, x4, x12;\n"
        "adc x10, x10, xzr;\n"
        "add x2, x10, #1;\n"
        "lsl x16, x2, #32;\n"
        "adds x4, x4, x16;\n"
        "adc x10, x10, xzr;\n"
        "neg x15, x2;\n"
        "sub x16, x16, #1;\n"
        "subs x13, x13, x15;\n"
        "sbcs x14, x14, x16;\n"
        "sbcs x3, x3, xzr;\n"
        "sbcs x4, x4, x2;\n"
        "sbcs x7, x10, x2;\n"
        "adds x13, x13, x7;\n"
        "mov x10, #4294967295;\n"
        "and x10, x10, x7;\n"
        "adcs x14, x14, x10;\n"
        "adcs x3, x3, xzr;\n"
        "mov x10, #-4294967295;\n"
        "and x10, x10, x7;\n"
        "adc x4, x4, x10;\n"
        "stp x13, x14, [" $P0 "];\n"
        "stp x3, x4, [" $P0 "+ 16]"
    )}
}

// Corresponds to bignum_montsqr_p256 but uses x0 in place of x17

macro_rules! montsqr_p256 {
    ($P0:expr, $P1:expr) => { Q!(
        "ldp x2, x3, [" $P1 "];\n"
        "ldp x4, x5, [" $P1 "+ 16];\n"
        "umull x15, w2, w2;\n"
        "lsr x11, x2, #32;\n"
        "umull x16, w11, w11;\n"
        "umull x11, w2, w11;\n"
        "adds x15, x15, x11, lsl #33;\n"
        "lsr x11, x11, #31;\n"
        "adc x16, x16, x11;\n"
        "umull x0, w3, w3;\n"
        "lsr x11, x3, #32;\n"
        "umull x1, w11, w11;\n"
        "umull x11, w3, w11;\n"
        "mul x12, x2, x3;\n"
        "umulh x13, x2, x3;\n"
        "adds x0, x0, x11, lsl #33;\n"
        "lsr x11, x11, #31;\n"
        "adc x1, x1, x11;\n"
        "adds x12, x12, x12;\n"
        "adcs x13, x13, x13;\n"
        "adc x1, x1, xzr;\n"
        "adds x16, x16, x12;\n"
        "adcs x0, x0, x13;\n"
        "adc x1, x1, xzr;\n"
        "lsl x12, x15, #32;\n"
        "subs x13, x15, x12;\n"
        "lsr x11, x15, #32;\n"
        "sbc x15, x15, x11;\n"
        "adds x16, x16, x12;\n"
        "adcs x0, x0, x11;\n"
        "adcs x1, x1, x13;\n"
        "adc x15, x15, xzr;\n"
        "lsl x12, x16, #32;\n"
        "subs x13, x16, x12;\n"
        "lsr x11, x16, #32;\n"
        "sbc x16, x16, x11;\n"
        "adds x0, x0, x12;\n"
        "adcs x1, x1, x11;\n"
        "adcs x15, x15, x13;\n"
        "adc x16, x16, xzr;\n"
        "mul x6, x2, x4;\n"
        "mul x14, x3, x5;\n"
        "umulh x8, x2, x4;\n"
        "subs x10, x2, x3;\n"
        "cneg x10, x10, lo;\n"
        "csetm x13, lo;\n"
        "subs x12, x5, x4;\n"
        "cneg x12, x12, lo;\n"
        "mul x11, x10, x12;\n"
        "umulh x12, x10, x12;\n"
        "cinv x13, x13, lo;\n"
        "eor x11, x11, x13;\n"
        "eor x12, x12, x13;\n"
        "adds x7, x6, x8;\n"
        "adc x8, x8, xzr;\n"
        "umulh x9, x3, x5;\n"
        "adds x7, x7, x14;\n"
        "adcs x8, x8, x9;\n"
        "adc x9, x9, xzr;\n"
        "adds x8, x8, x14;\n"
        "adc x9, x9, xzr;\n"
        "cmn x13, #1;\n"
        "adcs x7, x7, x11;\n"
        "adcs x8, x8, x12;\n"
        "adc x9, x9, x13;\n"
        "adds x6, x6, x6;\n"
        "adcs x7, x7, x7;\n"
        "adcs x8, x8, x8;\n"
        "adcs x9, x9, x9;\n"
        "adc x10, xzr, xzr;\n"
        "adds x6, x6, x0;\n"
        "adcs x7, x7, x1;\n"
        "adcs x8, x8, x15;\n"
        "adcs x9, x9, x16;\n"
        "adc x10, x10, xzr;\n"
        "lsl x12, x6, #32;\n"
        "subs x13, x6, x12;\n"
        "lsr x11, x6, #32;\n"
        "sbc x6, x6, x11;\n"
        "adds x7, x7, x12;\n"
        "adcs x8, x8, x11;\n"
        "adcs x9, x9, x13;\n"
        "adcs x10, x10, x6;\n"
        "adc x6, xzr, xzr;\n"
        "lsl x12, x7, #32;\n"
        "subs x13, x7, x12;\n"
        "lsr x11, x7, #32;\n"
        "sbc x7, x7, x11;\n"
        "adds x8, x8, x12;\n"
        "adcs x9, x9, x11;\n"
        "adcs x10, x10, x13;\n"
        "adcs x6, x6, x7;\n"
        "adc x7, xzr, xzr;\n"
        "mul x11, x4, x4;\n"
        "adds x8, x8, x11;\n"
        "mul x12, x5, x5;\n"
        "umulh x11, x4, x4;\n"
        "adcs x9, x9, x11;\n"
        "adcs x10, x10, x12;\n"
        "umulh x12, x5, x5;\n"
        "adcs x6, x6, x12;\n"
        "adc x7, x7, xzr;\n"
        "mul x11, x4, x5;\n"
        "umulh x12, x4, x5;\n"
        "adds x11, x11, x11;\n"
        "adcs x12, x12, x12;\n"
        "adc x13, xzr, xzr;\n"
        "adds x9, x9, x11;\n"
        "adcs x10, x10, x12;\n"
        "adcs x6, x6, x13;\n"
        "adcs x7, x7, xzr;\n"
        "mov x11, #4294967295;\n"
        "adds x5, x8, #1;\n"
        "sbcs x11, x9, x11;\n"
        "mov x13, #-4294967295;\n"
        "sbcs x12, x10, xzr;\n"
        "sbcs x13, x6, x13;\n"
        "sbcs xzr, x7, xzr;\n"
        "csel x8, x5, x8, hs;\n"
        "csel x9, x11, x9, hs;\n"
        "csel x10, x12, x10, hs;\n"
        "csel x6, x13, x6, hs;\n"
        "stp x8, x9, [" $P0 "];\n"
        "stp x10, x6, [" $P0 "+ 16]"
    )}
}

// Corresponds exactly to bignum_sub_p256

macro_rules! sub_p256 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "ldp x5, x6, [" $P1 "];\n"
        "ldp x4, x3, [" $P2 "];\n"
        "subs x5, x5, x4;\n"
        "sbcs x6, x6, x3;\n"
        "ldp x7, x8, [" $P1 "+ 16];\n"
        "ldp x4, x3, [" $P2 "+ 16];\n"
        "sbcs x7, x7, x4;\n"
        "sbcs x8, x8, x3;\n"
        "csetm x3, cc;\n"
        "adds x5, x5, x3;\n"
        "mov x4, #0xffffffff;\n"
        "and x4, x4, x3;\n"
        "adcs x6, x6, x4;\n"
        "adcs x7, x7, xzr;\n"
        "mov x4, #0xffffffff00000001;\n"
        "and x4, x4, x3;\n"
        "adc x8, x8, x4;\n"
        "stp x5, x6, [" $P0 "];\n"
        "stp x7, x8, [" $P0 "+ 16]"
    )}
}

pub fn p256_montjmixadd(p3: &mut [u64; 12], p1: &[u64; 12], p2: &[u64; 8]) {
    unsafe {
        core::arch::asm!(


        // Save regs and make room on stack for temporary variables

        Q!("    stp             " "x19, x20, [sp, #-16] !"),
        Q!("    sub             " "sp, sp, " NSPACE!()),

        // Move the input arguments to stable places

        Q!("    mov             " input_z!() ", x0"),
        Q!("    mov             " input_x!() ", x1"),
        Q!("    mov             " input_y!() ", x2"),

        // Main code, just a sequence of basic field operations
        // 8 * multiply + 3 * square + 7 * subtract

        montsqr_p256!(zp2!(), z_1!()),
        montmul_p256!(y2a!(), z_1!(), y_2!()),

        montmul_p256!(x2a!(), zp2!(), x_2!()),
        montmul_p256!(y2a!(), zp2!(), y2a!()),

        sub_p256!(xd!(), x2a!(), x_1!()),
        sub_p256!(yd!(), y2a!(), y_1!()),

        montsqr_p256!(zz!(), xd!()),
        montsqr_p256!(ww!(), yd!()),

        montmul_p256!(zzx1!(), zz!(), x_1!()),
        montmul_p256!(zzx2!(), zz!(), x2a!()),

        sub_p256!(resx!(), ww!(), zzx1!()),
        sub_p256!(t1!(), zzx2!(), zzx1!()),

        montmul_p256!(resz!(), xd!(), z_1!()),

        sub_p256!(resx!(), resx!(), zzx2!()),

        sub_p256!(t2!(), zzx1!(), resx!()),

        montmul_p256!(t1!(), t1!(), y_1!()),
        montmul_p256!(t2!(), yd!(), t2!()),

        sub_p256!(resy!(), t2!(), t1!()),

        // Test if z_1 = 0 to decide if p1 = 0 (up to projective equivalence)

        Q!("    ldp             " "x0, x1, [" z_1!() "]"),
        Q!("    ldp             " "x2, x3, [" z_1!() "+ 16]"),
        Q!("    orr             " "x4, x0, x1"),
        Q!("    orr             " "x5, x2, x3"),
        Q!("    orr             " "x4, x4, x5"),
        Q!("    cmp             " "x4, xzr"),

        // Multiplex: if p1 <> 0 just copy the computed result from the staging area.
        // If p1 = 0 then return the point p2 augmented with a z = 1 coordinate (in
        // Montgomery form so not the simple constant 1 but rather 2^256 - p_256),
        // hence giving 0 + p2 = p2 for the final result.

        Q!("    ldp             " "x0, x1, [" resx!() "]"),
        Q!("    ldp             " "x12, x13, [" x_2!() "]"),
        Q!("    csel            " "x0, x0, x12, ne"),
        Q!("    csel            " "x1, x1, x13, ne"),
        Q!("    ldp             " "x2, x3, [" resx!() "+ 16]"),
        Q!("    ldp             " "x12, x13, [" x_2!() "+ 16]"),
        Q!("    csel            " "x2, x2, x12, ne"),
        Q!("    csel            " "x3, x3, x13, ne"),

        Q!("    ldp             " "x4, x5, [" resy!() "]"),
        Q!("    ldp             " "x12, x13, [" y_2!() "]"),
        Q!("    csel            " "x4, x4, x12, ne"),
        Q!("    csel            " "x5, x5, x13, ne"),
        Q!("    ldp             " "x6, x7, [" resy!() "+ 16]"),
        Q!("    ldp             " "x12, x13, [" y_2!() "+ 16]"),
        Q!("    csel            " "x6, x6, x12, ne"),
        Q!("    csel            " "x7, x7, x13, ne"),

        Q!("    ldp             " "x8, x9, [" resz!() "]"),
        Q!("    mov             " "x12, #0x0000000000000001"),
        Q!("    mov             " "x13, #0xffffffff00000000"),
        Q!("    csel            " "x8, x8, x12, ne"),
        Q!("    csel            " "x9, x9, x13, ne"),
        Q!("    ldp             " "x10, x11, [" resz!() "+ 16]"),
        Q!("    mov             " "x12, #0xffffffffffffffff"),
        Q!("    mov             " "x13, #0x00000000fffffffe"),
        Q!("    csel            " "x10, x10, x12, ne"),
        Q!("    csel            " "x11, x11, x13, ne"),

        Q!("    stp             " "x0, x1, [" x_3!() "]"),
        Q!("    stp             " "x2, x3, [" x_3!() "+ 16]"),
        Q!("    stp             " "x4, x5, [" y_3!() "]"),
        Q!("    stp             " "x6, x7, [" y_3!() "+ 16]"),
        Q!("    stp             " "x8, x9, [" z_3!() "]"),
        Q!("    stp             " "x10, x11, [" z_3!() "+ 16]"),

        // Restore registers and return

        Q!("    add             " "sp, sp, " NSPACE!()),
        Q!("    ldp             " "x19, x20, [sp], 16"),
        inout("x0") p3.as_mut_ptr() => _,
        inout("x1") p1.as_ptr() => _,
        inout("x2") p2.as_ptr() => _,
        // clobbers
        out("x10") _,
        out("x11") _,
        out("x12") _,
        out("x13") _,
        out("x14") _,
        out("x15") _,
        out("x16") _,
        out("x17") _,
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
