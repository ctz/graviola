#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Point mixed addition on NIST curve P-384 in Montgomery-Jacobian coordinates
//
//    extern void p384_montjmixadd
//      (uint64_t p3[static 18],uint64_t p1[static 18],uint64_t p2[static 12]);
//
// Does p3 := p1 + p2 where all points are regarded as Jacobian triples with
// each coordinate in the Montgomery domain, i.e. x' = (2^384 * x) mod p_384.
// A Jacobian triple (x',y',z') represents affine point (x/z^2,y/z^3).
// The "mixed" part means that p2 only has x and y coordinates, with the
// implicit z coordinate assumed to be the identity.
//
// Standard ARM ABI: X0 = p3, X1 = p1, X2 = p2
// ----------------------------------------------------------------------------

// Size of individual field elements

macro_rules! NUMSIZE {
    () => {
        Q!("48")
    };
}

// Stable homes for input arguments during main code sequence

macro_rules! input_z {
    () => {
        Q!("x24")
    };
}
macro_rules! input_x {
    () => {
        Q!("x25")
    };
}
macro_rules! input_y {
    () => {
        Q!("x26")
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

// Corresponds to bignum_montmul_p384 except x24 -> x0

macro_rules! montmul_p384 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "ldp x3, x4, [" $P1 "];\n"
        "ldp x5, x6, [" $P1 "+ 16];\n"
        "ldp x7, x8, [" $P1 "+ 32];\n"
        "ldp x9, x10, [" $P2 "];\n"
        "ldp x11, x12, [" $P2 "+ 16];\n"
        "ldp x13, x14, [" $P2 "+ 32];\n"
        "mul x15, x3, x9;\n"
        "mul x21, x4, x10;\n"
        "mul x22, x5, x11;\n"
        "umulh x23, x3, x9;\n"
        "umulh x0, x4, x10;\n"
        "umulh x1, x5, x11;\n"
        "adds x23, x23, x21;\n"
        "adcs x0, x0, x22;\n"
        "adc x1, x1, xzr;\n"
        "adds x16, x23, x15;\n"
        "adcs x17, x0, x23;\n"
        "adcs x19, x1, x0;\n"
        "adc x20, x1, xzr;\n"
        "adds x17, x17, x15;\n"
        "adcs x19, x19, x23;\n"
        "adcs x20, x20, x0;\n"
        "adc x1, x1, xzr;\n"
        "subs x0, x3, x4;\n"
        "cneg x0, x0, lo;\n"
        "csetm x23, lo;\n"
        "subs x22, x10, x9;\n"
        "cneg x22, x22, lo;\n"
        "mul x21, x0, x22;\n"
        "umulh x22, x0, x22;\n"
        "cinv x23, x23, lo;\n"
        "eor x21, x21, x23;\n"
        "eor x22, x22, x23;\n"
        "cmn x23, #1;\n"
        "adcs x16, x16, x21;\n"
        "adcs x17, x17, x22;\n"
        "adcs x19, x19, x23;\n"
        "adcs x20, x20, x23;\n"
        "adc x1, x1, x23;\n"
        "subs x0, x3, x5;\n"
        "cneg x0, x0, lo;\n"
        "csetm x23, lo;\n"
        "subs x22, x11, x9;\n"
        "cneg x22, x22, lo;\n"
        "mul x21, x0, x22;\n"
        "umulh x22, x0, x22;\n"
        "cinv x23, x23, lo;\n"
        "eor x21, x21, x23;\n"
        "eor x22, x22, x23;\n"
        "cmn x23, #1;\n"
        "adcs x17, x17, x21;\n"
        "adcs x19, x19, x22;\n"
        "adcs x20, x20, x23;\n"
        "adc x1, x1, x23;\n"
        "subs x0, x4, x5;\n"
        "cneg x0, x0, lo;\n"
        "csetm x23, lo;\n"
        "subs x22, x11, x10;\n"
        "cneg x22, x22, lo;\n"
        "mul x21, x0, x22;\n"
        "umulh x22, x0, x22;\n"
        "cinv x23, x23, lo;\n"
        "eor x21, x21, x23;\n"
        "eor x22, x22, x23;\n"
        "cmn x23, #1;\n"
        "adcs x19, x19, x21;\n"
        "adcs x20, x20, x22;\n"
        "adc x1, x1, x23;\n"
        "lsl x23, x15, #32;\n"
        "add x15, x23, x15;\n"
        "lsr x23, x15, #32;\n"
        "subs x23, x23, x15;\n"
        "sbc x22, x15, xzr;\n"
        "extr x23, x22, x23, #32;\n"
        "lsr x22, x22, #32;\n"
        "adds x22, x22, x15;\n"
        "adc x21, xzr, xzr;\n"
        "subs x16, x16, x23;\n"
        "sbcs x17, x17, x22;\n"
        "sbcs x19, x19, x21;\n"
        "sbcs x20, x20, xzr;\n"
        "sbcs x1, x1, xzr;\n"
        "sbc x15, x15, xzr;\n"
        "lsl x23, x16, #32;\n"
        "add x16, x23, x16;\n"
        "lsr x23, x16, #32;\n"
        "subs x23, x23, x16;\n"
        "sbc x22, x16, xzr;\n"
        "extr x23, x22, x23, #32;\n"
        "lsr x22, x22, #32;\n"
        "adds x22, x22, x16;\n"
        "adc x21, xzr, xzr;\n"
        "subs x17, x17, x23;\n"
        "sbcs x19, x19, x22;\n"
        "sbcs x20, x20, x21;\n"
        "sbcs x1, x1, xzr;\n"
        "sbcs x15, x15, xzr;\n"
        "sbc x16, x16, xzr;\n"
        "lsl x23, x17, #32;\n"
        "add x17, x23, x17;\n"
        "lsr x23, x17, #32;\n"
        "subs x23, x23, x17;\n"
        "sbc x22, x17, xzr;\n"
        "extr x23, x22, x23, #32;\n"
        "lsr x22, x22, #32;\n"
        "adds x22, x22, x17;\n"
        "adc x21, xzr, xzr;\n"
        "subs x19, x19, x23;\n"
        "sbcs x20, x20, x22;\n"
        "sbcs x1, x1, x21;\n"
        "sbcs x15, x15, xzr;\n"
        "sbcs x16, x16, xzr;\n"
        "sbc x17, x17, xzr;\n"
        "stp x19, x20, [" $P0 "];\n"
        "stp x1, x15, [" $P0 "+ 16];\n"
        "stp x16, x17, [" $P0 "+ 32];\n"
        "mul x15, x6, x12;\n"
        "mul x21, x7, x13;\n"
        "mul x22, x8, x14;\n"
        "umulh x23, x6, x12;\n"
        "umulh x0, x7, x13;\n"
        "umulh x1, x8, x14;\n"
        "adds x23, x23, x21;\n"
        "adcs x0, x0, x22;\n"
        "adc x1, x1, xzr;\n"
        "adds x16, x23, x15;\n"
        "adcs x17, x0, x23;\n"
        "adcs x19, x1, x0;\n"
        "adc x20, x1, xzr;\n"
        "adds x17, x17, x15;\n"
        "adcs x19, x19, x23;\n"
        "adcs x20, x20, x0;\n"
        "adc x1, x1, xzr;\n"
        "subs x0, x6, x7;\n"
        "cneg x0, x0, lo;\n"
        "csetm x23, lo;\n"
        "subs x22, x13, x12;\n"
        "cneg x22, x22, lo;\n"
        "mul x21, x0, x22;\n"
        "umulh x22, x0, x22;\n"
        "cinv x23, x23, lo;\n"
        "eor x21, x21, x23;\n"
        "eor x22, x22, x23;\n"
        "cmn x23, #1;\n"
        "adcs x16, x16, x21;\n"
        "adcs x17, x17, x22;\n"
        "adcs x19, x19, x23;\n"
        "adcs x20, x20, x23;\n"
        "adc x1, x1, x23;\n"
        "subs x0, x6, x8;\n"
        "cneg x0, x0, lo;\n"
        "csetm x23, lo;\n"
        "subs x22, x14, x12;\n"
        "cneg x22, x22, lo;\n"
        "mul x21, x0, x22;\n"
        "umulh x22, x0, x22;\n"
        "cinv x23, x23, lo;\n"
        "eor x21, x21, x23;\n"
        "eor x22, x22, x23;\n"
        "cmn x23, #1;\n"
        "adcs x17, x17, x21;\n"
        "adcs x19, x19, x22;\n"
        "adcs x20, x20, x23;\n"
        "adc x1, x1, x23;\n"
        "subs x0, x7, x8;\n"
        "cneg x0, x0, lo;\n"
        "csetm x23, lo;\n"
        "subs x22, x14, x13;\n"
        "cneg x22, x22, lo;\n"
        "mul x21, x0, x22;\n"
        "umulh x22, x0, x22;\n"
        "cinv x23, x23, lo;\n"
        "eor x21, x21, x23;\n"
        "eor x22, x22, x23;\n"
        "cmn x23, #1;\n"
        "adcs x19, x19, x21;\n"
        "adcs x20, x20, x22;\n"
        "adc x1, x1, x23;\n"
        "subs x6, x6, x3;\n"
        "sbcs x7, x7, x4;\n"
        "sbcs x8, x8, x5;\n"
        "ngc x3, xzr;\n"
        "cmn x3, #1;\n"
        "eor x6, x6, x3;\n"
        "adcs x6, x6, xzr;\n"
        "eor x7, x7, x3;\n"
        "adcs x7, x7, xzr;\n"
        "eor x8, x8, x3;\n"
        "adc x8, x8, xzr;\n"
        "subs x9, x9, x12;\n"
        "sbcs x10, x10, x13;\n"
        "sbcs x11, x11, x14;\n"
        "ngc x14, xzr;\n"
        "cmn x14, #1;\n"
        "eor x9, x9, x14;\n"
        "adcs x9, x9, xzr;\n"
        "eor x10, x10, x14;\n"
        "adcs x10, x10, xzr;\n"
        "eor x11, x11, x14;\n"
        "adc x11, x11, xzr;\n"
        "eor x14, x3, x14;\n"
        "ldp x21, x22, [" $P0 "];\n"
        "adds x15, x15, x21;\n"
        "adcs x16, x16, x22;\n"
        "ldp x21, x22, [" $P0 "+ 16];\n"
        "adcs x17, x17, x21;\n"
        "adcs x19, x19, x22;\n"
        "ldp x21, x22, [" $P0 "+ 32];\n"
        "adcs x20, x20, x21;\n"
        "adcs x1, x1, x22;\n"
        "adc x2, xzr, xzr;\n"
        "stp x15, x16, [" $P0 "];\n"
        "stp x17, x19, [" $P0 "+ 16];\n"
        "stp x20, x1, [" $P0 "+ 32];\n"
        "mul x15, x6, x9;\n"
        "mul x21, x7, x10;\n"
        "mul x22, x8, x11;\n"
        "umulh x23, x6, x9;\n"
        "umulh x0, x7, x10;\n"
        "umulh x1, x8, x11;\n"
        "adds x23, x23, x21;\n"
        "adcs x0, x0, x22;\n"
        "adc x1, x1, xzr;\n"
        "adds x16, x23, x15;\n"
        "adcs x17, x0, x23;\n"
        "adcs x19, x1, x0;\n"
        "adc x20, x1, xzr;\n"
        "adds x17, x17, x15;\n"
        "adcs x19, x19, x23;\n"
        "adcs x20, x20, x0;\n"
        "adc x1, x1, xzr;\n"
        "subs x0, x6, x7;\n"
        "cneg x0, x0, lo;\n"
        "csetm x23, lo;\n"
        "subs x22, x10, x9;\n"
        "cneg x22, x22, lo;\n"
        "mul x21, x0, x22;\n"
        "umulh x22, x0, x22;\n"
        "cinv x23, x23, lo;\n"
        "eor x21, x21, x23;\n"
        "eor x22, x22, x23;\n"
        "cmn x23, #1;\n"
        "adcs x16, x16, x21;\n"
        "adcs x17, x17, x22;\n"
        "adcs x19, x19, x23;\n"
        "adcs x20, x20, x23;\n"
        "adc x1, x1, x23;\n"
        "subs x0, x6, x8;\n"
        "cneg x0, x0, lo;\n"
        "csetm x23, lo;\n"
        "subs x22, x11, x9;\n"
        "cneg x22, x22, lo;\n"
        "mul x21, x0, x22;\n"
        "umulh x22, x0, x22;\n"
        "cinv x23, x23, lo;\n"
        "eor x21, x21, x23;\n"
        "eor x22, x22, x23;\n"
        "cmn x23, #1;\n"
        "adcs x17, x17, x21;\n"
        "adcs x19, x19, x22;\n"
        "adcs x20, x20, x23;\n"
        "adc x1, x1, x23;\n"
        "subs x0, x7, x8;\n"
        "cneg x0, x0, lo;\n"
        "csetm x23, lo;\n"
        "subs x22, x11, x10;\n"
        "cneg x22, x22, lo;\n"
        "mul x21, x0, x22;\n"
        "umulh x22, x0, x22;\n"
        "cinv x23, x23, lo;\n"
        "eor x21, x21, x23;\n"
        "eor x22, x22, x23;\n"
        "cmn x23, #1;\n"
        "adcs x19, x19, x21;\n"
        "adcs x20, x20, x22;\n"
        "adc x1, x1, x23;\n"
        "ldp x3, x4, [" $P0 "];\n"
        "ldp x5, x6, [" $P0 "+ 16];\n"
        "ldp x7, x8, [" $P0 "+ 32];\n"
        "cmn x14, #1;\n"
        "eor x15, x15, x14;\n"
        "adcs x15, x15, x3;\n"
        "eor x16, x16, x14;\n"
        "adcs x16, x16, x4;\n"
        "eor x17, x17, x14;\n"
        "adcs x17, x17, x5;\n"
        "eor x19, x19, x14;\n"
        "adcs x19, x19, x6;\n"
        "eor x20, x20, x14;\n"
        "adcs x20, x20, x7;\n"
        "eor x1, x1, x14;\n"
        "adcs x1, x1, x8;\n"
        "adcs x9, x14, x2;\n"
        "adcs x10, x14, xzr;\n"
        "adcs x11, x14, xzr;\n"
        "adc x12, x14, xzr;\n"
        "adds x19, x19, x3;\n"
        "adcs x20, x20, x4;\n"
        "adcs x1, x1, x5;\n"
        "adcs x9, x9, x6;\n"
        "adcs x10, x10, x7;\n"
        "adcs x11, x11, x8;\n"
        "adc x12, x12, x2;\n"
        "lsl x23, x15, #32;\n"
        "add x15, x23, x15;\n"
        "lsr x23, x15, #32;\n"
        "subs x23, x23, x15;\n"
        "sbc x22, x15, xzr;\n"
        "extr x23, x22, x23, #32;\n"
        "lsr x22, x22, #32;\n"
        "adds x22, x22, x15;\n"
        "adc x21, xzr, xzr;\n"
        "subs x16, x16, x23;\n"
        "sbcs x17, x17, x22;\n"
        "sbcs x19, x19, x21;\n"
        "sbcs x20, x20, xzr;\n"
        "sbcs x1, x1, xzr;\n"
        "sbc x15, x15, xzr;\n"
        "lsl x23, x16, #32;\n"
        "add x16, x23, x16;\n"
        "lsr x23, x16, #32;\n"
        "subs x23, x23, x16;\n"
        "sbc x22, x16, xzr;\n"
        "extr x23, x22, x23, #32;\n"
        "lsr x22, x22, #32;\n"
        "adds x22, x22, x16;\n"
        "adc x21, xzr, xzr;\n"
        "subs x17, x17, x23;\n"
        "sbcs x19, x19, x22;\n"
        "sbcs x20, x20, x21;\n"
        "sbcs x1, x1, xzr;\n"
        "sbcs x15, x15, xzr;\n"
        "sbc x16, x16, xzr;\n"
        "lsl x23, x17, #32;\n"
        "add x17, x23, x17;\n"
        "lsr x23, x17, #32;\n"
        "subs x23, x23, x17;\n"
        "sbc x22, x17, xzr;\n"
        "extr x23, x22, x23, #32;\n"
        "lsr x22, x22, #32;\n"
        "adds x22, x22, x17;\n"
        "adc x21, xzr, xzr;\n"
        "subs x19, x19, x23;\n"
        "sbcs x20, x20, x22;\n"
        "sbcs x1, x1, x21;\n"
        "sbcs x15, x15, xzr;\n"
        "sbcs x16, x16, xzr;\n"
        "sbc x17, x17, xzr;\n"
        "adds x9, x9, x15;\n"
        "adcs x10, x10, x16;\n"
        "adcs x11, x11, x17;\n"
        "adc x12, x12, xzr;\n"
        "add x22, x12, #1;\n"
        "lsl x21, x22, #32;\n"
        "subs x0, x22, x21;\n"
        "sbc x21, x21, xzr;\n"
        "adds x19, x19, x0;\n"
        "adcs x20, x20, x21;\n"
        "adcs x1, x1, x22;\n"
        "adcs x9, x9, xzr;\n"
        "adcs x10, x10, xzr;\n"
        "adcs x11, x11, xzr;\n"
        "csetm x22, lo;\n"
        "mov x23, #4294967295;\n"
        "and x23, x23, x22;\n"
        "adds x19, x19, x23;\n"
        "eor x23, x23, x22;\n"
        "adcs x20, x20, x23;\n"
        "mov x23, #-2;\n"
        "and x23, x23, x22;\n"
        "adcs x1, x1, x23;\n"
        "adcs x9, x9, x22;\n"
        "adcs x10, x10, x22;\n"
        "adc x11, x11, x22;\n"
        "stp x19, x20, [" $P0 "];\n"
        "stp x1, x9, [" $P0 "+ 16];\n"
        "stp x10, x11, [" $P0 "+ 32]"
    )}
}

// Corresponds exactly to bignum_montsqr_p384

macro_rules! montsqr_p384 {
    ($P0:expr, $P1:expr) => { Q!(
        "ldp x2, x3, [" $P1 "];\n"
        "ldp x4, x5, [" $P1 "+ 16];\n"
        "ldp x6, x7, [" $P1 "+ 32];\n"
        "mul x14, x2, x3;\n"
        "mul x15, x2, x4;\n"
        "mul x16, x3, x4;\n"
        "mul x8, x2, x2;\n"
        "mul x10, x3, x3;\n"
        "mul x12, x4, x4;\n"
        "umulh x17, x2, x3;\n"
        "adds x15, x15, x17;\n"
        "umulh x17, x2, x4;\n"
        "adcs x16, x16, x17;\n"
        "umulh x17, x3, x4;\n"
        "adcs x17, x17, xzr;\n"
        "umulh x9, x2, x2;\n"
        "umulh x11, x3, x3;\n"
        "umulh x13, x4, x4;\n"
        "adds x14, x14, x14;\n"
        "adcs x15, x15, x15;\n"
        "adcs x16, x16, x16;\n"
        "adcs x17, x17, x17;\n"
        "adc x13, x13, xzr;\n"
        "adds x9, x9, x14;\n"
        "adcs x10, x10, x15;\n"
        "adcs x11, x11, x16;\n"
        "adcs x12, x12, x17;\n"
        "adc x13, x13, xzr;\n"
        "lsl x16, x8, #32;\n"
        "add x8, x16, x8;\n"
        "lsr x16, x8, #32;\n"
        "subs x16, x16, x8;\n"
        "sbc x15, x8, xzr;\n"
        "extr x16, x15, x16, #32;\n"
        "lsr x15, x15, #32;\n"
        "adds x15, x15, x8;\n"
        "adc x14, xzr, xzr;\n"
        "subs x9, x9, x16;\n"
        "sbcs x10, x10, x15;\n"
        "sbcs x11, x11, x14;\n"
        "sbcs x12, x12, xzr;\n"
        "sbcs x13, x13, xzr;\n"
        "sbc x8, x8, xzr;\n"
        "lsl x16, x9, #32;\n"
        "add x9, x16, x9;\n"
        "lsr x16, x9, #32;\n"
        "subs x16, x16, x9;\n"
        "sbc x15, x9, xzr;\n"
        "extr x16, x15, x16, #32;\n"
        "lsr x15, x15, #32;\n"
        "adds x15, x15, x9;\n"
        "adc x14, xzr, xzr;\n"
        "subs x10, x10, x16;\n"
        "sbcs x11, x11, x15;\n"
        "sbcs x12, x12, x14;\n"
        "sbcs x13, x13, xzr;\n"
        "sbcs x8, x8, xzr;\n"
        "sbc x9, x9, xzr;\n"
        "lsl x16, x10, #32;\n"
        "add x10, x16, x10;\n"
        "lsr x16, x10, #32;\n"
        "subs x16, x16, x10;\n"
        "sbc x15, x10, xzr;\n"
        "extr x16, x15, x16, #32;\n"
        "lsr x15, x15, #32;\n"
        "adds x15, x15, x10;\n"
        "adc x14, xzr, xzr;\n"
        "subs x11, x11, x16;\n"
        "sbcs x12, x12, x15;\n"
        "sbcs x13, x13, x14;\n"
        "sbcs x8, x8, xzr;\n"
        "sbcs x9, x9, xzr;\n"
        "sbc x10, x10, xzr;\n"
        "stp x11, x12, [" $P0 "];\n"
        "stp x13, x8, [" $P0 "+ 16];\n"
        "stp x9, x10, [" $P0 "+ 32];\n"
        "mul x8, x2, x5;\n"
        "mul x14, x3, x6;\n"
        "mul x15, x4, x7;\n"
        "umulh x16, x2, x5;\n"
        "umulh x17, x3, x6;\n"
        "umulh x1, x4, x7;\n"
        "adds x16, x16, x14;\n"
        "adcs x17, x17, x15;\n"
        "adc x1, x1, xzr;\n"
        "adds x9, x16, x8;\n"
        "adcs x10, x17, x16;\n"
        "adcs x11, x1, x17;\n"
        "adc x12, x1, xzr;\n"
        "adds x10, x10, x8;\n"
        "adcs x11, x11, x16;\n"
        "adcs x12, x12, x17;\n"
        "adc x13, x1, xzr;\n"
        "subs x17, x2, x3;\n"
        "cneg x17, x17, lo;\n"
        "csetm x14, lo;\n"
        "subs x15, x6, x5;\n"
        "cneg x15, x15, lo;\n"
        "mul x16, x17, x15;\n"
        "umulh x15, x17, x15;\n"
        "cinv x14, x14, lo;\n"
        "eor x16, x16, x14;\n"
        "eor x15, x15, x14;\n"
        "cmn x14, #1;\n"
        "adcs x9, x9, x16;\n"
        "adcs x10, x10, x15;\n"
        "adcs x11, x11, x14;\n"
        "adcs x12, x12, x14;\n"
        "adc x13, x13, x14;\n"
        "subs x17, x2, x4;\n"
        "cneg x17, x17, lo;\n"
        "csetm x14, lo;\n"
        "subs x15, x7, x5;\n"
        "cneg x15, x15, lo;\n"
        "mul x16, x17, x15;\n"
        "umulh x15, x17, x15;\n"
        "cinv x14, x14, lo;\n"
        "eor x16, x16, x14;\n"
        "eor x15, x15, x14;\n"
        "cmn x14, #1;\n"
        "adcs x10, x10, x16;\n"
        "adcs x11, x11, x15;\n"
        "adcs x12, x12, x14;\n"
        "adc x13, x13, x14;\n"
        "subs x17, x3, x4;\n"
        "cneg x17, x17, lo;\n"
        "csetm x14, lo;\n"
        "subs x15, x7, x6;\n"
        "cneg x15, x15, lo;\n"
        "mul x16, x17, x15;\n"
        "umulh x15, x17, x15;\n"
        "cinv x14, x14, lo;\n"
        "eor x16, x16, x14;\n"
        "eor x15, x15, x14;\n"
        "cmn x14, #1;\n"
        "adcs x11, x11, x16;\n"
        "adcs x12, x12, x15;\n"
        "adc x13, x13, x14;\n"
        "adds x8, x8, x8;\n"
        "adcs x9, x9, x9;\n"
        "adcs x10, x10, x10;\n"
        "adcs x11, x11, x11;\n"
        "adcs x12, x12, x12;\n"
        "adcs x13, x13, x13;\n"
        "adc x17, xzr, xzr;\n"
        "ldp x2, x3, [" $P0 "];\n"
        "adds x8, x8, x2;\n"
        "adcs x9, x9, x3;\n"
        "ldp x2, x3, [" $P0 "+ 16];\n"
        "adcs x10, x10, x2;\n"
        "adcs x11, x11, x3;\n"
        "ldp x2, x3, [" $P0 "+ 32];\n"
        "adcs x12, x12, x2;\n"
        "adcs x13, x13, x3;\n"
        "adc x17, x17, xzr;\n"
        "lsl x4, x8, #32;\n"
        "add x8, x4, x8;\n"
        "lsr x4, x8, #32;\n"
        "subs x4, x4, x8;\n"
        "sbc x3, x8, xzr;\n"
        "extr x4, x3, x4, #32;\n"
        "lsr x3, x3, #32;\n"
        "adds x3, x3, x8;\n"
        "adc x2, xzr, xzr;\n"
        "subs x9, x9, x4;\n"
        "sbcs x10, x10, x3;\n"
        "sbcs x11, x11, x2;\n"
        "sbcs x12, x12, xzr;\n"
        "sbcs x13, x13, xzr;\n"
        "sbc x8, x8, xzr;\n"
        "lsl x4, x9, #32;\n"
        "add x9, x4, x9;\n"
        "lsr x4, x9, #32;\n"
        "subs x4, x4, x9;\n"
        "sbc x3, x9, xzr;\n"
        "extr x4, x3, x4, #32;\n"
        "lsr x3, x3, #32;\n"
        "adds x3, x3, x9;\n"
        "adc x2, xzr, xzr;\n"
        "subs x10, x10, x4;\n"
        "sbcs x11, x11, x3;\n"
        "sbcs x12, x12, x2;\n"
        "sbcs x13, x13, xzr;\n"
        "sbcs x8, x8, xzr;\n"
        "sbc x9, x9, xzr;\n"
        "lsl x4, x10, #32;\n"
        "add x10, x4, x10;\n"
        "lsr x4, x10, #32;\n"
        "subs x4, x4, x10;\n"
        "sbc x3, x10, xzr;\n"
        "extr x4, x3, x4, #32;\n"
        "lsr x3, x3, #32;\n"
        "adds x3, x3, x10;\n"
        "adc x2, xzr, xzr;\n"
        "subs x11, x11, x4;\n"
        "sbcs x12, x12, x3;\n"
        "sbcs x13, x13, x2;\n"
        "sbcs x8, x8, xzr;\n"
        "sbcs x9, x9, xzr;\n"
        "sbc x10, x10, xzr;\n"
        "adds x17, x17, x8;\n"
        "adcs x8, x9, xzr;\n"
        "adcs x9, x10, xzr;\n"
        "adcs x10, xzr, xzr;\n"
        "mul x1, x5, x5;\n"
        "adds x11, x11, x1;\n"
        "mul x14, x6, x6;\n"
        "mul x15, x7, x7;\n"
        "umulh x1, x5, x5;\n"
        "adcs x12, x12, x1;\n"
        "umulh x1, x6, x6;\n"
        "adcs x13, x13, x14;\n"
        "adcs x17, x17, x1;\n"
        "umulh x1, x7, x7;\n"
        "adcs x8, x8, x15;\n"
        "adcs x9, x9, x1;\n"
        "adc x10, x10, xzr;\n"
        "mul x1, x5, x6;\n"
        "mul x14, x5, x7;\n"
        "mul x15, x6, x7;\n"
        "umulh x16, x5, x6;\n"
        "adds x14, x14, x16;\n"
        "umulh x16, x5, x7;\n"
        "adcs x15, x15, x16;\n"
        "umulh x16, x6, x7;\n"
        "adc x16, x16, xzr;\n"
        "adds x1, x1, x1;\n"
        "adcs x14, x14, x14;\n"
        "adcs x15, x15, x15;\n"
        "adcs x16, x16, x16;\n"
        "adc x5, xzr, xzr;\n"
        "adds x12, x12, x1;\n"
        "adcs x13, x13, x14;\n"
        "adcs x17, x17, x15;\n"
        "adcs x8, x8, x16;\n"
        "adcs x9, x9, x5;\n"
        "adc x10, x10, xzr;\n"
        "mov x1, #-4294967295;\n"
        "mov x14, #4294967295;\n"
        "mov x15, #1;\n"
        "cmn x11, x1;\n"
        "adcs xzr, x12, x14;\n"
        "adcs xzr, x13, x15;\n"
        "adcs xzr, x17, xzr;\n"
        "adcs xzr, x8, xzr;\n"
        "adcs xzr, x9, xzr;\n"
        "adc x10, x10, xzr;\n"
        "neg x10, x10;\n"
        "and x1, x1, x10;\n"
        "adds x11, x11, x1;\n"
        "and x14, x14, x10;\n"
        "adcs x12, x12, x14;\n"
        "and x15, x15, x10;\n"
        "adcs x13, x13, x15;\n"
        "adcs x17, x17, xzr;\n"
        "adcs x8, x8, xzr;\n"
        "adc x9, x9, xzr;\n"
        "stp x11, x12, [" $P0 "];\n"
        "stp x13, x17, [" $P0 "+ 16];\n"
        "stp x8, x9, [" $P0 "+ 32]"
    )}
}

// Corresponds exactly to bignum_sub_p384

macro_rules! sub_p384 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "ldp x5, x6, [" $P1 "];\n"
        "ldp x4, x3, [" $P2 "];\n"
        "subs x5, x5, x4;\n"
        "sbcs x6, x6, x3;\n"
        "ldp x7, x8, [" $P1 "+ 16];\n"
        "ldp x4, x3, [" $P2 "+ 16];\n"
        "sbcs x7, x7, x4;\n"
        "sbcs x8, x8, x3;\n"
        "ldp x9, x10, [" $P1 "+ 32];\n"
        "ldp x4, x3, [" $P2 "+ 32];\n"
        "sbcs x9, x9, x4;\n"
        "sbcs x10, x10, x3;\n"
        "csetm x3, lo;\n"
        "mov x4, #4294967295;\n"
        "and x4, x4, x3;\n"
        "adds x5, x5, x4;\n"
        "eor x4, x4, x3;\n"
        "adcs x6, x6, x4;\n"
        "mov x4, #-2;\n"
        "and x4, x4, x3;\n"
        "adcs x7, x7, x4;\n"
        "adcs x8, x8, x3;\n"
        "adcs x9, x9, x3;\n"
        "adc x10, x10, x3;\n"
        "stp x5, x6, [" $P0 "];\n"
        "stp x7, x8, [" $P0 "+ 16];\n"
        "stp x9, x10, [" $P0 "+ 32]"
    )}
}

pub fn p384_montjmixadd(p3: &mut [u64; 18], p1: &[u64; 18], p2: &[u64; 12]) {
    unsafe {
        core::arch::asm!(


        // Save regs and make room on stack for temporary variables

        Q!("    stp             " "x19, x20, [sp, #-16] !"),
        Q!("    stp             " "x21, x22, [sp, #-16] !"),
        Q!("    stp             " "x23, x24, [sp, #-16] !"),
        Q!("    stp             " "x25, x26, [sp, #-16] !"),
        Q!("    sub             " "sp, sp, " NSPACE!()),

        // Move the input arguments to stable places

        Q!("    mov             " input_z!() ", x0"),
        Q!("    mov             " input_x!() ", x1"),
        Q!("    mov             " input_y!() ", x2"),

        // Main code, just a sequence of basic field operations
        // 8 * multiply + 3 * square + 7 * subtract

        montsqr_p384!(zp2!(), z_1!()),
        montmul_p384!(y2a!(), z_1!(), y_2!()),

        montmul_p384!(x2a!(), zp2!(), x_2!()),
        montmul_p384!(y2a!(), zp2!(), y2a!()),

        sub_p384!(xd!(), x2a!(), x_1!()),
        sub_p384!(yd!(), y2a!(), y_1!()),

        montsqr_p384!(zz!(), xd!()),
        montsqr_p384!(ww!(), yd!()),

        montmul_p384!(zzx1!(), zz!(), x_1!()),
        montmul_p384!(zzx2!(), zz!(), x2a!()),

        sub_p384!(resx!(), ww!(), zzx1!()),
        sub_p384!(t1!(), zzx2!(), zzx1!()),

        montmul_p384!(resz!(), xd!(), z_1!()),

        sub_p384!(resx!(), resx!(), zzx2!()),

        sub_p384!(t2!(), zzx1!(), resx!()),

        montmul_p384!(t1!(), t1!(), y_1!()),
        montmul_p384!(t2!(), yd!(), t2!()),

        sub_p384!(resy!(), t2!(), t1!()),

        // Test if z_1 = 0 to decide if p1 = 0 (up to projective equivalence)

        Q!("    ldp             " "x0, x1, [" z_1!() "]"),
        Q!("    ldp             " "x2, x3, [" z_1!() "+ 16]"),
        Q!("    ldp             " "x4, x5, [" z_1!() "+ 32]"),
        Q!("    orr             " "x6, x0, x1"),
        Q!("    orr             " "x7, x2, x3"),
        Q!("    orr             " "x8, x4, x5"),
        Q!("    orr             " "x6, x6, x7"),
        Q!("    orr             " "x6, x6, x8"),
        Q!("    cmp             " "x6, xzr"),

        // Multiplex: if p1 <> 0 just copy the computed result from the staging area.
        // If p1 = 0 then return the point p2 augmented with a z = 1 coordinate (in
        // Montgomery form so not the simple constant 1 but rather 2^384 - p_384),
        // hence giving 0 + p2 = p2 for the final result.

        Q!("    ldp             " "x0, x1, [" resx!() "]"),
        Q!("    ldp             " "x19, x20, [" x_2!() "]"),
        Q!("    csel            " "x0, x0, x19, ne"),
        Q!("    csel            " "x1, x1, x20, ne"),
        Q!("    ldp             " "x2, x3, [" resx!() "+ 16]"),
        Q!("    ldp             " "x19, x20, [" x_2!() "+ 16]"),
        Q!("    csel            " "x2, x2, x19, ne"),
        Q!("    csel            " "x3, x3, x20, ne"),
        Q!("    ldp             " "x4, x5, [" resx!() "+ 32]"),
        Q!("    ldp             " "x19, x20, [" x_2!() "+ 32]"),
        Q!("    csel            " "x4, x4, x19, ne"),
        Q!("    csel            " "x5, x5, x20, ne"),

        Q!("    ldp             " "x6, x7, [" resy!() "]"),
        Q!("    ldp             " "x19, x20, [" y_2!() "]"),
        Q!("    csel            " "x6, x6, x19, ne"),
        Q!("    csel            " "x7, x7, x20, ne"),
        Q!("    ldp             " "x8, x9, [" resy!() "+ 16]"),
        Q!("    ldp             " "x19, x20, [" y_2!() "+ 16]"),
        Q!("    csel            " "x8, x8, x19, ne"),
        Q!("    csel            " "x9, x9, x20, ne"),
        Q!("    ldp             " "x10, x11, [" resy!() "+ 32]"),
        Q!("    ldp             " "x19, x20, [" y_2!() "+ 32]"),
        Q!("    csel            " "x10, x10, x19, ne"),
        Q!("    csel            " "x11, x11, x20, ne"),

        Q!("    ldp             " "x12, x13, [" resz!() "]"),
        Q!("    mov             " "x19, #0xffffffff00000001"),
        Q!("    mov             " "x20, #0x00000000ffffffff"),
        Q!("    csel            " "x12, x12, x19, ne"),
        Q!("    csel            " "x13, x13, x20, ne"),
        Q!("    ldp             " "x14, x15, [" resz!() "+ 16]"),
        Q!("    mov             " "x19, #1"),
        Q!("    csel            " "x14, x14, x19, ne"),
        Q!("    csel            " "x15, x15, xzr, ne"),
        Q!("    ldp             " "x16, x17, [" resz!() "+ 32]"),
        Q!("    csel            " "x16, x16, xzr, ne"),
        Q!("    csel            " "x17, x17, xzr, ne"),

        Q!("    stp             " "x0, x1, [" x_3!() "]"),
        Q!("    stp             " "x2, x3, [" x_3!() "+ 16]"),
        Q!("    stp             " "x4, x5, [" x_3!() "+ 32]"),
        Q!("    stp             " "x6, x7, [" y_3!() "]"),
        Q!("    stp             " "x8, x9, [" y_3!() "+ 16]"),
        Q!("    stp             " "x10, x11, [" y_3!() "+ 32]"),
        Q!("    stp             " "x12, x13, [" z_3!() "]"),
        Q!("    stp             " "x14, x15, [" z_3!() "+ 16]"),
        Q!("    stp             " "x16, x17, [" z_3!() "+ 32]"),

        // Restore stack and registers

        Q!("    add             " "sp, sp, " NSPACE!()),

        Q!("    ldp             " "x25, x26, [sp], 16"),
        Q!("    ldp             " "x23, x24, [sp], 16"),
        Q!("    ldp             " "x21, x22, [sp], 16"),
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
        out("x21") _,
        out("x22") _,
        out("x23") _,
        out("x24") _,
        out("x25") _,
        out("x26") _,
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
