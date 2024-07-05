#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::{Label, Q};

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Point addition on NIST curve P-256 in Montgomery-Jacobian coordinates
//
//    extern void p256_montjadd
//      (uint64_t p3[static 12],uint64_t p1[static 12],uint64_t p2[static 12]);
//
// Does p3 := p1 + p2 where all points are regarded as Jacobian triples with
// each coordinate in the Montgomery domain, i.e. x' = (2^256 * x) mod p_256.
// A Jacobian triple (x',y',z') represents affine point (x/z^2,y/z^3).
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
macro_rules! z_2 { () => { Q!(input_y!() ", # (2 * " NUMSIZE!() ")") } }

macro_rules! x_3 { () => { Q!(input_z!() ", #0") } }
macro_rules! y_3 { () => { Q!(input_z!() ", # " NUMSIZE!()) } }
macro_rules! z_3 { () => { Q!(input_z!() ", # (2 * " NUMSIZE!() ")") } }

// Pointer-offset pairs for temporaries, with some aliasing
// NSPACE is the total stack needed for these temporaries

macro_rules! z1sq { () => { Q!("sp, # (" NUMSIZE!() "* 0)") } }
macro_rules! ww { () => { Q!("sp, # (" NUMSIZE!() "* 0)") } }
macro_rules! resx { () => { Q!("sp, # (" NUMSIZE!() "* 0)") } }

macro_rules! yd { () => { Q!("sp, # (" NUMSIZE!() "* 1)") } }
macro_rules! y2a { () => { Q!("sp, # (" NUMSIZE!() "* 1)") } }

macro_rules! x2a { () => { Q!("sp, # (" NUMSIZE!() "* 2)") } }
macro_rules! zzx2 { () => { Q!("sp, # (" NUMSIZE!() "* 2)") } }

macro_rules! zz { () => { Q!("sp, # (" NUMSIZE!() "* 3)") } }
macro_rules! t1 { () => { Q!("sp, # (" NUMSIZE!() "* 3)") } }

macro_rules! t2 { () => { Q!("sp, # (" NUMSIZE!() "* 4)") } }
macro_rules! x1a { () => { Q!("sp, # (" NUMSIZE!() "* 4)") } }
macro_rules! zzx1 { () => { Q!("sp, # (" NUMSIZE!() "* 4)") } }
macro_rules! resy { () => { Q!("sp, # (" NUMSIZE!() "* 4)") } }

macro_rules! xd { () => { Q!("sp, # (" NUMSIZE!() "* 5)") } }
macro_rules! z2sq { () => { Q!("sp, # (" NUMSIZE!() "* 5)") } }
macro_rules! resz { () => { Q!("sp, # (" NUMSIZE!() "* 5)") } }

macro_rules! y1a { () => { Q!("sp, # (" NUMSIZE!() "* 6)") } }

macro_rules! NSPACE { () => { Q!("(" NUMSIZE!() "* 7)") } }

// Corresponds to bignum_montmul_p256 but uses x0 in place of x17

macro_rules! montmul_p256 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "ldp x3, x4, [" $P1 "];"
        "ldp x5, x6, [" $P1 "+ 16];"
        "ldp x7, x8, [" $P2 "];"
        "ldp x9, x10, [" $P2 "+ 16];"
        "mul x11, x3, x7;"
        "mul x13, x4, x8;"
        "umulh x12, x3, x7;"
        "adds x16, x11, x13;"
        "umulh x14, x4, x8;"
        "adcs x0, x12, x14;"
        "adcs x14, x14, xzr;"
        "adds x12, x12, x16;"
        "adcs x13, x13, x0;"
        "adcs x14, x14, xzr;"
        "subs x15, x3, x4;"
        "cneg x15, x15, lo;"
        "csetm x1, lo;"
        "subs x0, x8, x7;"
        "cneg x0, x0, lo;"
        "mul x16, x15, x0;"
        "umulh x0, x15, x0;"
        "cinv x1, x1, lo;"
        "eor x16, x16, x1;"
        "eor x0, x0, x1;"
        "cmn x1, # 1;"
        "adcs x12, x12, x16;"
        "adcs x13, x13, x0;"
        "adc x14, x14, x1;"
        "lsl x0, x11, # 32;"
        "subs x1, x11, x0;"
        "lsr x16, x11, # 32;"
        "sbc x11, x11, x16;"
        "adds x12, x12, x0;"
        "adcs x13, x13, x16;"
        "adcs x14, x14, x1;"
        "adc x11, x11, xzr;"
        "lsl x0, x12, # 32;"
        "subs x1, x12, x0;"
        "lsr x16, x12, # 32;"
        "sbc x12, x12, x16;"
        "adds x13, x13, x0;"
        "adcs x14, x14, x16;"
        "adcs x11, x11, x1;"
        "adc x12, x12, xzr;"
        "stp x13, x14, [" $P0 "];"
        "stp x11, x12, [" $P0 "+ 16];"
        "mul x11, x5, x9;"
        "mul x13, x6, x10;"
        "umulh x12, x5, x9;"
        "adds x16, x11, x13;"
        "umulh x14, x6, x10;"
        "adcs x0, x12, x14;"
        "adcs x14, x14, xzr;"
        "adds x12, x12, x16;"
        "adcs x13, x13, x0;"
        "adcs x14, x14, xzr;"
        "subs x15, x5, x6;"
        "cneg x15, x15, lo;"
        "csetm x1, lo;"
        "subs x0, x10, x9;"
        "cneg x0, x0, lo;"
        "mul x16, x15, x0;"
        "umulh x0, x15, x0;"
        "cinv x1, x1, lo;"
        "eor x16, x16, x1;"
        "eor x0, x0, x1;"
        "cmn x1, # 1;"
        "adcs x12, x12, x16;"
        "adcs x13, x13, x0;"
        "adc x14, x14, x1;"
        "subs x3, x5, x3;"
        "sbcs x4, x6, x4;"
        "ngc x5, xzr;"
        "cmn x5, # 1;"
        "eor x3, x3, x5;"
        "adcs x3, x3, xzr;"
        "eor x4, x4, x5;"
        "adcs x4, x4, xzr;"
        "subs x7, x7, x9;"
        "sbcs x8, x8, x10;"
        "ngc x9, xzr;"
        "cmn x9, # 1;"
        "eor x7, x7, x9;"
        "adcs x7, x7, xzr;"
        "eor x8, x8, x9;"
        "adcs x8, x8, xzr;"
        "eor x10, x5, x9;"
        "ldp x15, x1, [" $P0 "];"
        "adds x15, x11, x15;"
        "adcs x1, x12, x1;"
        "ldp x5, x9, [" $P0 "+ 16];"
        "adcs x5, x13, x5;"
        "adcs x9, x14, x9;"
        "adc x2, xzr, xzr;"
        "mul x11, x3, x7;"
        "mul x13, x4, x8;"
        "umulh x12, x3, x7;"
        "adds x16, x11, x13;"
        "umulh x14, x4, x8;"
        "adcs x0, x12, x14;"
        "adcs x14, x14, xzr;"
        "adds x12, x12, x16;"
        "adcs x13, x13, x0;"
        "adcs x14, x14, xzr;"
        "subs x3, x3, x4;"
        "cneg x3, x3, lo;"
        "csetm x4, lo;"
        "subs x0, x8, x7;"
        "cneg x0, x0, lo;"
        "mul x16, x3, x0;"
        "umulh x0, x3, x0;"
        "cinv x4, x4, lo;"
        "eor x16, x16, x4;"
        "eor x0, x0, x4;"
        "cmn x4, # 1;"
        "adcs x12, x12, x16;"
        "adcs x13, x13, x0;"
        "adc x14, x14, x4;"
        "cmn x10, # 1;"
        "eor x11, x11, x10;"
        "adcs x11, x11, x15;"
        "eor x12, x12, x10;"
        "adcs x12, x12, x1;"
        "eor x13, x13, x10;"
        "adcs x13, x13, x5;"
        "eor x14, x14, x10;"
        "adcs x14, x14, x9;"
        "adcs x3, x2, x10;"
        "adcs x4, x10, xzr;"
        "adc x10, x10, xzr;"
        "adds x13, x13, x15;"
        "adcs x14, x14, x1;"
        "adcs x3, x3, x5;"
        "adcs x4, x4, x9;"
        "adc x10, x10, x2;"
        "lsl x0, x11, # 32;"
        "subs x1, x11, x0;"
        "lsr x16, x11, # 32;"
        "sbc x11, x11, x16;"
        "adds x12, x12, x0;"
        "adcs x13, x13, x16;"
        "adcs x14, x14, x1;"
        "adc x11, x11, xzr;"
        "lsl x0, x12, # 32;"
        "subs x1, x12, x0;"
        "lsr x16, x12, # 32;"
        "sbc x12, x12, x16;"
        "adds x13, x13, x0;"
        "adcs x14, x14, x16;"
        "adcs x11, x11, x1;"
        "adc x12, x12, xzr;"
        "adds x3, x3, x11;"
        "adcs x4, x4, x12;"
        "adc x10, x10, xzr;"
        "add x2, x10, # 1;"
        "lsl x16, x2, # 32;"
        "adds x4, x4, x16;"
        "adc x10, x10, xzr;"
        "neg x15, x2;"
        "sub x16, x16, # 1;"
        "subs x13, x13, x15;"
        "sbcs x14, x14, x16;"
        "sbcs x3, x3, xzr;"
        "sbcs x4, x4, x2;"
        "sbcs x7, x10, x2;"
        "adds x13, x13, x7;"
        "mov x10, # 4294967295;"
        "and x10, x10, x7;"
        "adcs x14, x14, x10;"
        "adcs x3, x3, xzr;"
        "mov x10, # - 4294967295;"
        "and x10, x10, x7;"
        "adc x4, x4, x10;"
        "stp x13, x14, [" $P0 "];"
        "stp x3, x4, [" $P0 "+ 16]"
    )}
}

// Corresponds to bignum_montsqr_p256 but uses x0 in place of x17

macro_rules! montsqr_p256 {
    ($P0:expr, $P1:expr) => { Q!(
        "ldp x2, x3, [" $P1 "];"
        "ldp x4, x5, [" $P1 "+ 16];"
        "umull x15, w2, w2;"
        "lsr x11, x2, # 32;"
        "umull x16, w11, w11;"
        "umull x11, w2, w11;"
        "adds x15, x15, x11, lsl # 33;"
        "lsr x11, x11, # 31;"
        "adc x16, x16, x11;"
        "umull x0, w3, w3;"
        "lsr x11, x3, # 32;"
        "umull x1, w11, w11;"
        "umull x11, w3, w11;"
        "mul x12, x2, x3;"
        "umulh x13, x2, x3;"
        "adds x0, x0, x11, lsl # 33;"
        "lsr x11, x11, # 31;"
        "adc x1, x1, x11;"
        "adds x12, x12, x12;"
        "adcs x13, x13, x13;"
        "adc x1, x1, xzr;"
        "adds x16, x16, x12;"
        "adcs x0, x0, x13;"
        "adc x1, x1, xzr;"
        "lsl x12, x15, # 32;"
        "subs x13, x15, x12;"
        "lsr x11, x15, # 32;"
        "sbc x15, x15, x11;"
        "adds x16, x16, x12;"
        "adcs x0, x0, x11;"
        "adcs x1, x1, x13;"
        "adc x15, x15, xzr;"
        "lsl x12, x16, # 32;"
        "subs x13, x16, x12;"
        "lsr x11, x16, # 32;"
        "sbc x16, x16, x11;"
        "adds x0, x0, x12;"
        "adcs x1, x1, x11;"
        "adcs x15, x15, x13;"
        "adc x16, x16, xzr;"
        "mul x6, x2, x4;"
        "mul x14, x3, x5;"
        "umulh x8, x2, x4;"
        "subs x10, x2, x3;"
        "cneg x10, x10, lo;"
        "csetm x13, lo;"
        "subs x12, x5, x4;"
        "cneg x12, x12, lo;"
        "mul x11, x10, x12;"
        "umulh x12, x10, x12;"
        "cinv x13, x13, lo;"
        "eor x11, x11, x13;"
        "eor x12, x12, x13;"
        "adds x7, x6, x8;"
        "adc x8, x8, xzr;"
        "umulh x9, x3, x5;"
        "adds x7, x7, x14;"
        "adcs x8, x8, x9;"
        "adc x9, x9, xzr;"
        "adds x8, x8, x14;"
        "adc x9, x9, xzr;"
        "cmn x13, # 1;"
        "adcs x7, x7, x11;"
        "adcs x8, x8, x12;"
        "adc x9, x9, x13;"
        "adds x6, x6, x6;"
        "adcs x7, x7, x7;"
        "adcs x8, x8, x8;"
        "adcs x9, x9, x9;"
        "adc x10, xzr, xzr;"
        "adds x6, x6, x0;"
        "adcs x7, x7, x1;"
        "adcs x8, x8, x15;"
        "adcs x9, x9, x16;"
        "adc x10, x10, xzr;"
        "lsl x12, x6, # 32;"
        "subs x13, x6, x12;"
        "lsr x11, x6, # 32;"
        "sbc x6, x6, x11;"
        "adds x7, x7, x12;"
        "adcs x8, x8, x11;"
        "adcs x9, x9, x13;"
        "adcs x10, x10, x6;"
        "adc x6, xzr, xzr;"
        "lsl x12, x7, # 32;"
        "subs x13, x7, x12;"
        "lsr x11, x7, # 32;"
        "sbc x7, x7, x11;"
        "adds x8, x8, x12;"
        "adcs x9, x9, x11;"
        "adcs x10, x10, x13;"
        "adcs x6, x6, x7;"
        "adc x7, xzr, xzr;"
        "mul x11, x4, x4;"
        "adds x8, x8, x11;"
        "mul x12, x5, x5;"
        "umulh x11, x4, x4;"
        "adcs x9, x9, x11;"
        "adcs x10, x10, x12;"
        "umulh x12, x5, x5;"
        "adcs x6, x6, x12;"
        "adc x7, x7, xzr;"
        "mul x11, x4, x5;"
        "umulh x12, x4, x5;"
        "adds x11, x11, x11;"
        "adcs x12, x12, x12;"
        "adc x13, xzr, xzr;"
        "adds x9, x9, x11;"
        "adcs x10, x10, x12;"
        "adcs x6, x6, x13;"
        "adcs x7, x7, xzr;"
        "mov x11, # 4294967295;"
        "adds x5, x8, # 1;"
        "sbcs x11, x9, x11;"
        "mov x13, # - 4294967295;"
        "sbcs x12, x10, xzr;"
        "sbcs x13, x6, x13;"
        "sbcs xzr, x7, xzr;"
        "csel x8, x5, x8, hs;"
        "csel x9, x11, x9, hs;"
        "csel x10, x12, x10, hs;"
        "csel x6, x13, x6, hs;"
        "stp x8, x9, [" $P0 "];"
        "stp x10, x6, [" $P0 "+ 16]"
    )}
}

// Corresponds exactly to bignum_sub_p256

macro_rules! sub_p256 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "ldp x5, x6, [" $P1 "];"
        "ldp x4, x3, [" $P2 "];"
        "subs x5, x5, x4;"
        "sbcs x6, x6, x3;"
        "ldp x7, x8, [" $P1 "+ 16];"
        "ldp x4, x3, [" $P2 "+ 16];"
        "sbcs x7, x7, x4;"
        "sbcs x8, x8, x3;"
        "csetm x3, cc;"
        "adds x5, x5, x3;"
        "mov x4, #0xffffffff;"
        "and x4, x4, x3;"
        "adcs x6, x6, x4;"
        "adcs x7, x7, xzr;"
        "mov x4, #0xffffffff00000001;"
        "and x4, x4, x3;"
        "adc x8, x8, x4;"
        "stp x5, x6, [" $P0 "];"
        "stp x7, x8, [" $P0 "+ 16]"
    )}
}

pub fn p256_montjadd(p3: &mut [u64; 12], p1: &[u64; 12], p2: &[u64; 12]) {
    unsafe {
        core::arch::asm!(


        // Save regs and make room on stack for temporary variables

        Q!("    stp       " "x19, x20, [sp, # - 16] !"),
        Q!("    sub       " "sp, sp, " NSPACE!()),

        // Move the input arguments to stable places

        Q!("    mov       " input_z!() ", x0"),
        Q!("    mov       " input_x!() ", x1"),
        Q!("    mov       " input_y!() ", x2"),

        // Main code, just a sequence of basic field operations
        // 12 * multiply + 4 * square + 7 * subtract

        montsqr_p256!(z1sq!(), z_1!()),
        montsqr_p256!(z2sq!(), z_2!()),

        montmul_p256!(y1a!(), z_2!(), y_1!()),
        montmul_p256!(y2a!(), z_1!(), y_2!()),

        montmul_p256!(x2a!(), z1sq!(), x_2!()),
        montmul_p256!(x1a!(), z2sq!(), x_1!()),
        montmul_p256!(y2a!(), z1sq!(), y2a!()),
        montmul_p256!(y1a!(), z2sq!(), y1a!()),

        sub_p256!(xd!(), x2a!(), x1a!()),
        sub_p256!(yd!(), y2a!(), y1a!()),

        montsqr_p256!(zz!(), xd!()),
        montsqr_p256!(ww!(), yd!()),

        montmul_p256!(zzx1!(), zz!(), x1a!()),
        montmul_p256!(zzx2!(), zz!(), x2a!()),

        sub_p256!(resx!(), ww!(), zzx1!()),
        sub_p256!(t1!(), zzx2!(), zzx1!()),

        montmul_p256!(xd!(), xd!(), z_1!()),

        sub_p256!(resx!(), resx!(), zzx2!()),

        sub_p256!(t2!(), zzx1!(), resx!()),

        montmul_p256!(t1!(), t1!(), y1a!()),
        montmul_p256!(resz!(), xd!(), z_2!()),
        montmul_p256!(t2!(), yd!(), t2!()),

        sub_p256!(resy!(), t2!(), t1!()),

        // Load in the z coordinates of the inputs to check for P1 = 0 and P2 = 0
        // The condition codes get set by a comparison (P2 != 0) - (P1 != 0)
        // So  "HI" <=> CF /\ ~ZF <=> P1 = 0 /\ ~(P2 = 0)
        // and "LO" <=> ~CF       <=> ~(P1 = 0) /\ P2 = 0

        Q!("    ldp       " "x0, x1, [" z_1!() "]"),
        Q!("    ldp       " "x2, x3, [" z_1!() "+ 16]"),

        Q!("    orr       " "x12, x0, x1"),
        Q!("    orr       " "x13, x2, x3"),
        Q!("    orr       " "x12, x12, x13"),
        Q!("    cmp       " "x12, xzr"),
        Q!("    cset      " "x12, ne"),

        Q!("    ldp       " "x4, x5, [" z_2!() "]"),
        Q!("    ldp       " "x6, x7, [" z_2!() "+ 16]"),

        Q!("    orr       " "x13, x4, x5"),
        Q!("    orr       " "x14, x6, x7"),
        Q!("    orr       " "x13, x13, x14"),
        Q!("    cmp       " "x13, xzr"),
        Q!("    cset      " "x13, ne"),

        Q!("    cmp       " "x13, x12"),

        // Multiplex the outputs accordingly, re-using the z's in registers

        Q!("    ldp       " "x8, x9, [" resz!() "]"),
        Q!("    csel      " "x8, x0, x8, lo"),
        Q!("    csel      " "x9, x1, x9, lo"),
        Q!("    csel      " "x8, x4, x8, hi"),
        Q!("    csel      " "x9, x5, x9, hi"),
        Q!("    ldp       " "x10, x11, [" resz!() "+ 16]"),
        Q!("    csel      " "x10, x2, x10, lo"),
        Q!("    csel      " "x11, x3, x11, lo"),
        Q!("    csel      " "x10, x6, x10, hi"),
        Q!("    csel      " "x11, x7, x11, hi"),

        Q!("    ldp       " "x12, x13, [" x_1!() "]"),
        Q!("    ldp       " "x0, x1, [" resx!() "]"),
        Q!("    csel      " "x0, x12, x0, lo"),
        Q!("    csel      " "x1, x13, x1, lo"),
        Q!("    ldp       " "x12, x13, [" x_2!() "]"),
        Q!("    csel      " "x0, x12, x0, hi"),
        Q!("    csel      " "x1, x13, x1, hi"),

        Q!("    ldp       " "x12, x13, [" x_1!() "+ 16]"),
        Q!("    ldp       " "x2, x3, [" resx!() "+ 16]"),
        Q!("    csel      " "x2, x12, x2, lo"),
        Q!("    csel      " "x3, x13, x3, lo"),
        Q!("    ldp       " "x12, x13, [" x_2!() "+ 16]"),
        Q!("    csel      " "x2, x12, x2, hi"),
        Q!("    csel      " "x3, x13, x3, hi"),

        Q!("    ldp       " "x12, x13, [" y_1!() "]"),
        Q!("    ldp       " "x4, x5, [" resy!() "]"),
        Q!("    csel      " "x4, x12, x4, lo"),
        Q!("    csel      " "x5, x13, x5, lo"),
        Q!("    ldp       " "x12, x13, [" y_2!() "]"),
        Q!("    csel      " "x4, x12, x4, hi"),
        Q!("    csel      " "x5, x13, x5, hi"),

        Q!("    ldp       " "x12, x13, [" y_1!() "+ 16]"),
        Q!("    ldp       " "x6, x7, [" resy!() "+ 16]"),
        Q!("    csel      " "x6, x12, x6, lo"),
        Q!("    csel      " "x7, x13, x7, lo"),
        Q!("    ldp       " "x12, x13, [" y_2!() "+ 16]"),
        Q!("    csel      " "x6, x12, x6, hi"),
        Q!("    csel      " "x7, x13, x7, hi"),

        // Finally store back the multiplexed values

        Q!("    stp       " "x0, x1, [" x_3!() "]"),
        Q!("    stp       " "x2, x3, [" x_3!() "+ 16]"),
        Q!("    stp       " "x4, x5, [" y_3!() "]"),
        Q!("    stp       " "x6, x7, [" y_3!() "+ 16]"),
        Q!("    stp       " "x8, x9, [" z_3!() "]"),
        Q!("    stp       " "x10, x11, [" z_3!() "+ 16]"),

        // Restore registers and return

        Q!("    add       " "sp, sp, " NSPACE!()),
        Q!("    ldp       " "x19, x20, [sp], 16"),
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
