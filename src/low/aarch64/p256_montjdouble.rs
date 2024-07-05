#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::{Label, Q};

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Point doubling on NIST curve P-256 in Montgomery-Jacobian coordinates
//
//    extern void p256_montjdouble
//      (uint64_t p3[static 12],uint64_t p1[static 12]);
//
// Does p3 := 2 * p1 where all points are regarded as Jacobian triples with
// each coordinate in the Montgomery domain, i.e. x' = (2^256 * x) mod p_256.
// A Jacobian triple (x',y',z') represents affine point (x/z^2,y/z^3).
//
// Standard ARM ABI: X0 = p3, X1 = p1
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
        Q!("x19")
    };
}
macro_rules! input_x {
    () => {
        Q!("x20")
    };
}

// Pointer-offset pairs for inputs and outputs

macro_rules! x_1 { () => { Q!(input_x!() ", #0") } }
macro_rules! y_1 { () => { Q!(input_x!() ", # " NUMSIZE!()) } }
macro_rules! z_1 { () => { Q!(input_x!() ", # (2 * " NUMSIZE!() ")") } }

macro_rules! x_3 { () => { Q!(input_z!() ", #0") } }
macro_rules! y_3 { () => { Q!(input_z!() ", # " NUMSIZE!()) } }
macro_rules! z_3 { () => { Q!(input_z!() ", # (2 * " NUMSIZE!() ")") } }

// Pointer-offset pairs for temporaries, with some aliasing
// NSPACE is the total stack needed for these temporaries

macro_rules! z2 { () => { Q!("sp, # (" NUMSIZE!() "* 0)") } }
macro_rules! y2 { () => { Q!("sp, # (" NUMSIZE!() "* 1)") } }
macro_rules! x2p { () => { Q!("sp, # (" NUMSIZE!() "* 2)") } }
macro_rules! xy2 { () => { Q!("sp, # (" NUMSIZE!() "* 3)") } }

macro_rules! y4 { () => { Q!("sp, # (" NUMSIZE!() "* 4)") } }
macro_rules! t2 { () => { Q!("sp, # (" NUMSIZE!() "* 4)") } }

macro_rules! dx2 { () => { Q!("sp, # (" NUMSIZE!() "* 5)") } }
macro_rules! t1 { () => { Q!("sp, # (" NUMSIZE!() "* 5)") } }

macro_rules! d { () => { Q!("sp, # (" NUMSIZE!() "* 6)") } }
macro_rules! x4p { () => { Q!("sp, # (" NUMSIZE!() "* 6)") } }

macro_rules! NSPACE { () => { Q!("# (" NUMSIZE!() "* 7)") } }

// Corresponds exactly to bignum_montmul_p256

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
        "adcs x17, x12, x14;"
        "adcs x14, x14, xzr;"
        "adds x12, x12, x16;"
        "adcs x13, x13, x17;"
        "adcs x14, x14, xzr;"
        "subs x15, x3, x4;"
        "cneg x15, x15, lo;"
        "csetm x1, lo;"
        "subs x17, x8, x7;"
        "cneg x17, x17, lo;"
        "mul x16, x15, x17;"
        "umulh x17, x15, x17;"
        "cinv x1, x1, lo;"
        "eor x16, x16, x1;"
        "eor x17, x17, x1;"
        "cmn x1, # 1;"
        "adcs x12, x12, x16;"
        "adcs x13, x13, x17;"
        "adc x14, x14, x1;"
        "lsl x17, x11, # 32;"
        "subs x1, x11, x17;"
        "lsr x16, x11, # 32;"
        "sbc x11, x11, x16;"
        "adds x12, x12, x17;"
        "adcs x13, x13, x16;"
        "adcs x14, x14, x1;"
        "adc x11, x11, xzr;"
        "lsl x17, x12, # 32;"
        "subs x1, x12, x17;"
        "lsr x16, x12, # 32;"
        "sbc x12, x12, x16;"
        "adds x13, x13, x17;"
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
        "adcs x17, x12, x14;"
        "adcs x14, x14, xzr;"
        "adds x12, x12, x16;"
        "adcs x13, x13, x17;"
        "adcs x14, x14, xzr;"
        "subs x15, x5, x6;"
        "cneg x15, x15, lo;"
        "csetm x1, lo;"
        "subs x17, x10, x9;"
        "cneg x17, x17, lo;"
        "mul x16, x15, x17;"
        "umulh x17, x15, x17;"
        "cinv x1, x1, lo;"
        "eor x16, x16, x1;"
        "eor x17, x17, x1;"
        "cmn x1, # 1;"
        "adcs x12, x12, x16;"
        "adcs x13, x13, x17;"
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
        "adcs x17, x12, x14;"
        "adcs x14, x14, xzr;"
        "adds x12, x12, x16;"
        "adcs x13, x13, x17;"
        "adcs x14, x14, xzr;"
        "subs x3, x3, x4;"
        "cneg x3, x3, lo;"
        "csetm x4, lo;"
        "subs x17, x8, x7;"
        "cneg x17, x17, lo;"
        "mul x16, x3, x17;"
        "umulh x17, x3, x17;"
        "cinv x4, x4, lo;"
        "eor x16, x16, x4;"
        "eor x17, x17, x4;"
        "cmn x4, # 1;"
        "adcs x12, x12, x16;"
        "adcs x13, x13, x17;"
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
        "lsl x17, x11, # 32;"
        "subs x1, x11, x17;"
        "lsr x16, x11, # 32;"
        "sbc x11, x11, x16;"
        "adds x12, x12, x17;"
        "adcs x13, x13, x16;"
        "adcs x14, x14, x1;"
        "adc x11, x11, xzr;"
        "lsl x17, x12, # 32;"
        "subs x1, x12, x17;"
        "lsr x16, x12, # 32;"
        "sbc x12, x12, x16;"
        "adds x13, x13, x17;"
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

// Corresponds exactly to bignum_montsqr_p256

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
        "umull x17, w3, w3;"
        "lsr x11, x3, # 32;"
        "umull x1, w11, w11;"
        "umull x11, w3, w11;"
        "mul x12, x2, x3;"
        "umulh x13, x2, x3;"
        "adds x17, x17, x11, lsl # 33;"
        "lsr x11, x11, # 31;"
        "adc x1, x1, x11;"
        "adds x12, x12, x12;"
        "adcs x13, x13, x13;"
        "adc x1, x1, xzr;"
        "adds x16, x16, x12;"
        "adcs x17, x17, x13;"
        "adc x1, x1, xzr;"
        "lsl x12, x15, # 32;"
        "subs x13, x15, x12;"
        "lsr x11, x15, # 32;"
        "sbc x15, x15, x11;"
        "adds x16, x16, x12;"
        "adcs x17, x17, x11;"
        "adcs x1, x1, x13;"
        "adc x15, x15, xzr;"
        "lsl x12, x16, # 32;"
        "subs x13, x16, x12;"
        "lsr x11, x16, # 32;"
        "sbc x16, x16, x11;"
        "adds x17, x17, x12;"
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
        "adds x6, x6, x17;"
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
        "csetm x3, lo;"
        "adds x5, x5, x3;"
        "and x4, x3, #0xffffffff;"
        "adcs x6, x6, x4;"
        "adcs x7, x7, xzr;"
        "and x4, x3, #0xffffffff00000001;"
        "adc x8, x8, x4;"
        "stp x5, x6, [" $P0 "];"
        "stp x7, x8, [" $P0 "+ 16]"
    )}
}

// Corresponds exactly to bignum_add_p256

macro_rules! add_p256 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "ldp x5, x6, [" $P1 "];"
        "ldp x4, x3, [" $P2 "];"
        "adds x5, x5, x4;"
        "adcs x6, x6, x3;"
        "ldp x7, x8, [" $P1 "+ 16];"
        "ldp x4, x3, [" $P2 "+ 16];"
        "adcs x7, x7, x4;"
        "adcs x8, x8, x3;"
        "adc x3, xzr, xzr;"
        "cmn x5, # 1;"
        "mov x4, # 4294967295;"
        "sbcs xzr, x6, x4;"
        "sbcs xzr, x7, xzr;"
        "mov x4, # - 4294967295;"
        "sbcs xzr, x8, x4;"
        "adcs x3, x3, xzr;"
        "csetm x3, ne;"
        "subs x5, x5, x3;"
        "and x4, x3, #0xffffffff;"
        "sbcs x6, x6, x4;"
        "sbcs x7, x7, xzr;"
        "and x4, x3, #0xffffffff00000001;"
        "sbc x8, x8, x4;"
        "stp x5, x6, [" $P0 "];"
        "stp x7, x8, [" $P0 "+ 16]"
    )}
}

// A weak version of add that only guarantees sum in 4 digits

macro_rules! weakadd_p256 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "ldp x5, x6, [" $P1 "];"
        "ldp x4, x3, [" $P2 "];"
        "adds x5, x5, x4;"
        "adcs x6, x6, x3;"
        "ldp x7, x8, [" $P1 "+ 16];"
        "ldp x4, x3, [" $P2 "+ 16];"
        "adcs x7, x7, x4;"
        "adcs x8, x8, x3;"
        "csetm x3, cs;"
        "subs x5, x5, x3;"
        "and x1, x3, # 4294967295;"
        "sbcs x6, x6, x1;"
        "sbcs x7, x7, xzr;"
        "and x2, x3, # - 4294967295;"
        "sbc x8, x8, x2;"
        "stp x5, x6, [" $P0 "];"
        "stp x7, x8, [" $P0 "+ 16]"
    )}
}

// P0 = C * P1 - D * P2 computed as D * (p_256 - P2) + C * P1
// Quotient estimation is done just as q = h + 1 as in bignum_triple_p256
// This also applies to the other functions following.

macro_rules! cmsub_p256 {
    ($P0:expr, $C:expr, $P1:expr, $D:expr, $P2:expr) => { Q!(
        "mov x1, " $D ";"
        "mov x2, # - 1;"
        "ldp x9, x10, [" $P2 "];"
        "subs x9, x2, x9;"
        "mov x2, # 4294967295;"
        "sbcs x10, x2, x10;"
        "ldp x11, x12, [" $P2 "+ 16];"
        "sbcs x11, xzr, x11;"
        "mov x2, # - 4294967295;"
        "sbc x12, x2, x12;"
        "mul x3, x1, x9;"
        "mul x4, x1, x10;"
        "mul x5, x1, x11;"
        "mul x6, x1, x12;"
        "umulh x9, x1, x9;"
        "umulh x10, x1, x10;"
        "umulh x11, x1, x11;"
        "umulh x7, x1, x12;"
        "adds x4, x4, x9;"
        "adcs x5, x5, x10;"
        "adcs x6, x6, x11;"
        "adc x7, x7, xzr;"
        "mov x1, " $C ";"
        "ldp x9, x10, [" $P1 "];"
        "mul x8, x9, x1;"
        "umulh x9, x9, x1;"
        "adds x3, x3, x8;"
        "mul x8, x10, x1;"
        "umulh x10, x10, x1;"
        "adcs x4, x4, x8;"
        "ldp x11, x12, [" $P1 "+ 16];"
        "mul x8, x11, x1;"
        "umulh x11, x11, x1;"
        "adcs x5, x5, x8;"
        "mul x8, x12, x1;"
        "umulh x12, x12, x1;"
        "adcs x6, x6, x8;"
        "adc x7, x7, xzr;"
        "adds x4, x4, x9;"
        "adcs x5, x5, x10;"
        "adcs x6, x6, x11;"
        "adc x7, x7, x12;"
        "add x8, x7, # 1;"
        "lsl x10, x8, # 32;"
        "adds x6, x6, x10;"
        "adc x7, x7, xzr;"
        "neg x9, x8;"
        "sub x10, x10, # 1;"
        "subs x3, x3, x9;"
        "sbcs x4, x4, x10;"
        "sbcs x5, x5, xzr;"
        "sbcs x6, x6, x8;"
        "sbc x8, x7, x8;"
        "adds x3, x3, x8;"
        "and x9, x8, # 4294967295;"
        "adcs x4, x4, x9;"
        "adcs x5, x5, xzr;"
        "neg x10, x9;"
        "adc x6, x6, x10;"
        "stp x3, x4, [" $P0 "];"
        "stp x5, x6, [" $P0 "+ 16]"
    )}
}

// P0 = 4 * P1 - P2, by direct subtraction of P2; the method
// in bignum_cmul_p256 etc. for quotient estimation still
// works when the value to be reduced is negative, as
// long as it is  > -p_256, which is the case here. The
// actual accumulation of q * p_256 is done a bit differently
// so it works for the q = 0 case.

macro_rules! cmsub41_p256 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "ldp x1, x2, [" $P1 "];"
        "lsl x0, x1, # 2;"
        "ldp x6, x7, [" $P2 "];"
        "subs x0, x0, x6;"
        "extr x1, x2, x1, # 62;"
        "sbcs x1, x1, x7;"
        "ldp x3, x4, [" $P1 "+ 16];"
        "extr x2, x3, x2, # 62;"
        "ldp x6, x7, [" $P2 "+ 16];"
        "sbcs x2, x2, x6;"
        "extr x3, x4, x3, # 62;"
        "sbcs x3, x3, x7;"
        "lsr x4, x4, # 62;"
        "sbc x4, x4, xzr;"
        "add x5, x4, # 1;"
        "lsl x8, x5, # 32;"
        "subs x6, xzr, x8;"
        "sbcs x7, xzr, xzr;"
        "sbc x8, x8, x5;"
        "adds x0, x0, x5;"
        "adcs x1, x1, x6;"
        "adcs x2, x2, x7;"
        "adcs x3, x3, x8;"
        "csetm x5, cc;"
        "adds x0, x0, x5;"
        "and x6, x5, # 4294967295;"
        "adcs x1, x1, x6;"
        "adcs x2, x2, xzr;"
        "neg x7, x6;"
        "adc x3, x3, x7;"
        "stp x0, x1, [" $P0 "];"
        "stp x2, x3, [" $P0 "+ 16]"
    )}
}

// P0 = 3 * P1 - 8 * P2, computed as (p_256 - P2) << 3 + 3 * P1

macro_rules! cmsub38_p256 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "mov x1, 8;"
        "mov x2, # - 1;"
        "ldp x9, x10, [" $P2 "];"
        "subs x9, x2, x9;"
        "mov x2, # 4294967295;"
        "sbcs x10, x2, x10;"
        "ldp x11, x12, [" $P2 "+ 16];"
        "sbcs x11, xzr, x11;"
        "mov x2, # - 4294967295;"
        "sbc x12, x2, x12;"
        "lsl x3, x9, # 3;"
        "extr x4, x10, x9, # 61;"
        "extr x5, x11, x10, # 61;"
        "extr x6, x12, x11, # 61;"
        "lsr x7, x12, # 61;"
        "mov x1, 3;"
        "ldp x9, x10, [" $P1 "];"
        "mul x8, x9, x1;"
        "umulh x9, x9, x1;"
        "adds x3, x3, x8;"
        "mul x8, x10, x1;"
        "umulh x10, x10, x1;"
        "adcs x4, x4, x8;"
        "ldp x11, x12, [" $P1 "+ 16];"
        "mul x8, x11, x1;"
        "umulh x11, x11, x1;"
        "adcs x5, x5, x8;"
        "mul x8, x12, x1;"
        "umulh x12, x12, x1;"
        "adcs x6, x6, x8;"
        "adc x7, x7, xzr;"
        "adds x4, x4, x9;"
        "adcs x5, x5, x10;"
        "adcs x6, x6, x11;"
        "adc x7, x7, x12;"
        "add x8, x7, # 1;"
        "lsl x10, x8, # 32;"
        "adds x6, x6, x10;"
        "adc x7, x7, xzr;"
        "neg x9, x8;"
        "sub x10, x10, # 1;"
        "subs x3, x3, x9;"
        "sbcs x4, x4, x10;"
        "sbcs x5, x5, xzr;"
        "sbcs x6, x6, x8;"
        "sbc x8, x7, x8;"
        "adds x3, x3, x8;"
        "and x9, x8, # 4294967295;"
        "adcs x4, x4, x9;"
        "adcs x5, x5, xzr;"
        "neg x10, x9;"
        "adc x6, x6, x10;"
        "stp x3, x4, [" $P0 "];"
        "stp x5, x6, [" $P0 "+ 16]"
    )}
}

pub fn p256_montjdouble(p3: &mut [u64; 12], p1: &[u64; 12]) {
    unsafe {
        core::arch::asm!(


        // Save registers and make room on stack for temporary variables

        Q!("    sub       " "sp, sp, " NSPACE!() "+ 16"),
        Q!("    stp       " "x19, x20, [sp, " NSPACE!() "]"),

        // Move the input arguments to stable places

        Q!("    mov       " input_z!() ", x0"),
        Q!("    mov       " input_x!() ", x1"),

        // Main code, just a sequence of basic field operations

        // z2 = z^2
        // y2 = y^2

        montsqr_p256!(z2!(), z_1!()),
        montsqr_p256!(y2!(), y_1!()),

        // x2p = x^2 - z^4 = (x + z^2) * (x - z^2)

        weakadd_p256!(t1!(), x_1!(), z2!()),
        sub_p256!(t2!(), x_1!(), z2!()),
        montmul_p256!(x2p!(), t1!(), t2!()),

        // t1 = y + z
        // x4p = x2p^2
        // xy2 = x * y^2

        add_p256!(t1!(), y_1!(), z_1!()),
        montsqr_p256!(x4p!(), x2p!()),
        montmul_p256!(xy2!(), x_1!(), y2!()),

        // t2 = (y + z)^2

        montsqr_p256!(t2!(), t1!()),

        // d = 12 * xy2 - 9 * x4p
        // t1 = y^2 + 2 * y * z

        cmsub_p256!(d!(), "12", xy2!(), "9", x4p!()),
        sub_p256!(t1!(), t2!(), z2!()),

        // y4 = y^4

        montsqr_p256!(y4!(), y2!()),

        // z_3' = 2 * y * z
        // dx2 = d * x2p

        sub_p256!(z_3!(), t1!(), y2!()),
        montmul_p256!(dx2!(), d!(), x2p!()),

        // x' = 4 * xy2 - d

        cmsub41_p256!(x_3!(), xy2!(), d!()),

        // y' = 3 * dx2 - 8 * y4

        cmsub38_p256!(y_3!(), dx2!(), y4!()),

        // Restore registers and stack and return

        Q!("    ldp       " "x19, x20, [sp, " NSPACE!() "]"),
        Q!("    add       " "sp, sp, " NSPACE!() "+ 16"),
        inout("x0") p3.as_mut_ptr() => _,
        inout("x1") p1.as_ptr() => _,
        // clobbers
        out("x10") _,
        out("x11") _,
        out("x12") _,
        out("x13") _,
        out("x14") _,
        out("x15") _,
        out("x16") _,
        out("x17") _,
        out("x2") _,
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
