#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::{Label, Q};

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// 256-bit nonzeroness test, returning 1 if x is nonzero, 0 if x is zero
// Input x[4]; output function return
//
//    extern uint64_t bignum_nonzero_4(uint64_t x[static 4]);
//
// Standard ARM ABI: X0 = x, returns X0
// ----------------------------------------------------------------------------

macro_rules! x {
    () => {
        Q!("x0")
    };
}
macro_rules! a {
    () => {
        Q!("x1")
    };
}
macro_rules! d {
    () => {
        Q!("x2")
    };
}
macro_rules! c {
    () => {
        Q!("x3")
    };
}

pub fn bignum_nonzero_4(x: &[u64; 4]) -> bool {
    let ret: u64;
    unsafe {
        core::arch::asm!(


        // Generate a = an OR of all the words in the bignum

        Q!("    ldp       " a!() ", " d!() ", [" x!() "]"),
        Q!("    orr       " a!() ", " a!() ", " d!()),
        Q!("    ldp       " c!() ", " d!() ", [" x!() ", # 16]"),
        Q!("    orr       " c!() ", " c!() ", " d!()),
        Q!("    orr       " a!() ", " a!() ", " c!()),

        // Set a standard C condition based on whether a is nonzero

        Q!("    cmp       " a!() ", xzr"),
        Q!("    cset      " "x0, ne"),

        inout("x0") x.as_ptr() => ret,
        // clobbers
        out("x1") _,
        out("x2") _,
        out("x3") _,
            )
    };
    ret > 0
}
