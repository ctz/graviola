#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::{Label, Q};

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Test bignums for equality, x = y
// Inputs x[m], y[n]; output function return
//
//    extern uint64_t bignum_eq
//     (uint64_t m, uint64_t *x, uint64_t n, uint64_t *y);
//
// Standard ARM ABI: X0 = m, X1 = x, X2 = n, X3 = y, returns X0
// ----------------------------------------------------------------------------

macro_rules! m {
    () => {
        Q!("x0")
    };
}
macro_rules! x {
    () => {
        Q!("x1")
    };
}
macro_rules! n {
    () => {
        Q!("x2")
    };
}
macro_rules! y {
    () => {
        Q!("x3")
    };
}
macro_rules! a {
    () => {
        Q!("x4")
    };
}
macro_rules! c {
    () => {
        Q!("x5")
    };
}
//  We can re-use n for this, not needed when d appears
macro_rules! d {
    () => {
        Q!("x2")
    };
}

pub fn bignum_eq(x: &[u64], y: &[u64]) -> bool {
    let ret: u64;
    unsafe {
        core::arch::asm!(


        // Initialize the accumulated OR of differences to zero

        Q!("    mov       " c!() ", xzr"),

        // If m >= n jump into the m > n loop at the final equality test
        // This will drop through for m = n

        Q!("    cmp       " m!() ", " n!()),
        Q!("    bcs       " Label!("mtest", 2, After)),

        // Toploop for the case n > m

        Q!(Label!("nloop", 3) ":"),
        Q!("    sub       " n!() ", " n!() ", #1"),
        Q!("    ldr       " a!() ", [" y!() ", " n!() ", lsl #3]"),
        Q!("    orr       " c!() ", " c!() ", " a!()),
        Q!("    cmp       " m!() ", " n!()),
        Q!("    bne       " Label!("nloop", 3, Before)),
        Q!("    b         " Label!("mmain", 4, After)),

        // Toploop for the case m > n (or n = m which enters at "mtest")

        Q!(Label!("mloop", 5) ":"),
        Q!("    sub       " m!() ", " m!() ", #1"),
        Q!("    ldr       " a!() ", [" x!() ", " m!() ", lsl #3]"),
        Q!("    orr       " c!() ", " c!() ", " a!()),
        Q!("    cmp       " m!() ", " n!()),
        Q!(Label!("mtest", 2) ":"),
        Q!("    bne       " Label!("mloop", 5, Before)),

        // Combined main loop for the min(m,n) lower words

        Q!(Label!("mmain", 4) ":"),
        Q!("    cbz       " m!() ", " Label!("end", 6, After)),

        Q!(Label!("loop", 7) ":"),
        Q!("    sub       " m!() ", " m!() ", #1"),
        Q!("    ldr       " a!() ", [" x!() ", " m!() ", lsl #3]"),
        Q!("    ldr       " d!() ", [" y!() ", " m!() ", lsl #3]"),
        Q!("    eor       " a!() ", " a!() ", " d!()),
        Q!("    orr       " c!() ", " c!() ", " a!()),
        Q!("    cbnz      " m!() ", " Label!("loop", 7, Before)),

        Q!(Label!("end", 6) ":"),
        Q!("    cmp       " c!() ", xzr"),
        Q!("    cset      " "x0, eq"),
        inout("x0") x.len() => ret,
        inout("x1") x.as_ptr() => _,
        inout("x2") y.len() => _,
        inout("x3") y.as_ptr() => _,
        // clobbers
        out("x4") _,
        out("x5") _,
            )
    };
    ret > 0
}
