#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Add, z := x + y
// Inputs x[m], y[n]; outputs function return (carry-out) and z[p]
//
//    extern uint64_t bignum_add
//     (uint64_t p, uint64_t *z,
//      uint64_t m, uint64_t *x, uint64_t n, uint64_t *y);
//
// Does the z := x + y operation, truncating modulo p words in general and
// returning a top carry (0 or 1) in the p'th place, only adding the input
// words below p (as well as m and n respectively) to get the sum and carry.
//
// Standard ARM ABI: X0 = p, X1 = z, X2 = m, X3 = x, X4 = n, X5 = y, returns X0
// ----------------------------------------------------------------------------

macro_rules! p {
    () => {
        Q!("x0")
    };
}
macro_rules! z {
    () => {
        Q!("x1")
    };
}
macro_rules! m {
    () => {
        Q!("x2")
    };
}
macro_rules! x {
    () => {
        Q!("x3")
    };
}
macro_rules! n {
    () => {
        Q!("x4")
    };
}
macro_rules! y {
    () => {
        Q!("x5")
    };
}
macro_rules! i {
    () => {
        Q!("x6")
    };
}
macro_rules! a {
    () => {
        Q!("x7")
    };
}
macro_rules! d {
    () => {
        Q!("x8")
    };
}

pub(crate) fn bignum_add(z: &mut [u64], x: &[u64], y: &[u64]) {
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(


        // First clamp the two input sizes m := min(p,m) and n := min(p,n) since
        // we'll never need words past the p'th. Can now assume m <= p and n <= p.
        // Then compare the modified m and n and branch accordingly

        Q!("    cmp             " m!() ", " p!()),
        Q!("    csel            " m!() ", " p!() ", " m!() ", cs"),
        Q!("    cmp             " n!() ", " p!()),
        Q!("    csel            " n!() ", " p!() ", " n!() ", cs"),
        Q!("    cmp             " m!() ", " n!()),
        Q!("    bcc             " Label!("ylonger", 2, After)),

        // The case where x is longer or of the same size (p >= m >= n)

        Q!("    sub             " p!() ", " p!() ", " m!()),
        Q!("    sub             " m!() ", " m!() ", " n!()),
        Q!("    ands            " i!() ", xzr, xzr"),
        Q!("    cbz             " n!() ", " Label!("xmainskip", 3, After)),
        Q!(Label!("xmainloop", 4) ":"),
        Q!("    ldr             " a!() ", [" x!() ", " i!() ", lsl #3]"),
        Q!("    ldr             " d!() ", [" y!() ", " i!() ", lsl #3]"),
        Q!("    adcs            " a!() ", " a!() ", " d!()),
        Q!("    str             " a!() ", [" z!() ", " i!() ", lsl #3]"),
        Q!("    add             " i!() ", " i!() ", #1"),
        Q!("    sub             " n!() ", " n!() ", #1"),
        Q!("    cbnz            " n!() ", " Label!("xmainloop", 4, Before)),
        Q!(Label!("xmainskip", 3) ":"),
        Q!("    cbz             " m!() ", " Label!("xtopskip", 5, After)),
        Q!(Label!("xtoploop", 6) ":"),
        Q!("    ldr             " a!() ", [" x!() ", " i!() ", lsl #3]"),
        Q!("    adcs            " a!() ", " a!() ", xzr"),
        Q!("    str             " a!() ", [" z!() ", " i!() ", lsl #3]"),
        Q!("    add             " i!() ", " i!() ", #1"),
        Q!("    sub             " m!() ", " m!() ", #1"),
        Q!("    cbnz            " m!() ", " Label!("xtoploop", 6, Before)),
        Q!(Label!("xtopskip", 5) ":"),
        Q!("    cbnz            " p!() ", " Label!("tails", 7, After)),
        Q!("    cset            " "x0, cs"),
        // linear hoisting in -> ret after tail
        Q!("    b               " Label!("hoist_finish", 8, After)),

        // The case where y is longer (p >= n > m)

        Q!(Label!("ylonger", 2) ":"),
        Q!("    sub             " p!() ", " p!() ", " n!()),
        Q!("    sub             " n!() ", " n!() ", " m!()),
        Q!("    ands            " i!() ", xzr, xzr"),
        Q!("    cbz             " m!() ", " Label!("ytoploop", 9, After)),
        Q!(Label!("ymainloop", 12) ":"),
        Q!("    ldr             " a!() ", [" x!() ", " i!() ", lsl #3]"),
        Q!("    ldr             " d!() ", [" y!() ", " i!() ", lsl #3]"),
        Q!("    adcs            " a!() ", " a!() ", " d!()),
        Q!("    str             " a!() ", [" z!() ", " i!() ", lsl #3]"),
        Q!("    add             " i!() ", " i!() ", #1"),
        Q!("    sub             " m!() ", " m!() ", #1"),
        Q!("    cbnz            " m!() ", " Label!("ymainloop", 12, Before)),
        Q!(Label!("ytoploop", 9) ":"),
        Q!("    ldr             " a!() ", [" y!() ", " i!() ", lsl #3]"),
        Q!("    adcs            " a!() ", xzr, " a!()),
        Q!("    str             " a!() ", [" z!() ", " i!() ", lsl #3]"),
        Q!("    add             " i!() ", " i!() ", #1"),
        Q!("    sub             " n!() ", " n!() ", #1"),
        Q!("    cbnz            " n!() ", " Label!("ytoploop", 9, Before)),
        Q!(Label!("ytopskip", 13) ":"),
        Q!("    cbnz            " p!() ", " Label!("tails", 7, After)),
        Q!("    cset            " "x0, cs"),
        Q!("    b               " Label!("hoist_finish", 8, After)),

        // Adding a non-trivial tail, when p > max(m,n)

        Q!(Label!("tails", 7) ":"),
        Q!("    cset            " a!() ", cs"),
        Q!("    str             " a!() ", [" z!() ", " i!() ", lsl #3]"),
        Q!("    b               " Label!("tail", 14, After)),
        Q!(Label!("tailloop", 15) ":"),
        Q!("    str             " "xzr, [" z!() ", " i!() ", lsl #3]"),
        Q!(Label!("tail", 14) ":"),
        Q!("    add             " i!() ", " i!() ", #1"),
        Q!("    sub             " p!() ", " p!() ", #1"),
        Q!("    cbnz            " p!() ", " Label!("tailloop", 15, Before)),
        Q!("    mov             " "x0, xzr"),
        Q!(Label!("hoist_finish", 8) ":"),
        inout("x0") z.len() => _,
        inout("x1") z.as_mut_ptr() => _,
        inout("x2") x.len() => _,
        inout("x3") x.as_ptr() => _,
        inout("x4") y.len() => _,
        inout("x5") y.as_ptr() => _,
        // clobbers
        out("x6") _,
        out("x7") _,
        out("x8") _,
            )
    };
}
