#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Add modulo m, z := (x + y) mod m, assuming x and y reduced
// Inputs x[k], y[k], m[k]; output z[k]
//
//    extern void bignum_modadd
//     (uint64_t k, uint64_t *z, uint64_t *x, uint64_t *y, uint64_t *m);
//
// Standard ARM ABI: X0 = k, X1 = z, X2 = x, X3 = y, X4 = m
// ----------------------------------------------------------------------------

macro_rules! k {
    () => {
        Q!("x0")
    };
}
macro_rules! z {
    () => {
        Q!("x1")
    };
}
macro_rules! x {
    () => {
        Q!("x2")
    };
}
macro_rules! y {
    () => {
        Q!("x3")
    };
}
macro_rules! m {
    () => {
        Q!("x4")
    };
}
macro_rules! i {
    () => {
        Q!("x5")
    };
}
macro_rules! j {
    () => {
        Q!("x6")
    };
}
macro_rules! a {
    () => {
        Q!("x7")
    };
}
macro_rules! b {
    () => {
        Q!("x8")
    };
}
macro_rules! c {
    () => {
        Q!("x9")
    };
}

pub fn bignum_modadd(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64]) {
    debug_assert!(z.len() == x.len());
    debug_assert!(z.len() == y.len());
    debug_assert!(z.len() == m.len());
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(


        Q!("    adds            " j!() ", " k!() ", xzr"),
        Q!("    beq             " Label!("end", 2, After)),
        Q!("    adds            " i!() ", xzr, xzr"),

        // First just add (c::z) := x + y

        Q!(Label!("addloop", 3) ":"),
        Q!("    ldr             " a!() ", [" x!() ", " i!() "]"),
        Q!("    ldr             " b!() ", [" y!() ", " i!() "]"),
        Q!("    adcs            " a!() ", " a!() ", " b!()),
        Q!("    str             " a!() ", [" z!() ", " i!() "]"),
        Q!("    add             " i!() ", " i!() ", #8"),
        Q!("    sub             " j!() ", " j!() ", #1"),
        Q!("    cbnz            " j!() ", " Label!("addloop", 3, Before)),
        Q!("    cset            " c!() ", cs"),

        // Now do a comparison subtraction (c::z) - m, recording mask for (c::z) >= m

        Q!("    mov             " j!() ", " k!()),
        Q!("    subs            " i!() ", xzr, xzr"),
        Q!(Label!("cmploop", 4) ":"),
        Q!("    ldr             " a!() ", [" z!() ", " i!() "]"),
        Q!("    ldr             " b!() ", [" m!() ", " i!() "]"),
        Q!("    sbcs            " "xzr, " a!() ", " b!()),
        Q!("    add             " i!() ", " i!() ", #8"),
        Q!("    sub             " j!() ", " j!() ", #1"),
        Q!("    cbnz            " j!() ", " Label!("cmploop", 4, Before)),
        Q!("    sbcs            " c!() ", " c!() ", xzr"),
        Q!("    mvn             " c!() ", " c!()),

        // Now do a masked subtraction z := z - [c] * m

        Q!("    mov             " j!() ", " k!()),
        Q!("    subs            " i!() ", xzr, xzr"),
        Q!(Label!("subloop", 5) ":"),
        Q!("    ldr             " a!() ", [" z!() ", " i!() "]"),
        Q!("    ldr             " b!() ", [" m!() ", " i!() "]"),
        Q!("    and             " b!() ", " b!() ", " c!()),
        Q!("    sbcs            " a!() ", " a!() ", " b!()),
        Q!("    str             " a!() ", [" z!() ", " i!() "]"),
        Q!("    add             " i!() ", " i!() ", #8"),
        Q!("    sub             " j!() ", " j!() ", #1"),
        Q!("    cbnz            " j!() ", " Label!("subloop", 5, Before)),

        Q!(Label!("end", 2) ":"),
        inout("x0") m.len() => _,
        inout("x1") z.as_mut_ptr() => _,
        inout("x2") x.as_ptr() => _,
        inout("x3") y.as_ptr() => _,
        inout("x4") m.as_ptr() => _,
        // clobbers
        out("x5") _,
        out("x6") _,
        out("x7") _,
        out("x8") _,
        out("x9") _,
            )
    };
}
