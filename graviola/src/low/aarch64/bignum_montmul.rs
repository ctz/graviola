// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Montgomery multiply, z := (x * y / 2^{64k}) mod m
// Inputs x[k], y[k], m[k]; output z[k]
//
//    extern void bignum_montmul(uint64_t k, uint64_t *z, const uint64_t *x,
//                               const uint64_t *y, const uint64_t *m);
//
// Does z := (x * y / 2^{64k}) mod m, assuming x * y <= 2^{64k} * m, which is
// guaranteed in particular if x < m, y < m initially (the "intended" case).
//
// Standard ARM ABI: X0 = k, X1 = z, X2 = x, X3 = y, X4 = m
// ----------------------------------------------------------------------------

macro_rules! k {
    () => {
        "x0"
    };
}
macro_rules! z {
    () => {
        "x1"
    };
}
macro_rules! x {
    () => {
        "x2"
    };
}
macro_rules! y {
    () => {
        "x3"
    };
}
macro_rules! m {
    () => {
        "x4"
    };
}

// Negated modular inverse
macro_rules! w {
    () => {
        "x5"
    };
}
// Top carry for k'th position
macro_rules! c0 {
    () => {
        "x6"
    };
}
// Additional top carry for (k+1)'th position
macro_rules! c1 {
    () => {
        "x7"
    };
}
// Outer loop counter
macro_rules! i {
    () => {
        "x8"
    };
}
// Home for i'th digit or Montgomery multiplier
macro_rules! d {
    () => {
        "x9"
    };
}
// Inner loop counter
macro_rules! j {
    () => {
        "x10"
    };
}

macro_rules! h {
    () => {
        "x11"
    };
}
macro_rules! e {
    () => {
        "x12"
    };
}
macro_rules! l {
    () => {
        "x13"
    };
}
macro_rules! a {
    () => {
        "x14"
    };
}

// This is just a short-term temporary used in zero-test subtraction.
// It's aliased to the same register as "a" which is always safe here.

macro_rules! t {
    () => {
        "x14"
    };
}

// Some more intuitive names for temp regs in initial word-level negmodinv.
// These just use c0 and c1 again, which aren't initialized early on.

macro_rules! one {
    () => {
        "x6"
    };
}
macro_rules! e1 {
    () => {
        "x6"
    };
}
macro_rules! e2 {
    () => {
        "x7"
    };
}
macro_rules! e4 {
    () => {
        "x6"
    };
}
macro_rules! e8 {
    () => {
        "x7"
    };
}

/// Montgomery multiply, z := (x * y / 2^{64k}) mod m
///
/// Inputs x[k], y[k], m[k]; output z[k]
///
/// Does z := (x * y / 2^{64k}) mod m, assuming x * y <= 2^{64k} * m, which is
/// guaranteed in particular if x < m, y < m initially (the "intended" case).
pub(crate) fn bignum_montmul(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64]) {
    debug_assert!(z.len() == x.len());
    debug_assert!(z.len() == y.len());
    debug_assert!(z.len() == m.len());
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(


        // If k = 0 the whole operation is trivial

        Q!("    cbz             " k!() ", " Label!("bignum_montmul_end", 2, After)),

        // Compute word-level negated modular inverse w for m == m[0].
        // This is essentially the same as word_negmodinv.

        Q!("    ldr             " a!() ", [" m!() "]"),
        Q!("    lsl             " w!() ", " a!() ", #2"),
        Q!("    sub             " w!() ", " a!() ", " w!()),
        Q!("    eor             " w!() ", " w!() ", #2"),
        Q!("    mov             " one!() ", #1"),
        Q!("    madd            " e1!() ", " a!() ", " w!() ", " one!()),
        Q!("    mul             " e2!() ", " e1!() ", " e1!()),
        Q!("    madd            " w!() ", " e1!() ", " w!() ", " w!()),
        Q!("    mul             " e4!() ", " e2!() ", " e2!()),
        Q!("    madd            " w!() ", " e2!() ", " w!() ", " w!()),
        Q!("    mul             " e8!() ", " e4!() ", " e4!()),
        Q!("    madd            " w!() ", " e4!() ", " w!() ", " w!()),
        Q!("    madd            " w!() ", " e8!() ", " w!() ", " w!()),

        // Initialize the output c0::z to zero so we can then consistently add rows.
        // It would be a bit more efficient to special-case the zeroth row, but
        // this keeps the code slightly simpler.

        Q!("    mov             " i!() ", xzr"),
        Q!(Label!("bignum_montmul_zoop", 3) ":"),
        Q!("    str             " "xzr, [" z!() ", " i!() ", lsl #3]"),
        Q!("    add             " i!() ", " i!() ", #1"),
        Q!("    cmp             " i!() ", " k!()),
        Q!("    bcc             " Label!("bignum_montmul_zoop", 3, Before)),
        Q!("    mov             " c0!() ", xzr"),

        // Outer loop pulling down digits d=x[i], multiplying by y and reducing

        Q!("    mov             " i!() ", xzr"),
        Q!(Label!("bignum_montmul_outerloop", 4) ":"),

        // Multiply-add loop where we always have CF + previous high part h to add in
        // Note that in general we do need yet one more carry in this phase and hence
        // initialize c1 with the top carry.

        Q!("    ldr             " d!() ", [" x!() ", " i!() ", lsl #3]"),
        Q!("    mov             " j!() ", xzr"),
        Q!("    adds            " h!() ", xzr, xzr"),
        Q!(Label!("bignum_montmul_maddloop", 5) ":"),
        Q!("    ldr             " a!() ", [" y!() ", " j!() ", lsl #3]"),
        Q!("    ldr             " e!() ", [" z!() ", " j!() ", lsl #3]"),
        Q!("    mul             " l!() ", " d!() ", " a!()),
        Q!("    adcs            " e!() ", " e!() ", " h!()),
        Q!("    umulh           " h!() ", " d!() ", " a!()),
        Q!("    adc             " h!() ", " h!() ", xzr"),
        Q!("    adds            " e!() ", " e!() ", " l!()),
        Q!("    str             " e!() ", [" z!() ", " j!() ", lsl #3]"),
        Q!("    add             " j!() ", " j!() ", #1"),
        Q!("    sub             " t!() ", " j!() ", " k!()),
        Q!("    cbnz            " t!() ", " Label!("bignum_montmul_maddloop", 5, Before)),
        Q!("    adcs            " c0!() ", " c0!() ", " h!()),
        Q!("    adc             " c1!() ", xzr, xzr"),

        // Montgomery reduction loop, similar but offsetting writebacks

        Q!("    ldr             " e!() ", [" z!() "]"),
        Q!("    mul             " d!() ", " e!() ", " w!()),
        Q!("    ldr             " a!() ", [" m!() "]"),
        Q!("    mul             " l!() ", " d!() ", " a!()),
        Q!("    umulh           " h!() ", " d!() ", " a!()),
        Q!("    adds            " e!() ", " e!() ", " l!()),
        Q!("    mov             " j!() ", #1"),
        Q!("    sub             " t!() ", " k!() ", #1"),
        Q!("    cbz             " t!() ", " Label!("bignum_montmul_montend", 6, After)),
        Q!(Label!("bignum_montmul_montloop", 7) ":"),
        Q!("    ldr             " a!() ", [" m!() ", " j!() ", lsl #3]"),
        Q!("    ldr             " e!() ", [" z!() ", " j!() ", lsl #3]"),
        Q!("    mul             " l!() ", " d!() ", " a!()),
        Q!("    adcs            " e!() ", " e!() ", " h!()),
        Q!("    umulh           " h!() ", " d!() ", " a!()),
        Q!("    adc             " h!() ", " h!() ", xzr"),
        Q!("    adds            " e!() ", " e!() ", " l!()),
        Q!("    sub             " l!() ", " j!() ", #1"),
        Q!("    str             " e!() ", [" z!() ", " l!() ", lsl #3]"),
        Q!("    add             " j!() ", " j!() ", #1"),
        Q!("    sub             " t!() ", " j!() ", " k!()),
        Q!("    cbnz            " t!() ", " Label!("bignum_montmul_montloop", 7, Before)),
        Q!(Label!("bignum_montmul_montend", 6) ":"),
        Q!("    adcs            " h!() ", " c0!() ", " h!()),
        Q!("    adc             " c0!() ", " c1!() ", xzr"),
        Q!("    sub             " l!() ", " j!() ", #1"),
        Q!("    str             " h!() ", [" z!() ", " l!() ", lsl #3]"),

        // End of outer loop

        Q!("    add             " i!() ", " i!() ", #1"),
        Q!("    cmp             " i!() ", " k!()),
        Q!("    bcc             " Label!("bignum_montmul_outerloop", 4, Before)),

        // Now do a comparison of (c0::z) with (0::m) to set a final correction mask
        // indicating that (c0::z) >= m and so we need to subtract m.

        Q!("    subs            " j!() ", xzr, xzr"),
        Q!(Label!("bignum_montmul_cmploop", 8) ":"),
        Q!("    ldr             " a!() ", [" z!() ", " j!() ", lsl #3]"),
        Q!("    ldr             " e!() ", [" m!() ", " j!() ", lsl #3]"),
        Q!("    sbcs            " "xzr, " a!() ", " e!()),
        Q!("    add             " j!() ", " j!() ", #1"),
        Q!("    sub             " t!() ", " j!() ", " k!()),
        Q!("    cbnz            " t!() ", " Label!("bignum_montmul_cmploop", 8, Before)),

        Q!("    sbcs            " "xzr, " c0!() ", xzr"),
        Q!("    csetm           " c0!() ", cs"),

        // Now do a masked subtraction of m for the final reduced result.

        Q!("    subs            " j!() ", xzr, xzr"),
        Q!(Label!("bignum_montmul_corrloop", 9) ":"),
        Q!("    ldr             " a!() ", [" z!() ", " j!() ", lsl #3]"),
        Q!("    ldr             " e!() ", [" m!() ", " j!() ", lsl #3]"),
        Q!("    and             " e!() ", " e!() ", " c0!()),
        Q!("    sbcs            " a!() ", " a!() ", " e!()),
        Q!("    str             " a!() ", [" z!() ", " j!() ", lsl #3]"),
        Q!("    add             " j!() ", " j!() ", #1"),
        Q!("    sub             " t!() ", " j!() ", " k!()),
        Q!("    cbnz            " t!() ", " Label!("bignum_montmul_corrloop", 9, Before)),

        Q!(Label!("bignum_montmul_end", 2) ":"),
        inout("x0") m.len() => _,
        inout("x1") z.as_mut_ptr() => _,
        inout("x2") x.as_ptr() => _,
        inout("x3") y.as_ptr() => _,
        inout("x4") m.as_ptr() => _,
        // clobbers
        out("x10") _,
        out("x11") _,
        out("x12") _,
        out("x13") _,
        out("x14") _,
        out("x5") _,
        out("x6") _,
        out("x7") _,
        out("x8") _,
        out("x9") _,
            )
    };
}
