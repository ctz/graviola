#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::{Label, Q};

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Compare bignums, x < y
// Inputs x[m], y[n]; output function return
//
//    extern uint64_t bignum_lt
//     (uint64_t m, uint64_t *x, uint64_t n, uint64_t *y);
//
// Standard x86-64 ABI: RDI = m, RSI = x, RDX = n, RCX = y, returns RAX
// Microsoft x64 ABI:   RCX = m, RDX = x, R8 = n, R9 = y, returns RAX
// ----------------------------------------------------------------------------

macro_rules! m {
    () => {
        Q!("rdi")
    };
}
macro_rules! x {
    () => {
        Q!("rsi")
    };
}
macro_rules! n {
    () => {
        Q!("rdx")
    };
}
macro_rules! y {
    () => {
        Q!("rcx")
    };
}
macro_rules! i {
    () => {
        Q!("r8")
    };
}
macro_rules! a {
    () => {
        Q!("rax")
    };
}

macro_rules! ashort {
    () => {
        Q!("eax")
    };
}

pub fn bignum_cmp_lt(x: &[u64], y: &[u64]) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(



        // Zero the main index counter for both branches

        Q!("    xor             " i!() ", " i!()),

        // Speculatively form m := m - n and do case split

        Q!("    sub             " m!() ", " n!()),
        Q!("    jc              " Label!("ylonger", 2, After)),

        // The case where x is longer or of the same size (m >= n)

        Q!("    inc             " m!()),
        Q!("    test            " n!() ", " n!()),
        Q!("    jz              " Label!("xtest", 3, After)),
        Q!(Label!("xmainloop", 4) ":"),
        Q!("    mov             " a!() ", [" x!() "+ 8 * " i!() "]"),
        Q!("    sbb             " a!() ", [" y!() "+ 8 * " i!() "]"),
        Q!("    inc             " i!()),
        Q!("    dec             " n!()),
        Q!("    jnz             " Label!("xmainloop", 4, Before)),
        Q!("    jmp             " Label!("xtest", 3, After)),
        Q!(Label!("xtoploop", 5) ":"),
        Q!("    mov             " a!() ", [" x!() "+ 8 * " i!() "]"),
        Q!("    sbb             " a!() ", 0"),
        Q!("    inc             " i!()),
        Q!(Label!("xtest", 3) ":"),
        Q!("    dec             " m!()),
        Q!("    jnz             " Label!("xtoploop", 5, Before)),
        Q!("    sbb             " a!() ", " a!()),
        Q!("    neg             " a!()),
        // linear hoisting in -> ret after ytoploop
        Q!("    jmp             " Label!("hoist_finish", 6, After)),

        // The case where y is longer (n > m)

        Q!(Label!("ylonger", 2) ":"),
        Q!("    add             " m!() ", " n!()),
        Q!("    sub             " n!() ", " m!()),
        Q!("    test            " m!() ", " m!()),
        Q!("    jz              " Label!("ytoploop", 7, After)),
        Q!(Label!("ymainloop", 8) ":"),
        Q!("    mov             " a!() ", [" x!() "+ 8 * " i!() "]"),
        Q!("    sbb             " a!() ", [" y!() "+ 8 * " i!() "]"),
        Q!("    inc             " i!()),
        Q!("    dec             " m!()),
        Q!("    jnz             " Label!("ymainloop", 8, Before)),
        Q!(Label!("ytoploop", 7) ":"),
        Q!("    mov             " ashort!() ", 0"),
        Q!("    sbb             " a!() ", [" y!() "+ 8 * " i!() "]"),
        Q!("    inc             " i!()),
        Q!("    dec             " n!()),
        Q!("    jnz             " Label!("ytoploop", 7, Before)),

        Q!("    sbb             " a!() ", " a!()),
        Q!("    neg             " a!()),
        Q!(Label!("hoist_finish", 6) ":"),
        inout("rdi") x.len() => _,
        inout("rsi") x.as_ptr() => _,
        inout("rdx") y.len() => _,
        inout("rcx") y.as_ptr() => _,
        out("rax") ret,
        // clobbers
        out("r8") _,
            )
    };
    ret
}
