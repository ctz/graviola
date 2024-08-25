#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::{Label, Q};

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Return size of bignum in digits (64-bit word)
// Input x[k]; output function return
//
//    extern uint64_t bignum_digitsize (uint64_t k, uint64_t *x);
//
// In the case of a zero bignum as input the result is 0
//
// Standard x86-64 ABI: RDI = k, RSI = x, returns RAX
// Microsoft x64 ABI:   RCX = k, RDX = x, returns RAX
// ----------------------------------------------------------------------------

macro_rules! k {
    () => {
        Q!("rdi")
    };
}
macro_rules! x {
    () => {
        Q!("rsi")
    };
}
macro_rules! i {
    () => {
        Q!("rax")
    };
}
macro_rules! a {
    () => {
        Q!("rcx")
    };
}
macro_rules! j {
    () => {
        Q!("rdx")
    };
}

pub fn bignum_digitsize(z: &[u64]) -> usize {
    let ret: u64;
    unsafe {
        core::arch::asm!(



        // Initialize the index i and also prepare default return value of 0 (i = rax)

        Q!("    xor             " i!() ", " i!()),

        // If the bignum is zero-length, just return 0

        Q!("    test            " k!() ", " k!()),
        Q!("    jz              " Label!("end", 2, After)),

        // Run over the words j = 0..i-1, and set i := j + 1 when hitting nonzero a[j]

        Q!("    xor             " j!() ", " j!()),
        Q!(Label!("loop", 3) ":"),
        Q!("    mov             " a!() ", [" x!() "+ 8 * " j!() "]"),
        Q!("    inc             " j!()),
        Q!("    test            " a!() ", " a!()),
        Q!("    cmovnz          " i!() ", " j!()),
        Q!("    cmp             " j!() ", " k!()),
        Q!("    jnz             " Label!("loop", 3, Before)),

        Q!(Label!("end", 2) ":"),
        inout("rdi") z.len() => _,
        inout("rsi") z.as_ptr() => _,
        out("rax") ret,
        // clobbers
        out("rcx") _,
        out("rdx") _,
            )
    };
    ret as usize
}
