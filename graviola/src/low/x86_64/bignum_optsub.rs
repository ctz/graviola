#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Optionally subtract, z := x - y (if p nonzero) or z := x (if p zero)
// Inputs x[k], p, y[k]; outputs function return (carry-out) and z[k]
//
//    extern uint64_t bignum_optsub
//     (uint64_t k, uint64_t *z, uint64_t *x, uint64_t p, uint64_t *y);
//
// It is assumed that all numbers x, y and z have the same size k digits.
// Returns carry-out as per usual subtraction, always 0 if p was zero.
//
// Standard x86-64 ABI: RDI = k, RSI = z, RDX = x, RCX = p, R8 = y, returns RAX
// Microsoft x64 ABI:   RCX = k, RDX = z, R8 = x, R9 = p, [RSP+40] = y, returns RAX
// ----------------------------------------------------------------------------

macro_rules! k {
    () => {
        Q!("rdi")
    };
}
macro_rules! z {
    () => {
        Q!("rsi")
    };
}
macro_rules! x {
    () => {
        Q!("rdx")
    };
}
macro_rules! p {
    () => {
        Q!("rcx")
    };
}
macro_rules! y {
    () => {
        Q!("r8")
    };
}

macro_rules! i {
    () => {
        Q!("r9")
    };
}
macro_rules! b {
    () => {
        Q!("r10")
    };
}
macro_rules! c {
    () => {
        Q!("rax")
    };
}
macro_rules! a {
    () => {
        Q!("r11")
    };
}

pub fn bignum_optsub(z: &mut [u64], x: &[u64], y: &[u64], p: u64) {
    unsafe {
        core::arch::asm!(



        // Initialize top carry to zero in all cases (also return value)

        Q!("    xor             " c!() ", " c!()),

        // If k = 0 do nothing

        Q!("    test            " k!() ", " k!()),
        Q!("    jz              " Label!("end", 2, After)),

        // Convert the nonzero/zero status of p into an all-1s or all-0s mask

        Q!("    neg             " p!()),
        Q!("    sbb             " p!() ", " p!()),

        // Now go round the loop for i=0...k-1, saving the carry in c each iteration

        Q!("    xor             " i!() ", " i!()),
        Q!(Label!("loop", 3) ":"),
        Q!("    mov             " a!() ", [" x!() "+ 8 * " i!() "]"),
        Q!("    mov             " b!() ", [" y!() "+ 8 * " i!() "]"),
        Q!("    and             " b!() ", " p!()),
        Q!("    neg             " c!()),
        Q!("    sbb             " a!() ", " b!()),
        Q!("    sbb             " c!() ", " c!()),
        Q!("    mov             " "[" z!() "+ 8 * " i!() "], " a!()),
        Q!("    inc             " i!()),
        Q!("    cmp             " i!() ", " k!()),
        Q!("    jc              " Label!("loop", 3, Before)),

        // Return top carry

        Q!("    neg             " "rax"),

        Q!(Label!("end", 2) ":"),
        inout("rdi") z.len() => _,
        inout("rsi") z.as_mut_ptr() => _,
        inout("rdx") x.as_ptr() => _,
        inout("rcx") p => _,
        inout("r8") y.as_ptr() => _,
        // clobbers
        out("r10") _,
        out("r11") _,
        out("r9") _,
        out("rax") _,
            )
    };
}
