#![allow(non_upper_case_globals, unused_macros)]
use crate::low::macros::{Label, Q};

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// 256-bit multiplex/select z := x (if p nonzero) or z := y (if p zero)
// Inputs p, x[4], y[4]; output z[4]
//
//    extern void bignum_mux_4
//     (uint64_t p, uint64_t z[static 4],
//      uint64_t x[static 4], uint64_t y[static 4]);
//
// It is assumed that all numbers x, y and z have the same size 4 digits.
//
// Standard x86-64 ABI: RDI = p, RSI = z, RDX = x, RCX = y
// Microsoft x64 ABI:   RCX = p, RDX = z, R8 = x, R9 = y
// ----------------------------------------------------------------------------

macro_rules! p {
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
macro_rules! y {
    () => {
        Q!("rcx")
    };
}
macro_rules! a {
    () => {
        Q!("rax")
    };
}
macro_rules! b {
    () => {
        Q!("r8")
    };
}

pub fn bignum_mux_4(p: u64, z: &mut [u64; 4], x_if_p: &[u64; 4], y_if_not_p: &[u64; 4]) {
    unsafe {
        core::arch::asm!(


        Q!("    test      " p!() ", " p!()),

        Q!("    mov       " a!() ", [" x!() "]"),
        Q!("    mov       " b!() ", [" y!() "]"),
        Q!("    cmovz     " a!() ", " b!()),
        Q!("    mov       " "[" z!() "], " a!()),

        Q!("    mov       " a!() ", [" x!() "+ 8]"),
        Q!("    mov       " b!() ", [" y!() "+ 8]"),
        Q!("    cmovz     " a!() ", " b!()),
        Q!("    mov       " "[" z!() "+ 8], " a!()),

        Q!("    mov       " a!() ", [" x!() "+ 16]"),
        Q!("    mov       " b!() ", [" y!() "+ 16]"),
        Q!("    cmovz     " a!() ", " b!()),
        Q!("    mov       " "[" z!() "+ 16], " a!()),

        Q!("    mov       " a!() ", [" x!() "+ 24]"),
        Q!("    mov       " b!() ", [" y!() "+ 24]"),
        Q!("    cmovz     " a!() ", " b!()),
        Q!("    mov       " "[" z!() "+ 24], " a!()),

        inout("rdi") p => _,
        inout("rsi") z.as_mut_ptr() => _,
        inout("rdx") x_if_p.as_ptr() => _,
        inout("rcx") y_if_not_p.as_ptr() => _,
        // clobbers
        out("r8") _,
        out("rax") _,
            )
    };
}
