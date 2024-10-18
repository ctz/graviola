#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Multiplex/select z := x (if p nonzero) or z := y (if p zero)
// Inputs p, x[k], y[k]; output z[k]
//
//    extern void bignum_mux
//     (uint64_t p, uint64_t k, uint64_t *z, uint64_t *x, uint64_t *y);
//
// It is assumed that all numbers x, y and z have the same size k digits.
//
// Standard x86-64 ABI: RDI = p, RSI = k, RDX = z, RCX = x, R8 = y
// Microsoft x64 ABI:   RCX = p, RDX = k, R8 = z, R9 = x, [RSP+40] = y
// ----------------------------------------------------------------------------

macro_rules! b {
    () => {
        Q!("rdi")
    };
}
macro_rules! k {
    () => {
        Q!("rsi")
    };
}
macro_rules! z {
    () => {
        Q!("rdx")
    };
}
macro_rules! x {
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
macro_rules! a {
    () => {
        Q!("rax")
    };
}

pub(crate) fn bignum_mux(p: u64, z: &mut [u64], x_if_p: &[u64], y_if_not_p: &[u64]) {
    debug_assert!(z.len() == x_if_p.len());
    debug_assert!(z.len() == y_if_not_p.len());
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(


        Q!("    test            " k!() ", " k!()),
        Q!("    jz              " Label!("end", 2, After)),

        Q!("    xor             " i!() ", " i!()),
        Q!("    neg             " b!()),
        Q!(Label!("loop", 3) ":"),
        Q!("    mov             " a!() ", [" x!() "+ 8 * " i!() "]"),
        Q!("    mov             " b!() ", [" y!() "+ 8 * " i!() "]"),
        Q!("    cmovnc          " a!() ", " b!()),
        Q!("    mov             " "[" z!() "+ 8 * " i!() "], " a!()),
        Q!("    inc             " i!()),
        Q!("    dec             " k!()),
        Q!("    jnz             " Label!("loop", 3, Before)),
        Q!(Label!("end", 2) ":"),
        inout("rdi") p => _,
        inout("rsi") z.len() => _,
        inout("rdx") z.as_mut_ptr() => _,
        inout("rcx") x_if_p.as_ptr() => _,
        inout("r8") y_if_not_p.as_ptr() => _,
        // clobbers
        out("r9") _,
        out("rax") _,
            )
    };
}
