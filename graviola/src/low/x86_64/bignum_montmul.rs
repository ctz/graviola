#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Montgomery multiply, z := (x * y / 2^{64k}) mod m
// Inputs x[k], y[k], m[k]; output z[k]
//
//    extern void bignum_montmul
//     (uint64_t k, uint64_t *z, uint64_t *x, uint64_t *y, uint64_t *m);
//
// Does z := (x * y / 2^{64k}) mod m, assuming x * y <= 2^{64k} * m, which is
// guaranteed in particular if x < m, y < m initially (the "intended" case).
//
// Standard x86-64 ABI: RDI = k, RSI = z, RDX = x, RCX = y, R8 = m
// Microsoft x64 ABI:   RCX = k, RDX = z, R8 = x, R9 = y, [RSP+40] = m
// ----------------------------------------------------------------------------

// We copy x to r9 but it comes in in rdx originally

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
        Q!("r9")
    };
}
macro_rules! y {
    () => {
        Q!("rcx")
    };
}
macro_rules! m {
    () => {
        Q!("r8")
    };
}

// General temp, low part of product and mul input
macro_rules! a {
    () => {
        Q!("rax")
    };
}
// General temp, High part of product
macro_rules! b {
    () => {
        Q!("rdx")
    };
}
// Inner loop counter
macro_rules! j {
    () => {
        Q!("rbx")
    };
}
// Home for i'th digit or Montgomery multiplier
macro_rules! d {
    () => {
        Q!("rbp")
    };
}
macro_rules! h {
    () => {
        Q!("r10")
    };
}
macro_rules! e {
    () => {
        Q!("r11")
    };
}
macro_rules! n {
    () => {
        Q!("r12")
    };
}
macro_rules! i {
    () => {
        Q!("r13")
    };
}
macro_rules! c0 {
    () => {
        Q!("r14")
    };
}
macro_rules! c1 {
    () => {
        Q!("r15")
    };
}

// This one variable we store on the stack as we are a register short.
// At least it's only used once per iteration of the outer loop (k times)
// and with a single read each time, after one initial write. It's the
// word-level negated modular inverse.

macro_rules! w {
    () => {
        Q!("QWORD PTR [rsp]")
    };
}

// Some more intuitive names for temp regs in initial word-level negmodinv.

macro_rules! t1 {
    () => {
        Q!("rbx")
    };
}
macro_rules! t2 {
    () => {
        Q!("rdx")
    };
}

macro_rules! ashort {
    () => {
        Q!("eax")
    };
}
macro_rules! jshort {
    () => {
        Q!("ebx")
    };
}

pub fn bignum_montmul(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64]) {
    debug_assert!(z.len() == x.len());
    debug_assert!(z.len() == y.len());
    debug_assert!(z.len() == m.len());
    unsafe {
        core::arch::asm!(



        // Save registers and allocate space on stack for non-register variable w

        Q!("    push            " "rbx"),
        Q!("    push            " "rbp"),
        Q!("    push            " "r12"),
        Q!("    push            " "r13"),
        Q!("    push            " "r14"),
        Q!("    push            " "r15"),
        Q!("    sub             " "rsp, 8"),

        // If k = 0 the whole operation is trivial

        Q!("    test            " k!() ", " k!()),
        Q!("    jz              " Label!("end", 2, After)),

        // Move x input into its permanent home, since we need rdx for multiplications

        Q!("    mov             " x!() ", rdx"),

        // Compute word-level negated modular inverse w for m == m[0].

        Q!("    mov             " a!() ", [" m!() "]"),

        Q!("    mov             " t2!() ", " a!()),
        Q!("    mov             " t1!() ", " a!()),
        Q!("    shl             " t2!() ", 2"),
        Q!("    sub             " t1!() ", " t2!()),
        Q!("    xor             " t1!() ", 2"),

        Q!("    mov             " t2!() ", " t1!()),
        Q!("    imul            " t2!() ", " a!()),
        Q!("    mov             " ashort!() ", 2"),
        Q!("    add             " a!() ", " t2!()),
        Q!("    add             " t2!() ", 1"),

        Q!("    imul            " t1!() ", " a!()),

        Q!("    imul            " t2!() ", " t2!()),
        Q!("    mov             " ashort!() ", 1"),
        Q!("    add             " a!() ", " t2!()),
        Q!("    imul            " t1!() ", " a!()),

        Q!("    imul            " t2!() ", " t2!()),
        Q!("    mov             " ashort!() ", 1"),
        Q!("    add             " a!() ", " t2!()),
        Q!("    imul            " t1!() ", " a!()),

        Q!("    imul            " t2!() ", " t2!()),
        Q!("    mov             " ashort!() ", 1"),
        Q!("    add             " a!() ", " t2!()),
        Q!("    imul            " t1!() ", " a!()),

        Q!("    mov             " w!() ", " t1!()),

        // Initialize the output c0::z to zero so we can then consistently add rows.
        // It would be a bit more efficient to special-case the zeroth row, but
        // this keeps the code slightly simpler.

        Q!("    xor             " i!() ", " i!()),
        Q!("    xor             " j!() ", " j!()),
        Q!(Label!("zoop", 3) ":"),
        Q!("    mov             " "[" z!() "+ 8 * " j!() "], " i!()),
        Q!("    inc             " j!()),
        Q!("    cmp             " j!() ", " k!()),
        Q!("    jc              " Label!("zoop", 3, Before)),

        Q!("    xor             " c0!() ", " c0!()),

        // Outer loop pulling down digits d=x[i], multiplying by y and reducing

        Q!(Label!("outerloop", 4) ":"),

        // Multiply-add loop where we always have CF + previous high part h to add in.
        // Note that in general we do need yet one more carry in this phase and hence
        // initialize c1 with the top carry.

        Q!("    mov             " d!() ", [" x!() "+ 8 * " i!() "]"),
        Q!("    xor             " j!() ", " j!()),
        Q!("    xor             " h!() ", " h!()),
        Q!("    xor             " c1!() ", " c1!()),
        Q!("    mov             " n!() ", " k!()),

        Q!(Label!("maddloop", 5) ":"),
        Q!("    adc             " h!() ", [" z!() "+ 8 * " j!() "]"),
        Q!("    sbb             " e!() ", " e!()),
        Q!("    mov             " a!() ", [" y!() "+ 8 * " j!() "]"),
        Q!("    mul             " d!()),
        Q!("    sub             " "rdx, " e!()),
        Q!("    add             " a!() ", " h!()),
        Q!("    mov             " "[" z!() "+ 8 * " j!() "], " a!()),
        Q!("    mov             " h!() ", rdx"),
        Q!("    inc             " j!()),
        Q!("    dec             " n!()),
        Q!("    jnz             " Label!("maddloop", 5, Before)),
        Q!("    adc             " c0!() ", " h!()),
        Q!("    adc             " c1!() ", " c1!()),

        // Montgomery reduction loop, similar but offsetting writebacks

        Q!("    mov             " e!() ", [" z!() "]"),
        Q!("    mov             " d!() ", " w!()),
        Q!("    imul            " d!() ", " e!()),
        Q!("    mov             " a!() ", [" m!() "]"),
        Q!("    mul             " d!()),
        Q!("    add             " a!() ", " e!()),
        Q!("    mov             " h!() ", rdx"),
        Q!("    mov             " jshort!() ", 1"),
        Q!("    mov             " n!() ", " k!()),
        Q!("    dec             " n!()),
        Q!("    jz              " Label!("montend", 6, After)),

        Q!(Label!("montloop", 7) ":"),
        Q!("    adc             " h!() ", [" z!() "+ 8 * " j!() "]"),
        Q!("    sbb             " e!() ", " e!()),
        Q!("    mov             " a!() ", [" m!() "+ 8 * " j!() "]"),
        Q!("    mul             " d!()),
        Q!("    sub             " "rdx, " e!()),
        Q!("    add             " a!() ", " h!()),
        Q!("    mov             " "[" z!() "+ 8 * " j!() "-8], " a!()),
        Q!("    mov             " h!() ", rdx"),
        Q!("    inc             " j!()),
        Q!("    dec             " n!()),
        Q!("    jnz             " Label!("montloop", 7, Before)),

        Q!(Label!("montend", 6) ":"),
        Q!("    adc             " h!() ", " c0!()),
        Q!("    adc             " c1!() ", 0"),
        Q!("    mov             " c0!() ", " c1!()),
        Q!("    mov             " "[" z!() "+ 8 * " j!() "-8], " h!()),

        // End of outer loop.

        Q!("    inc             " i!()),
        Q!("    cmp             " i!() ", " k!()),
        Q!("    jc              " Label!("outerloop", 4, Before)),

        // Now do a comparison of (c0::z) with (0::m) to set a final correction mask
        // indicating that (c0::z) >= m and so we need to subtract m.

        Q!("    xor             " j!() ", " j!()),
        Q!("    mov             " n!() ", " k!()),
        Q!(Label!("cmploop", 8) ":"),
        Q!("    mov             " a!() ", [" z!() "+ 8 * " j!() "]"),
        Q!("    sbb             " a!() ", [" m!() "+ 8 * " j!() "]"),
        Q!("    inc             " j!()),
        Q!("    dec             " n!()),
        Q!("    jnz             " Label!("cmploop", 8, Before)),

        Q!("    sbb             " c0!() ", 0"),
        Q!("    sbb             " d!() ", " d!()),
        Q!("    not             " d!()),

        // Now do a masked subtraction of m for the final reduced result.

        Q!("    xor             " e!() ", " e!()),
        Q!("    xor             " j!() ", " j!()),
        Q!(Label!("corrloop", 9) ":"),
        Q!("    mov             " a!() ", [" m!() "+ 8 * " j!() "]"),
        Q!("    and             " a!() ", " d!()),
        Q!("    neg             " e!()),
        Q!("    sbb             " "[" z!() "+ 8 * " j!() "], " a!()),
        Q!("    sbb             " e!() ", " e!()),
        Q!("    inc             " j!()),
        Q!("    cmp             " j!() ", " k!()),
        Q!("    jc              " Label!("corrloop", 9, Before)),

        Q!(Label!("end", 2) ":"),
        Q!("    add             " "rsp, 8"),
        Q!("    pop             " "r15"),
        Q!("    pop             " "r14"),
        Q!("    pop             " "r13"),
        Q!("    pop             " "r12"),
        Q!("    pop             " "rbp"),
        Q!("    pop             " "rbx"),

        inout("rdi") m.len() => _,
        inout("rsi") z.as_mut_ptr() => _,
        inout("rdx") x.as_ptr() => _,
        inout("rcx") y.as_ptr() => _,
        inout("r8") m.as_ptr() => _,
        // clobbers
        out("r10") _,
        out("r11") _,
        out("r12") _,
        out("r13") _,
        out("r14") _,
        out("r15") _,
        out("r9") _,
        out("rax") _,
            )
    };
}
