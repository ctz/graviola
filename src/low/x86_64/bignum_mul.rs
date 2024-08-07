#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::{Label, Q};

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Multiply z := x * y
// Inputs x[m], y[n]; output z[k]
//
//    extern void bignum_mul
//     (uint64_t k, uint64_t *z,
//      uint64_t m, uint64_t *x, uint64_t n, uint64_t *y);
//
// Does the "z := x * y" operation where x is m digits, y is n, result z is k.
// Truncates the result in general unless k >= m + n
//
// Standard x86-64 ABI: RDI = k, RSI = z, RDX = m, RCX = x, R8 = n, R9 = y
// Microsoft x64 ABI:   RCX = k, RDX = z, R8 = m, R9 = x, [RSP+40] = n, [RSP+48] = y
// ----------------------------------------------------------------------------

// These are actually right

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
macro_rules! n {
    () => {
        Q!("r8")
    };
}

// These are not

macro_rules! c {
    () => {
        Q!("r15")
    };
}
macro_rules! h {
    () => {
        Q!("r14")
    };
}
macro_rules! l {
    () => {
        Q!("r13")
    };
}
macro_rules! x {
    () => {
        Q!("r12")
    };
}
macro_rules! y {
    () => {
        Q!("r11")
    };
}
macro_rules! i {
    () => {
        Q!("rbx")
    };
}
macro_rules! k {
    () => {
        Q!("r10")
    };
}
macro_rules! m {
    () => {
        Q!("rbp")
    };
}

// These are always local scratch since multiplier result is in these

macro_rules! a {
    () => {
        Q!("rax")
    };
}
macro_rules! d {
    () => {
        Q!("rdx")
    };
}

pub fn bignum_mul(z: &mut [u64], x: &[u64], y: &[u64]) {
    debug_assert!(z.len() >= x.len() + y.len());
    unsafe {
        core::arch::asm!(



        // We use too many registers, and also we need rax:rdx for multiplications

        Q!("    push            " "rbx"),
        Q!("    push            " "rbp"),
        Q!("    push            " "r12"),
        Q!("    push            " "r13"),
        Q!("    push            " "r14"),
        Q!("    push            " "r15"),
        Q!("    mov             " m!() ", rdx"),

        // If the result size is zero, do nothing
        // Note that even if either or both inputs has size zero, we can't
        // just give up because we at least need to zero the output array
        // If we did a multiply-add variant, however, then we could

        Q!("    test            " p!() ", " p!()),
        Q!("    jz              " Label!("end", 2, After)),

        // Set initial 2-part sum to zero (we zero c inside the body)

        Q!("    xor             " h!() ", " h!()),
        Q!("    xor             " l!() ", " l!()),

        // Otherwise do outer loop k = 0 ... k = p - 1

        Q!("    xor             " k!() ", " k!()),

        Q!(Label!("outerloop", 3) ":"),

        // Zero our carry term first; we eventually want it and a zero is useful now
        // Set a =  max 0 (k + 1 - n), i = min (k + 1) m
        // This defines the range a <= j < i for the inner summation
        // Note that since k < p < 2^64 we can assume k + 1 doesn't overflow
        // And since we want to increment it anyway, we might as well do it now

        Q!("    xor             " c!() ", " c!()),
        Q!("    inc             " k!()),

        Q!("    mov             " a!() ", " k!()),
        Q!("    sub             " a!() ", " n!()),
        Q!("    cmovc           " a!() ", " c!()),

        Q!("    mov             " i!() ", " m!()),
        Q!("    cmp             " k!() ", " m!()),
        Q!("    cmovc           " i!() ", " k!()),

        // Turn i into a loop count, and skip things if it's <= 0
        // Otherwise set up initial pointers x -> x0[a] and y -> y0[k - a]
        // and then launch into the main inner loop, postdecrementing i

        Q!("    mov             " d!() ", " k!()),
        Q!("    sub             " d!() ", " i!()),
        Q!("    sub             " i!() ", " a!()),
        Q!("    jbe             " Label!("innerend", 4, After)),
        Q!("    lea             " x!() ", [rcx + 8 * " a!() "]"),
        Q!("    lea             " y!() ", [r9 + 8 * " d!() "-8]"),

        Q!(Label!("innerloop", 5) ":"),
        Q!("    mov             " "rax, [" y!() "+ 8 * " i!() "]"),
        Q!("    mul             " "QWORD PTR [" x!() "]"),
        Q!("    add             " x!() ", 8"),
        Q!("    add             " l!() ", rax"),
        Q!("    adc             " h!() ", rdx"),
        Q!("    adc             " c!() ", 0"),
        Q!("    dec             " i!()),
        Q!("    jnz             " Label!("innerloop", 5, Before)),

        Q!(Label!("innerend", 4) ":"),

        Q!("    mov             " "[" z!() "], " l!()),
        Q!("    mov             " l!() ", " h!()),
        Q!("    mov             " h!() ", " c!()),
        Q!("    add             " z!() ", 8"),

        Q!("    cmp             " k!() ", " p!()),
        Q!("    jc              " Label!("outerloop", 3, Before)),

        Q!(Label!("end", 2) ":"),
        Q!("    pop             " "r15"),
        Q!("    pop             " "r14"),
        Q!("    pop             " "r13"),
        Q!("    pop             " "r12"),
        Q!("    pop             " "rbp"),
        Q!("    pop             " "rbx"),
        inout("rdi") z.len() => _,
        inout("rsi") z.as_mut_ptr() => _,
        inout("rdx") x.len() => _,
        inout("rcx") x.as_ptr() => _,
        inout("r8") y.len() => _,
        inout("r9") y.as_ptr() => _,
        // clobbers
        out("r10") _,
        out("r11") _,
        out("r12") _,
        out("r13") _,
        out("r14") _,
        out("r15") _,
        out("rax") _,
            )
    };
}
