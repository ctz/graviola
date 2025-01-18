// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Divide by a single (nonzero) word, z := x / m and return x mod m
// Inputs x[n], m; outputs function return (remainder) and z[k]
//
//    extern uint64_t bignum_cdiv
//     (uint64_t k, uint64_t *z, uint64_t n, uint64_t *x, uint64_t m);
//
// Does the "z := x / m" operation where x is n digits, result z is k.
// Truncates the quotient in general, but always (for nonzero m) returns
// the true remainder x mod m.
//
// Standard x86-64 ABI: RDI = k, RSI = z, RDX = n, RCX = x, R8 = m
// Microsoft x64 ABI:   RCX = k, RDX = z, R8 = n, R9 = x, [RSP+40] = m
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
macro_rules! m {
    () => {
        Q!("r8")
    };
}

// These parameters get moved because of special uses for rcx, rdx

macro_rules! n {
    () => {
        Q!("r9")
    };
}
macro_rules! x {
    () => {
        Q!("r10")
    };
}

// This needs to be in rcx for variable shifts with cl

macro_rules! e {
    () => {
        Q!("rcx")
    };
}

// Other variables

macro_rules! w {
    () => {
        Q!("r11")
    };
}
macro_rules! d {
    () => {
        Q!("r12")
    };
}
macro_rules! i {
    () => {
        Q!("rbx")
    };
}
macro_rules! c {
    () => {
        Q!("r13")
    };
}
macro_rules! l {
    () => {
        Q!("r14")
    };
}

macro_rules! a {
    () => {
        Q!("rax")
    };
}
macro_rules! h {
    () => {
        Q!("rdx")
    };
}

macro_rules! ashort {
    () => {
        Q!("eax")
    };
}
macro_rules! ishort {
    () => {
        Q!("ebx")
    };
}
macro_rules! hshort {
    () => {
        Q!("edx")
    };
}

// The remainder

macro_rules! r {
    () => {
        Q!("r15")
    };
}

/// Divide by a single (nonzero) word, z := x / m and return x mod m
///
/// Inputs x[n], m; outputs function return (remainder) and z[k]
///
/// Does the "z := x / m" operation where x is n digits, result z is k.
/// Truncates the quotient in general, but always (for nonzero m) returns
/// the true remainder x mod m.
pub(crate) fn bignum_cdiv(z: &mut [u64], x: &[u64], m: u64) -> u64 {
    let ret: u64;
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(



        Q!("    push            " "rbx"),
        Q!("    push            " "r12"),
        Q!("    push            " "r13"),
        Q!("    push            " "r14"),
        Q!("    push            " "r15"),

        // Move parameters that need a new home

        Q!("    mov             " n!() ", rdx"),
        Q!("    mov             " x!() ", rcx"),

        // First do a modulus computation, slightly tweaked from bignum_cmod,
        // changing variables and avoiding modification of the size parameter.
        // Initialize l = 0 now for convenience (we eventually need to do it).
        // If the bignum is zero-length, l is already the right answer of 0

        Q!("    xor             " l!() ", " l!()),
        Q!("    test            " n!() ", " n!()),
        Q!("    jz              " Label!("nomodulus", 2, After)),

        Q!("    bsr             " e!() ", " m!()),
        Q!("    xor             " e!() ", 63"),
        Q!("    shl             " m!() ", cl"),

        Q!("    mov             " r!() ", " m!()),
        Q!("    mov             " w!() ", 0x1FFFFFFFFFFFF"),
        Q!("    shr             " r!() ", 16"),
        Q!("    xor             " w!() ", " r!()),
        Q!("    inc             " r!()),
        Q!("    shr             " w!() ", 32"),
        Q!("    mov             " h!() ", " r!()),
        Q!("    imul            " h!() ", " w!()),
        Q!("    neg             " h!()),
        Q!("    mov             " a!() ", " h!()),
        Q!("    shr             " a!() ", 49"),
        Q!("    imul            " a!() ", " a!()),
        Q!("    shr             " h!() ", 34"),
        Q!("    add             " h!() ", " a!()),
        Q!("    or              " a!() ", 0x40000000"),
        Q!("    imul            " a!() ", " h!()),
        Q!("    shr             " a!() ", 30"),
        Q!("    imul            " a!() ", " w!()),
        Q!("    shl             " w!() ", 30"),
        Q!("    add             " w!() ", " a!()),
        Q!("    shr             " w!() ", 30"),
        Q!("    mov             " h!() ", " r!()),
        Q!("    imul            " h!() ", " w!()),
        Q!("    neg             " h!()),
        Q!("    shr             " h!() ", 24"),
        Q!("    imul            " h!() ", " w!()),
        Q!("    shl             " w!() ", 16"),
        Q!("    shr             " h!() ", 24"),
        Q!("    add             " w!() ", " h!()),
        Q!("    mov             " h!() ", " r!()),
        Q!("    imul            " h!() ", " w!()),
        Q!("    neg             " h!()),
        Q!("    shr             " h!() ", 32"),
        Q!("    imul            " h!() ", " w!()),
        Q!("    shl             " w!() ", 31"),
        Q!("    shr             " h!() ", 17"),
        Q!("    add             " w!() ", " h!()),
        Q!("    mov             " a!() ", " m!()),
        Q!("    mul             " w!()),
        Q!("    shrd            " a!() ", " h!() ", 60"),
        Q!("    mov             " h!() ", " w!()),
        Q!("    shr             " h!() ", 33"),
        Q!("    not             " a!()),
        Q!("    imul            " a!() ", " h!()),
        Q!("    shl             " w!() ", 1"),
        Q!("    shr             " a!() ", 33"),
        Q!("    add             " w!() ", " a!()),
        Q!("    add             " w!() ", 1"),
        Q!("    mov             " a!() ", " m!()),
        Q!("    sbb             " w!() ", 0"),
        Q!("    mul             " w!()),
        Q!("    add             " h!() ", " m!()),
        Q!("    sbb             " w!() ", 0"),

        Q!("    mov             " r!() ", " m!()),
        Q!("    imul            " r!() ", " w!()),
        Q!("    neg             " r!()),

        Q!("    xor             " hshort!() ", " hshort!()),
        Q!("    mov             " i!() ", " n!()),
        Q!(Label!("modloop", 3) ":"),
        Q!("    mov             " a!() ", " h!()),
        Q!("    mul             " r!()),
        Q!("    add             " a!() ", [" x!() "+ 8 * " i!() "-8]"),
        Q!("    adc             " h!() ", " l!()),
        Q!("    mov             " l!() ", " a!()),
        Q!("    sbb             " a!() ", " a!()),
        Q!("    and             " a!() ", " r!()),
        Q!("    add             " l!() ", " a!()),
        Q!("    adc             " h!() ", 0"),
        Q!("    dec             " i!()),
        Q!("    jnz             " Label!("modloop", 3, Before)),

        Q!("    mov             " i!() ", " h!()),
        Q!("    mov             " a!() ", " w!()),
        Q!("    mul             " h!()),
        Q!("    add             " h!() ", " i!()),
        Q!("    sbb             " r!() ", " r!()),
        Q!("    and             " r!() ", " m!()),

        Q!("    mov             " a!() ", " h!()),
        Q!("    mul             " m!()),
        Q!("    add             " h!() ", " r!()),
        Q!("    xor             " r!() ", " r!()),
        Q!("    sub             " l!() ", " a!()),
        Q!("    sbb             " i!() ", " h!()),

        Q!("    cmovnz          " r!() ", " m!()),
        Q!("    xor             " ashort!() ", " ashort!()),
        Q!("    sub             " l!() ", " r!()),
        Q!("    sbb             " i!() ", " a!()),

        Q!("    cmovnz          " a!() ", " m!()),
        Q!("    sub             " l!() ", " a!()),

        Q!("    mov             " a!() ", " w!()),
        Q!("    mul             " l!()),
        Q!("    add             " h!() ", " l!()),
        Q!("    rcr             " h!() ", 1"),

        Q!("    shr             " m!() ", cl"),
        Q!("    xor             " e!() ", 63"),
        Q!("    shr             " h!() ", cl"),

        Q!("    imul            " h!() ", " m!()),
        Q!("    sub             " l!() ", " h!()),

        Q!("    mov             " r!() ", " l!()),
        Q!("    sub             " l!() ", " m!()),
        Q!(Label!("nomodulus", 2) ":"),
        Q!("    cmovnc          " r!() ", " l!()),

        // If k = 0 then there's no more to be done

        Q!("    test            " k!() ", " k!()),
        Q!("    jz              " Label!("end", 4, After)),

        // Let e be the number of trailing zeros in m (we can ignore m = 0)

        Q!("    bsf             " e!() ", " m!()),

        // Now just shift m right by e bits. So hereafter we can assume m is odd
        // but we first need to shift the input right by e bits then divide by m.

        Q!("    shr             " m!() ", cl"),

        // Compute the negated modular inverse w with w * m + 1 == 0 (mod 2^64)
        // This is essentially the same as word_negmodinv.

        Q!("    mov             " a!() ", " m!()),
        Q!("    mov             " w!() ", " m!()),
        Q!("    shl             " a!() ", 2"),
        Q!("    sub             " w!() ", " a!()),
        Q!("    xor             " w!() ", 2"),
        Q!("    mov             " a!() ", " w!()),
        Q!("    imul            " a!() ", " m!()),
        Q!("    mov             " hshort!() ", 2"),
        Q!("    add             " h!() ", " a!()),
        Q!("    add             " a!() ", 1"),
        Q!("    imul            " w!() ", " h!()),
        Q!("    imul            " a!() ", " a!()),
        Q!("    mov             " hshort!() ", 1"),
        Q!("    add             " h!() ", " a!()),
        Q!("    imul            " w!() ", " h!()),
        Q!("    imul            " a!() ", " a!()),
        Q!("    mov             " hshort!() ", 1"),
        Q!("    add             " h!() ", " a!()),
        Q!("    imul            " w!() ", " h!()),
        Q!("    imul            " a!() ", " a!()),
        Q!("    mov             " hshort!() ", 1"),
        Q!("    add             " h!() ", " a!()),
        Q!("    imul            " w!() ", " h!()),

        // We have the remainder r, so now x = m * y + r for some quotient y
        // to be computed. Consider x' = x + (m - r) = m * (y + 1) and do a
        // Montgomery reduction, keeping the cofactor z. This gives us
        // x' + m * z = 2^{64k} * c where c <= m. Thus since x' = m * (y + 1)
        // we have
        //
        //     m * (y + z + 1) = 2^{64k} * c
        //
        // This means m * (y + z + 1) == 0 (mod 2^{64k}), even when we truncate
        // x to k digits (if in fact k < n). Since m is odd, it's coprime to
        // 2^{64k} so we can cancel and get y + z + 1 == 0 (mod 2^{64k}), and
        // hence using logical complement y == ~z (mod 2^{64k}). Thus we can
        // write back the logical complements of the cofactor as the answer.
        // Start with carry word c = m - r/2^e to make the initial tweak
        // x' = x + (m - r); since we've shifted everything initially by e
        // we need to shift the remainder too before subtracting from the
        // shifted m.

        Q!("    mov             " d!() ", " r!()),
        Q!("    shr             " d!() ", cl"),
        Q!("    mov             " c!() ", " m!()),
        Q!("    sub             " c!() ", " d!()),
        Q!("    xor             " ishort!() ", " ishort!()),

        // Unless n = 0, preload the zeroth digit and bump up the x pointer by
        // 8 and n down by 1, to ease indexing and comparison using the same
        // variable i in the main loop. When n = 0 we leave it alone, as the
        // comparison i < n will always fail and the x pointer is unused.

        Q!("    xor             " d!() ", " d!()),
        Q!("    test            " n!() ", " n!()),
        Q!("    jz              " Label!("loop", 5, After)),
        Q!("    mov             " d!() ", [" x!() "]"),
        Q!("    add             " x!() ", 8"),
        Q!("    dec             " n!()),

        Q!(Label!("loop", 5) ":"),

        // Load the next digit up to get [l,d] then shift right e places

        Q!("    xor             " l!() ", " l!()),
        Q!("    cmp             " i!() ", " n!()),
        Q!("    jnc             " Label!("noload", 6, After)),
        Q!("    mov             " l!() ", [" x!() "+ 8 * " i!() "]"),
        Q!(Label!("noload", 6) ":"),
        Q!("    shrd            " d!() ", " l!() ", cl"),
        Q!("    add             " d!() ", " c!()),
        Q!("    sbb             " c!() ", " c!()),
        Q!("    neg             " c!()),

        // Now the effective sum is [c,a] where the carry-in has been absorbed.
        // Do the main Montgomery step with the (odd) m, writing back ~q. Finally
        // set d to the next digit ready for the following iteration.

        Q!("    mov             " a!() ", " w!()),
        Q!("    imul            " a!() ", " d!()),
        Q!("    not             " a!()),
        Q!("    mov             " "[" z!() "+ 8 * " i!() "], " a!()),
        Q!("    not             " a!()),

        Q!("    mul             " m!()),
        Q!("    add             " a!() ", " d!()),
        Q!("    adc             " c!() ", " h!()),

        Q!("    mov             " d!() ", " l!()),

        Q!("    inc             " i!()),
        Q!("    cmp             " i!() ", " k!()),
        Q!("    jc              " Label!("loop", 5, Before)),

        // Return the modulus

        Q!(Label!("end", 4) ":"),
        Q!("    mov             " "rax, " r!()),

        Q!("    pop             " "r15"),
        Q!("    pop             " "r14"),
        Q!("    pop             " "r13"),
        Q!("    pop             " "r12"),
        Q!("    pop             " "rbx"),
        inout("rdi") z.len() => _,
        inout("rsi") z.as_ptr() => _,
        inout("rdx") x.len() => _,
        inout("rcx") x.as_ptr() => _,
        inout("r8") m => _,
        out("rax") ret,
        // clobbers
        out("r10") _,
        out("r11") _,
        out("r12") _,
        out("r13") _,
        out("r14") _,
        out("r15") _,
        out("r9") _,
            )
    };
    ret
}
