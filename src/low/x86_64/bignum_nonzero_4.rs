#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::{Label, Q};

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// 256-bit nonzeroness test, returning 1 if x is nonzero, 0 if x is zero
// Input x[4]; output function return
//
//    extern uint64_t bignum_nonzero_4(uint64_t x[static 4]);
//
// Standard x86-64 ABI: RDI = x, returns RAX
// Microsoft x64 ABI:   RCX = x, returns RAX
// ----------------------------------------------------------------------------

macro_rules! x {
    () => {
        Q!("rdi")
    };
}
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
macro_rules! dshort {
    () => {
        Q!("edx")
    };
}

pub fn bignum_nonzero_4(x: &[u64; 4]) -> bool {
    let ret: u64;
    unsafe {
        core::arch::asm!(



        // Generate a = an OR of all the words in the bignum

        Q!("    mov       " a!() ", [" x!() "]"),
        Q!("    mov       " d!() ", [" x!() "+ 8]"),
        Q!("    or        " a!() ", [" x!() "+ 16]"),
        Q!("    or        " d!() ", [" x!() "+ 24]"),
        Q!("    or        " a!() ", " d!()),

        // Set a standard C condition based on whether a is nonzero

        Q!("    mov       " dshort!() ", 1"),
        Q!("    cmovnz    " a!() ", " d!()),

        inout("rdi") x.as_ptr() => _,
        out("rax") ret,
        // clobbers
        out("rdx") _,
            )
    };
    ret > 0
}
