#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Given table: uint64_t[height*16], copy table[idx*16...(idx+1)*16-1]
// into z[0..row-1].
// This function is constant-time with respect to the value of `idx`. This is
// achieved by reading the whole table and using the bit-masking to get the
// `idx`-th row.
//
//    extern void bignum_copy_from_table_16_neon
//     (uint64_t *z, uint64_t *table, uint64_t height, uint64_t idx);
//
// Initial version written by Hanno Becker
// Standard ARM ABI: X0 = z, X1 = table, X2 = height, X3 = idx
// ----------------------------------------------------------------------------

// *****************************************************
// Main code
// *****************************************************

macro_rules! z {
    () => {
        Q!("x0")
    };
}
macro_rules! tbl {
    () => {
        Q!("x1")
    };
}
macro_rules! height {
    () => {
        Q!("x2")
    };
}
macro_rules! idx {
    () => {
        Q!("x3")
    };
}

macro_rules! mask {
    () => {
        Q!("x5")
    };
}
macro_rules! cnt {
    () => {
        Q!("x6")
    };
}

macro_rules! ventry0 {
    () => {
        Q!("v20")
    };
}
macro_rules! qentry0 {
    () => {
        Q!("q20")
    };
}
macro_rules! ventry1 {
    () => {
        Q!("v21")
    };
}
macro_rules! qentry1 {
    () => {
        Q!("q21")
    };
}
macro_rules! ventry2 {
    () => {
        Q!("v22")
    };
}
macro_rules! qentry2 {
    () => {
        Q!("q22")
    };
}
macro_rules! ventry3 {
    () => {
        Q!("v23")
    };
}
macro_rules! qentry3 {
    () => {
        Q!("q23")
    };
}
macro_rules! ventry4 {
    () => {
        Q!("v24")
    };
}
macro_rules! qentry4 {
    () => {
        Q!("q24")
    };
}
macro_rules! ventry5 {
    () => {
        Q!("v25")
    };
}
macro_rules! qentry5 {
    () => {
        Q!("q25")
    };
}
macro_rules! ventry6 {
    () => {
        Q!("v26")
    };
}
macro_rules! qentry6 {
    () => {
        Q!("q26")
    };
}
macro_rules! ventry7 {
    () => {
        Q!("v27")
    };
}
macro_rules! qentry7 {
    () => {
        Q!("q27")
    };
}
macro_rules! ventry8 {
    () => {
        Q!("v28")
    };
}

macro_rules! vtmp {
    () => {
        Q!("v16")
    };
}
macro_rules! qtmp {
    () => {
        Q!("q16")
    };
}

macro_rules! vmask {
    () => {
        Q!("v17")
    };
}

pub fn bignum_copy_row_from_table_16_neon(z: &mut [u64], table: &[u64], height: u64, index: u64) {
    debug_assert!(z.len() == 16);
    debug_assert!(index < height);
    unsafe {
        core::arch::asm!(


        // Clear accumulator
        // Zeroing can be done via xor, but xor isn't formalized yet.
        Q!("    dup             " ventry0!() ".2d, xzr"),
        Q!("    mov             " ventry1!() ".16b, " ventry0!() ".16b"),
        Q!("    mov             " ventry2!() ".16b, " ventry0!() ".16b"),
        Q!("    mov             " ventry3!() ".16b, " ventry0!() ".16b"),
        Q!("    mov             " ventry4!() ".16b, " ventry0!() ".16b"),
        Q!("    mov             " ventry5!() ".16b, " ventry0!() ".16b"),
        Q!("    mov             " ventry6!() ".16b, " ventry0!() ".16b"),
        Q!("    mov             " ventry7!() ".16b, " ventry0!() ".16b"),

        Q!("    mov             " cnt!() ", #0"),
        Q!(Label!("bignum_copy_row_from_table_16_neon_loop", 2) ":"),

        // Compute mask: Check if current index matches target index
        Q!("    subs            " "xzr, " cnt!() ", " idx!()),
        Q!("    cinv            " mask!() ", xzr, eq"),
        Q!("    dup             " vmask!() ".2d, " mask!()),

        Q!("    ldr             " qtmp!() ", [" tbl!() ", #16 * 0]"),
        Q!("    bit             " ventry0!() ".16b, " vtmp!() ".16b, " vmask!() ".16b"),

        Q!("    ldr             " qtmp!() ", [" tbl!() ", #16 * 1]"),
        Q!("    bit             " ventry1!() ".16b, " vtmp!() ".16b, " vmask!() ".16b"),

        Q!("    ldr             " qtmp!() ", [" tbl!() ", #16 * 2]"),
        Q!("    bit             " ventry2!() ".16b, " vtmp!() ".16b, " vmask!() ".16b"),

        Q!("    ldr             " qtmp!() ", [" tbl!() ", #16 * 3]"),
        Q!("    bit             " ventry3!() ".16b, " vtmp!() ".16b, " vmask!() ".16b"),

        Q!("    ldr             " qtmp!() ", [" tbl!() ", #16 * 4]"),
        Q!("    bit             " ventry4!() ".16b, " vtmp!() ".16b, " vmask!() ".16b"),

        Q!("    ldr             " qtmp!() ", [" tbl!() ", #16 * 5]"),
        Q!("    bit             " ventry5!() ".16b, " vtmp!() ".16b, " vmask!() ".16b"),

        Q!("    ldr             " qtmp!() ", [" tbl!() ", #16 * 6]"),
        Q!("    bit             " ventry6!() ".16b, " vtmp!() ".16b, " vmask!() ".16b"),

        Q!("    ldr             " qtmp!() ", [" tbl!() ", #16 * 7]"),
        Q!("    bit             " ventry7!() ".16b, " vtmp!() ".16b, " vmask!() ".16b"),

        Q!("    add             " tbl!() ", " tbl!() ", #16 * 8"),

        Q!("    add             " cnt!() ", " cnt!() ", #1"),
        Q!("    subs            " "xzr, " height!() ", " cnt!()),
        Q!("    b.ne            " Label!("bignum_copy_row_from_table_16_neon_loop", 2, Before)),

        Q!(Label!("bignum_copy_row_from_table_16_neon_end", 3) ":"),

        Q!("    str             " qentry0!() ", [" z!() ", #16 * 0]"),
        Q!("    str             " qentry1!() ", [" z!() ", #16 * 1]"),
        Q!("    str             " qentry2!() ", [" z!() ", #16 * 2]"),
        Q!("    str             " qentry3!() ", [" z!() ", #16 * 3]"),
        Q!("    str             " qentry4!() ", [" z!() ", #16 * 4]"),
        Q!("    str             " qentry5!() ", [" z!() ", #16 * 5]"),
        Q!("    str             " qentry6!() ", [" z!() ", #16 * 6]"),
        Q!("    str             " qentry7!() ", [" z!() ", #16 * 7]"),

        inout("x0") z.as_mut_ptr() => _,
        inout("x1") table.as_ptr() => _,
        inout("x2") height => _,
        inout("x3") index => _,
        // clobbers
        out("v16") _,
        out("v17") _,
        out("v20") _,
        out("v21") _,
        out("v22") _,
        out("v23") _,
        out("v24") _,
        out("v25") _,
        out("v26") _,
        out("v27") _,
        out("x5") _,
        out("x6") _,
            )
    };
}
