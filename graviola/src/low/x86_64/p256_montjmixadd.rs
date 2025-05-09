// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Point mixed addition on NIST curve P-256 in Montgomery-Jacobian coordinates
//
//    extern void p256_montjmixadd(uint64_t p3[static 12],
//                                 const uint64_t p1[static 12],
//                                 const uint64_t p2[static 8]);
//
// Does p3 := p1 + p2 where all points are regarded as Jacobian triples with
// each coordinate in the Montgomery domain, i.e. x' = (2^256 * x) mod p_256.
// A Jacobian triple (x',y',z') represents affine point (x/z^2,y/z^3).
// The "mixed" part means that p2 only has x and y coordinates, with the
// implicit z coordinate assumed to be the identity.
//
// Standard x86-64 ABI: RDI = p3, RSI = p1, RDX = p2
// Microsoft x64 ABI:   RCX = p3, RDX = p1, R8 = p2
// ----------------------------------------------------------------------------

// Size of individual field elements

macro_rules! NUMSIZE {
    () => {
        "32"
    };
}

// Pointer-offset pairs for inputs and outputs.
// These assume rdi = p3, rsi = p1 and rbp = p2,
// which needs to be set up explicitly before use.
// The first two hold initially, and the second is
// set up by copying the initial rdx input to rbp.
// Thereafter, no code macro modifies any of them.

macro_rules! x_1 {
    () => {
        "rsi + 0"
    };
}
macro_rules! y_1 { () => { Q!("rsi + " NUMSIZE!()) } }
macro_rules! z_1 { () => { Q!("rsi + (2 * " NUMSIZE!() ")") } }

macro_rules! x_2 {
    () => {
        "rbp + 0"
    };
}
macro_rules! y_2 { () => { Q!("rbp + " NUMSIZE!()) } }

macro_rules! x_3 {
    () => {
        "rdi + 0"
    };
}
macro_rules! y_3 { () => { Q!("rdi + " NUMSIZE!()) } }
macro_rules! z_3 { () => { Q!("rdi + (2 * " NUMSIZE!() ")") } }

// Pointer-offset pairs for temporaries, with some aliasing.
// NSPACE is the total stack needed for all temporaries.

macro_rules! zp2 { () => { Q!("rsp + (" NUMSIZE!() "* 0)") } }
macro_rules! ww { () => { Q!("rsp + (" NUMSIZE!() "* 0)") } }
macro_rules! resx { () => { Q!("rsp + (" NUMSIZE!() "* 0)") } }

macro_rules! yd { () => { Q!("rsp + (" NUMSIZE!() "* 1)") } }
macro_rules! y2a { () => { Q!("rsp + (" NUMSIZE!() "* 1)") } }

macro_rules! x2a { () => { Q!("rsp + (" NUMSIZE!() "* 2)") } }
macro_rules! zzx2 { () => { Q!("rsp + (" NUMSIZE!() "* 2)") } }

macro_rules! zz { () => { Q!("rsp + (" NUMSIZE!() "* 3)") } }
macro_rules! t1 { () => { Q!("rsp + (" NUMSIZE!() "* 3)") } }

macro_rules! t2 { () => { Q!("rsp + (" NUMSIZE!() "* 4)") } }
macro_rules! zzx1 { () => { Q!("rsp + (" NUMSIZE!() "* 4)") } }
macro_rules! resy { () => { Q!("rsp + (" NUMSIZE!() "* 4)") } }

macro_rules! xd { () => { Q!("rsp + (" NUMSIZE!() "* 5)") } }
macro_rules! resz { () => { Q!("rsp + (" NUMSIZE!() "* 5)") } }

macro_rules! NSPACE { () => { Q!("(" NUMSIZE!() "* 6)") } }

// Corresponds exactly to bignum_montmul_p256

macro_rules! montmul_p256 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "xor r13d, r13d;\n"
        "mov rdx, [" $P2 "];\n"
        "mulx r9, r8, [" $P1 "];\n"
        "mulx r10, rbx, [" $P1 "+ 0x8];\n"
        "adc r9, rbx;\n"
        "mulx r11, rbx, [" $P1 "+ 0x10];\n"
        "adc r10, rbx;\n"
        "mulx r12, rbx, [" $P1 "+ 0x18];\n"
        "adc r11, rbx;\n"
        "adc r12, r13;\n"
        "mov rdx, [" $P2 "+ 0x8];\n"
        "xor r14d, r14d;\n"
        "mulx rbx, rax, [" $P1 "];\n"
        "adcx r9, rax;\n"
        "adox r10, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x8];\n"
        "adcx r10, rax;\n"
        "adox r11, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x10];\n"
        "adcx r11, rax;\n"
        "adox r12, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x18];\n"
        "adcx r12, rax;\n"
        "adox r13, rbx;\n"
        "adc r13, r14;\n"
        "xor r15d, r15d;\n"
        "movabs rdx, 0x100000000;\n"
        "mulx rbx, rax, r8;\n"
        "adcx r9, rax;\n"
        "adox r10, rbx;\n"
        "mulx rbx, rax, r9;\n"
        "adcx r10, rax;\n"
        "adox r11, rbx;\n"
        "not rdx;\n"
        "lea rdx, [rdx + 0x2];\n"
        "mulx rbx, rax, r8;\n"
        "adcx r11, rax;\n"
        "adox r12, rbx;\n"
        "mulx rbx, rax, r9;\n"
        "adcx r12, rax;\n"
        "adox r13, rbx;\n"
        "adcx r13, r15;\n"
        "adox r14, r15;\n"
        "adc r14, r15;\n"
        "mov rdx, [" $P2 "+ 0x10];\n"
        "xor r8d, r8d;\n"
        "mulx rbx, rax, [" $P1 "];\n"
        "adcx r10, rax;\n"
        "adox r11, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x8];\n"
        "adcx r11, rax;\n"
        "adox r12, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x10];\n"
        "adcx r12, rax;\n"
        "adox r13, rbx;\n"
        "adox r14, r8;\n"
        "mulx rbx, rax, [" $P1 "+ 0x18];\n"
        "adc r13, rax;\n"
        "adc r14, rbx;\n"
        "adc r15, r8;\n"
        "mov rdx, [" $P2 "+ 0x18];\n"
        "xor r9d, r9d;\n"
        "mulx rbx, rax, [" $P1 "];\n"
        "adcx r11, rax;\n"
        "adox r12, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x8];\n"
        "adcx r12, rax;\n"
        "adox r13, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x10];\n"
        "adcx r13, rax;\n"
        "adox r14, rbx;\n"
        "adox r15, r9;\n"
        "mulx rbx, rax, [" $P1 "+ 0x18];\n"
        "adc r14, rax;\n"
        "adc r15, rbx;\n"
        "adc r8, r9;\n"
        "xor r9d, r9d;\n"
        "movabs rdx, 0x100000000;\n"
        "mulx rbx, rax, r10;\n"
        "adcx r11, rax;\n"
        "adox r12, rbx;\n"
        "mulx rbx, rax, r11;\n"
        "adcx r12, rax;\n"
        "adox r13, rbx;\n"
        "not rdx;\n"
        "lea rdx, [rdx + 0x2];\n"
        "mulx rbx, rax, r10;\n"
        "adcx r13, rax;\n"
        "adox r14, rbx;\n"
        "mulx rbx, rax, r11;\n"
        "adcx r14, rax;\n"
        "adox r15, rbx;\n"
        "adcx r15, r9;\n"
        "adox r8, r9;\n"
        "adc r8, r9;\n"
        "mov ecx, 0x1;\n"
        "add rcx, r12;\n"
        "dec rdx;\n"
        "adc rdx, r13;\n"
        "dec r9;\n"
        "mov rax, r9;\n"
        "adc r9, r14;\n"
        "mov r11d, 0xfffffffe;\n"
        "adc r11, r15;\n"
        "adc rax, r8;\n"
        "cmovb r12, rcx;\n"
        "cmovb r13, rdx;\n"
        "cmovb r14, r9;\n"
        "cmovb r15, r11;\n"
        "mov [" $P0 "], r12;\n"
        "mov [" $P0 "+ 0x8], r13;\n"
        "mov [" $P0 "+ 0x10], r14;\n"
        "mov [" $P0 "+ 0x18], r15"
    )}
}

// Corresponds exactly to bignum_montsqr_p256 except for
// register tweaks to avoid modifying rbp.

macro_rules! montsqr_p256 {
    ($P0:expr, $P1:expr) => { Q!(
        "mov rdx, [" $P1 "];\n"
        "mulx r15, r8, rdx;\n"
        "mulx r10, r9, [" $P1 "+ 0x8];\n"
        "mulx r12, r11, [" $P1 "+ 0x18];\n"
        "mov rdx, [" $P1 "+ 0x10];\n"
        "mulx r14, r13, [" $P1 "+ 0x18];\n"
        "xor ecx, ecx;\n"
        "mulx rbx, rax, [" $P1 "];\n"
        "adcx r10, rax;\n"
        "adox r11, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x8];\n"
        "adcx r11, rax;\n"
        "adox r12, rbx;\n"
        "mov rdx, [" $P1 "+ 0x18];\n"
        "mulx rbx, rax, [" $P1 "+ 0x8];\n"
        "adcx r12, rax;\n"
        "adox r13, rbx;\n"
        "adcx r13, rcx;\n"
        "adox r14, rcx;\n"
        "adc r14, rcx;\n"
        "xor ecx, ecx;\n"
        "adcx r9, r9;\n"
        "adox r9, r15;\n"
        "mov rdx, [" $P1 "+ 0x8];\n"
        "mulx rdx, rax, rdx;\n"
        "adcx r10, r10;\n"
        "adox r10, rax;\n"
        "adcx r11, r11;\n"
        "adox r11, rdx;\n"
        "mov rdx, [" $P1 "+ 0x10];\n"
        "mulx rdx, rax, rdx;\n"
        "adcx r12, r12;\n"
        "adox r12, rax;\n"
        "adcx r13, r13;\n"
        "adox r13, rdx;\n"
        "mov rdx, [" $P1 "+ 0x18];\n"
        "mulx r15, rax, rdx;\n"
        "adcx r14, r14;\n"
        "adox r14, rax;\n"
        "adcx r15, rcx;\n"
        "adox r15, rcx;\n"
        "xor ecx, ecx;\n"
        "movabs rdx, 0x100000000;\n"
        "mulx rbx, rax, r8;\n"
        "adcx r9, rax;\n"
        "adox r10, rbx;\n"
        "mulx rbx, rax, r9;\n"
        "adcx r10, rax;\n"
        "adox r11, rbx;\n"
        "movabs rdx, 0xffffffff00000001;\n"
        "mulx rbx, rax, r8;\n"
        "adcx r11, rax;\n"
        "adox r12, rbx;\n"
        "mulx rbx, rax, r9;\n"
        "adcx r12, rax;\n"
        "adox r13, rbx;\n"
        "adcx r13, rcx;\n"
        "mov r9d, ecx;\n"
        "adox r9, rcx;\n"
        "adcx r9, rcx;\n"
        "add r14, r9;\n"
        "adc r15, rcx;\n"
        "mov r8d, ecx;\n"
        "adc r8, rcx;\n"
        "xor ecx, ecx;\n"
        "movabs rdx, 0x100000000;\n"
        "mulx rbx, rax, r10;\n"
        "adcx r11, rax;\n"
        "adox r12, rbx;\n"
        "mulx rbx, rax, r11;\n"
        "adcx r12, rax;\n"
        "adox r13, rbx;\n"
        "movabs rdx, 0xffffffff00000001;\n"
        "mulx rbx, rax, r10;\n"
        "adcx r13, rax;\n"
        "adox r14, rbx;\n"
        "mulx rbx, rax, r11;\n"
        "adcx r14, rax;\n"
        "adox r15, rbx;\n"
        "adcx r15, rcx;\n"
        "adox r8, rcx;\n"
        "adc r8, rcx;\n"
        "mov ebx, 0x1;\n"
        "add rbx, r12;\n"
        "lea rdx, [rdx -0x1];\n"
        "adc rdx, r13;\n"
        "lea rcx, [rcx -0x1];\n"
        "mov rax, rcx;\n"
        "adc rcx, r14;\n"
        "mov r11d, 0xfffffffe;\n"
        "adc r11, r15;\n"
        "adc rax, r8;\n"
        "cmovb r12, rbx;\n"
        "cmovb r13, rdx;\n"
        "cmovb r14, rcx;\n"
        "cmovb r15, r11;\n"
        "mov [" $P0 "], r12;\n"
        "mov [" $P0 "+ 0x8], r13;\n"
        "mov [" $P0 "+ 0x10], r14;\n"
        "mov [" $P0 "+ 0x18], r15"
    )}
}

// Almost-Montgomery variant which we use when an input to other muls
// with the other argument fully reduced (which is always safe).
// Again, the basic squaring code is tweaked to avoid modifying rbp.

macro_rules! amontsqr_p256 {
    ($P0:expr, $P1:expr) => { Q!(
        "mov rdx, [" $P1 "];\n"
        "mulx r15, r8, rdx;\n"
        "mulx r10, r9, [" $P1 "+ 0x8];\n"
        "mulx r12, r11, [" $P1 "+ 0x18];\n"
        "mov rdx, [" $P1 "+ 0x10];\n"
        "mulx r14, r13, [" $P1 "+ 0x18];\n"
        "xor ecx, ecx;\n"
        "mulx rbx, rax, [" $P1 "];\n"
        "adcx r10, rax;\n"
        "adox r11, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x8];\n"
        "adcx r11, rax;\n"
        "adox r12, rbx;\n"
        "mov rdx, [" $P1 "+ 0x18];\n"
        "mulx rbx, rax, [" $P1 "+ 0x8];\n"
        "adcx r12, rax;\n"
        "adox r13, rbx;\n"
        "adcx r13, rcx;\n"
        "adox r14, rcx;\n"
        "adc r14, rcx;\n"
        "xor ecx, ecx;\n"
        "adcx r9, r9;\n"
        "adox r9, r15;\n"
        "mov rdx, [" $P1 "+ 0x8];\n"
        "mulx rdx, rax, rdx;\n"
        "adcx r10, r10;\n"
        "adox r10, rax;\n"
        "adcx r11, r11;\n"
        "adox r11, rdx;\n"
        "mov rdx, [" $P1 "+ 0x10];\n"
        "mulx rdx, rax, rdx;\n"
        "adcx r12, r12;\n"
        "adox r12, rax;\n"
        "adcx r13, r13;\n"
        "adox r13, rdx;\n"
        "mov rdx, [" $P1 "+ 0x18];\n"
        "mulx r15, rax, rdx;\n"
        "adcx r14, r14;\n"
        "adox r14, rax;\n"
        "adcx r15, rcx;\n"
        "adox r15, rcx;\n"
        "xor ecx, ecx;\n"
        "movabs rdx, 0x100000000;\n"
        "mulx rbx, rax, r8;\n"
        "adcx r9, rax;\n"
        "adox r10, rbx;\n"
        "mulx rbx, rax, r9;\n"
        "adcx r10, rax;\n"
        "adox r11, rbx;\n"
        "movabs rdx, 0xffffffff00000001;\n"
        "mulx rbx, rax, r8;\n"
        "adcx r11, rax;\n"
        "adox r12, rbx;\n"
        "mulx rbx, rax, r9;\n"
        "adcx r12, rax;\n"
        "adox r13, rbx;\n"
        "adcx r13, rcx;\n"
        "mov r9d, ecx;\n"
        "adox r9, rcx;\n"
        "adcx r9, rcx;\n"
        "add r14, r9;\n"
        "adc r15, rcx;\n"
        "mov r8d, ecx;\n"
        "adc r8, rcx;\n"
        "xor ecx, ecx;\n"
        "movabs rdx, 0x100000000;\n"
        "mulx rbx, rax, r10;\n"
        "adcx r11, rax;\n"
        "adox r12, rbx;\n"
        "mulx rbx, rax, r11;\n"
        "adcx r12, rax;\n"
        "adox r13, rbx;\n"
        "movabs rdx, 0xffffffff00000001;\n"
        "mulx rbx, rax, r10;\n"
        "adcx r13, rax;\n"
        "adox r14, rbx;\n"
        "mulx rbx, rax, r11;\n"
        "adcx r14, rax;\n"
        "adox r15, rbx;\n"
        "adcx r15, rcx;\n"
        "adox r8, rcx;\n"
        "adc r8, rcx;\n"
        "mov r8d, 0x1;\n"
        "lea rdx, [rdx -0x1];\n"
        "lea rax, [rcx -0x1];\n"
        "mov r11d, 0xfffffffe;\n"
        "cmovz r8, rcx;\n"
        "cmovz rdx, rcx;\n"
        "cmovz rax, rcx;\n"
        "cmovz r11, rcx;\n"
        "add r12, r8;\n"
        "adc r13, rdx;\n"
        "adc r14, rax;\n"
        "adc r15, r11;\n"
        "mov [" $P0 "], r12;\n"
        "mov [" $P0 "+ 0x8], r13;\n"
        "mov [" $P0 "+ 0x10], r14;\n"
        "mov [" $P0 "+ 0x18], r15"
    )}
}

// Corresponds exactly to bignum_sub_p256

macro_rules! sub_p256 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "mov rax, [" $P1 "];\n"
        "sub rax, [" $P2 "];\n"
        "mov rcx, [" $P1 "+ 0x8];\n"
        "sbb rcx, [" $P2 "+ 0x8];\n"
        "mov r8, [" $P1 "+ 0x10];\n"
        "sbb r8, [" $P2 "+ 0x10];\n"
        "mov r9, [" $P1 "+ 0x18];\n"
        "sbb r9, [" $P2 "+ 0x18];\n"
        "mov r10d, 0xffffffff;\n"
        "sbb r11, r11;\n"
        "xor rdx, rdx;\n"
        "and r10, r11;\n"
        "sub rdx, r10;\n"
        "add rax, r11;\n"
        "mov [" $P0 "], rax;\n"
        "adc rcx, r10;\n"
        "mov [" $P0 "+ 0x8], rcx;\n"
        "adc r8, 0x0;\n"
        "mov [" $P0 "+ 0x10], r8;\n"
        "adc r9, rdx;\n"
        "mov [" $P0 "+ 0x18], r9"
    )}
}

// Additional macros to help with final multiplexing

macro_rules! testzero4 {
    ($P:expr) => { Q!(
        "mov rax, [" $P "];\n"
        "mov rdx, [" $P "+ 8];\n"
        "or rax, [" $P "+ 16];\n"
        "or rdx, [" $P "+ 24];\n"
        "or rax, rdx"
    )}
}

macro_rules! mux4 {
    ($r0:expr, $r1:expr, $r2:expr, $r3:expr, $PNE:expr, $PEQ:expr) => { Q!(
        "mov " $r0 ", [" $PNE "];\n"
        "mov rax, [" $PEQ "];\n"
        "cmovz " $r0 ", rax;\n"
        "mov " $r1 ", [" $PNE "+ 8];\n"
        "mov rax, [" $PEQ "+ 8];\n"
        "cmovz " $r1 ", rax;\n"
        "mov " $r2 ", [" $PNE "+ 16];\n"
        "mov rax, [" $PEQ "+ 16];\n"
        "cmovz " $r2 ", rax;\n"
        "mov " $r3 ", [" $PNE "+ 24];\n"
        "mov rax, [" $PEQ "+ 24];\n"
        "cmovz " $r3 ", rax"
    )}
}

macro_rules! load4 {
    ($r0:expr, $r1:expr, $r2:expr, $r3:expr, $P:expr) => { Q!(
        "mov " $r0 ", [" $P "];\n"
        "mov " $r1 ", [" $P "+ 8];\n"
        "mov " $r2 ", [" $P "+ 16];\n"
        "mov " $r3 ", [" $P "+ 24]"
    )}
}

macro_rules! store4 {
    ($P:expr, $r0:expr, $r1:expr, $r2:expr, $r3:expr) => { Q!(
        "mov [" $P "], " $r0 ";\n"
        "mov [" $P "+ 8], " $r1 ";\n"
        "mov [" $P "+ 16], " $r2 ";\n"
        "mov [" $P "+ 24], " $r3
    )}
}

/// Point mixed addition on NIST curve P-256 in Montgomery-Jacobian coordinates
///
///
/// Does p3 := p1 + p2 where all points are regarded as Jacobian triples with
/// each coordinate in the Montgomery domain, i.e. x' = (2^256 * x) mod p_256.
/// A Jacobian triple (x',y',z') represents affine point (x/z^2,y/z^3).
/// The "mixed" part means that p2 only has x and y coordinates, with the
/// implicit z coordinate assumed to be the identity.
pub(crate) fn p256_montjmixadd(p3: &mut [u64; 12], p1: &[u64; 12], p2: &[u64; 8]) {
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(

        Q!("    endbr64         " ),


        // Save registers and make room on stack for temporary variables
        // Put the input y in rbp where it lasts as long as it's needed.

        Q!("    push            " "rbx"),
        Q!("    push            " "rbp"),
        Q!("    push            " "r12"),
        Q!("    push            " "r13"),
        Q!("    push            " "r14"),
        Q!("    push            " "r15"),

        Q!("    sub             " "rsp, " NSPACE!()),

        Q!("    mov             " "rbp, rdx"),

        // Main code, just a sequence of basic field operations
        // 8 * multiply + 3 * square + 7 * subtract

        amontsqr_p256!(zp2!(), z_1!()),

        montmul_p256!(y2a!(), z_1!(), y_2!()),
        montmul_p256!(x2a!(), zp2!(), x_2!()),
        montmul_p256!(y2a!(), zp2!(), y2a!()),

        sub_p256!(xd!(), x2a!(), x_1!()),

        sub_p256!(yd!(), y2a!(), y_1!()),

        amontsqr_p256!(zz!(), xd!()),
        montsqr_p256!(ww!(), yd!()),

        montmul_p256!(zzx1!(), zz!(), x_1!()),
        montmul_p256!(zzx2!(), zz!(), x2a!()),

        sub_p256!(resx!(), ww!(), zzx1!()),
        sub_p256!(t1!(), zzx2!(), zzx1!()),

        montmul_p256!(resz!(), xd!(), z_1!()),

        sub_p256!(resx!(), resx!(), zzx2!()),

        sub_p256!(t2!(), zzx1!(), resx!()),

        montmul_p256!(t1!(), t1!(), y_1!()),
        montmul_p256!(t2!(), yd!(), t2!()),

        sub_p256!(resy!(), t2!(), t1!()),

        // Test if z_1 = 0 to decide if p1 = 0 (up to projective equivalence)

        testzero4!(z_1!()),

        // Multiplex: if p1 <> 0 just copy the computed result from the staging area.
        // If p1 = 0 then return the point p2 augmented with a z = 1 coordinate (in
        // Montgomery form so not the simple constant 1 but rather 2^256 - p_256),
        // hence giving 0 + p2 = p2 for the final result.

        mux4!("r8", "r9", "r10", "r11", resx!(), x_2!()),
        mux4!("r12", "r13", "r14", "r15", resy!(), y_2!()),

        store4!(x_3!(), "r8", "r9", "r10", "r11"),
        store4!(y_3!(), "r12", "r13", "r14", "r15"),

        load4!("r8", "r9", "r10", "r11", resz!()),
        Q!("    mov             " "eax, 1"),
        Q!("    cmovz           " "r8, rax"),
        Q!("    mov             " "rax, 0xffffffff00000000"),
        Q!("    cmovz           " "r9, rax"),
        Q!("    mov             " "rax, 0xffffffffffffffff"),
        Q!("    cmovz           " "r10, rax"),
        Q!("    mov             " "eax, 0x00000000fffffffe"),
        Q!("    cmovz           " "r11, rax"),

        store4!(z_3!(), "r8", "r9", "r10", "r11"),

        // Restore stack and registers

        Q!("    add             " "rsp, " NSPACE!()),
        Q!("    pop             " "r15"),
        Q!("    pop             " "r14"),
        Q!("    pop             " "r13"),
        Q!("    pop             " "r12"),
        Q!("    pop             " "rbp"),
        Q!("    pop             " "rbx"),

        inout("rdi") p3.as_mut_ptr() => _,
        inout("rsi") p1.as_ptr() => _,
        inout("rdx") p2.as_ptr() => _,
        // clobbers
        out("r10") _,
        out("r11") _,
        out("r12") _,
        out("r13") _,
        out("r14") _,
        out("r15") _,
        out("r8") _,
        out("r9") _,
        out("rax") _,
        out("rcx") _,
            )
    };
}
