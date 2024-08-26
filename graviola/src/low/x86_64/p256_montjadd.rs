#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Point addition on NIST curve P-256 in Montgomery-Jacobian coordinates
//
//    extern void p256_montjadd
//      (uint64_t p3[static 12],uint64_t p1[static 12],uint64_t p2[static 12]);
//
// Does p3 := p1 + p2 where all points are regarded as Jacobian triples with
// each coordinate in the Montgomery domain, i.e. x' = (2^256 * x) mod p_256.
// A Jacobian triple (x',y',z') represents affine point (x/z^2,y/z^3).
//
// Standard x86-64 ABI: RDI = p3, RSI = p1, RDX = p2
// Microsoft x64 ABI:   RCX = p3, RDX = p1, R8 = p2
// ----------------------------------------------------------------------------

// Size of individual field elements

macro_rules! NUMSIZE {
    () => {
        Q!("32")
    };
}

// Pointer-offset pairs for inputs and outputs
// These assume rdi = p3, rsi = p1 and rbp = p2,
// which needs to be set up explicitly before use.
// The first two hold initially, and the second is
// set up by copying the initial rdx input to rbp.
// Thereafter, no code macro modifies any of them.

macro_rules! x_1 {
    () => {
        Q!("rsi + 0")
    };
}
macro_rules! y_1 { () => { Q!("rsi + " NUMSIZE!()) } }
macro_rules! z_1 { () => { Q!("rsi + (2 * " NUMSIZE!() ")") } }

macro_rules! x_2 {
    () => {
        Q!("rbp + 0")
    };
}
macro_rules! y_2 { () => { Q!("rbp + " NUMSIZE!()) } }
macro_rules! z_2 { () => { Q!("rbp + (2 * " NUMSIZE!() ")") } }

macro_rules! x_3 {
    () => {
        Q!("rdi + 0")
    };
}
macro_rules! y_3 { () => { Q!("rdi + " NUMSIZE!()) } }
macro_rules! z_3 { () => { Q!("rdi + (2 * " NUMSIZE!() ")") } }

// Pointer-offset pairs for temporaries, with some aliasing
// NSPACE is the total stack needed for these temporaries

macro_rules! z1sq { () => { Q!("rsp + (" NUMSIZE!() "* 0)") } }
macro_rules! ww { () => { Q!("rsp + (" NUMSIZE!() "* 0)") } }
macro_rules! resx { () => { Q!("rsp + (" NUMSIZE!() "* 0)") } }

macro_rules! yd { () => { Q!("rsp + (" NUMSIZE!() "* 1)") } }
macro_rules! y2a { () => { Q!("rsp + (" NUMSIZE!() "* 1)") } }

macro_rules! x2a { () => { Q!("rsp + (" NUMSIZE!() "* 2)") } }
macro_rules! zzx2 { () => { Q!("rsp + (" NUMSIZE!() "* 2)") } }

macro_rules! zz { () => { Q!("rsp + (" NUMSIZE!() "* 3)") } }
macro_rules! t1 { () => { Q!("rsp + (" NUMSIZE!() "* 3)") } }

macro_rules! t2 { () => { Q!("rsp + (" NUMSIZE!() "* 4)") } }
macro_rules! x1a { () => { Q!("rsp + (" NUMSIZE!() "* 4)") } }
macro_rules! zzx1 { () => { Q!("rsp + (" NUMSIZE!() "* 4)") } }
macro_rules! resy { () => { Q!("rsp + (" NUMSIZE!() "* 4)") } }

macro_rules! xd { () => { Q!("rsp + (" NUMSIZE!() "* 5)") } }
macro_rules! z2sq { () => { Q!("rsp + (" NUMSIZE!() "* 5)") } }
macro_rules! resz { () => { Q!("rsp + (" NUMSIZE!() "* 5)") } }

macro_rules! y1a { () => { Q!("rsp + (" NUMSIZE!() "* 6)") } }

macro_rules! NSPACE { () => { Q!("(" NUMSIZE!() "* 7)") } }

// Corresponds exactly to bignum_montmul_p256

macro_rules! montmul_p256 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "xor r13d, r13d;"
        "mov rdx, [" $P2 "];"
        "mulx r9, r8, [" $P1 "];"
        "mulx r10, rbx, [" $P1 "+ 0x8];"
        "adc r9, rbx;"
        "mulx r11, rbx, [" $P1 "+ 0x10];"
        "adc r10, rbx;"
        "mulx r12, rbx, [" $P1 "+ 0x18];"
        "adc r11, rbx;"
        "adc r12, r13;"
        "mov rdx, [" $P2 "+ 0x8];"
        "xor r14d, r14d;"
        "mulx rbx, rax, [" $P1 "];"
        "adcx r9, rax;"
        "adox r10, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x8];"
        "adcx r10, rax;"
        "adox r11, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x10];"
        "adcx r11, rax;"
        "adox r12, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x18];"
        "adcx r12, rax;"
        "adox r13, rbx;"
        "adc r13, r14;"
        "xor r15d, r15d;"
        "movabs rdx, 0x100000000;"
        "mulx rbx, rax, r8;"
        "adcx r9, rax;"
        "adox r10, rbx;"
        "mulx rbx, rax, r9;"
        "adcx r10, rax;"
        "adox r11, rbx;"
        "not rdx;"
        "lea rdx, [rdx + 0x2];"
        "mulx rbx, rax, r8;"
        "adcx r11, rax;"
        "adox r12, rbx;"
        "mulx rbx, rax, r9;"
        "adcx r12, rax;"
        "adox r13, rbx;"
        "adcx r13, r15;"
        "adox r14, r15;"
        "adc r14, r15;"
        "mov rdx, [" $P2 "+ 0x10];"
        "xor r8d, r8d;"
        "mulx rbx, rax, [" $P1 "];"
        "adcx r10, rax;"
        "adox r11, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x8];"
        "adcx r11, rax;"
        "adox r12, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x10];"
        "adcx r12, rax;"
        "adox r13, rbx;"
        "adox r14, r8;"
        "mulx rbx, rax, [" $P1 "+ 0x18];"
        "adc r13, rax;"
        "adc r14, rbx;"
        "adc r15, r8;"
        "mov rdx, [" $P2 "+ 0x18];"
        "xor r9d, r9d;"
        "mulx rbx, rax, [" $P1 "];"
        "adcx r11, rax;"
        "adox r12, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x8];"
        "adcx r12, rax;"
        "adox r13, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x10];"
        "adcx r13, rax;"
        "adox r14, rbx;"
        "adox r15, r9;"
        "mulx rbx, rax, [" $P1 "+ 0x18];"
        "adc r14, rax;"
        "adc r15, rbx;"
        "adc r8, r9;"
        "xor r9d, r9d;"
        "movabs rdx, 0x100000000;"
        "mulx rbx, rax, r10;"
        "adcx r11, rax;"
        "adox r12, rbx;"
        "mulx rbx, rax, r11;"
        "adcx r12, rax;"
        "adox r13, rbx;"
        "not rdx;"
        "lea rdx, [rdx + 0x2];"
        "mulx rbx, rax, r10;"
        "adcx r13, rax;"
        "adox r14, rbx;"
        "mulx rbx, rax, r11;"
        "adcx r14, rax;"
        "adox r15, rbx;"
        "adcx r15, r9;"
        "adox r8, r9;"
        "adc r8, r9;"
        "mov ecx, 0x1;"
        "add rcx, r12;"
        "dec rdx;"
        "adc rdx, r13;"
        "dec r9;"
        "mov rax, r9;"
        "adc r9, r14;"
        "mov r11d, 0xfffffffe;"
        "adc r11, r15;"
        "adc rax, r8;"
        "cmovb r12, rcx;"
        "cmovb r13, rdx;"
        "cmovb r14, r9;"
        "cmovb r15, r11;"
        "mov [" $P0 "], r12;"
        "mov [" $P0 "+ 0x8], r13;"
        "mov [" $P0 "+ 0x10], r14;"
        "mov [" $P0 "+ 0x18], r15"
    )}
}

// Corresponds exactly to bignum_montsqr_p256 except for
// register tweaks to avoid modifying rbp.

macro_rules! montsqr_p256 {
    ($P0:expr, $P1:expr) => { Q!(
        "mov rdx, [" $P1 "];"
        "mulx r15, r8, rdx;"
        "mulx r10, r9, [" $P1 "+ 0x8];"
        "mulx r12, r11, [" $P1 "+ 0x18];"
        "mov rdx, [" $P1 "+ 0x10];"
        "mulx r14, r13, [" $P1 "+ 0x18];"
        "xor ecx, ecx;"
        "mulx rbx, rax, [" $P1 "];"
        "adcx r10, rax;"
        "adox r11, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x8];"
        "adcx r11, rax;"
        "adox r12, rbx;"
        "mov rdx, [" $P1 "+ 0x18];"
        "mulx rbx, rax, [" $P1 "+ 0x8];"
        "adcx r12, rax;"
        "adox r13, rbx;"
        "adcx r13, rcx;"
        "adox r14, rcx;"
        "adc r14, rcx;"
        "xor ecx, ecx;"
        "adcx r9, r9;"
        "adox r9, r15;"
        "mov rdx, [" $P1 "+ 0x8];"
        "mulx rdx, rax, rdx;"
        "adcx r10, r10;"
        "adox r10, rax;"
        "adcx r11, r11;"
        "adox r11, rdx;"
        "mov rdx, [" $P1 "+ 0x10];"
        "mulx rdx, rax, rdx;"
        "adcx r12, r12;"
        "adox r12, rax;"
        "adcx r13, r13;"
        "adox r13, rdx;"
        "mov rdx, [" $P1 "+ 0x18];"
        "mulx r15, rax, rdx;"
        "adcx r14, r14;"
        "adox r14, rax;"
        "adcx r15, rcx;"
        "adox r15, rcx;"
        "xor ecx, ecx;"
        "movabs rdx, 0x100000000;"
        "mulx rbx, rax, r8;"
        "adcx r9, rax;"
        "adox r10, rbx;"
        "mulx rbx, rax, r9;"
        "adcx r10, rax;"
        "adox r11, rbx;"
        "movabs rdx, 0xffffffff00000001;"
        "mulx rbx, rax, r8;"
        "adcx r11, rax;"
        "adox r12, rbx;"
        "mulx rbx, rax, r9;"
        "adcx r12, rax;"
        "adox r13, rbx;"
        "adcx r13, rcx;"
        "mov r9d, ecx;"
        "adox r9, rcx;"
        "adcx r9, rcx;"
        "add r14, r9;"
        "adc r15, rcx;"
        "mov r8d, ecx;"
        "adc r8, rcx;"
        "xor ecx, ecx;"
        "movabs rdx, 0x100000000;"
        "mulx rbx, rax, r10;"
        "adcx r11, rax;"
        "adox r12, rbx;"
        "mulx rbx, rax, r11;"
        "adcx r12, rax;"
        "adox r13, rbx;"
        "movabs rdx, 0xffffffff00000001;"
        "mulx rbx, rax, r10;"
        "adcx r13, rax;"
        "adox r14, rbx;"
        "mulx rbx, rax, r11;"
        "adcx r14, rax;"
        "adox r15, rbx;"
        "adcx r15, rcx;"
        "adox r8, rcx;"
        "adc r8, rcx;"
        "mov ebx, 0x1;"
        "add rbx, r12;"
        "lea rdx, [rdx -0x1];"
        "adc rdx, r13;"
        "lea rcx, [rcx -0x1];"
        "mov rax, rcx;"
        "adc rcx, r14;"
        "mov r11d, 0xfffffffe;"
        "adc r11, r15;"
        "adc rax, r8;"
        "cmovb r12, rbx;"
        "cmovb r13, rdx;"
        "cmovb r14, rcx;"
        "cmovb r15, r11;"
        "mov [" $P0 "], r12;"
        "mov [" $P0 "+ 0x8], r13;"
        "mov [" $P0 "+ 0x10], r14;"
        "mov [" $P0 "+ 0x18], r15"
    )}
}

// Almost-Montgomery variant which we use when an input to other muls
// with the other argument fully reduced (which is always safe).
// Again, the basic squaring code is tweaked to avoid modifying rbp.

macro_rules! amontsqr_p256 {
    ($P0:expr, $P1:expr) => { Q!(
        "mov rdx, [" $P1 "];"
        "mulx r15, r8, rdx;"
        "mulx r10, r9, [" $P1 "+ 0x8];"
        "mulx r12, r11, [" $P1 "+ 0x18];"
        "mov rdx, [" $P1 "+ 0x10];"
        "mulx r14, r13, [" $P1 "+ 0x18];"
        "xor ecx, ecx;"
        "mulx rbx, rax, [" $P1 "];"
        "adcx r10, rax;"
        "adox r11, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x8];"
        "adcx r11, rax;"
        "adox r12, rbx;"
        "mov rdx, [" $P1 "+ 0x18];"
        "mulx rbx, rax, [" $P1 "+ 0x8];"
        "adcx r12, rax;"
        "adox r13, rbx;"
        "adcx r13, rcx;"
        "adox r14, rcx;"
        "adc r14, rcx;"
        "xor ecx, ecx;"
        "adcx r9, r9;"
        "adox r9, r15;"
        "mov rdx, [" $P1 "+ 0x8];"
        "mulx rdx, rax, rdx;"
        "adcx r10, r10;"
        "adox r10, rax;"
        "adcx r11, r11;"
        "adox r11, rdx;"
        "mov rdx, [" $P1 "+ 0x10];"
        "mulx rdx, rax, rdx;"
        "adcx r12, r12;"
        "adox r12, rax;"
        "adcx r13, r13;"
        "adox r13, rdx;"
        "mov rdx, [" $P1 "+ 0x18];"
        "mulx r15, rax, rdx;"
        "adcx r14, r14;"
        "adox r14, rax;"
        "adcx r15, rcx;"
        "adox r15, rcx;"
        "xor ecx, ecx;"
        "movabs rdx, 0x100000000;"
        "mulx rbx, rax, r8;"
        "adcx r9, rax;"
        "adox r10, rbx;"
        "mulx rbx, rax, r9;"
        "adcx r10, rax;"
        "adox r11, rbx;"
        "movabs rdx, 0xffffffff00000001;"
        "mulx rbx, rax, r8;"
        "adcx r11, rax;"
        "adox r12, rbx;"
        "mulx rbx, rax, r9;"
        "adcx r12, rax;"
        "adox r13, rbx;"
        "adcx r13, rcx;"
        "mov r9d, ecx;"
        "adox r9, rcx;"
        "adcx r9, rcx;"
        "add r14, r9;"
        "adc r15, rcx;"
        "mov r8d, ecx;"
        "adc r8, rcx;"
        "xor ecx, ecx;"
        "movabs rdx, 0x100000000;"
        "mulx rbx, rax, r10;"
        "adcx r11, rax;"
        "adox r12, rbx;"
        "mulx rbx, rax, r11;"
        "adcx r12, rax;"
        "adox r13, rbx;"
        "movabs rdx, 0xffffffff00000001;"
        "mulx rbx, rax, r10;"
        "adcx r13, rax;"
        "adox r14, rbx;"
        "mulx rbx, rax, r11;"
        "adcx r14, rax;"
        "adox r15, rbx;"
        "adcx r15, rcx;"
        "adox r8, rcx;"
        "adc r8, rcx;"
        "mov r8d, 0x1;"
        "lea rdx, [rdx -0x1];"
        "lea rax, [rcx -0x1];"
        "mov r11d, 0xfffffffe;"
        "cmovz r8, rcx;"
        "cmovz rdx, rcx;"
        "cmovz rax, rcx;"
        "cmovz r11, rcx;"
        "add r12, r8;"
        "adc r13, rdx;"
        "adc r14, rax;"
        "adc r15, r11;"
        "mov [" $P0 "], r12;"
        "mov [" $P0 "+ 0x8], r13;"
        "mov [" $P0 "+ 0x10], r14;"
        "mov [" $P0 "+ 0x18], r15"
    )}
}

// Corresponds exactly to bignum_sub_p256

macro_rules! sub_p256 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "mov rax, [" $P1 "];"
        "sub rax, [" $P2 "];"
        "mov rcx, [" $P1 "+ 0x8];"
        "sbb rcx, [" $P2 "+ 0x8];"
        "mov r8, [" $P1 "+ 0x10];"
        "sbb r8, [" $P2 "+ 0x10];"
        "mov r9, [" $P1 "+ 0x18];"
        "sbb r9, [" $P2 "+ 0x18];"
        "mov r10d, 0xffffffff;"
        "sbb r11, r11;"
        "xor rdx, rdx;"
        "and r10, r11;"
        "sub rdx, r10;"
        "add rax, r11;"
        "mov [" $P0 "], rax;"
        "adc rcx, r10;"
        "mov [" $P0 "+ 0x8], rcx;"
        "adc r8, 0x0;"
        "mov [" $P0 "+ 0x10], r8;"
        "adc r9, rdx;"
        "mov [" $P0 "+ 0x18], r9"
    )}
}

// Additional macros to help with final multiplexing

macro_rules! load4 {
    ($r0:expr, $r1:expr, $r2:expr, $r3:expr, $P:expr) => { Q!(
        "mov " $r0 ", [" $P "];"
        "mov " $r1 ", [" $P "+ 8];"
        "mov " $r2 ", [" $P "+ 16];"
        "mov " $r3 ", [" $P "+ 24]"
    )}
}

macro_rules! store4 {
    ($P:expr, $r0:expr, $r1:expr, $r2:expr, $r3:expr) => { Q!(
        "mov [" $P "], " $r0 ";"
        "mov [" $P "+ 8], " $r1 ";"
        "mov [" $P "+ 16], " $r2 ";"
        "mov [" $P "+ 24], " $r3
    )}
}

macro_rules! czload4 {
    ($r0:expr, $r1:expr, $r2:expr, $r3:expr, $P:expr) => { Q!(
        "cmovz " $r0 ", [" $P "];"
        "cmovz " $r1 ", [" $P "+ 8];"
        "cmovz " $r2 ", [" $P "+ 16];"
        "cmovz " $r3 ", [" $P "+ 24]"
    )}
}

macro_rules! muxload4 {
    ($r0:expr, $r1:expr, $r2:expr, $r3:expr, $P0:expr, $P1:expr, $P2:expr) => { Q!(
        "mov " $r0 ", [" $P0 "];"
        "cmovb " $r0 ", [" $P1 "];"
        "cmovnbe " $r0 ", [" $P2 "];"
        "mov " $r1 ", [" $P0 "+ 8];"
        "cmovb " $r1 ", [" $P1 "+ 8];"
        "cmovnbe " $r1 ", [" $P2 "+ 8];"
        "mov " $r2 ", [" $P0 "+ 16];"
        "cmovb " $r2 ", [" $P1 "+ 16];"
        "cmovnbe " $r2 ", [" $P2 "+ 16];"
        "mov " $r3 ", [" $P0 "+ 24];"
        "cmovb " $r3 ", [" $P1 "+ 24];"
        "cmovnbe " $r3 ", [" $P2 "+ 24]"
    )}
}

pub fn p256_montjadd(p3: &mut [u64; 12], p1: &[u64; 12], p2: &[u64; 12]) {
    unsafe {
        core::arch::asm!(



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
        // 12 * multiply + 4 * square + 7 * subtract

        amontsqr_p256!(z1sq!(), z_1!()),
        amontsqr_p256!(z2sq!(), z_2!()),

        montmul_p256!(y1a!(), z_2!(), y_1!()),
        montmul_p256!(y2a!(), z_1!(), y_2!()),

        montmul_p256!(x2a!(), z1sq!(), x_2!()),
        montmul_p256!(x1a!(), z2sq!(), x_1!()),
        montmul_p256!(y2a!(), z1sq!(), y2a!()),
        montmul_p256!(y1a!(), z2sq!(), y1a!()),

        sub_p256!(xd!(), x2a!(), x1a!()),
        sub_p256!(yd!(), y2a!(), y1a!()),

        amontsqr_p256!(zz!(), xd!()),
        montsqr_p256!(ww!(), yd!()),

        montmul_p256!(zzx1!(), zz!(), x1a!()),
        montmul_p256!(zzx2!(), zz!(), x2a!()),

        sub_p256!(resx!(), ww!(), zzx1!()),
        sub_p256!(t1!(), zzx2!(), zzx1!()),

        montmul_p256!(xd!(), xd!(), z_1!()),

        sub_p256!(resx!(), resx!(), zzx2!()),

        sub_p256!(t2!(), zzx1!(), resx!()),

        montmul_p256!(t1!(), t1!(), y1a!()),

        montmul_p256!(resz!(), xd!(), z_2!()),
        montmul_p256!(t2!(), yd!(), t2!()),

        sub_p256!(resy!(), t2!(), t1!()),

        // Load in the z coordinates of the inputs to check for P1 = 0 and P2 = 0
        // The condition codes get set by a comparison (P2 != 0) - (P1 != 0)
        // So "NBE" <=> ~(CF \/ ZF) <=> P1 = 0 /\ ~(P2 = 0)
        // and "B"  <=> CF          <=> ~(P1 = 0) /\ P2 = 0
        // and "Z"  <=> ZF          <=> (P1 = 0 <=> P2 = 0)

        load4!("r8", "r9", "r10", "r11", z_1!()),

        Q!("    mov             " "rax, r8"),
        Q!("    mov             " "rdx, r9"),
        Q!("    or              " "rax, r10"),
        Q!("    or              " "rdx, r11"),
        Q!("    or              " "rax, rdx"),
        Q!("    neg             " "rax"),
        Q!("    sbb             " "rax, rax"),

        load4!("r12", "r13", "r14", "r15", z_2!()),

        Q!("    mov             " "rbx, r12"),
        Q!("    mov             " "rdx, r13"),
        Q!("    or              " "rbx, r14"),
        Q!("    or              " "rdx, r15"),
        Q!("    or              " "rbx, rdx"),
        Q!("    neg             " "rbx"),
        Q!("    sbb             " "rbx, rbx"),

        Q!("    cmp             " "rbx, rax"),

        // Multiplex the outputs accordingly, re-using the z's in registers

        Q!("    cmovb           " "r12, r8"),
        Q!("    cmovb           " "r13, r9"),
        Q!("    cmovb           " "r14, r10"),
        Q!("    cmovb           " "r15, r11"),

        czload4!("r12", "r13", "r14", "r15", resz!()),

        muxload4!("rax", "rbx", "rcx", "rdx", resx!(), x_1!(), x_2!()),
        muxload4!("r8", "r9", "r10", "r11", resy!(), y_1!(), y_2!()),

        // Finally store back the multiplexed values

        store4!(x_3!(), "rax", "rbx", "rcx", "rdx"),
        store4!(y_3!(), "r8", "r9", "r10", "r11"),
        store4!(z_3!(), "r12", "r13", "r14", "r15"),

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
