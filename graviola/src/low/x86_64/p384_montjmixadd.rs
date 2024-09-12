#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Point mixed addition on NIST curve P-384 in Montgomery-Jacobian coordinates
//
//    extern void p384_montjmixadd
//      (uint64_t p3[static 18],uint64_t p1[static 18],uint64_t p2[static 12]);
//
// Does p3 := p1 + p2 where all points are regarded as Jacobian triples with
// each coordinate in the Montgomery domain, i.e. x' = (2^384 * x) mod p_384.
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
        Q!("48")
    };
}

// Pointer-offset pairs for inputs and outputs
// These assume rdi = p3, rsi = p1 and rcx = p2,
// which needs to be set up explicitly before use.
// However the rdi value never changes.

macro_rules! x_1 {
    () => {
        Q!("rsi + 0")
    };
}
macro_rules! y_1 { () => { Q!("rsi + " NUMSIZE!()) } }
macro_rules! z_1 { () => { Q!("rsi + (2 * " NUMSIZE!() ")") } }

macro_rules! x_2 {
    () => {
        Q!("rcx + 0")
    };
}
macro_rules! y_2 { () => { Q!("rcx + " NUMSIZE!()) } }

macro_rules! x_3 {
    () => {
        Q!("rdi + 0")
    };
}
macro_rules! y_3 { () => { Q!("rdi + " NUMSIZE!()) } }
macro_rules! z_3 { () => { Q!("rdi + (2 * " NUMSIZE!() ")") } }

// Pointer-offset pairs for temporaries, with some aliasing
// NSPACE is the total stack needed for these temporaries

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

// Temporaries for the actual input pointers

macro_rules! input_x { () => { Q!("[rsp + (" NUMSIZE!() "* 6)]") } }
macro_rules! input_y { () => { Q!("[rsp + (" NUMSIZE!() "* 6 + 8)]") } }

macro_rules! NSPACE { () => { Q!("(" NUMSIZE!() "* 6 + 16)") } }

// Corresponds exactly to bignum_montmul_p384

macro_rules! montmul_p384 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "mov rdx, [" $P2 "];\n"
        "xor r15d, r15d;\n"
        "mulx r9, r8, [" $P1 "];\n"
        "mulx r10, rbx, [" $P1 "+ 0x8];\n"
        "add r9, rbx;\n"
        "mulx r11, rbx, [" $P1 "+ 0x10];\n"
        "adc r10, rbx;\n"
        "mulx r12, rbx, [" $P1 "+ 0x18];\n"
        "adc r11, rbx;\n"
        "mulx r13, rbx, [" $P1 "+ 0x20];\n"
        "adc r12, rbx;\n"
        "mulx r14, rbx, [" $P1 "+ 0x28];\n"
        "adc r13, rbx;\n"
        "adc r14, r15;\n"
        "mov rdx, r8;\n"
        "shl rdx, 0x20;\n"
        "add rdx, r8;\n"
        "xor ebp, ebp;\n"
        "mov rax, 0xffffffff00000001;\n"
        "mulx rax, rbx, rax;\n"
        "mov ebx, 0xffffffff;\n"
        "mulx rbx, r8, rbx;\n"
        "adc rax, r8;\n"
        "adc rbx, rdx;\n"
        "adc ebp, ebp;\n"
        "sub r9, rax;\n"
        "sbb r10, rbx;\n"
        "sbb r11, rbp;\n"
        "sbb r12, 0x0;\n"
        "sbb r13, 0x0;\n"
        "sbb rdx, 0x0;\n"
        "add r14, rdx;\n"
        "adc r15, 0x0;\n"
        "mov rdx, [" $P2 "+ 0x8];\n"
        "xor r8d, r8d;\n"
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
        "mulx rbx, rax, [" $P1 "+ 0x20];\n"
        "adcx r13, rax;\n"
        "adox r14, rbx;\n"
        "adox r15, r8;\n"
        "mulx rbx, rax, [" $P1 "+ 0x28];\n"
        "adc r14, rax;\n"
        "adc r15, rbx;\n"
        "adc r8, r8;\n"
        "mov rdx, r9;\n"
        "shl rdx, 0x20;\n"
        "add rdx, r9;\n"
        "xor ebp, ebp;\n"
        "mov rax, 0xffffffff00000001;\n"
        "mulx rax, rbx, rax;\n"
        "mov ebx, 0xffffffff;\n"
        "mulx rbx, r9, rbx;\n"
        "adc rax, r9;\n"
        "adc rbx, rdx;\n"
        "adc ebp, ebp;\n"
        "sub r10, rax;\n"
        "sbb r11, rbx;\n"
        "sbb r12, rbp;\n"
        "sbb r13, 0x0;\n"
        "sbb r14, 0x0;\n"
        "sbb rdx, 0x0;\n"
        "add r15, rdx;\n"
        "adc r8, 0x0;\n"
        "mov rdx, [" $P2 "+ 0x10];\n"
        "xor r9d, r9d;\n"
        "mulx rbx, rax, [" $P1 "];\n"
        "adcx r10, rax;\n"
        "adox r11, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x8];\n"
        "adcx r11, rax;\n"
        "adox r12, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x10];\n"
        "adcx r12, rax;\n"
        "adox r13, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x18];\n"
        "adcx r13, rax;\n"
        "adox r14, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x20];\n"
        "adcx r14, rax;\n"
        "adox r15, rbx;\n"
        "adox r8, r9;\n"
        "mulx rbx, rax, [" $P1 "+ 0x28];\n"
        "adc r15, rax;\n"
        "adc r8, rbx;\n"
        "adc r9, r9;\n"
        "mov rdx, r10;\n"
        "shl rdx, 0x20;\n"
        "add rdx, r10;\n"
        "xor ebp, ebp;\n"
        "mov rax, 0xffffffff00000001;\n"
        "mulx rax, rbx, rax;\n"
        "mov ebx, 0xffffffff;\n"
        "mulx rbx, r10, rbx;\n"
        "adc rax, r10;\n"
        "adc rbx, rdx;\n"
        "adc ebp, ebp;\n"
        "sub r11, rax;\n"
        "sbb r12, rbx;\n"
        "sbb r13, rbp;\n"
        "sbb r14, 0x0;\n"
        "sbb r15, 0x0;\n"
        "sbb rdx, 0x0;\n"
        "add r8, rdx;\n"
        "adc r9, 0x0;\n"
        "mov rdx, [" $P2 "+ 0x18];\n"
        "xor r10d, r10d;\n"
        "mulx rbx, rax, [" $P1 "];\n"
        "adcx r11, rax;\n"
        "adox r12, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x8];\n"
        "adcx r12, rax;\n"
        "adox r13, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x10];\n"
        "adcx r13, rax;\n"
        "adox r14, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x18];\n"
        "adcx r14, rax;\n"
        "adox r15, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x20];\n"
        "adcx r15, rax;\n"
        "adox r8, rbx;\n"
        "adox r9, r10;\n"
        "mulx rbx, rax, [" $P1 "+ 0x28];\n"
        "adc r8, rax;\n"
        "adc r9, rbx;\n"
        "adc r10, r10;\n"
        "mov rdx, r11;\n"
        "shl rdx, 0x20;\n"
        "add rdx, r11;\n"
        "xor ebp, ebp;\n"
        "mov rax, 0xffffffff00000001;\n"
        "mulx rax, rbx, rax;\n"
        "mov ebx, 0xffffffff;\n"
        "mulx rbx, r11, rbx;\n"
        "adc rax, r11;\n"
        "adc rbx, rdx;\n"
        "adc ebp, ebp;\n"
        "sub r12, rax;\n"
        "sbb r13, rbx;\n"
        "sbb r14, rbp;\n"
        "sbb r15, 0x0;\n"
        "sbb r8, 0x0;\n"
        "sbb rdx, 0x0;\n"
        "add r9, rdx;\n"
        "adc r10, 0x0;\n"
        "mov rdx, [" $P2 "+ 0x20];\n"
        "xor r11d, r11d;\n"
        "mulx rbx, rax, [" $P1 "];\n"
        "adcx r12, rax;\n"
        "adox r13, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x8];\n"
        "adcx r13, rax;\n"
        "adox r14, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x10];\n"
        "adcx r14, rax;\n"
        "adox r15, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x18];\n"
        "adcx r15, rax;\n"
        "adox r8, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x20];\n"
        "adcx r8, rax;\n"
        "adox r9, rbx;\n"
        "adox r10, r11;\n"
        "mulx rbx, rax, [" $P1 "+ 0x28];\n"
        "adc r9, rax;\n"
        "adc r10, rbx;\n"
        "adc r11, r11;\n"
        "mov rdx, r12;\n"
        "shl rdx, 0x20;\n"
        "add rdx, r12;\n"
        "xor ebp, ebp;\n"
        "mov rax, 0xffffffff00000001;\n"
        "mulx rax, rbx, rax;\n"
        "mov ebx, 0xffffffff;\n"
        "mulx rbx, r12, rbx;\n"
        "adc rax, r12;\n"
        "adc rbx, rdx;\n"
        "adc ebp, ebp;\n"
        "sub r13, rax;\n"
        "sbb r14, rbx;\n"
        "sbb r15, rbp;\n"
        "sbb r8, 0x0;\n"
        "sbb r9, 0x0;\n"
        "sbb rdx, 0x0;\n"
        "add r10, rdx;\n"
        "adc r11, 0x0;\n"
        "mov rdx, [" $P2 "+ 0x28];\n"
        "xor r12d, r12d;\n"
        "mulx rbx, rax, [" $P1 "];\n"
        "adcx r13, rax;\n"
        "adox r14, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x8];\n"
        "adcx r14, rax;\n"
        "adox r15, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x10];\n"
        "adcx r15, rax;\n"
        "adox r8, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x18];\n"
        "adcx r8, rax;\n"
        "adox r9, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x20];\n"
        "adcx r9, rax;\n"
        "adox r10, rbx;\n"
        "adox r11, r12;\n"
        "mulx rbx, rax, [" $P1 "+ 0x28];\n"
        "adc r10, rax;\n"
        "adc r11, rbx;\n"
        "adc r12, r12;\n"
        "mov rdx, r13;\n"
        "shl rdx, 0x20;\n"
        "add rdx, r13;\n"
        "xor ebp, ebp;\n"
        "mov rax, 0xffffffff00000001;\n"
        "mulx rax, rbx, rax;\n"
        "mov ebx, 0xffffffff;\n"
        "mulx rbx, r13, rbx;\n"
        "adc rax, r13;\n"
        "adc rbx, rdx;\n"
        "adc ebp, ebp;\n"
        "sub r14, rax;\n"
        "sbb r15, rbx;\n"
        "sbb r8, rbp;\n"
        "sbb r9, 0x0;\n"
        "sbb r10, 0x0;\n"
        "sbb rdx, 0x0;\n"
        "add r11, rdx;\n"
        "adc r12, 0x0;\n"
        "xor edx, edx;\n"
        "xor ebp, ebp;\n"
        "xor r13d, r13d;\n"
        "mov rax, 0xffffffff00000001;\n"
        "add rax, r14;\n"
        "mov ebx, 0xffffffff;\n"
        "adc rbx, r15;\n"
        "mov ecx, 0x1;\n"
        "adc rcx, r8;\n"
        "adc rdx, r9;\n"
        "adc rbp, r10;\n"
        "adc r13, r11;\n"
        "adc r12, 0x0;\n"
        "cmovne r14, rax;\n"
        "cmovne r15, rbx;\n"
        "cmovne r8, rcx;\n"
        "cmovne r9, rdx;\n"
        "cmovne r10, rbp;\n"
        "cmovne r11, r13;\n"
        "mov [" $P0 "], r14;\n"
        "mov [" $P0 "+ 0x8], r15;\n"
        "mov [" $P0 "+ 0x10], r8;\n"
        "mov [" $P0 "+ 0x18], r9;\n"
        "mov [" $P0 "+ 0x20], r10;\n"
        "mov [" $P0 "+ 0x28], r11"
    )}
}

// Corresponds exactly to bignum_montsqr_p384

macro_rules! montsqr_p384 {
    ($P0:expr, $P1:expr) => { Q!(
        "mov rdx, [" $P1 "];\n"
        "mulx r10, r9, [" $P1 "+ 0x8];\n"
        "mulx r12, r11, [" $P1 "+ 0x18];\n"
        "mulx r14, r13, [" $P1 "+ 0x28];\n"
        "mov rdx, [" $P1 "+ 0x18];\n"
        "mulx rcx, r15, [" $P1 "+ 0x20];\n"
        "xor ebp, ebp;\n"
        "mov rdx, [" $P1 "+ 0x10];\n"
        "mulx rbx, rax, [" $P1 "];\n"
        "adcx r10, rax;\n"
        "adox r11, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x8];\n"
        "adcx r11, rax;\n"
        "adox r12, rbx;\n"
        "mov rdx, [" $P1 "+ 0x8];\n"
        "mulx rbx, rax, [" $P1 "+ 0x18];\n"
        "adcx r12, rax;\n"
        "adox r13, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x20];\n"
        "adcx r13, rax;\n"
        "adox r14, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x28];\n"
        "adcx r14, rax;\n"
        "adox r15, rbx;\n"
        "adcx r15, rbp;\n"
        "adox rcx, rbp;\n"
        "adc rcx, rbp;\n"
        "xor ebp, ebp;\n"
        "mov rdx, [" $P1 "+ 0x20];\n"
        "mulx rbx, rax, [" $P1 "];\n"
        "adcx r12, rax;\n"
        "adox r13, rbx;\n"
        "mov rdx, [" $P1 "+ 0x10];\n"
        "mulx rbx, rax, [" $P1 "+ 0x18];\n"
        "adcx r13, rax;\n"
        "adox r14, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x20];\n"
        "adcx r14, rax;\n"
        "adox r15, rbx;\n"
        "mulx rdx, rax, [" $P1 "+ 0x28];\n"
        "adcx r15, rax;\n"
        "adox rcx, rdx;\n"
        "mov rdx, [" $P1 "+ 0x28];\n"
        "mulx rbp, rbx, [" $P1 "+ 0x20];\n"
        "mulx rdx, rax, [" $P1 "+ 0x18];\n"
        "adcx rcx, rax;\n"
        "adox rbx, rdx;\n"
        "mov eax, 0x0;\n"
        "adcx rbx, rax;\n"
        "adox rbp, rax;\n"
        "adc rbp, rax;\n"
        "xor rax, rax;\n"
        "mov rdx, [" $P1 "];\n"
        "mulx rax, r8, [" $P1 "];\n"
        "adcx r9, r9;\n"
        "adox r9, rax;\n"
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
        "mulx rdx, rax, rdx;\n"
        "adcx r14, r14;\n"
        "adox r14, rax;\n"
        "adcx r15, r15;\n"
        "adox r15, rdx;\n"
        "mov rdx, [" $P1 "+ 0x20];\n"
        "mulx rdx, rax, rdx;\n"
        "adcx rcx, rcx;\n"
        "adox rcx, rax;\n"
        "adcx rbx, rbx;\n"
        "adox rbx, rdx;\n"
        "mov rdx, [" $P1 "+ 0x28];\n"
        "mulx rsi, rax, rdx;\n"
        "adcx rbp, rbp;\n"
        "adox rbp, rax;\n"
        "mov eax, 0x0;\n"
        "adcx rsi, rax;\n"
        "adox rsi, rax;\n"
        "mov [" $P0 "], rbx;\n"
        "mov rdx, r8;\n"
        "shl rdx, 0x20;\n"
        "add rdx, r8;\n"
        "mov rax, 0xffffffff00000001;\n"
        "mulx rax, r8, rax;\n"
        "mov ebx, 0xffffffff;\n"
        "mulx r8, rbx, rbx;\n"
        "add rax, rbx;\n"
        "adc r8, rdx;\n"
        "mov ebx, 0x0;\n"
        "adc rbx, rbx;\n"
        "sub r9, rax;\n"
        "sbb r10, r8;\n"
        "sbb r11, rbx;\n"
        "sbb r12, 0x0;\n"
        "sbb r13, 0x0;\n"
        "mov r8, rdx;\n"
        "sbb r8, 0x0;\n"
        "mov rdx, r9;\n"
        "shl rdx, 0x20;\n"
        "add rdx, r9;\n"
        "mov rax, 0xffffffff00000001;\n"
        "mulx rax, r9, rax;\n"
        "mov ebx, 0xffffffff;\n"
        "mulx r9, rbx, rbx;\n"
        "add rax, rbx;\n"
        "adc r9, rdx;\n"
        "mov ebx, 0x0;\n"
        "adc rbx, rbx;\n"
        "sub r10, rax;\n"
        "sbb r11, r9;\n"
        "sbb r12, rbx;\n"
        "sbb r13, 0x0;\n"
        "sbb r8, 0x0;\n"
        "mov r9, rdx;\n"
        "sbb r9, 0x0;\n"
        "mov rdx, r10;\n"
        "shl rdx, 0x20;\n"
        "add rdx, r10;\n"
        "mov rax, 0xffffffff00000001;\n"
        "mulx rax, r10, rax;\n"
        "mov ebx, 0xffffffff;\n"
        "mulx r10, rbx, rbx;\n"
        "add rax, rbx;\n"
        "adc r10, rdx;\n"
        "mov ebx, 0x0;\n"
        "adc rbx, rbx;\n"
        "sub r11, rax;\n"
        "sbb r12, r10;\n"
        "sbb r13, rbx;\n"
        "sbb r8, 0x0;\n"
        "sbb r9, 0x0;\n"
        "mov r10, rdx;\n"
        "sbb r10, 0x0;\n"
        "mov rdx, r11;\n"
        "shl rdx, 0x20;\n"
        "add rdx, r11;\n"
        "mov rax, 0xffffffff00000001;\n"
        "mulx rax, r11, rax;\n"
        "mov ebx, 0xffffffff;\n"
        "mulx r11, rbx, rbx;\n"
        "add rax, rbx;\n"
        "adc r11, rdx;\n"
        "mov ebx, 0x0;\n"
        "adc rbx, rbx;\n"
        "sub r12, rax;\n"
        "sbb r13, r11;\n"
        "sbb r8, rbx;\n"
        "sbb r9, 0x0;\n"
        "sbb r10, 0x0;\n"
        "mov r11, rdx;\n"
        "sbb r11, 0x0;\n"
        "mov rdx, r12;\n"
        "shl rdx, 0x20;\n"
        "add rdx, r12;\n"
        "mov rax, 0xffffffff00000001;\n"
        "mulx rax, r12, rax;\n"
        "mov ebx, 0xffffffff;\n"
        "mulx r12, rbx, rbx;\n"
        "add rax, rbx;\n"
        "adc r12, rdx;\n"
        "mov ebx, 0x0;\n"
        "adc rbx, rbx;\n"
        "sub r13, rax;\n"
        "sbb r8, r12;\n"
        "sbb r9, rbx;\n"
        "sbb r10, 0x0;\n"
        "sbb r11, 0x0;\n"
        "mov r12, rdx;\n"
        "sbb r12, 0x0;\n"
        "mov rdx, r13;\n"
        "shl rdx, 0x20;\n"
        "add rdx, r13;\n"
        "mov rax, 0xffffffff00000001;\n"
        "mulx rax, r13, rax;\n"
        "mov ebx, 0xffffffff;\n"
        "mulx r13, rbx, rbx;\n"
        "add rax, rbx;\n"
        "adc r13, rdx;\n"
        "mov ebx, 0x0;\n"
        "adc rbx, rbx;\n"
        "sub r8, rax;\n"
        "sbb r9, r13;\n"
        "sbb r10, rbx;\n"
        "sbb r11, 0x0;\n"
        "sbb r12, 0x0;\n"
        "mov r13, rdx;\n"
        "sbb r13, 0x0;\n"
        "mov rbx, [" $P0 "];\n"
        "add r14, r8;\n"
        "adc r15, r9;\n"
        "adc rcx, r10;\n"
        "adc rbx, r11;\n"
        "adc rbp, r12;\n"
        "adc rsi, r13;\n"
        "mov r8d, 0x0;\n"
        "adc r8, r8;\n"
        "xor r11, r11;\n"
        "xor r12, r12;\n"
        "xor r13, r13;\n"
        "mov rax, 0xffffffff00000001;\n"
        "add rax, r14;\n"
        "mov r9d, 0xffffffff;\n"
        "adc r9, r15;\n"
        "mov r10d, 0x1;\n"
        "adc r10, rcx;\n"
        "adc r11, rbx;\n"
        "adc r12, rbp;\n"
        "adc r13, rsi;\n"
        "adc r8, 0x0;\n"
        "cmovne r14, rax;\n"
        "cmovne r15, r9;\n"
        "cmovne rcx, r10;\n"
        "cmovne rbx, r11;\n"
        "cmovne rbp, r12;\n"
        "cmovne rsi, r13;\n"
        "mov [" $P0 "], r14;\n"
        "mov [" $P0 "+ 0x8], r15;\n"
        "mov [" $P0 "+ 0x10], rcx;\n"
        "mov [" $P0 "+ 0x18], rbx;\n"
        "mov [" $P0 "+ 0x20], rbp;\n"
        "mov [" $P0 "+ 0x28], rsi"
    )}
}

// Almost-Montgomery variant which we use when an input to other muls
// with the other argument fully reduced (which is always safe).

macro_rules! amontsqr_p384 {
    ($P0:expr, $P1:expr) => { Q!(
        "mov rdx, [" $P1 "];\n"
        "mulx r10, r9, [" $P1 "+ 0x8];\n"
        "mulx r12, r11, [" $P1 "+ 0x18];\n"
        "mulx r14, r13, [" $P1 "+ 0x28];\n"
        "mov rdx, [" $P1 "+ 0x18];\n"
        "mulx rcx, r15, [" $P1 "+ 0x20];\n"
        "xor ebp, ebp;\n"
        "mov rdx, [" $P1 "+ 0x10];\n"
        "mulx rbx, rax, [" $P1 "];\n"
        "adcx r10, rax;\n"
        "adox r11, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x8];\n"
        "adcx r11, rax;\n"
        "adox r12, rbx;\n"
        "mov rdx, [" $P1 "+ 0x8];\n"
        "mulx rbx, rax, [" $P1 "+ 0x18];\n"
        "adcx r12, rax;\n"
        "adox r13, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x20];\n"
        "adcx r13, rax;\n"
        "adox r14, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x28];\n"
        "adcx r14, rax;\n"
        "adox r15, rbx;\n"
        "adcx r15, rbp;\n"
        "adox rcx, rbp;\n"
        "adc rcx, rbp;\n"
        "xor ebp, ebp;\n"
        "mov rdx, [" $P1 "+ 0x20];\n"
        "mulx rbx, rax, [" $P1 "];\n"
        "adcx r12, rax;\n"
        "adox r13, rbx;\n"
        "mov rdx, [" $P1 "+ 0x10];\n"
        "mulx rbx, rax, [" $P1 "+ 0x18];\n"
        "adcx r13, rax;\n"
        "adox r14, rbx;\n"
        "mulx rbx, rax, [" $P1 "+ 0x20];\n"
        "adcx r14, rax;\n"
        "adox r15, rbx;\n"
        "mulx rdx, rax, [" $P1 "+ 0x28];\n"
        "adcx r15, rax;\n"
        "adox rcx, rdx;\n"
        "mov rdx, [" $P1 "+ 0x28];\n"
        "mulx rbp, rbx, [" $P1 "+ 0x20];\n"
        "mulx rdx, rax, [" $P1 "+ 0x18];\n"
        "adcx rcx, rax;\n"
        "adox rbx, rdx;\n"
        "mov eax, 0x0;\n"
        "adcx rbx, rax;\n"
        "adox rbp, rax;\n"
        "adc rbp, rax;\n"
        "xor rax, rax;\n"
        "mov rdx, [" $P1 "];\n"
        "mulx rax, r8, [" $P1 "];\n"
        "adcx r9, r9;\n"
        "adox r9, rax;\n"
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
        "mulx rdx, rax, rdx;\n"
        "adcx r14, r14;\n"
        "adox r14, rax;\n"
        "adcx r15, r15;\n"
        "adox r15, rdx;\n"
        "mov rdx, [" $P1 "+ 0x20];\n"
        "mulx rdx, rax, rdx;\n"
        "adcx rcx, rcx;\n"
        "adox rcx, rax;\n"
        "adcx rbx, rbx;\n"
        "adox rbx, rdx;\n"
        "mov rdx, [" $P1 "+ 0x28];\n"
        "mulx rsi, rax, rdx;\n"
        "adcx rbp, rbp;\n"
        "adox rbp, rax;\n"
        "mov eax, 0x0;\n"
        "adcx rsi, rax;\n"
        "adox rsi, rax;\n"
        "mov [" $P0 "], rbx;\n"
        "mov rdx, r8;\n"
        "shl rdx, 0x20;\n"
        "add rdx, r8;\n"
        "mov rax, 0xffffffff00000001;\n"
        "mulx rax, r8, rax;\n"
        "mov ebx, 0xffffffff;\n"
        "mulx r8, rbx, rbx;\n"
        "add rax, rbx;\n"
        "adc r8, rdx;\n"
        "mov ebx, 0x0;\n"
        "adc rbx, rbx;\n"
        "sub r9, rax;\n"
        "sbb r10, r8;\n"
        "sbb r11, rbx;\n"
        "sbb r12, 0x0;\n"
        "sbb r13, 0x0;\n"
        "mov r8, rdx;\n"
        "sbb r8, 0x0;\n"
        "mov rdx, r9;\n"
        "shl rdx, 0x20;\n"
        "add rdx, r9;\n"
        "mov rax, 0xffffffff00000001;\n"
        "mulx rax, r9, rax;\n"
        "mov ebx, 0xffffffff;\n"
        "mulx r9, rbx, rbx;\n"
        "add rax, rbx;\n"
        "adc r9, rdx;\n"
        "mov ebx, 0x0;\n"
        "adc rbx, rbx;\n"
        "sub r10, rax;\n"
        "sbb r11, r9;\n"
        "sbb r12, rbx;\n"
        "sbb r13, 0x0;\n"
        "sbb r8, 0x0;\n"
        "mov r9, rdx;\n"
        "sbb r9, 0x0;\n"
        "mov rdx, r10;\n"
        "shl rdx, 0x20;\n"
        "add rdx, r10;\n"
        "mov rax, 0xffffffff00000001;\n"
        "mulx rax, r10, rax;\n"
        "mov ebx, 0xffffffff;\n"
        "mulx r10, rbx, rbx;\n"
        "add rax, rbx;\n"
        "adc r10, rdx;\n"
        "mov ebx, 0x0;\n"
        "adc rbx, rbx;\n"
        "sub r11, rax;\n"
        "sbb r12, r10;\n"
        "sbb r13, rbx;\n"
        "sbb r8, 0x0;\n"
        "sbb r9, 0x0;\n"
        "mov r10, rdx;\n"
        "sbb r10, 0x0;\n"
        "mov rdx, r11;\n"
        "shl rdx, 0x20;\n"
        "add rdx, r11;\n"
        "mov rax, 0xffffffff00000001;\n"
        "mulx rax, r11, rax;\n"
        "mov ebx, 0xffffffff;\n"
        "mulx r11, rbx, rbx;\n"
        "add rax, rbx;\n"
        "adc r11, rdx;\n"
        "mov ebx, 0x0;\n"
        "adc rbx, rbx;\n"
        "sub r12, rax;\n"
        "sbb r13, r11;\n"
        "sbb r8, rbx;\n"
        "sbb r9, 0x0;\n"
        "sbb r10, 0x0;\n"
        "mov r11, rdx;\n"
        "sbb r11, 0x0;\n"
        "mov rdx, r12;\n"
        "shl rdx, 0x20;\n"
        "add rdx, r12;\n"
        "mov rax, 0xffffffff00000001;\n"
        "mulx rax, r12, rax;\n"
        "mov ebx, 0xffffffff;\n"
        "mulx r12, rbx, rbx;\n"
        "add rax, rbx;\n"
        "adc r12, rdx;\n"
        "mov ebx, 0x0;\n"
        "adc rbx, rbx;\n"
        "sub r13, rax;\n"
        "sbb r8, r12;\n"
        "sbb r9, rbx;\n"
        "sbb r10, 0x0;\n"
        "sbb r11, 0x0;\n"
        "mov r12, rdx;\n"
        "sbb r12, 0x0;\n"
        "mov rdx, r13;\n"
        "shl rdx, 0x20;\n"
        "add rdx, r13;\n"
        "mov rax, 0xffffffff00000001;\n"
        "mulx rax, r13, rax;\n"
        "mov ebx, 0xffffffff;\n"
        "mulx r13, rbx, rbx;\n"
        "add rax, rbx;\n"
        "adc r13, rdx;\n"
        "mov ebx, 0x0;\n"
        "adc rbx, rbx;\n"
        "sub r8, rax;\n"
        "sbb r9, r13;\n"
        "sbb r10, rbx;\n"
        "sbb r11, 0x0;\n"
        "sbb r12, 0x0;\n"
        "mov r13, rdx;\n"
        "sbb r13, 0x0;\n"
        "mov rbx, [" $P0 "];\n"
        "add r14, r8;\n"
        "adc r15, r9;\n"
        "adc rcx, r10;\n"
        "adc rbx, r11;\n"
        "adc rbp, r12;\n"
        "adc rsi, r13;\n"
        "mov r8d, 0x0;\n"
        "mov rax, 0xffffffff00000001;\n"
        "mov r9d, 0xffffffff;\n"
        "mov r10d, 0x1;\n"
        "cmovnc rax, r8;\n"
        "cmovnc r9, r8;\n"
        "cmovnc r10, r8;\n"
        "add r14, rax;\n"
        "adc r15, r9;\n"
        "adc rcx, r10;\n"
        "adc rbx, r8;\n"
        "adc rbp, r8;\n"
        "adc rsi, r8;\n"
        "mov [" $P0 "], r14;\n"
        "mov [" $P0 "+ 0x8], r15;\n"
        "mov [" $P0 "+ 0x10], rcx;\n"
        "mov [" $P0 "+ 0x18], rbx;\n"
        "mov [" $P0 "+ 0x20], rbp;\n"
        "mov [" $P0 "+ 0x28], rsi"
    )}
}

// Corresponds exactly to bignum_sub_p384

macro_rules! sub_p384 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "mov rax, [" $P1 "];\n"
        "sub rax, [" $P2 "];\n"
        "mov rdx, [" $P1 "+ 0x8];\n"
        "sbb rdx, [" $P2 "+ 0x8];\n"
        "mov r8, [" $P1 "+ 0x10];\n"
        "sbb r8, [" $P2 "+ 0x10];\n"
        "mov r9, [" $P1 "+ 0x18];\n"
        "sbb r9, [" $P2 "+ 0x18];\n"
        "mov r10, [" $P1 "+ 0x20];\n"
        "sbb r10, [" $P2 "+ 0x20];\n"
        "mov r11, [" $P1 "+ 0x28];\n"
        "sbb r11, [" $P2 "+ 0x28];\n"
        "sbb rcx, rcx;\n"
        "mov esi, 0xffffffff;\n"
        "and rcx, rsi;\n"
        "xor rsi, rsi;\n"
        "sub rsi, rcx;\n"
        "sub rax, rsi;\n"
        "mov [" $P0 "], rax;\n"
        "sbb rdx, rcx;\n"
        "mov [" $P0 "+ 0x8], rdx;\n"
        "sbb rax, rax;\n"
        "and rcx, rsi;\n"
        "neg rax;\n"
        "sbb r8, rcx;\n"
        "mov [" $P0 "+ 0x10], r8;\n"
        "sbb r9, 0x0;\n"
        "mov [" $P0 "+ 0x18], r9;\n"
        "sbb r10, 0x0;\n"
        "mov [" $P0 "+ 0x20], r10;\n"
        "sbb r11, 0x0;\n"
        "mov [" $P0 "+ 0x28], r11"
    )}
}

// Additional macros to help with final multiplexing

macro_rules! testzero6 {
    ($P:expr) => { Q!(
        "mov rax, [" $P "];\n"
        "mov rdx, [" $P "+ 8];\n"
        "or rax, [" $P "+ 16];\n"
        "or rdx, [" $P "+ 24];\n"
        "or rax, [" $P "+ 32];\n"
        "or rdx, [" $P "+ 40];\n"
        "or rax, rdx"
    )}
}

macro_rules! mux6 {
    ($r0:expr, $r1:expr, $r2:expr, $r3:expr, $r4:expr, $r5:expr, $PNE:expr, $PEQ:expr) => { Q!(
        "mov rax, [" $PEQ "];\n"
        "mov " $r0 ", [" $PNE "];\n"
        "cmovz " $r0 ", rax;\n"
        "mov rax, [" $PEQ "+ 8];\n"
        "mov " $r1 ", [" $PNE "+ 8];\n"
        "cmovz " $r1 ", rax;\n"
        "mov rax, [" $PEQ "+ 16];\n"
        "mov " $r2 ", [" $PNE "+ 16];\n"
        "cmovz " $r2 ", rax;\n"
        "mov rax, [" $PEQ "+ 24];\n"
        "mov " $r3 ", [" $PNE "+ 24];\n"
        "cmovz " $r3 ", rax;\n"
        "mov rax, [" $PEQ "+ 32];\n"
        "mov " $r4 ", [" $PNE "+ 32];\n"
        "cmovz " $r4 ", rax;\n"
        "mov rax, [" $PEQ "+ 40];\n"
        "mov " $r5 ", [" $PNE "+ 40];\n"
        "cmovz " $r5 ", rax"
    )}
}

macro_rules! load6 {
    ($r0:expr, $r1:expr, $r2:expr, $r3:expr, $r4:expr, $r5:expr, $P:expr) => { Q!(
        "mov " $r0 ", [" $P "];\n"
        "mov " $r1 ", [" $P "+ 8];\n"
        "mov " $r2 ", [" $P "+ 16];\n"
        "mov " $r3 ", [" $P "+ 24];\n"
        "mov " $r4 ", [" $P "+ 32];\n"
        "mov " $r5 ", [" $P "+ 40]"
    )}
}

macro_rules! store6 {
    ($P:expr, $r0:expr, $r1:expr, $r2:expr, $r3:expr, $r4:expr, $r5:expr) => { Q!(
        "mov [" $P "], " $r0 ";\n"
        "mov [" $P "+ 8], " $r1 ";\n"
        "mov [" $P "+ 16], " $r2 ";\n"
        "mov [" $P "+ 24], " $r3 ";\n"
        "mov [" $P "+ 32], " $r4 ";\n"
        "mov [" $P "+ 40], " $r5
    )}
}

pub fn p384_montjmixadd(p3: &mut [u64; 18], p1: &[u64; 18], p2: &[u64; 12]) {
    unsafe {
        core::arch::asm!(



        // Save registers and make room on stack for temporary variables
        // Put the input arguments in non-volatile places on the stack

        Q!("    push            " "rbx"),
        Q!("    push            " "rbp"),
        Q!("    push            " "r12"),
        Q!("    push            " "r13"),
        Q!("    push            " "r14"),
        Q!("    push            " "r15"),

        Q!("    sub             " "rsp, " NSPACE!()),

        Q!("    mov             " input_x!() ", rsi"),
        Q!("    mov             " input_y!() ", rdx"),

        // Main code, just a sequence of basic field operations
        // 8 * multiply + 3 * square + 7 * subtract

        amontsqr_p384!(zp2!(), z_1!()),

        Q!("    mov             " "rsi, " input_x!()),
        Q!("    mov             " "rcx, " input_y!()),
        montmul_p384!(y2a!(), z_1!(), y_2!()),

        Q!("    mov             " "rcx, " input_y!()),
        montmul_p384!(x2a!(), zp2!(), x_2!()),

        montmul_p384!(y2a!(), zp2!(), y2a!()),

        Q!("    mov             " "rsi, " input_x!()),
        sub_p384!(xd!(), x2a!(), x_1!()),
        Q!("    mov             " "rsi, " input_x!()),
        sub_p384!(yd!(), y2a!(), y_1!()),

        amontsqr_p384!(zz!(), xd!()),
        montsqr_p384!(ww!(), yd!()),

        Q!("    mov             " "rsi, " input_x!()),
        montmul_p384!(zzx1!(), zz!(), x_1!()),
        montmul_p384!(zzx2!(), zz!(), x2a!()),

        sub_p384!(resx!(), ww!(), zzx1!()),
        sub_p384!(t1!(), zzx2!(), zzx1!()),

        Q!("    mov             " "rsi, " input_x!()),
        montmul_p384!(resz!(), xd!(), z_1!()),

        sub_p384!(resx!(), resx!(), zzx2!()),

        sub_p384!(t2!(), zzx1!(), resx!()),

        Q!("    mov             " "rsi, " input_x!()),
        montmul_p384!(t1!(), t1!(), y_1!()),
        montmul_p384!(t2!(), yd!(), t2!()),

        sub_p384!(resy!(), t2!(), t1!()),

        // Test if z_1 = 0 to decide if p1 = 0 (up to projective equivalence)

        Q!("    mov             " "rsi, " input_x!()),
        testzero6!(z_1!()),

        // Multiplex: if p1 <> 0 just copy the computed result from the staging area.
        // If p1 = 0 then return the point p2 augmented with a z = 1 coordinate (in
        // Montgomery form so not the simple constant 1 but rather 2^384 - p_384),
        // hence giving 0 + p2 = p2 for the final result.

        Q!("    mov             " "rcx, " input_y!()),
        mux6!("r8", "r9", "r10", "r11", "rbx", "rbp", resx!(), x_2!()),
        mux6!("r12", "r13", "r14", "r15", "rdx", "rcx", resy!(), y_2!()),

        store6!(x_3!(), "r8", "r9", "r10", "r11", "rbx", "rbp"),
        store6!(y_3!(), "r12", "r13", "r14", "r15", "rdx", "rcx"),

        load6!("r8", "r9", "r10", "r11", "rbx", "rbp", resz!()),
        Q!("    mov             " "rax, 0xffffffff00000001"),
        Q!("    cmovz           " "r8, rax"),
        Q!("    mov             " "eax, 0x00000000ffffffff"),
        Q!("    cmovz           " "r9, rax"),
        Q!("    mov             " "rax, 1"),
        Q!("    cmovz           " "r10, rax"),
        Q!("    mov             " "eax, 0"),
        Q!("    cmovz           " "r11, rax"),
        Q!("    cmovz           " "rbx, rax"),
        Q!("    cmovz           " "rbp, rax"),

        store6!(z_3!(), "r8", "r9", "r10", "r11", "rbx", "rbp"),

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
