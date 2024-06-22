
/// takes a sequence of expressions, and feeds them into
/// concat!() to form a single string
///
/// named after perl's q operator. lol.
macro_rules! Q {
    ($($e:expr)*) => {
        concat!($($e ,)*)
    };
}

/// Label macro, which just resolves to the id as a string,
/// but keeps the name close to it in the code.
macro_rules! Label {
    ($name:literal, $id:literal) => {
        stringify!($id)
    };

    ($name:literal, $id:literal, After) => {
        stringify!($id f)
    };

    ($name:literal, $id:literal, Before) => {
        stringify!($id b)
    }
}
        
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// The x25519 function for curve25519 on base element 9
// Input scalar[4]; output res[4]
// 
// extern void curve25519_x25519base
//   (uint64_t res[static 4],uint64_t scalar[static 4])
// 
// The function has a second prototype considering the arguments as arrays
// of bytes rather than 64-bit words. The underlying code is the same, since
// the x86 platform is little-endian.
// 
// extern void curve25519_x25519base_byte
//   (uint8_t res[static 32],uint8_t scalar[static 32])
// 
// Given a scalar n, returns the X coordinate of n * G where G = (9,...) is
// the standard generator. The scalar is first slightly modified/mangled
// as specified in the relevant RFC (https://www.rfc-editor.org/rfc/rfc7748).
// 
// Standard x86-64 ABI: RDI = res, RSI = scalar
// Microsoft x64 ABI:   RCX = res, RDX = scalar
// ----------------------------------------------------------------------------


// Size of individual field elements

macro_rules! NUMSIZE { () => { Q!("32") } }

// Pointer-offset pairs for result and temporaries on stack with some aliasing.
// The result "resx" assumes the "res" pointer has been preloaded into rbp.

macro_rules! resx { () => { Q!("rbp + (0 * " NUMSIZE!() ")") } }

macro_rules! scalar { () => { Q!("rsp + (0 * " NUMSIZE!() ")") } }

macro_rules! tabent { () => { Q!("rsp + (1 * " NUMSIZE!() ")") } }
macro_rules! ymx_2 { () => { Q!("rsp + (1 * " NUMSIZE!() ")") } }
macro_rules! xpy_2 { () => { Q!("rsp + (2 * " NUMSIZE!() ")") } }
macro_rules! kxy_2 { () => { Q!("rsp + (3 * " NUMSIZE!() ")") } }

macro_rules! acc { () => { Q!("rsp + (4 * " NUMSIZE!() ")") } }
macro_rules! x_1 { () => { Q!("rsp + (4 * " NUMSIZE!() ")") } }
macro_rules! y_1 { () => { Q!("rsp + (5 * " NUMSIZE!() ")") } }
macro_rules! z_1 { () => { Q!("rsp + (6 * " NUMSIZE!() ")") } }
macro_rules! w_1 { () => { Q!("rsp + (7 * " NUMSIZE!() ")") } }
macro_rules! x_3 { () => { Q!("rsp + (4 * " NUMSIZE!() ")") } }
macro_rules! y_3 { () => { Q!("rsp + (5 * " NUMSIZE!() ")") } }
macro_rules! z_3 { () => { Q!("rsp + (6 * " NUMSIZE!() ")") } }
macro_rules! w_3 { () => { Q!("rsp + (7 * " NUMSIZE!() ")") } }

macro_rules! tmpspace { () => { Q!("rsp + (8 * " NUMSIZE!() ")") } }
macro_rules! t0 { () => { Q!("rsp + (8 * " NUMSIZE!() ")") } }
macro_rules! t1 { () => { Q!("rsp + (9 * " NUMSIZE!() ")") } }
macro_rules! t2 { () => { Q!("rsp + (10 * " NUMSIZE!() ")") } }
macro_rules! t3 { () => { Q!("rsp + (11 * " NUMSIZE!() ")") } }
macro_rules! t4 { () => { Q!("rsp + (12 * " NUMSIZE!() ")") } }
macro_rules! t5 { () => { Q!("rsp + (13 * " NUMSIZE!() ")") } }

// Stable homes for the input result pointer, and other variables

macro_rules! res { () => { Q!("QWORD PTR [rsp + 14 * " NUMSIZE!() "]") } }

macro_rules! i { () => { Q!("QWORD PTR [rsp + 14 * " NUMSIZE!() "+ 8]") } }

macro_rules! bias { () => { Q!("QWORD PTR [rsp + 14 * " NUMSIZE!() "+ 16]") } }

macro_rules! bf { () => { Q!("QWORD PTR [rsp + 14 * " NUMSIZE!() "+ 24]") } }
macro_rules! ix { () => { Q!("QWORD PTR [rsp + 14 * " NUMSIZE!() "+ 24]") } }

macro_rules! tab { () => { Q!("QWORD PTR [rsp + 15 * " NUMSIZE!() "]") } }

// Total size to reserve on the stack

macro_rules! NSPACE { () => { Q!("(15 * " NUMSIZE!() "+ 8)") } }

// Macro wrapping up the basic field multiplication, only trivially
// different from a pure function call to bignum_mul_p25519.

macro_rules! mul_p25519 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "xor esi, esi;"
        "mov rdx, [" $P2 "];"
        "mulx r9, r8, [" $P1 "];"
        "mulx r10, rax, [" $P1 "+ 0x8];"
        "add r9, rax;"
        "mulx r11, rax, [" $P1 "+ 0x10];"
        "adc r10, rax;"
        "mulx r12, rax, [" $P1 "+ 0x18];"
        "adc r11, rax;"
        "adc r12, rsi;"
        "xor esi, esi;"
        "mov rdx, [" $P2 "+ 0x8];"
        "mulx rbx, rax, [" $P1 "];"
        "adcx r9, rax;"
        "adox r10, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x8];"
        "adcx r10, rax;"
        "adox r11, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x10];"
        "adcx r11, rax;"
        "adox r12, rbx;"
        "mulx r13, rax, [" $P1 "+ 0x18];"
        "adcx r12, rax;"
        "adox r13, rsi;"
        "adcx r13, rsi;"
        "xor esi, esi;"
        "mov rdx, [" $P2 "+ 0x10];"
        "mulx rbx, rax, [" $P1 "];"
        "adcx r10, rax;"
        "adox r11, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x8];"
        "adcx r11, rax;"
        "adox r12, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x10];"
        "adcx r12, rax;"
        "adox r13, rbx;"
        "mulx r14, rax, [" $P1 "+ 0x18];"
        "adcx r13, rax;"
        "adox r14, rsi;"
        "adcx r14, rsi;"
        "xor esi, esi;"
        "mov rdx, [" $P2 "+ 0x18];"
        "mulx rbx, rax, [" $P1 "];"
        "adcx r11, rax;"
        "adox r12, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x8];"
        "adcx r12, rax;"
        "adox r13, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x10];"
        "adcx r13, rax;"
        "adox r14, rbx;"
        "mulx r15, rax, [" $P1 "+ 0x18];"
        "adcx r14, rax;"
        "adox r15, rsi;"
        "adcx r15, rsi;"
        "mov edx, 0x26;"
        "xor esi, esi;"
        "mulx rbx, rax, r12;"
        "adcx r8, rax;"
        "adox r9, rbx;"
        "mulx rbx, rax, r13;"
        "adcx r9, rax;"
        "adox r10, rbx;"
        "mulx rbx, rax, r14;"
        "adcx r10, rax;"
        "adox r11, rbx;"
        "mulx r12, rax, r15;"
        "adcx r11, rax;"
        "adox r12, rsi;"
        "adcx r12, rsi;"
        "shld r12, r11, 0x1;"
        "mov edx, 0x13;"
        "inc r12;"
        "bts r11, 63;"
        "mulx rbx, rax, r12;"
        "add r8, rax;"
        "adc r9, rbx;"
        "adc r10, rsi;"
        "adc r11, rsi;"
        "sbb rax, rax;"
        "not rax;"
        "and rax, rdx;"
        "sub r8, rax;"
        "sbb r9, rsi;"
        "sbb r10, rsi;"
        "sbb r11, rsi;"
        "btr r11, 63;"
        "mov [" $P0 "], r8;"
        "mov [" $P0 "+ 0x8], r9;"
        "mov [" $P0 "+ 0x10], r10;"
        "mov [" $P0 "+ 0x18], r11"
    )}
}

// A version of multiplication that only guarantees output < 2 * p_25519.
// This basically skips the +1 and final correction in quotient estimation.

macro_rules! mul_4 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "xor ecx, ecx;"
        "mov rdx, [" $P2 "];"
        "mulx r9, r8, [" $P1 "];"
        "mulx r10, rax, [" $P1 "+ 0x8];"
        "add r9, rax;"
        "mulx r11, rax, [" $P1 "+ 0x10];"
        "adc r10, rax;"
        "mulx r12, rax, [" $P1 "+ 0x18];"
        "adc r11, rax;"
        "adc r12, rcx;"
        "xor ecx, ecx;"
        "mov rdx, [" $P2 "+ 0x8];"
        "mulx rbx, rax, [" $P1 "];"
        "adcx r9, rax;"
        "adox r10, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x8];"
        "adcx r10, rax;"
        "adox r11, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x10];"
        "adcx r11, rax;"
        "adox r12, rbx;"
        "mulx r13, rax, [" $P1 "+ 0x18];"
        "adcx r12, rax;"
        "adox r13, rcx;"
        "adcx r13, rcx;"
        "xor ecx, ecx;"
        "mov rdx, [" $P2 "+ 0x10];"
        "mulx rbx, rax, [" $P1 "];"
        "adcx r10, rax;"
        "adox r11, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x8];"
        "adcx r11, rax;"
        "adox r12, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x10];"
        "adcx r12, rax;"
        "adox r13, rbx;"
        "mulx r14, rax, [" $P1 "+ 0x18];"
        "adcx r13, rax;"
        "adox r14, rcx;"
        "adcx r14, rcx;"
        "xor ecx, ecx;"
        "mov rdx, [" $P2 "+ 0x18];"
        "mulx rbx, rax, [" $P1 "];"
        "adcx r11, rax;"
        "adox r12, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x8];"
        "adcx r12, rax;"
        "adox r13, rbx;"
        "mulx rbx, rax, [" $P1 "+ 0x10];"
        "adcx r13, rax;"
        "adox r14, rbx;"
        "mulx r15, rax, [" $P1 "+ 0x18];"
        "adcx r14, rax;"
        "adox r15, rcx;"
        "adcx r15, rcx;"
        "mov edx, 0x26;"
        "xor ecx, ecx;"
        "mulx rbx, rax, r12;"
        "adcx r8, rax;"
        "adox r9, rbx;"
        "mulx rbx, rax, r13;"
        "adcx r9, rax;"
        "adox r10, rbx;"
        "mulx rbx, rax, r14;"
        "adcx r10, rax;"
        "adox r11, rbx;"
        "mulx r12, rax, r15;"
        "adcx r11, rax;"
        "adox r12, rcx;"
        "adcx r12, rcx;"
        "shld r12, r11, 0x1;"
        "btr r11, 0x3f;"
        "mov edx, 0x13;"
        "imul rdx, r12;"
        "add r8, rdx;"
        "adc r9, rcx;"
        "adc r10, rcx;"
        "adc r11, rcx;"
        "mov [" $P0 "], r8;"
        "mov [" $P0 "+ 0x8], r9;"
        "mov [" $P0 "+ 0x10], r10;"
        "mov [" $P0 "+ 0x18], r11"
    )}
}

// Modular subtraction with double modulus 2 * p_25519 = 2^256 - 38

macro_rules! sub_twice4 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "mov r8, [" $P1 "];"
        "xor ebx, ebx;"
        "sub r8, [" $P2 "];"
        "mov r9, [" $P1 "+ 8];"
        "sbb r9, [" $P2 "+ 8];"
        "mov ecx, 38;"
        "mov r10, [" $P1 "+ 16];"
        "sbb r10, [" $P2 "+ 16];"
        "mov rax, [" $P1 "+ 24];"
        "sbb rax, [" $P2 "+ 24];"
        "cmovnc rcx, rbx;"
        "sub r8, rcx;"
        "sbb r9, rbx;"
        "sbb r10, rbx;"
        "sbb rax, rbx;"
        "mov [" $P0 "], r8;"
        "mov [" $P0 "+ 8], r9;"
        "mov [" $P0 "+ 16], r10;"
        "mov [" $P0 "+ 24], rax"
    )}
}

// Modular addition and doubling with double modulus 2 * p_25519 = 2^256 - 38.
// This only ensures that the result fits in 4 digits, not that it is reduced
// even w.r.t. double modulus. The result is always correct modulo provided
// the sum of the inputs is < 2^256 + 2^256 - 38, so in particular provided
// at least one of them is reduced double modulo.

macro_rules! add_twice4 {
    ($P0:expr, $P1:expr, $P2:expr) => { Q!(
        "mov r8, [" $P1 "];"
        "xor ecx, ecx;"
        "add r8, [" $P2 "];"
        "mov r9, [" $P1 "+ 0x8];"
        "adc r9, [" $P2 "+ 0x8];"
        "mov r10, [" $P1 "+ 0x10];"
        "adc r10, [" $P2 "+ 0x10];"
        "mov r11, [" $P1 "+ 0x18];"
        "adc r11, [" $P2 "+ 0x18];"
        "mov eax, 38;"
        "cmovnc rax, rcx;"
        "add r8, rax;"
        "adc r9, rcx;"
        "adc r10, rcx;"
        "adc r11, rcx;"
        "mov [" $P0 "], r8;"
        "mov [" $P0 "+ 0x8], r9;"
        "mov [" $P0 "+ 0x10], r10;"
        "mov [" $P0 "+ 0x18], r11"
    )}
}

macro_rules! double_twice4 {
    ($P0:expr, $P1:expr) => { Q!(
        "mov r8, [" $P1 "];"
        "xor ecx, ecx;"
        "add r8, r8;"
        "mov r9, [" $P1 "+ 0x8];"
        "adc r9, r9;"
        "mov r10, [" $P1 "+ 0x10];"
        "adc r10, r10;"
        "mov r11, [" $P1 "+ 0x18];"
        "adc r11, r11;"
        "mov eax, 38;"
        "cmovnc rax, rcx;"
        "add r8, rax;"
        "adc r9, rcx;"
        "adc r10, rcx;"
        "adc r11, rcx;"
        "mov [" $P0 "], r8;"
        "mov [" $P0 "+ 0x8], r9;"
        "mov [" $P0 "+ 0x10], r10;"
        "mov [" $P0 "+ 0x18], r11"
    )}
}


// In this case the Windows form literally makes a subroutine call.
// This avoids hassle arising from keeping code and data together.



// Save registers, make room for temps, preserve input arguments.

Q!("    push      " "rbx"),
Q!("    push      " "rbp"),
Q!("    push      " "r12"),
Q!("    push      " "r13"),
Q!("    push      " "r14"),
Q!("    push      " "r15"),
Q!("    sub       " "rsp, " NSPACE!()),

// Move the output pointer to a stable place

Q!("    mov       " res!() ", rdi"),

// Copy the input scalar to its local variable while mangling it.
// In principle the mangling is into 01xxx...xxx000, but actually
// we only clear the top two bits so 00xxx...xxxxxx. The additional
// 2^254 * G is taken care of by the starting value for the addition
// chain below, while we never look at the three low bits at all.

Q!("    mov       " "rax, [rsi]"),
Q!("    mov       " "[rsp], rax"),
Q!("    mov       " "rax, [rsi + 8]"),
Q!("    mov       " "[rsp + 8], rax"),
Q!("    mov       " "rax, [rsi + 16]"),
Q!("    mov       " "[rsp + 16], rax"),
Q!("    mov       " "rax, 0x3fffffffffffffff"),
Q!("    and       " "rax, [rsi + 24]"),
Q!("    mov       " "[rsp + 24], rax"),

// The main part of the computation is on the edwards25519 curve in
// extended-projective coordinates (X,Y,Z,T), representing a point
// (x,y) via x = X/Z, y = Y/Z and x * y = T/Z (so X * Y = T * Z).
// Only at the very end do we translate back to curve25519. So G
// below means the generator within edwards25519 corresponding to
// (9,...) for curve25519, via the standard isomorphism.
// 
// Initialize accumulator "acc" to either (2^254 + 8) * G or just 2^254 * G
// depending on bit 3 of the scalar, the only nonzero bit of the bottom 4.
// Thus, we have effectively dealt with bits 0, 1, 2, 3, 254 and 255.

Q!("    mov       " "rax, [rsp]"),
Q!("    and       " "rax, 8"),

Q!("    lea       " "r10, [rip + " Label!("curve25519_x25519base_edwards25519_0g", 2, After) "]"),
Q!("    lea       " "r11, [rip + " Label!("curve25519_x25519base_edwards25519_8g", 3, After) "]"),

Q!("    mov       " "rax, [r10]"),
Q!("    mov       " "rcx, [r11]"),
Q!("    cmovnz    " "rax, rcx"),
Q!("    mov       " "[rsp + 8 * 16], rax"),

Q!("    mov       " "rax, [r10 + 8 * 1]"),
Q!("    mov       " "rcx, [r11 + 8 * 1]"),
Q!("    cmovnz    " "rax, rcx"),
Q!("    mov       " "[rsp + 8 * 17], rax"),

Q!("    mov       " "rax, [r10 + 8 * 2]"),
Q!("    mov       " "rcx, [r11 + 8 * 2]"),
Q!("    cmovnz    " "rax, rcx"),
Q!("    mov       " "[rsp + 8 * 18], rax"),

Q!("    mov       " "rax, [r10 + 8 * 3]"),
Q!("    mov       " "rcx, [r11 + 8 * 3]"),
Q!("    cmovnz    " "rax, rcx"),
Q!("    mov       " "[rsp + 8 * 19], rax"),

Q!("    mov       " "rax, [r10 + 8 * 4]"),
Q!("    mov       " "rcx, [r11 + 8 * 4]"),
Q!("    cmovnz    " "rax, rcx"),
Q!("    mov       " "[rsp + 8 * 20], rax"),

Q!("    mov       " "rax, [r10 + 8 * 5]"),
Q!("    mov       " "rcx, [r11 + 8 * 5]"),
Q!("    cmovnz    " "rax, rcx"),
Q!("    mov       " "[rsp + 8 * 21], rax"),

Q!("    mov       " "rax, [r10 + 8 * 6]"),
Q!("    mov       " "rcx, [r11 + 8 * 6]"),
Q!("    cmovnz    " "rax, rcx"),
Q!("    mov       " "[rsp + 8 * 22], rax"),

Q!("    mov       " "rax, [r10 + 8 * 7]"),
Q!("    mov       " "rcx, [r11 + 8 * 7]"),
Q!("    cmovnz    " "rax, rcx"),
Q!("    mov       " "[rsp + 8 * 23], rax"),

Q!("    mov       " "eax, 1"),
Q!("    mov       " "[rsp + 8 * 24], rax"),
Q!("    mov       " "eax, 0"),
Q!("    mov       " "[rsp + 8 * 25], rax"),
Q!("    mov       " "[rsp + 8 * 26], rax"),
Q!("    mov       " "[rsp + 8 * 27], rax"),

Q!("    mov       " "rax, [r10 + 8 * 8]"),
Q!("    mov       " "rcx, [r11 + 8 * 8]"),
Q!("    cmovnz    " "rax, rcx"),
Q!("    mov       " "[rsp + 8 * 28], rax"),

Q!("    mov       " "rax, [r10 + 8 * 9]"),
Q!("    mov       " "rcx, [r11 + 8 * 9]"),
Q!("    cmovnz    " "rax, rcx"),
Q!("    mov       " "[rsp + 8 * 29], rax"),

Q!("    mov       " "rax, [r10 + 8 * 10]"),
Q!("    mov       " "rcx, [r11 + 8 * 10]"),
Q!("    cmovnz    " "rax, rcx"),
Q!("    mov       " "[rsp + 8 * 30], rax"),

Q!("    mov       " "rax, [r10 + 8 * 11]"),
Q!("    mov       " "rcx, [r11 + 8 * 11]"),
Q!("    cmovnz    " "rax, rcx"),
Q!("    mov       " "[rsp + 8 * 31], rax"),

// The counter "i" tracks the bit position for which the scalar has
// already been absorbed, starting at 4 and going up in chunks of 4.
// 
// The pointer "tab" points at the current block of the table for
// multiples (2^i * j) * G at the current bit position i; 1 <= j <= 8.
// 
// The bias is always either 0 and 1 and needs to be added to the
// partially processed scalar implicitly. This is used to absorb 4 bits
// of scalar per iteration from 3-bit table indexing by exploiting
// negation: (16 * h + l) * G = (16 * (h + 1) - (16 - l)) * G is used
// when l >= 9. Note that we can't have any bias left over at the
// end because of the clearing of bit 255 of the scalar, meaning the
// l >= 9 case cannot arise on the last iteration.

Q!("    mov       " i!() ", 4"),
Q!("    lea       " "rax, [rip + " Label!("curve25519_x25519base_edwards25519_gtable", 4, After) "]"),
Q!("    mov       " tab!() ", rax"),
Q!("    mov       " bias!() ", 0"),

// Start of the main loop, repeated 63 times for i = 4, 8, ..., 252

Q!(Label!("curve25519_x25519base_scalarloop", 5) ":"),

// Look at the next 4-bit field "bf", adding the previous bias as well.
// Choose the table index "ix" as bf when bf <= 8 and 16 - bf for bf >= 9,
// setting the bias to 1 for the next iteration in the latter case.

Q!("    mov       " "rax, " i!()),
Q!("    mov       " "rcx, rax"),
Q!("    shr       " "rax, 6"),
Q!("    mov       " "rax, [rsp + 8 * rax]"),
Q!("    shr       " "rax, cl"),
Q!("    and       " "rax, 15"),
Q!("    add       " "rax, " bias!()),
Q!("    mov       " bf!() ", rax"),

Q!("    cmp       " bf!() ", 9"),
Q!("    sbb       " "rax, rax"),
Q!("    inc       " "rax"),
Q!("    mov       " bias!() ", rax"),

Q!("    mov       " "rdi, 16"),
Q!("    sub       " "rdi, " bf!()),
Q!("    cmp       " bias!() ", 0"),
Q!("    cmovz     " "rdi, " bf!()),
Q!("    mov       " ix!() ", rdi"),

// Perform constant-time lookup in the table to get element number "ix".
// The table entry for the affine point (x,y) is actually a triple
// (y - x,x + y,2 * d * x * y) to precompute parts of the addition.
// Note that "ix" can be 0, so we set up the appropriate identity first.

Q!("    mov       " "eax, 1"),
Q!("    xor       " "ebx, ebx"),
Q!("    xor       " "ecx, ecx"),
Q!("    xor       " "edx, edx"),
Q!("    mov       " "r8d, 1"),
Q!("    xor       " "r9d, r9d"),
Q!("    xor       " "r10d, r10d"),
Q!("    xor       " "r11d, r11d"),
Q!("    xor       " "r12d, r12d"),
Q!("    xor       " "r13d, r13d"),
Q!("    xor       " "r14d, r14d"),
Q!("    xor       " "r15d, r15d"),

Q!("    mov       " "rbp, " tab!()),

Q!("    cmp       " ix!() ", 1"),
Q!("    mov       " "rsi, [rbp]"),
Q!("    cmovz     " "rax, rsi"),
Q!("    mov       " "rsi, [rbp + 8]"),
Q!("    cmovz     " "rbx, rsi"),
Q!("    mov       " "rsi, [rbp + 16]"),
Q!("    cmovz     " "rcx, rsi"),
Q!("    mov       " "rsi, [rbp + 24]"),
Q!("    cmovz     " "rdx, rsi"),
Q!("    mov       " "rsi, [rbp + 32]"),
Q!("    cmovz     " "r8, rsi"),
Q!("    mov       " "rsi, [rbp + 40]"),
Q!("    cmovz     " "r9, rsi"),
Q!("    mov       " "rsi, [rbp + 48]"),
Q!("    cmovz     " "r10, rsi"),
Q!("    mov       " "rsi, [rbp + 56]"),
Q!("    cmovz     " "r11, rsi"),
Q!("    mov       " "rsi, [rbp + 64]"),
Q!("    cmovz     " "r12, rsi"),
Q!("    mov       " "rsi, [rbp + 72]"),
Q!("    cmovz     " "r13, rsi"),
Q!("    mov       " "rsi, [rbp + 80]"),
Q!("    cmovz     " "r14, rsi"),
Q!("    mov       " "rsi, [rbp + 88]"),
Q!("    cmovz     " "r15, rsi"),
Q!("    add       " "rbp, 96"),

Q!("    cmp       " ix!() ", 2"),
Q!("    mov       " "rsi, [rbp]"),
Q!("    cmovz     " "rax, rsi"),
Q!("    mov       " "rsi, [rbp + 8]"),
Q!("    cmovz     " "rbx, rsi"),
Q!("    mov       " "rsi, [rbp + 16]"),
Q!("    cmovz     " "rcx, rsi"),
Q!("    mov       " "rsi, [rbp + 24]"),
Q!("    cmovz     " "rdx, rsi"),
Q!("    mov       " "rsi, [rbp + 32]"),
Q!("    cmovz     " "r8, rsi"),
Q!("    mov       " "rsi, [rbp + 40]"),
Q!("    cmovz     " "r9, rsi"),
Q!("    mov       " "rsi, [rbp + 48]"),
Q!("    cmovz     " "r10, rsi"),
Q!("    mov       " "rsi, [rbp + 56]"),
Q!("    cmovz     " "r11, rsi"),
Q!("    mov       " "rsi, [rbp + 64]"),
Q!("    cmovz     " "r12, rsi"),
Q!("    mov       " "rsi, [rbp + 72]"),
Q!("    cmovz     " "r13, rsi"),
Q!("    mov       " "rsi, [rbp + 80]"),
Q!("    cmovz     " "r14, rsi"),
Q!("    mov       " "rsi, [rbp + 88]"),
Q!("    cmovz     " "r15, rsi"),
Q!("    add       " "rbp, 96"),

Q!("    cmp       " ix!() ", 3"),
Q!("    mov       " "rsi, [rbp]"),
Q!("    cmovz     " "rax, rsi"),
Q!("    mov       " "rsi, [rbp + 8]"),
Q!("    cmovz     " "rbx, rsi"),
Q!("    mov       " "rsi, [rbp + 16]"),
Q!("    cmovz     " "rcx, rsi"),
Q!("    mov       " "rsi, [rbp + 24]"),
Q!("    cmovz     " "rdx, rsi"),
Q!("    mov       " "rsi, [rbp + 32]"),
Q!("    cmovz     " "r8, rsi"),
Q!("    mov       " "rsi, [rbp + 40]"),
Q!("    cmovz     " "r9, rsi"),
Q!("    mov       " "rsi, [rbp + 48]"),
Q!("    cmovz     " "r10, rsi"),
Q!("    mov       " "rsi, [rbp + 56]"),
Q!("    cmovz     " "r11, rsi"),
Q!("    mov       " "rsi, [rbp + 64]"),
Q!("    cmovz     " "r12, rsi"),
Q!("    mov       " "rsi, [rbp + 72]"),
Q!("    cmovz     " "r13, rsi"),
Q!("    mov       " "rsi, [rbp + 80]"),
Q!("    cmovz     " "r14, rsi"),
Q!("    mov       " "rsi, [rbp + 88]"),
Q!("    cmovz     " "r15, rsi"),
Q!("    add       " "rbp, 96"),

Q!("    cmp       " ix!() ", 4"),
Q!("    mov       " "rsi, [rbp]"),
Q!("    cmovz     " "rax, rsi"),
Q!("    mov       " "rsi, [rbp + 8]"),
Q!("    cmovz     " "rbx, rsi"),
Q!("    mov       " "rsi, [rbp + 16]"),
Q!("    cmovz     " "rcx, rsi"),
Q!("    mov       " "rsi, [rbp + 24]"),
Q!("    cmovz     " "rdx, rsi"),
Q!("    mov       " "rsi, [rbp + 32]"),
Q!("    cmovz     " "r8, rsi"),
Q!("    mov       " "rsi, [rbp + 40]"),
Q!("    cmovz     " "r9, rsi"),
Q!("    mov       " "rsi, [rbp + 48]"),
Q!("    cmovz     " "r10, rsi"),
Q!("    mov       " "rsi, [rbp + 56]"),
Q!("    cmovz     " "r11, rsi"),
Q!("    mov       " "rsi, [rbp + 64]"),
Q!("    cmovz     " "r12, rsi"),
Q!("    mov       " "rsi, [rbp + 72]"),
Q!("    cmovz     " "r13, rsi"),
Q!("    mov       " "rsi, [rbp + 80]"),
Q!("    cmovz     " "r14, rsi"),
Q!("    mov       " "rsi, [rbp + 88]"),
Q!("    cmovz     " "r15, rsi"),
Q!("    add       " "rbp, 96"),

Q!("    cmp       " ix!() ", 5"),
Q!("    mov       " "rsi, [rbp]"),
Q!("    cmovz     " "rax, rsi"),
Q!("    mov       " "rsi, [rbp + 8]"),
Q!("    cmovz     " "rbx, rsi"),
Q!("    mov       " "rsi, [rbp + 16]"),
Q!("    cmovz     " "rcx, rsi"),
Q!("    mov       " "rsi, [rbp + 24]"),
Q!("    cmovz     " "rdx, rsi"),
Q!("    mov       " "rsi, [rbp + 32]"),
Q!("    cmovz     " "r8, rsi"),
Q!("    mov       " "rsi, [rbp + 40]"),
Q!("    cmovz     " "r9, rsi"),
Q!("    mov       " "rsi, [rbp + 48]"),
Q!("    cmovz     " "r10, rsi"),
Q!("    mov       " "rsi, [rbp + 56]"),
Q!("    cmovz     " "r11, rsi"),
Q!("    mov       " "rsi, [rbp + 64]"),
Q!("    cmovz     " "r12, rsi"),
Q!("    mov       " "rsi, [rbp + 72]"),
Q!("    cmovz     " "r13, rsi"),
Q!("    mov       " "rsi, [rbp + 80]"),
Q!("    cmovz     " "r14, rsi"),
Q!("    mov       " "rsi, [rbp + 88]"),
Q!("    cmovz     " "r15, rsi"),
Q!("    add       " "rbp, 96"),

Q!("    cmp       " ix!() ", 6"),
Q!("    mov       " "rsi, [rbp]"),
Q!("    cmovz     " "rax, rsi"),
Q!("    mov       " "rsi, [rbp + 8]"),
Q!("    cmovz     " "rbx, rsi"),
Q!("    mov       " "rsi, [rbp + 16]"),
Q!("    cmovz     " "rcx, rsi"),
Q!("    mov       " "rsi, [rbp + 24]"),
Q!("    cmovz     " "rdx, rsi"),
Q!("    mov       " "rsi, [rbp + 32]"),
Q!("    cmovz     " "r8, rsi"),
Q!("    mov       " "rsi, [rbp + 40]"),
Q!("    cmovz     " "r9, rsi"),
Q!("    mov       " "rsi, [rbp + 48]"),
Q!("    cmovz     " "r10, rsi"),
Q!("    mov       " "rsi, [rbp + 56]"),
Q!("    cmovz     " "r11, rsi"),
Q!("    mov       " "rsi, [rbp + 64]"),
Q!("    cmovz     " "r12, rsi"),
Q!("    mov       " "rsi, [rbp + 72]"),
Q!("    cmovz     " "r13, rsi"),
Q!("    mov       " "rsi, [rbp + 80]"),
Q!("    cmovz     " "r14, rsi"),
Q!("    mov       " "rsi, [rbp + 88]"),
Q!("    cmovz     " "r15, rsi"),
Q!("    add       " "rbp, 96"),

Q!("    cmp       " ix!() ", 7"),
Q!("    mov       " "rsi, [rbp]"),
Q!("    cmovz     " "rax, rsi"),
Q!("    mov       " "rsi, [rbp + 8]"),
Q!("    cmovz     " "rbx, rsi"),
Q!("    mov       " "rsi, [rbp + 16]"),
Q!("    cmovz     " "rcx, rsi"),
Q!("    mov       " "rsi, [rbp + 24]"),
Q!("    cmovz     " "rdx, rsi"),
Q!("    mov       " "rsi, [rbp + 32]"),
Q!("    cmovz     " "r8, rsi"),
Q!("    mov       " "rsi, [rbp + 40]"),
Q!("    cmovz     " "r9, rsi"),
Q!("    mov       " "rsi, [rbp + 48]"),
Q!("    cmovz     " "r10, rsi"),
Q!("    mov       " "rsi, [rbp + 56]"),
Q!("    cmovz     " "r11, rsi"),
Q!("    mov       " "rsi, [rbp + 64]"),
Q!("    cmovz     " "r12, rsi"),
Q!("    mov       " "rsi, [rbp + 72]"),
Q!("    cmovz     " "r13, rsi"),
Q!("    mov       " "rsi, [rbp + 80]"),
Q!("    cmovz     " "r14, rsi"),
Q!("    mov       " "rsi, [rbp + 88]"),
Q!("    cmovz     " "r15, rsi"),
Q!("    add       " "rbp, 96"),

Q!("    cmp       " ix!() ", 8"),
Q!("    mov       " "rsi, [rbp]"),
Q!("    cmovz     " "rax, rsi"),
Q!("    mov       " "rsi, [rbp + 8]"),
Q!("    cmovz     " "rbx, rsi"),
Q!("    mov       " "rsi, [rbp + 16]"),
Q!("    cmovz     " "rcx, rsi"),
Q!("    mov       " "rsi, [rbp + 24]"),
Q!("    cmovz     " "rdx, rsi"),
Q!("    mov       " "rsi, [rbp + 32]"),
Q!("    cmovz     " "r8, rsi"),
Q!("    mov       " "rsi, [rbp + 40]"),
Q!("    cmovz     " "r9, rsi"),
Q!("    mov       " "rsi, [rbp + 48]"),
Q!("    cmovz     " "r10, rsi"),
Q!("    mov       " "rsi, [rbp + 56]"),
Q!("    cmovz     " "r11, rsi"),
Q!("    mov       " "rsi, [rbp + 64]"),
Q!("    cmovz     " "r12, rsi"),
Q!("    mov       " "rsi, [rbp + 72]"),
Q!("    cmovz     " "r13, rsi"),
Q!("    mov       " "rsi, [rbp + 80]"),
Q!("    cmovz     " "r14, rsi"),
Q!("    mov       " "rsi, [rbp + 88]"),
Q!("    cmovz     " "r15, rsi"),

Q!("    add       " "rbp, 96"),
Q!("    mov       " tab!() ", rbp"),

// We now have the triple from the table in registers as follows
// 
//      [rdx;rcx;rbx;rax] = y - x
//      [r11;r10;r9;r8] = x + y
//      [r15;r14;r13;r12] = 2 * d * x * y
// 
// In case bias = 1 we need to negate this. For Edwards curves
// -(x,y) = (-x,y), i.e. we need to negate the x coordinate.
// In this processed encoding, that amounts to swapping the
// first two fields and negating the third.
// 
// The optional negation here also pretends bias = 0 whenever
// ix = 0 so that it doesn't need to handle the case of zero
// inputs, since no non-trivial table entries are zero. Note
// that in the zero case the whole negation is trivial, and
// so indeed is the swapping.

Q!("    cmp       " bias!() ", 0"),

Q!("    mov       " "rsi, rax"),
Q!("    cmovnz    " "rsi, r8"),
Q!("    cmovnz    " "r8, rax"),
Q!("    mov       " "[rsp + 32], rsi"),
Q!("    mov       " "[rsp + 64], r8"),

Q!("    mov       " "rsi, rbx"),
Q!("    cmovnz    " "rsi, r9"),
Q!("    cmovnz    " "r9, rbx"),
Q!("    mov       " "[rsp + 40], rsi"),
Q!("    mov       " "[rsp + 72], r9"),

Q!("    mov       " "rsi, rcx"),
Q!("    cmovnz    " "rsi, r10"),
Q!("    cmovnz    " "r10, rcx"),
Q!("    mov       " "[rsp + 48], rsi"),
Q!("    mov       " "[rsp + 80], r10"),

Q!("    mov       " "rsi, rdx"),
Q!("    cmovnz    " "rsi, r11"),
Q!("    cmovnz    " "r11, rdx"),
Q!("    mov       " "[rsp + 56], rsi"),
Q!("    mov       " "[rsp + 88], r11"),

Q!("    mov       " "rax, - 19"),
Q!("    mov       " "rbx, - 1"),
Q!("    mov       " "rcx, - 1"),
Q!("    mov       " "rdx, 0x7fffffffffffffff"),
Q!("    sub       " "rax, r12"),
Q!("    sbb       " "rbx, r13"),
Q!("    sbb       " "rcx, r14"),
Q!("    sbb       " "rdx, r15"),

Q!("    mov       " "r8, " ix!()),
Q!("    mov       " "r9, " bias!()),
Q!("    test      " "r8, r8"),
Q!("    cmovz     " "r9, r8"),
Q!("    test      " "r9, r9"),

Q!("    cmovz     " "rax, r12"),
Q!("    cmovz     " "rbx, r13"),
Q!("    cmovz     " "rcx, r14"),
Q!("    cmovz     " "rdx, r15"),
Q!("    mov       " "[rsp + 96], rax"),
Q!("    mov       " "[rsp + 104], rbx"),
Q!("    mov       " "[rsp + 112], rcx"),
Q!("    mov       " "[rsp + 120], rdx"),

// Extended-projective and precomputed mixed addition.
// This is effectively the same as calling the standalone
// function edwards25519_pepadd(acc,acc,tabent), but we
// only retain slightly weaker normalization < 2 * p_25519
// throughout the inner loop, so the computation is
// slightly different, and faster overall.

double_twice4!(t0!(), z_1!()),
sub_twice4!(t1!(), y_1!(), x_1!()),
add_twice4!(t2!(), y_1!(), x_1!()),
mul_4!(t3!(), w_1!(), kxy_2!()),
mul_4!(t1!(), t1!(), ymx_2!()),
mul_4!(t2!(), t2!(), xpy_2!()),
sub_twice4!(t4!(), t0!(), t3!()),
add_twice4!(t0!(), t0!(), t3!()),
sub_twice4!(t5!(), t2!(), t1!()),
add_twice4!(t1!(), t2!(), t1!()),
mul_4!(z_3!(), t4!(), t0!()),
mul_4!(x_3!(), t5!(), t4!()),
mul_4!(y_3!(), t0!(), t1!()),
mul_4!(w_3!(), t5!(), t1!()),

// End of the main loop; move on by 4 bits.

Q!("    add       " i!() ", 4"),
Q!("    cmp       " i!() ", 256"),
Q!("    jc        " Label!("curve25519_x25519base_scalarloop", 5, Before)),

// Now we need to translate from Edwards curve edwards25519 back
// to the Montgomery form curve25519. The mapping in the affine
// representations is
// 
// (x,y) |-> ((1 + y) / (1 - y), c * (1 + y) / ((1 - y) * x))
// 
// For x25519, we only need the x coordinate, and we compute this as
// 
// (1 + y) / (1 - y) = (x + x * y) / (x - x * y)
//                   = (X/Z + T/Z) / (X/Z - T/Z)
//                   = (X + T) / (X - T)
//                   = (X + T) * inverse(X - T)
// 
// We could equally well use (Z + Y) / (Z - Y), but the above has the
// same cost, and it more explicitly forces zero output whenever X = 0,
// regardless of how the modular inverse behaves on zero inputs. In
// the present setting (base point 9, mangled scalar) that doesn't
// really matter anyway since X = 0 never arises, but it seems a
// little bit tidier. Note that both Edwards point (0,1) which maps to
// the Montgomery point at infinity, and Edwards (0,-1) which maps to
// Montgomery (0,0) [this is the 2-torsion point] are both by definition
// mapped to 0 by the X coordinate mapping used to define curve25519.
// 
// First the addition and subtraction:

add_twice4!(t1!(), x_3!(), w_3!()),
sub_twice4!(t2!(), x_3!(), w_3!()),

// Prepare to call the modular inverse function to get t0 = 1/t2
// Note that this works for the weakly normalized z_3 equally well.
// The non-coprime case z_3 == 0 (mod p_25519) cannot arise anyway.

Q!("    lea       " "rdi, [rsp + 256]"),
Q!("    lea       " "rsi, [rsp + 320]"),

// Inline copy of bignum_inv_p25519, identical except for stripping out
// the prologue and epilogue saving and restoring registers and making
// and reclaiming room on the stack. For more details and explanations see
// "x86/curve25519/bignum_inv_p25519.S". Note that the stack it uses for
// its own temporaries is 208 bytes, so it has no effect on variables
// that are needed in the rest of our computation here: res, t0, t1, t2.

Q!("    mov       " "[rsp + 0xc0], rdi"),
Q!("    xor       " "eax, eax"),
Q!("    lea       " "rcx, [rax - 0x13]"),
Q!("    not       " "rax"),
Q!("    mov       " "[rsp], rcx"),
Q!("    mov       " "[rsp + 0x8], rax"),
Q!("    mov       " "[rsp + 0x10], rax"),
Q!("    btr       " "rax, 0x3f"),
Q!("    mov       " "[rsp + 0x18], rax"),
Q!("    mov       " "rdx, [rsi]"),
Q!("    mov       " "rcx, [rsi + 0x8]"),
Q!("    mov       " "r8, [rsi + 0x10]"),
Q!("    mov       " "r9, [rsi + 0x18]"),
Q!("    mov       " "eax, 0x1"),
Q!("    xor       " "r10d, r10d"),
Q!("    bts       " "r9, 0x3f"),
Q!("    adc       " "rax, r10"),
Q!("    imul      " "rax, rax, 0x13"),
Q!("    add       " "rdx, rax"),
Q!("    adc       " "rcx, r10"),
Q!("    adc       " "r8, r10"),
Q!("    adc       " "r9, r10"),
Q!("    mov       " "eax, 0x13"),
Q!("    cmovb     " "rax, r10"),
Q!("    sub       " "rdx, rax"),
Q!("    sbb       " "rcx, r10"),
Q!("    sbb       " "r8, r10"),
Q!("    sbb       " "r9, r10"),
Q!("    btr       " "r9, 0x3f"),
Q!("    mov       " "[rsp + 0x20], rdx"),
Q!("    mov       " "[rsp + 0x28], rcx"),
Q!("    mov       " "[rsp + 0x30], r8"),
Q!("    mov       " "[rsp + 0x38], r9"),
Q!("    xor       " "eax, eax"),
Q!("    mov       " "[rsp + 0x40], rax"),
Q!("    mov       " "[rsp + 0x48], rax"),
Q!("    mov       " "[rsp + 0x50], rax"),
Q!("    mov       " "[rsp + 0x58], rax"),
Q!("    movabs    " "rax, 0xa0f99e2375022099"),
Q!("    mov       " "[rsp + 0x60], rax"),
Q!("    movabs    " "rax, 0xa8c68f3f1d132595"),
Q!("    mov       " "[rsp + 0x68], rax"),
Q!("    movabs    " "rax, 0x6c6c893805ac5242"),
Q!("    mov       " "[rsp + 0x70], rax"),
Q!("    movabs    " "rax, 0x276508b241770615"),
Q!("    mov       " "[rsp + 0x78], rax"),
Q!("    mov       " "QWORD PTR [rsp + 0x90], 0xa"),
Q!("    mov       " "QWORD PTR [rsp + 0x98], 0x1"),
Q!("    jmp       " Label!("curve25519_x25519base_midloop", 6, After)),
Q!(Label!("curve25519_x25519base_inverseloop", 7) ":"),
Q!("    mov       " "r9, r8"),
Q!("    sar       " "r9, 0x3f"),
Q!("    xor       " "r8, r9"),
Q!("    sub       " "r8, r9"),
Q!("    mov       " "r11, r10"),
Q!("    sar       " "r11, 0x3f"),
Q!("    xor       " "r10, r11"),
Q!("    sub       " "r10, r11"),
Q!("    mov       " "r13, r12"),
Q!("    sar       " "r13, 0x3f"),
Q!("    xor       " "r12, r13"),
Q!("    sub       " "r12, r13"),
Q!("    mov       " "r15, r14"),
Q!("    sar       " "r15, 0x3f"),
Q!("    xor       " "r14, r15"),
Q!("    sub       " "r14, r15"),
Q!("    mov       " "rax, r8"),
Q!("    and       " "rax, r9"),
Q!("    mov       " "rdi, r10"),
Q!("    and       " "rdi, r11"),
Q!("    add       " "rdi, rax"),
Q!("    mov       " "[rsp + 0x80], rdi"),
Q!("    mov       " "rax, r12"),
Q!("    and       " "rax, r13"),
Q!("    mov       " "rsi, r14"),
Q!("    and       " "rsi, r15"),
Q!("    add       " "rsi, rax"),
Q!("    mov       " "[rsp + 0x88], rsi"),
Q!("    xor       " "ebx, ebx"),
Q!("    mov       " "rax, [rsp]"),
Q!("    xor       " "rax, r9"),
Q!("    mul       " "r8"),
Q!("    add       " "rdi, rax"),
Q!("    adc       " "rbx, rdx"),
Q!("    mov       " "rax, [rsp + 0x20]"),
Q!("    xor       " "rax, r11"),
Q!("    mul       " "r10"),
Q!("    add       " "rdi, rax"),
Q!("    adc       " "rbx, rdx"),
Q!("    xor       " "ebp, ebp"),
Q!("    mov       " "rax, [rsp]"),
Q!("    xor       " "rax, r13"),
Q!("    mul       " "r12"),
Q!("    add       " "rsi, rax"),
Q!("    adc       " "rbp, rdx"),
Q!("    mov       " "rax, [rsp + 0x20]"),
Q!("    xor       " "rax, r15"),
Q!("    mul       " "r14"),
Q!("    add       " "rsi, rax"),
Q!("    adc       " "rbp, rdx"),
Q!("    xor       " "ecx, ecx"),
Q!("    mov       " "rax, [rsp + 0x8]"),
Q!("    xor       " "rax, r9"),
Q!("    mul       " "r8"),
Q!("    add       " "rbx, rax"),
Q!("    adc       " "rcx, rdx"),
Q!("    mov       " "rax, [rsp + 0x28]"),
Q!("    xor       " "rax, r11"),
Q!("    mul       " "r10"),
Q!("    add       " "rbx, rax"),
Q!("    adc       " "rcx, rdx"),
Q!("    shrd      " "rdi, rbx, 0x3b"),
Q!("    mov       " "[rsp], rdi"),
Q!("    xor       " "edi, edi"),
Q!("    mov       " "rax, [rsp + 0x8]"),
Q!("    xor       " "rax, r13"),
Q!("    mul       " "r12"),
Q!("    add       " "rbp, rax"),
Q!("    adc       " "rdi, rdx"),
Q!("    mov       " "rax, [rsp + 0x28]"),
Q!("    xor       " "rax, r15"),
Q!("    mul       " "r14"),
Q!("    add       " "rbp, rax"),
Q!("    adc       " "rdi, rdx"),
Q!("    shrd      " "rsi, rbp, 0x3b"),
Q!("    mov       " "[rsp + 0x20], rsi"),
Q!("    xor       " "esi, esi"),
Q!("    mov       " "rax, [rsp + 0x10]"),
Q!("    xor       " "rax, r9"),
Q!("    mul       " "r8"),
Q!("    add       " "rcx, rax"),
Q!("    adc       " "rsi, rdx"),
Q!("    mov       " "rax, [rsp + 0x30]"),
Q!("    xor       " "rax, r11"),
Q!("    mul       " "r10"),
Q!("    add       " "rcx, rax"),
Q!("    adc       " "rsi, rdx"),
Q!("    shrd      " "rbx, rcx, 0x3b"),
Q!("    mov       " "[rsp + 0x8], rbx"),
Q!("    xor       " "ebx, ebx"),
Q!("    mov       " "rax, [rsp + 0x10]"),
Q!("    xor       " "rax, r13"),
Q!("    mul       " "r12"),
Q!("    add       " "rdi, rax"),
Q!("    adc       " "rbx, rdx"),
Q!("    mov       " "rax, [rsp + 0x30]"),
Q!("    xor       " "rax, r15"),
Q!("    mul       " "r14"),
Q!("    add       " "rdi, rax"),
Q!("    adc       " "rbx, rdx"),
Q!("    shrd      " "rbp, rdi, 0x3b"),
Q!("    mov       " "[rsp + 0x28], rbp"),
Q!("    mov       " "rax, [rsp + 0x18]"),
Q!("    xor       " "rax, r9"),
Q!("    mov       " "rbp, rax"),
Q!("    sar       " "rbp, 0x3f"),
Q!("    and       " "rbp, r8"),
Q!("    neg       " "rbp"),
Q!("    mul       " "r8"),
Q!("    add       " "rsi, rax"),
Q!("    adc       " "rbp, rdx"),
Q!("    mov       " "rax, [rsp + 0x38]"),
Q!("    xor       " "rax, r11"),
Q!("    mov       " "rdx, rax"),
Q!("    sar       " "rdx, 0x3f"),
Q!("    and       " "rdx, r10"),
Q!("    sub       " "rbp, rdx"),
Q!("    mul       " "r10"),
Q!("    add       " "rsi, rax"),
Q!("    adc       " "rbp, rdx"),
Q!("    shrd      " "rcx, rsi, 0x3b"),
Q!("    mov       " "[rsp + 0x10], rcx"),
Q!("    shrd      " "rsi, rbp, 0x3b"),
Q!("    mov       " "rax, [rsp + 0x18]"),
Q!("    mov       " "[rsp + 0x18], rsi"),
Q!("    xor       " "rax, r13"),
Q!("    mov       " "rsi, rax"),
Q!("    sar       " "rsi, 0x3f"),
Q!("    and       " "rsi, r12"),
Q!("    neg       " "rsi"),
Q!("    mul       " "r12"),
Q!("    add       " "rbx, rax"),
Q!("    adc       " "rsi, rdx"),
Q!("    mov       " "rax, [rsp + 0x38]"),
Q!("    xor       " "rax, r15"),
Q!("    mov       " "rdx, rax"),
Q!("    sar       " "rdx, 0x3f"),
Q!("    and       " "rdx, r14"),
Q!("    sub       " "rsi, rdx"),
Q!("    mul       " "r14"),
Q!("    add       " "rbx, rax"),
Q!("    adc       " "rsi, rdx"),
Q!("    shrd      " "rdi, rbx, 0x3b"),
Q!("    mov       " "[rsp + 0x30], rdi"),
Q!("    shrd      " "rbx, rsi, 0x3b"),
Q!("    mov       " "[rsp + 0x38], rbx"),
Q!("    mov       " "rbx, [rsp + 0x80]"),
Q!("    mov       " "rbp, [rsp + 0x88]"),
Q!("    xor       " "ecx, ecx"),
Q!("    mov       " "rax, [rsp + 0x40]"),
Q!("    xor       " "rax, r9"),
Q!("    mul       " "r8"),
Q!("    add       " "rbx, rax"),
Q!("    adc       " "rcx, rdx"),
Q!("    mov       " "rax, [rsp + 0x60]"),
Q!("    xor       " "rax, r11"),
Q!("    mul       " "r10"),
Q!("    add       " "rbx, rax"),
Q!("    adc       " "rcx, rdx"),
Q!("    xor       " "esi, esi"),
Q!("    mov       " "rax, [rsp + 0x40]"),
Q!("    xor       " "rax, r13"),
Q!("    mul       " "r12"),
Q!("    mov       " "[rsp + 0x40], rbx"),
Q!("    add       " "rbp, rax"),
Q!("    adc       " "rsi, rdx"),
Q!("    mov       " "rax, [rsp + 0x60]"),
Q!("    xor       " "rax, r15"),
Q!("    mul       " "r14"),
Q!("    add       " "rbp, rax"),
Q!("    adc       " "rsi, rdx"),
Q!("    mov       " "[rsp + 0x60], rbp"),
Q!("    xor       " "ebx, ebx"),
Q!("    mov       " "rax, [rsp + 0x48]"),
Q!("    xor       " "rax, r9"),
Q!("    mul       " "r8"),
Q!("    add       " "rcx, rax"),
Q!("    adc       " "rbx, rdx"),
Q!("    mov       " "rax, [rsp + 0x68]"),
Q!("    xor       " "rax, r11"),
Q!("    mul       " "r10"),
Q!("    add       " "rcx, rax"),
Q!("    adc       " "rbx, rdx"),
Q!("    xor       " "ebp, ebp"),
Q!("    mov       " "rax, [rsp + 0x48]"),
Q!("    xor       " "rax, r13"),
Q!("    mul       " "r12"),
Q!("    mov       " "[rsp + 0x48], rcx"),
Q!("    add       " "rsi, rax"),
Q!("    adc       " "rbp, rdx"),
Q!("    mov       " "rax, [rsp + 0x68]"),
Q!("    xor       " "rax, r15"),
Q!("    mul       " "r14"),
Q!("    add       " "rsi, rax"),
Q!("    adc       " "rbp, rdx"),
Q!("    mov       " "[rsp + 0x68], rsi"),
Q!("    xor       " "ecx, ecx"),
Q!("    mov       " "rax, [rsp + 0x50]"),
Q!("    xor       " "rax, r9"),
Q!("    mul       " "r8"),
Q!("    add       " "rbx, rax"),
Q!("    adc       " "rcx, rdx"),
Q!("    mov       " "rax, [rsp + 0x70]"),
Q!("    xor       " "rax, r11"),
Q!("    mul       " "r10"),
Q!("    add       " "rbx, rax"),
Q!("    adc       " "rcx, rdx"),
Q!("    xor       " "esi, esi"),
Q!("    mov       " "rax, [rsp + 0x50]"),
Q!("    xor       " "rax, r13"),
Q!("    mul       " "r12"),
Q!("    mov       " "[rsp + 0x50], rbx"),
Q!("    add       " "rbp, rax"),
Q!("    adc       " "rsi, rdx"),
Q!("    mov       " "rax, [rsp + 0x70]"),
Q!("    xor       " "rax, r15"),
Q!("    mul       " "r14"),
Q!("    add       " "rbp, rax"),
Q!("    adc       " "rsi, rdx"),
Q!("    mov       " "[rsp + 0x70], rbp"),
Q!("    mov       " "rax, [rsp + 0x58]"),
Q!("    xor       " "rax, r9"),
Q!("    mov       " "rbx, r9"),
Q!("    and       " "rbx, r8"),
Q!("    neg       " "rbx"),
Q!("    mul       " "r8"),
Q!("    add       " "rcx, rax"),
Q!("    adc       " "rbx, rdx"),
Q!("    mov       " "rax, [rsp + 0x78]"),
Q!("    xor       " "rax, r11"),
Q!("    mov       " "rdx, r11"),
Q!("    and       " "rdx, r10"),
Q!("    sub       " "rbx, rdx"),
Q!("    mul       " "r10"),
Q!("    add       " "rcx, rax"),
Q!("    adc       " "rdx, rbx"),
Q!("    mov       " "rbx, rdx"),
Q!("    shld      " "rdx, rcx, 0x1"),
Q!("    sar       " "rbx, 0x3f"),
Q!("    add       " "rdx, rbx"),
Q!("    mov       " "eax, 0x13"),
Q!("    imul      " "rdx"),
Q!("    mov       " "r8, [rsp + 0x40]"),
Q!("    add       " "r8, rax"),
Q!("    mov       " "[rsp + 0x40], r8"),
Q!("    mov       " "r8, [rsp + 0x48]"),
Q!("    adc       " "r8, rdx"),
Q!("    mov       " "[rsp + 0x48], r8"),
Q!("    mov       " "r8, [rsp + 0x50]"),
Q!("    adc       " "r8, rbx"),
Q!("    mov       " "[rsp + 0x50], r8"),
Q!("    adc       " "rcx, rbx"),
Q!("    shl       " "rax, 0x3f"),
Q!("    add       " "rcx, rax"),
Q!("    mov       " "rax, [rsp + 0x58]"),
Q!("    mov       " "[rsp + 0x58], rcx"),
Q!("    xor       " "rax, r13"),
Q!("    mov       " "rcx, r13"),
Q!("    and       " "rcx, r12"),
Q!("    neg       " "rcx"),
Q!("    mul       " "r12"),
Q!("    add       " "rsi, rax"),
Q!("    adc       " "rcx, rdx"),
Q!("    mov       " "rax, [rsp + 0x78]"),
Q!("    xor       " "rax, r15"),
Q!("    mov       " "rdx, r15"),
Q!("    and       " "rdx, r14"),
Q!("    sub       " "rcx, rdx"),
Q!("    mul       " "r14"),
Q!("    add       " "rsi, rax"),
Q!("    adc       " "rdx, rcx"),
Q!("    mov       " "rcx, rdx"),
Q!("    shld      " "rdx, rsi, 0x1"),
Q!("    sar       " "rcx, 0x3f"),
Q!("    mov       " "eax, 0x13"),
Q!("    add       " "rdx, rcx"),
Q!("    imul      " "rdx"),
Q!("    mov       " "r8, [rsp + 0x60]"),
Q!("    add       " "r8, rax"),
Q!("    mov       " "[rsp + 0x60], r8"),
Q!("    mov       " "r8, [rsp + 0x68]"),
Q!("    adc       " "r8, rdx"),
Q!("    mov       " "[rsp + 0x68], r8"),
Q!("    mov       " "r8, [rsp + 0x70]"),
Q!("    adc       " "r8, rcx"),
Q!("    mov       " "[rsp + 0x70], r8"),
Q!("    adc       " "rsi, rcx"),
Q!("    shl       " "rax, 0x3f"),
Q!("    add       " "rsi, rax"),
Q!("    mov       " "[rsp + 0x78], rsi"),
Q!(Label!("curve25519_x25519base_midloop", 6) ":"),
Q!("    mov       " "rsi, [rsp + 0x98]"),
Q!("    mov       " "rdx, [rsp]"),
Q!("    mov       " "rcx, [rsp + 0x20]"),
Q!("    mov       " "rbx, rdx"),
Q!("    and       " "rbx, 0xfffff"),
Q!("    movabs    " "rax, 0xfffffe0000000000"),
Q!("    or        " "rbx, rax"),
Q!("    and       " "rcx, 0xfffff"),
Q!("    movabs    " "rax, 0xc000000000000000"),
Q!("    or        " "rcx, rax"),
Q!("    mov       " "rax, 0xfffffffffffffffe"),
Q!("    xor       " "ebp, ebp"),
Q!("    mov       " "edx, 0x2"),
Q!("    mov       " "rdi, rbx"),
Q!("    mov       " "r8, rax"),
Q!("    test      " "rsi, rsi"),
Q!("    cmovs     " "r8, rbp"),
Q!("    test      " "rcx, 0x1"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    sar       " "rcx, 1"),
Q!("    mov       " "eax, 0x100000"),
Q!("    lea       " "rdx, [rbx + rax]"),
Q!("    lea       " "rdi, [rcx + rax]"),
Q!("    shl       " "rdx, 0x16"),
Q!("    shl       " "rdi, 0x16"),
Q!("    sar       " "rdx, 0x2b"),
Q!("    sar       " "rdi, 0x2b"),
Q!("    movabs    " "rax, 0x20000100000"),
Q!("    lea       " "rbx, [rbx + rax]"),
Q!("    lea       " "rcx, [rcx + rax]"),
Q!("    sar       " "rbx, 0x2a"),
Q!("    sar       " "rcx, 0x2a"),
Q!("    mov       " "[rsp + 0xa0], rdx"),
Q!("    mov       " "[rsp + 0xa8], rbx"),
Q!("    mov       " "[rsp + 0xb0], rdi"),
Q!("    mov       " "[rsp + 0xb8], rcx"),
Q!("    mov       " "r12, [rsp]"),
Q!("    imul      " "rdi, r12"),
Q!("    imul      " "r12, rdx"),
Q!("    mov       " "r13, [rsp + 0x20]"),
Q!("    imul      " "rbx, r13"),
Q!("    imul      " "r13, rcx"),
Q!("    add       " "r12, rbx"),
Q!("    add       " "r13, rdi"),
Q!("    sar       " "r12, 0x14"),
Q!("    sar       " "r13, 0x14"),
Q!("    mov       " "rbx, r12"),
Q!("    and       " "rbx, 0xfffff"),
Q!("    movabs    " "rax, 0xfffffe0000000000"),
Q!("    or        " "rbx, rax"),
Q!("    mov       " "rcx, r13"),
Q!("    and       " "rcx, 0xfffff"),
Q!("    movabs    " "rax, 0xc000000000000000"),
Q!("    or        " "rcx, rax"),
Q!("    mov       " "rax, 0xfffffffffffffffe"),
Q!("    mov       " "edx, 0x2"),
Q!("    mov       " "rdi, rbx"),
Q!("    mov       " "r8, rax"),
Q!("    test      " "rsi, rsi"),
Q!("    cmovs     " "r8, rbp"),
Q!("    test      " "rcx, 0x1"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    sar       " "rcx, 1"),
Q!("    mov       " "eax, 0x100000"),
Q!("    lea       " "r8, [rbx + rax]"),
Q!("    lea       " "r10, [rcx + rax]"),
Q!("    shl       " "r8, 0x16"),
Q!("    shl       " "r10, 0x16"),
Q!("    sar       " "r8, 0x2b"),
Q!("    sar       " "r10, 0x2b"),
Q!("    movabs    " "rax, 0x20000100000"),
Q!("    lea       " "r15, [rbx + rax]"),
Q!("    lea       " "r11, [rcx + rax]"),
Q!("    sar       " "r15, 0x2a"),
Q!("    sar       " "r11, 0x2a"),
Q!("    mov       " "rbx, r13"),
Q!("    mov       " "rcx, r12"),
Q!("    imul      " "r12, r8"),
Q!("    imul      " "rbx, r15"),
Q!("    add       " "r12, rbx"),
Q!("    imul      " "r13, r11"),
Q!("    imul      " "rcx, r10"),
Q!("    add       " "r13, rcx"),
Q!("    sar       " "r12, 0x14"),
Q!("    sar       " "r13, 0x14"),
Q!("    mov       " "rbx, r12"),
Q!("    and       " "rbx, 0xfffff"),
Q!("    movabs    " "rax, 0xfffffe0000000000"),
Q!("    or        " "rbx, rax"),
Q!("    mov       " "rcx, r13"),
Q!("    and       " "rcx, 0xfffff"),
Q!("    movabs    " "rax, 0xc000000000000000"),
Q!("    or        " "rcx, rax"),
Q!("    mov       " "rax, [rsp + 0xa0]"),
Q!("    imul      " "rax, r8"),
Q!("    mov       " "rdx, [rsp + 0xb0]"),
Q!("    imul      " "rdx, r15"),
Q!("    imul      " "r8, [rsp + 0xa8]"),
Q!("    imul      " "r15, [rsp + 0xb8]"),
Q!("    add       " "r15, r8"),
Q!("    lea       " "r9, [rax + rdx]"),
Q!("    mov       " "rax, [rsp + 0xa0]"),
Q!("    imul      " "rax, r10"),
Q!("    mov       " "rdx, [rsp + 0xb0]"),
Q!("    imul      " "rdx, r11"),
Q!("    imul      " "r10, [rsp + 0xa8]"),
Q!("    imul      " "r11, [rsp + 0xb8]"),
Q!("    add       " "r11, r10"),
Q!("    lea       " "r13, [rax + rdx]"),
Q!("    mov       " "rax, 0xfffffffffffffffe"),
Q!("    mov       " "edx, 0x2"),
Q!("    mov       " "rdi, rbx"),
Q!("    mov       " "r8, rax"),
Q!("    test      " "rsi, rsi"),
Q!("    cmovs     " "r8, rbp"),
Q!("    test      " "rcx, 0x1"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    cmovs     " "r8, rbp"),
Q!("    mov       " "rdi, rbx"),
Q!("    test      " "rcx, rdx"),
Q!("    cmove     " "r8, rbp"),
Q!("    cmove     " "rdi, rbp"),
Q!("    sar       " "rcx, 1"),
Q!("    xor       " "rdi, r8"),
Q!("    xor       " "rsi, r8"),
Q!("    bt        " "r8, 0x3f"),
Q!("    cmovb     " "rbx, rcx"),
Q!("    mov       " "r8, rax"),
Q!("    sub       " "rsi, rax"),
Q!("    lea       " "rcx, [rcx + rdi]"),
Q!("    sar       " "rcx, 1"),
Q!("    mov       " "eax, 0x100000"),
Q!("    lea       " "r8, [rbx + rax]"),
Q!("    lea       " "r12, [rcx + rax]"),
Q!("    shl       " "r8, 0x15"),
Q!("    shl       " "r12, 0x15"),
Q!("    sar       " "r8, 0x2b"),
Q!("    sar       " "r12, 0x2b"),
Q!("    movabs    " "rax, 0x20000100000"),
Q!("    lea       " "r10, [rbx + rax]"),
Q!("    lea       " "r14, [rcx + rax]"),
Q!("    sar       " "r10, 0x2b"),
Q!("    sar       " "r14, 0x2b"),
Q!("    mov       " "rax, r9"),
Q!("    imul      " "rax, r8"),
Q!("    mov       " "rdx, r13"),
Q!("    imul      " "rdx, r10"),
Q!("    imul      " "r8, r15"),
Q!("    imul      " "r10, r11"),
Q!("    add       " "r10, r8"),
Q!("    lea       " "r8, [rax + rdx]"),
Q!("    mov       " "rax, r9"),
Q!("    imul      " "rax, r12"),
Q!("    mov       " "rdx, r13"),
Q!("    imul      " "rdx, r14"),
Q!("    imul      " "r12, r15"),
Q!("    imul      " "r14, r11"),
Q!("    add       " "r14, r12"),
Q!("    lea       " "r12, [rax + rdx]"),
Q!("    mov       " "[rsp + 0x98], rsi"),
Q!("    dec       " "QWORD PTR [rsp + 0x90]"),
Q!("    jne       " Label!("curve25519_x25519base_inverseloop", 7, Before)),
Q!("    mov       " "rax, [rsp]"),
Q!("    mov       " "rcx, [rsp + 0x20]"),
Q!("    imul      " "rax, r8"),
Q!("    imul      " "rcx, r10"),
Q!("    add       " "rax, rcx"),
Q!("    sar       " "rax, 0x3f"),
Q!("    mov       " "r9, r8"),
Q!("    sar       " "r9, 0x3f"),
Q!("    xor       " "r8, r9"),
Q!("    sub       " "r8, r9"),
Q!("    xor       " "r9, rax"),
Q!("    mov       " "r11, r10"),
Q!("    sar       " "r11, 0x3f"),
Q!("    xor       " "r10, r11"),
Q!("    sub       " "r10, r11"),
Q!("    xor       " "r11, rax"),
Q!("    mov       " "r13, r12"),
Q!("    sar       " "r13, 0x3f"),
Q!("    xor       " "r12, r13"),
Q!("    sub       " "r12, r13"),
Q!("    xor       " "r13, rax"),
Q!("    mov       " "r15, r14"),
Q!("    sar       " "r15, 0x3f"),
Q!("    xor       " "r14, r15"),
Q!("    sub       " "r14, r15"),
Q!("    xor       " "r15, rax"),
Q!("    mov       " "rax, r8"),
Q!("    and       " "rax, r9"),
Q!("    mov       " "r12, r10"),
Q!("    and       " "r12, r11"),
Q!("    add       " "r12, rax"),
Q!("    xor       " "r13d, r13d"),
Q!("    mov       " "rax, [rsp + 0x40]"),
Q!("    xor       " "rax, r9"),
Q!("    mul       " "r8"),
Q!("    add       " "r12, rax"),
Q!("    adc       " "r13, rdx"),
Q!("    mov       " "rax, [rsp + 0x60]"),
Q!("    xor       " "rax, r11"),
Q!("    mul       " "r10"),
Q!("    add       " "r12, rax"),
Q!("    adc       " "r13, rdx"),
Q!("    xor       " "r14d, r14d"),
Q!("    mov       " "rax, [rsp + 0x48]"),
Q!("    xor       " "rax, r9"),
Q!("    mul       " "r8"),
Q!("    add       " "r13, rax"),
Q!("    adc       " "r14, rdx"),
Q!("    mov       " "rax, [rsp + 0x68]"),
Q!("    xor       " "rax, r11"),
Q!("    mul       " "r10"),
Q!("    add       " "r13, rax"),
Q!("    adc       " "r14, rdx"),
Q!("    xor       " "r15d, r15d"),
Q!("    mov       " "rax, [rsp + 0x50]"),
Q!("    xor       " "rax, r9"),
Q!("    mul       " "r8"),
Q!("    add       " "r14, rax"),
Q!("    adc       " "r15, rdx"),
Q!("    mov       " "rax, [rsp + 0x70]"),
Q!("    xor       " "rax, r11"),
Q!("    mul       " "r10"),
Q!("    add       " "r14, rax"),
Q!("    adc       " "r15, rdx"),
Q!("    mov       " "rax, [rsp + 0x58]"),
Q!("    xor       " "rax, r9"),
Q!("    and       " "r9, r8"),
Q!("    neg       " "r9"),
Q!("    mul       " "r8"),
Q!("    add       " "r15, rax"),
Q!("    adc       " "r9, rdx"),
Q!("    mov       " "rax, [rsp + 0x78]"),
Q!("    xor       " "rax, r11"),
Q!("    mov       " "rdx, r11"),
Q!("    and       " "rdx, r10"),
Q!("    sub       " "r9, rdx"),
Q!("    mul       " "r10"),
Q!("    add       " "r15, rax"),
Q!("    adc       " "r9, rdx"),
Q!("    mov       " "rax, r9"),
Q!("    shld      " "rax, r15, 0x1"),
Q!("    sar       " "r9, 0x3f"),
Q!("    mov       " "ebx, 0x13"),
Q!("    lea       " "rax, [rax + r9 + 0x1]"),
Q!("    imul      " "rbx"),
Q!("    xor       " "ebp, ebp"),
Q!("    add       " "r12, rax"),
Q!("    adc       " "r13, rdx"),
Q!("    adc       " "r14, r9"),
Q!("    adc       " "r15, r9"),
Q!("    shl       " "rax, 0x3f"),
Q!("    add       " "r15, rax"),
Q!("    cmovns    " "rbx, rbp"),
Q!("    sub       " "r12, rbx"),
Q!("    sbb       " "r13, rbp"),
Q!("    sbb       " "r14, rbp"),
Q!("    sbb       " "r15, rbp"),
Q!("    btr       " "r15, 0x3f"),
Q!("    mov       " "rdi, [rsp + 0xc0]"),
Q!("    mov       " "[rdi], r12"),
Q!("    mov       " "[rdi + 0x8], r13"),
Q!("    mov       " "[rdi + 0x10], r14"),
Q!("    mov       " "[rdi + 0x18], r15"),

// The final result is (X + T) / (X - T)
// This is the only operation in the whole computation that
// fully reduces modulo p_25519 since now we want the canonical
// answer as output.

Q!("    mov       " "rbp, " res!()),
mul_p25519!(resx!(), t1!(), t0!()),

// Restore stack and registers

Q!("    add       " "rsp, " NSPACE!()),

Q!("    pop       " "r15"),
Q!("    pop       " "r14"),
Q!("    pop       " "r13"),
Q!("    pop       " "r12"),
Q!("    pop       " "rbp"),
Q!("    pop       " "rbx"),
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
    out("rdi") _,
    out("rdx") _,
    out("rip") _,
    out("rsi") _,
    )}

// ****************************************************************************
// The precomputed data (all read-only). This is currently part of the same
// text section, which gives position-independent code with simple PC-relative
// addressing. However it could be put in a separate section via something like
// 
// .section .rodata
// ****************************************************************************

// 2^254 * G and (2^254 + 8) * G in extended-projective coordinates
// but with z = 1 assumed and hence left out, so they are (X,Y,T) only.

Q!(Label!("curve25519_x25519base_edwards25519_0g", 2) ":"),

