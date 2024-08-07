from parse import parse_file
from driver import (
    Architecture_aarch64,
    Architecture_amd64,
    RustDriver,
)

if __name__ == "__main__":
    with open("../../s2n-bignum/x86/generic/bignum_montsqr.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_montsqr.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_montsqr",
            parameter_map=[
                ("inout", "rdi", "z.len() => _"),
                ("inout", "rsi", "z.as_mut_ptr() => _"),
                ("inout", "rdx", "x.as_ptr() => _"),
                ("inout", "rcx", "m.as_ptr() => _"),
            ],
            assertions=[
                "z.len() == x.len()",
                "z.len() == m.len()",
            ],
            rust_decl="pub fn bignum_montsqr(z: &mut [u64], x: &[u64], m: &[u64])",
        )
        parse_file(input, d)

    with open("../../s2n-bignum/x86/generic/bignum_bitsize.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_bitsize.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_bitsize",
            parameter_map=[
                ("inout", "rdi", "x.len() => _"),
                ("inout", "rsi", "x.as_ptr() => _"),
                ("out", "rax", "ret"),
            ],
            return_value=("u64", "ret", "ret as usize"),
            rust_decl="pub fn bignum_bitsize(x: &[u64]) -> usize",
        )
        parse_file(input, d)

    with open("../../s2n-bignum/x86/generic/bignum_lt.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_cmp_lt.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_lt",
            parameter_map=[
                ("inout", "rdi", "x.len() => _"),
                ("inout", "rsi", "x.as_ptr() => _"),
                ("inout", "rdx", "y.len() => _"),
                ("inout", "rcx", "y.as_ptr() => _"),
                ("out", "rax", "ret"),
            ],
            return_value=("u64", "ret", "ret > 0"),
            hoist=["linear", "ytoploop", "ret"],
            rust_decl="pub fn bignum_cmp_lt(x: &[u64], y: &[u64]) -> bool",
        )
        parse_file(input, d)

    with open("../../s2n-bignum/x86/generic/bignum_modexp.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_modexp.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_modexp",
            parameter_map=[
                ("inout", "rdi", "z.len() => _"),
                ("inout", "rsi", "z.as_mut_ptr() => _"),
                ("inout", "rdx", "a.as_ptr() => _"),
                ("inout", "rcx", "p.as_ptr() => _"),
                ("inout", "r8", "m.as_ptr() => _"),
                ("inout", "r9", "t.as_mut_ptr() => _"),
            ],
            assertions=[
                "z.len() == a.len()",
                "z.len() == p.len()",
                "z.len() == m.len()",
                "z.len() * 3 <= t.len()",
            ],
            hoist=["proc", "muxend", "ret"],
            rust_decl="pub fn bignum_modexp(z: &mut [u64], a: &[u64], p: &[u64], m: &[u64], t: &mut [u64])",
        )
        parse_file(input, d)

    with open("../../s2n-bignum/x86/generic/bignum_mul.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_mul.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_mul",
            parameter_map=[
                ("inout", "rdi", "z.len() => _"),
                ("inout", "rsi", "z.as_mut_ptr() => _"),
                ("inout", "rdx", "x.len() => _"),
                ("inout", "rcx", "x.as_ptr() => _"),
                ("inout", "r8", "y.len() => _"),
                ("inout", "r9", "y.as_ptr() => _"),
            ],
            assertions=[
                "z.len() >= x.len() + y.len()",
            ],
            rust_decl="pub fn bignum_mul(z: &mut [u64], x: &[u64], y: &[u64])",
        )
        parse_file(input, d)

    with open("../../s2n-bignum/x86/generic/bignum_add.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_add.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_add",
            parameter_map=[
                ("inout", "rdi", "z.len() => _"),
                ("inout", "rsi", "z.as_mut_ptr() => _"),
                ("inout", "rdx", "x.len() => _"),
                ("inout", "rcx", "x.as_ptr() => _"),
                ("inout", "r8", "y.len() => _"),
                ("inout", "r9", "y.as_ptr() => _"),
            ],
            hoist=["linear", "tail", "ret"],
            rust_decl="pub fn bignum_add(z: &mut [u64], x: &[u64], y: &[u64])",
        )
        parse_file(input, d)

    with open("../../s2n-bignum/x86/generic/bignum_modsub.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_modsub.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_modsub",
            parameter_map=[
                ("inout", "rdi", "z.len() => _"),
                ("inout", "rsi", "z.as_mut_ptr() => _"),
                ("inout", "rdx", "x.as_ptr() => _"),
                ("inout", "rcx", "y.as_ptr() => _"),
                ("inout", "r8", "m.as_ptr() => _"),
            ],
            assertions=[
                "z.len() == x.len()",
                "z.len() == y.len()",
                "z.len() == m.len()",
            ],
            rust_decl="pub fn bignum_modsub(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64])",
        )
        parse_file(input, d)

    with open("../../s2n-bignum/x86/generic/bignum_montredc.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_montredc.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_montredc",
            parameter_map=[
                ("inout", "rdi", "z.len() => _"),
                ("inout", "rsi", "z.as_mut_ptr() => _"),
                ("inout", "rdx", "x.len() => _"),
                ("inout", "rcx", "x.as_ptr() => _"),
                ("inout", "r8", "m.as_ptr() => _"),
                ("inout", "r9", "p => _"),
            ],
            assertions=["z.len() == m.len()"],
            rust_decl="pub fn bignum_montredc(z: &mut [u64], x: &[u64], m: &[u64], p: u64)",
        )
        parse_file(input, d)

    with open("../../s2n-bignum/x86/generic/bignum_digitsize.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_digitsize.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_digitsize",
            parameter_map=[
                ("inout", "rdi", "z.len() => _"),
                ("inout", "rsi", "z.as_ptr() => _"),
                ("out", "rax", "ret"),
            ],
            return_value=("u64", "ret", "ret as usize"),
            rust_decl="pub fn bignum_digitsize(z: &[u64]) -> usize",
        )
        parse_file(input, d)
