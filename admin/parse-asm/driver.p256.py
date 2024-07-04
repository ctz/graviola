from parse import parse_file
from driver import (
    Architecture_aarch64,
    Architecture_amd64,
    RustDriver,
)

if __name__ == "__main__":
    with open("../../s2n-bignum/x86/p256/bignum_nonzero_4.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_nonzero_4.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.set_label_prefix("bignum_")
        d.emit_rust_function(
            "bignum_nonzero_4",
            return_value=("u64", "ret", "ret > 0"),
            parameter_map=[
                ("inout", "rdi", "x.as_ptr() => _"),
                ("out", "rax", "ret"),
            ],
            rust_decl="pub fn bignum_nonzero_4(x: &[u64; 4]) -> bool",
        )
        parse_file(input, d)
        d.finish_file()

    with open("../../s2n-bignum/x86/p256/bignum_montsqr_p256.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_montsqr_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.set_label_prefix("bignum_")
        d.emit_rust_function(
            "bignum_montsqr_p256",
            parameter_map=[
                ("inout", "rdi", "z.as_mut_ptr() => _"),
                ("in", "rsi", "x.as_ptr()"),
            ],
            rust_decl="pub fn bignum_montsqr_p256(z: &mut [u64; 4], x: &[u64; 4])",
        )
        parse_file(input, d)
        d.finish_file()

    with open("../../s2n-bignum/x86/p256/bignum_montmul_p256.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_montmul_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.set_label_prefix("bignum_")
        d.emit_rust_function(
            "bignum_montmul_p256",
            parameter_map=[
                ("inout", "rdi", "z.as_mut_ptr() => _"),
                ("in", "rsi", "x.as_ptr()"),
                ("inout", "rdx", "y.as_ptr() => _"),
            ],
            rust_decl="pub fn bignum_montmul_p256(z: &mut [u64; 4], x: &[u64; 4], y: &[u64; 4])",
        )
        parse_file(input, d)
        d.finish_file()

    with open("../../s2n-bignum/x86/p256/bignum_add_p256.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_add_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.set_label_prefix("bignum_")
        d.emit_rust_function(
            "bignum_add_p256",
            parameter_map=[
                ("inout", "rdi", "z.as_mut_ptr() => _"),
                ("in", "rsi", "x.as_ptr()"),
                ("inout", "rdx", "y.as_ptr() => _"),
            ],
            rust_decl="pub fn bignum_add_p256(z: &mut [u64; 4], x: &[u64; 4], y: &[u64; 4])",
        )
        parse_file(input, d)
        d.finish_file()

    with open("../../s2n-bignum/x86/p256/bignum_demont_p256.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_demont_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.set_label_prefix("bignum_")
        d.emit_rust_function(
            "bignum_demont_p256",
            parameter_map=[
                ("inout", "rdi", "z.as_mut_ptr() => _"),
                ("in", "rsi", "x.as_ptr()"),
            ],
            rust_decl="pub fn bignum_demont_p256(z: &mut [u64; 4], x: &[u64; 4])",
        )
        parse_file(input, d)
        d.finish_file()

    with open("../../s2n-bignum/x86/p256/bignum_tomont_p256.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_tomont_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.set_label_prefix("bignum_")
        d.emit_rust_function(
            "bignum_tomont_p256",
            parameter_map=[
                ("inout", "rdi", "z.as_mut_ptr() => _"),
                ("in", "rsi", "x.as_ptr()"),
            ],
            rust_decl="pub fn bignum_tomont_p256(z: &mut [u64; 4], x: &[u64; 4])",
        )
        parse_file(input, d)
        d.finish_file()

    with open("../../s2n-bignum/x86/p256/bignum_neg_p256.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_neg_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.set_label_prefix("bignum_")
        d.emit_rust_function(
            "bignum_neg_p256",
            parameter_map=[
                ("inout", "rdi", "z.as_mut_ptr() => _"),
                ("in", "rsi", "x.as_ptr()"),
            ],
            rust_decl="pub fn bignum_neg_p256(z: &mut [u64; 4], x: &[u64; 4])",
        )
        parse_file(input, d)
        d.finish_file()

    with open("../../s2n-bignum/x86/p256/bignum_inv_p256.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_inv_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.set_label_prefix("bignum_", "loop", "midloop")
        d.emit_rust_function(
            "bignum_inv_p256",
            parameter_map=[
                ("inout", "rdi", "z.as_mut_ptr() => _"),
                ("inout", "rsi", "x.as_ptr() => _"),
            ],
            rust_decl="pub fn bignum_inv_p256(z: &mut [u64; 4], x: &[u64; 4])",
        )
        parse_file(input, d)
        d.finish_file()

    with open("../../s2n-bignum/x86/p256/bignum_mod_n256_4.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_mod_n256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.set_label_prefix("bignum_", "loop", "midloop")
        d.emit_rust_function(
            "bignum_mod_n256_4",
            parameter_map=[
                ("inout", "rdi", "z.as_mut_ptr() => _"),
                ("inout", "rsi", "x.as_ptr() => _"),
            ],
            rust_decl="pub fn bignum_mod_n256(z: &mut [u64; 4], x: &[u64; 4])",
        )
        parse_file(input, d)
        d.finish_file()

    with open("../../s2n-bignum/x86/generic/bignum_mux.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_mux.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_mux",
            parameter_map=[
                ("inout", "rdi", "p => _"),
                ("inout", "rsi", "z.len() => _"),
                ("inout", "rdx", "z.as_mut_ptr() => _"),
                ("inout", "rcx", "x_if_p.as_ptr() => _"),
                ("inout", "r8", "y_if_not_p.as_ptr() => _"),
            ],
            rust_decl="pub fn bignum_mux(p: u64, z: &mut [u64], x_if_p: &[u64], y_if_not_p: &[u64])",
        )
        parse_file(input, d)
        d.finish_file()

    with open("../../s2n-bignum/x86/generic/bignum_copy_row_from_table.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_copy_row_from_table.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.set_label_prefix('bignum_')
        d.emit_rust_function(
            "bignum_copy_row_from_table",
            parameter_map=[
                ("inout", "rdi", "z.as_mut_ptr() => _"),
                ("inout", "rsi", "table.as_ptr() => _"),
                ("inout", "rdx", "height => _"),
                ("inout", "rcx", "width => _"),
                ("inout", "r8", "index => _"),
            ],
            rust_decl="pub fn bignum_copy_row_from_table(z: &mut [u64], table: &[u64], height: u64, width: u64, index: u64)",
        )
        parse_file(input, d)
        d.finish_file()


    with open("../../s2n-bignum/x86/p256/p256_montjadd.S") as input, open(
        "../curve25519/src/low/x86_64/p256_montjadd.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.set_label_prefix("bignum_")
        d.emit_rust_function(
            "p256_montjadd",
            parameter_map=[
                ("inout", "rdi", "p3.as_mut_ptr() => _"),
                ("inout", "rsi", "p1.as_ptr() => _"),
                ("inout", "rdx", "p2.as_ptr() => _"),
            ],
            rust_decl="pub fn p256_montjadd(p3: &mut [u64; 12], p1: &[u64; 12], p2: &[u64; 12])",
        )
        parse_file(input, d)
        d.finish_file()

    with open("../../s2n-bignum/x86/p256/p256_montjmixadd.S") as input, open(
        "../curve25519/src/low/x86_64/p256_montjmixadd.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.set_label_prefix("bignum_")
        d.emit_rust_function(
            "p256_montjmixadd",
            parameter_map=[
                ("inout", "rdi", "p3.as_mut_ptr() => _"),
                ("inout", "rsi", "p1.as_ptr() => _"),
                ("inout", "rdx", "p2.as_ptr() => _"),
            ],
            rust_decl="pub fn p256_montjmixadd(p3: &mut [u64; 12], p1: &[u64; 12], p2: &[u64; 8])",
        )
        parse_file(input, d)
        d.finish_file()

    with open("../../s2n-bignum/x86/p256/p256_montjdouble.S") as input, open(
        "../curve25519/src/low/x86_64/p256_montjdouble.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.set_label_prefix("bignum_")
        d.emit_rust_function(
            "p256_montjdouble",
            parameter_map=[
                ("inout", "rdi", "p3.as_mut_ptr() => _"),
                ("inout", "rsi", "p1.as_ptr() => _"),
            ],
            rust_decl="pub fn p256_montjdouble(p3: &mut [u64; 12], p1: &[u64; 12])",
        )
        parse_file(input, d)
        d.finish_file()

    with open("../../s2n-bignum/x86/generic/bignum_eq.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_eq.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.set_label_prefix("bignum_", "nloop", "mloop", "mmain", "mtest", "loop", "end")
        d.emit_rust_function(
            "bignum_eq",
            return_value=("u64", "ret", "ret > 0"),
            parameter_map=[
                ("inout", "rdi", "x.len() => _"),
                ("inout", "rsi", "x.as_ptr() => _"),
                ("inout", "rdx", "y.len() => _"),
                ("inout", "rcx", "y.as_ptr() => _"),
                ("out", "rax", "ret"),
            ],
            rust_decl="pub fn bignum_eq(x: &[u64], y: &[u64]) -> bool",
        )
        parse_file(input, d)
        d.finish_file()

    # aarch64
    with open("../../s2n-bignum/arm/p256/bignum_nonzero_4.S") as input, open(
        "../curve25519/src/low/aarch64/bignum_nonzero_4.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.set_label_prefix("bignum_")
        d.emit_rust_function(
            "bignum_nonzero_4",
            return_value=("u64", "ret", "ret > 0"),
            parameter_map=[
                ("inout", "x0", "x.as_ptr() => ret"),
            ],
            rust_decl="pub fn bignum_nonzero_4(x: &[u64; 4]) -> bool",
        )
        parse_file(input, d)
        d.finish_file()
