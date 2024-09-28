from parse import parse_file
from driver import (
    Architecture_aarch64,
    Architecture_amd64,
    RustDriver,
)

if __name__ == "__main__":
    with open(
        "../../thirdparty/s2n-bignum/x86/p256/bignum_montsqr_p256.S"
    ) as input, open(
        "../../graviola/src/low/x86_64/bignum_montsqr_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_montsqr_p256",
            parameter_map=[
                ("inout", "rdi", "z.as_mut_ptr() => _"),
                ("inout", "rsi", "x.as_ptr() => _"),
            ],
            rust_decl="fn bignum_montsqr_p256(z: &mut [u64; 4], x: &[u64; 4])",
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/x86/p256/bignum_montmul_p256.S"
    ) as input, open(
        "../../graviola/src/low/x86_64/bignum_montmul_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_montmul_p256",
            parameter_map=[
                ("inout", "rdi", "z.as_mut_ptr() => _"),
                ("inout", "rsi", "x.as_ptr() => _"),
                ("inout", "rdx", "y.as_ptr() => _"),
            ],
            rust_decl="fn bignum_montmul_p256(z: &mut [u64; 4], x: &[u64; 4], y: &[u64; 4])",
        )
        parse_file(input, d)

    with open("../../thirdparty/s2n-bignum/x86/p256/bignum_add_p256.S") as input, open(
        "../../graviola/src/low/x86_64/bignum_add_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_add_p256",
            parameter_map=[
                ("inout", "rdi", "z.as_mut_ptr() => _"),
                ("inout", "rsi", "x.as_ptr() => _"),
                ("inout", "rdx", "y.as_ptr() => _"),
            ],
            rust_decl="fn bignum_add_p256(z: &mut [u64; 4], x: &[u64; 4], y: &[u64; 4])",
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/x86/p256/bignum_demont_p256.S"
    ) as input, open(
        "../../graviola/src/low/x86_64/bignum_demont_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_demont_p256",
            parameter_map=[
                ("inout", "rdi", "z.as_mut_ptr() => _"),
                ("inout", "rsi", "x.as_ptr() => _"),
            ],
            rust_decl="fn bignum_demont_p256(z: &mut [u64; 4], x: &[u64; 4])",
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/x86/p256/bignum_tomont_p256.S"
    ) as input, open(
        "../../graviola/src/low/x86_64/bignum_tomont_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_tomont_p256",
            parameter_map=[
                ("inout", "rdi", "z.as_mut_ptr() => _"),
                ("inout", "rsi", "x.as_ptr() => _"),
            ],
            rust_decl="fn bignum_tomont_p256(z: &mut [u64; 4], x: &[u64; 4])",
        )
        parse_file(input, d)

    with open("../../thirdparty/s2n-bignum/x86/p256/bignum_neg_p256.S") as input, open(
        "../../graviola/src/low/x86_64/bignum_neg_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_neg_p256",
            parameter_map=[
                ("inout", "rdi", "z.as_mut_ptr() => _"),
                ("inout", "rsi", "x.as_ptr() => _"),
            ],
            rust_decl="fn bignum_neg_p256(z: &mut [u64; 4], x: &[u64; 4])",
        )
        parse_file(input, d)

    with open("../../thirdparty/s2n-bignum/x86/p256/bignum_inv_p256.S") as input, open(
        "../../graviola/src/low/x86_64/bignum_inv_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_inv_p256",
            parameter_map=[
                ("inout", "rdi", "z.as_mut_ptr() => _"),
                ("inout", "rsi", "x.as_ptr() => _"),
            ],
            rust_decl="fn bignum_inv_p256(z: &mut [u64; 4], x: &[u64; 4])",
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/x86/p256/bignum_mod_n256_4.S"
    ) as input, open("../../graviola/src/low/x86_64/bignum_mod_n256.rs", "w") as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_mod_n256_4",
            parameter_map=[
                ("inout", "rdi", "z.as_mut_ptr() => _"),
                ("inout", "rsi", "x.as_ptr() => _"),
            ],
            rust_decl="fn bignum_mod_n256(z: &mut [u64; 4], x: &[u64; 4])",
        )
        parse_file(input, d)

    with open("../../thirdparty/s2n-bignum/x86/generic/bignum_mux.S") as input, open(
        "../../graviola/src/low/x86_64/bignum_mux.rs", "w"
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
            rust_decl="fn bignum_mux(p: u64, z: &mut [u64], x_if_p: &[u64], y_if_not_p: &[u64])",
            assertions=[
                "z.len() == x_if_p.len()",
                "z.len() == y_if_not_p.len()",
            ],
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/x86/generic/bignum_copy_row_from_table.S"
    ) as input, open(
        "../../graviola/src/low/x86_64/bignum_copy_row_from_table.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_copy_row_from_table",
            parameter_map=[
                ("inout", "rdi", "z.as_mut_ptr() => _"),
                ("inout", "rsi", "table.as_ptr() => _"),
                ("inout", "rdx", "height => _"),
                ("inout", "rcx", "width => _"),
                ("inout", "r8", "index => _"),
            ],
            rust_decl="fn bignum_copy_row_from_table(z: &mut [u64], table: &[u64], height: u64, width: u64, index: u64)",
            assertions=[
                "z.len() as u64 == width",
                "index < height",
            ],
        )
        parse_file(input, d)

    with open("../../thirdparty/s2n-bignum/x86/generic/bignum_modadd.S") as input, open(
        "../../graviola/src/low/x86_64/bignum_modadd.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_modadd",
            parameter_map=[
                ("inout", "rdi", "m.len() => _"),
                ("inout", "rsi", "z.as_mut_ptr() => _"),
                ("inout", "rdx", "x.as_ptr() => _"),
                ("inout", "rcx", "y.as_ptr() => _"),
                ("inout", "r8", "m.as_ptr() => _"),
            ],
            rust_decl="fn bignum_modadd(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64])",
            assertions=[
                "z.len() == x.len()",
                "z.len() == y.len()",
                "z.len() == m.len()",
            ],
        )
        parse_file(input, d)

    with open("../../thirdparty/s2n-bignum/x86/generic/bignum_modinv.S") as input, open(
        "../../graviola/src/low/x86_64/bignum_modinv.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_modinv",
            parameter_map=[
                ("inout", "rdi", "b.len() => _"),
                ("inout", "rsi", "z.as_mut_ptr() => _"),
                ("inout", "rdx", "a.as_ptr() => _"),
                ("inout", "rcx", "b.as_ptr() => _"),
                ("inout", "r8", "t.as_mut_ptr() => _"),
            ],
            rust_decl="fn bignum_modinv(z: &mut [u64], a: &[u64], b: &[u64], t: &mut [u64])",
            assertions=[
                "z.len() == a.len()",
                "z.len() == b.len()",
                "z.len() * 3 <= t.len()",
            ],
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/x86/generic/bignum_montmul.S"
    ) as input, open("../../graviola/src/low/x86_64/bignum_montmul.rs", "w") as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_montmul",
            parameter_map=[
                ("inout", "rdi", "m.len() => _"),
                ("inout", "rsi", "z.as_mut_ptr() => _"),
                ("inout", "rdx", "x.as_ptr() => _"),
                ("inout", "rcx", "y.as_ptr() => _"),
                ("inout", "r8", "m.as_ptr() => _"),
            ],
            rust_decl="fn bignum_montmul(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64])",
            assertions=[
                "z.len() == x.len()",
                "z.len() == y.len()",
                "z.len() == m.len()",
            ],
        )
        parse_file(input, d)

    with open("../../thirdparty/s2n-bignum/x86/generic/bignum_demont.S") as input, open(
        "../../graviola/src/low/x86_64/bignum_demont.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_demont",
            parameter_map=[
                ("inout", "rdi", "m.len() => _"),
                ("inout", "rsi", "z.as_mut_ptr() => _"),
                ("inout", "rdx", "x.as_ptr() => _"),
                ("inout", "rcx", "m.as_ptr() => _"),
            ],
            rust_decl="fn bignum_demont(z: &mut [u64], x: &[u64], m: &[u64])",
            assertions=[
                "z.len() == x.len()",
                "z.len() == m.len()",
            ],
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/x86/generic/bignum_montifier.S"
    ) as input, open(
        "../../graviola/src/low/x86_64/bignum_montifier.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_montifier",
            parameter_map=[
                ("inout", "rdi", "m.len() => _"),
                ("inout", "rsi", "z.as_mut_ptr() => _"),
                ("inout", "rdx", "m.as_ptr() => _"),
                ("inout", "rcx", "t.as_mut_ptr() => _"),
            ],
            rust_decl="fn bignum_montifier(z: &mut [u64], m: &[u64], t: &mut [u64])",
            assertions=[
                "z.len() == m.len()",
                "z.len() <= t.len()",
            ],
        )
        parse_file(input, d)

    with open("../../thirdparty/s2n-bignum/x86/p256/p256_montjadd.S") as input, open(
        "../../graviola/src/low/x86_64/p256_montjadd.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "p256_montjadd",
            parameter_map=[
                ("inout", "rdi", "p3.as_mut_ptr() => _"),
                ("inout", "rsi", "p1.as_ptr() => _"),
                ("inout", "rdx", "p2.as_ptr() => _"),
            ],
            rust_decl="fn p256_montjadd(p3: &mut [u64; 12], p1: &[u64; 12], p2: &[u64; 12])",
        )
        parse_file(input, d)

    with open("../../thirdparty/s2n-bignum/x86/p256/p256_montjmixadd.S") as input, open(
        "../../graviola/src/low/x86_64/p256_montjmixadd.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "p256_montjmixadd",
            parameter_map=[
                ("inout", "rdi", "p3.as_mut_ptr() => _"),
                ("inout", "rsi", "p1.as_ptr() => _"),
                ("inout", "rdx", "p2.as_ptr() => _"),
            ],
            rust_decl="fn p256_montjmixadd(p3: &mut [u64; 12], p1: &[u64; 12], p2: &[u64; 8])",
        )
        parse_file(input, d)

    with open("../../thirdparty/s2n-bignum/x86/p256/p256_montjdouble.S") as input, open(
        "../../graviola/src/low/x86_64/p256_montjdouble.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "p256_montjdouble",
            parameter_map=[
                ("inout", "rdi", "p3.as_mut_ptr() => _"),
                ("inout", "rsi", "p1.as_ptr() => _"),
            ],
            rust_decl="fn p256_montjdouble(p3: &mut [u64; 12], p1: &[u64; 12])",
        )
        parse_file(input, d)

    with open("../../thirdparty/s2n-bignum/x86/generic/bignum_eq.S") as input, open(
        "../../graviola/src/low/x86_64/bignum_eq.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
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
            rust_decl="fn bignum_eq(x: &[u64], y: &[u64]) -> bool",
        )
        parse_file(input, d)

    # aarch64
    with open(
        "../../thirdparty/s2n-bignum/arm/p256/bignum_montsqr_p256_neon.S"
    ) as input, open(
        "../../graviola/src/low/aarch64/bignum_montsqr_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_montsqr_p256_neon",
            parameter_map=[
                ("inout", "x0", "z.as_mut_ptr() => _"),
                ("inout", "x1", "x.as_ptr() => _"),
            ],
            rust_decl="fn bignum_montsqr_p256(z: &mut [u64; 4], x: &[u64; 4])",
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/arm/p256/bignum_montmul_p256_neon.S"
    ) as input, open(
        "../../graviola/src/low/aarch64/bignum_montmul_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_montmul_p256_neon",
            parameter_map=[
                ("inout", "x0", "z.as_mut_ptr() => _"),
                ("inout", "x1", "x.as_ptr() => _"),
                ("inout", "x2", "y.as_ptr() => _"),
            ],
            rust_decl="fn bignum_montmul_p256(z: &mut [u64; 4], x: &[u64; 4], y: &[u64; 4])",
        )
        parse_file(input, d)

    with open("../../thirdparty/s2n-bignum/arm/p256/bignum_add_p256.S") as input, open(
        "../../graviola/src/low/aarch64/bignum_add_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_add_p256",
            parameter_map=[
                ("inout", "x0", "z.as_mut_ptr() => _"),
                ("inout", "x1", "x.as_ptr() => _"),
                ("inout", "x2", "y.as_ptr() => _"),
            ],
            rust_decl="fn bignum_add_p256(z: &mut [u64; 4], x: &[u64; 4], y: &[u64; 4])",
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/arm/p256/bignum_demont_p256.S"
    ) as input, open(
        "../../graviola/src/low/aarch64/bignum_demont_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_demont_p256",
            parameter_map=[
                ("inout", "x0", "z.as_mut_ptr() => _"),
                ("inout", "x1", "x.as_ptr() => _"),
            ],
            rust_decl="fn bignum_demont_p256(z: &mut [u64; 4], x: &[u64; 4])",
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/arm/p256/bignum_tomont_p256.S"
    ) as input, open(
        "../../graviola/src/low/aarch64/bignum_tomont_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_tomont_p256",
            parameter_map=[
                ("inout", "x0", "z.as_mut_ptr() => _"),
                ("inout", "x1", "x.as_ptr() => _"),
            ],
            rust_decl="fn bignum_tomont_p256(z: &mut [u64; 4], x: &[u64; 4])",
        )
        parse_file(input, d)

    with open("../../thirdparty/s2n-bignum/arm/p256/bignum_neg_p256.S") as input, open(
        "../../graviola/src/low/aarch64/bignum_neg_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_neg_p256",
            parameter_map=[
                ("inout", "x0", "z.as_mut_ptr() => _"),
                ("inout", "x1", "x.as_ptr() => _"),
            ],
            rust_decl="fn bignum_neg_p256(z: &mut [u64; 4], x: &[u64; 4])",
        )
        parse_file(input, d)

    with open("../../thirdparty/s2n-bignum/arm/p256/bignum_inv_p256.S") as input, open(
        "../../graviola/src/low/aarch64/bignum_inv_p256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_inv_p256",
            parameter_map=[
                ("inout", "x0", "z.as_mut_ptr() => _"),
                ("inout", "x1", "x.as_ptr() => _"),
            ],
            rust_decl="fn bignum_inv_p256(z: &mut [u64; 4], x: &[u64; 4])",
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/arm/p256/bignum_mod_n256_4.S"
    ) as input, open(
        "../../graviola/src/low/aarch64/bignum_mod_n256.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_mod_n256_4",
            parameter_map=[
                ("inout", "x0", "z.as_mut_ptr() => _"),
                ("inout", "x1", "x.as_ptr() => _"),
            ],
            rust_decl="fn bignum_mod_n256(z: &mut [u64; 4], x: &[u64; 4])",
        )
        parse_file(input, d)

    with open("../../thirdparty/s2n-bignum/arm/generic/bignum_mux.S") as input, open(
        "../../graviola/src/low/aarch64/bignum_mux.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_mux",
            parameter_map=[
                ("inout", "x0", "p => _"),
                ("inout", "x1", "z.len() => _"),
                ("inout", "x2", "z.as_mut_ptr() => _"),
                ("inout", "x3", "x_if_p.as_ptr() => _"),
                ("inout", "x4", "y_if_not_p.as_ptr() => _"),
            ],
            rust_decl="fn bignum_mux(p: u64, z: &mut [u64], x_if_p: &[u64], y_if_not_p: &[u64])",
            assertions=[
                "z.len() == x_if_p.len()",
                "z.len() == y_if_not_p.len()",
            ],
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/arm/generic/bignum_copy_row_from_table.S"
    ) as input, open(
        "../../graviola/src/low/aarch64/bignum_copy_row_from_table.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_copy_row_from_table",
            parameter_map=[
                ("inout", "x0", "z.as_mut_ptr() => _"),
                ("inout", "x1", "table.as_ptr() => _"),
                ("inout", "x2", "height => _"),
                ("inout", "x3", "width => _"),
                ("inout", "x4", "index => _"),
            ],
            rust_decl="fn bignum_copy_row_from_table(z: &mut [u64], table: &[u64], height: u64, width: u64, index: u64)",
            assertions=[
                "z.len() as u64 == width",
                "index < height",
            ],
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/arm/generic/bignum_copy_row_from_table_8n_neon.S"
    ) as input, open(
        "../../graviola/src/low/aarch64/bignum_copy_row_from_table_8n_neon.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_copy_row_from_table_8n_neon",
            parameter_map=[
                ("inout", "x0", "z.as_mut_ptr() => _"),
                ("inout", "x1", "table.as_ptr() => _"),
                ("inout", "x2", "height => _"),
                ("inout", "x3", "width => _"),
                ("inout", "x4", "index => _"),
            ],
            rust_decl="fn bignum_copy_row_from_table_8n_neon(z: &mut [u64], table: &[u64], height: u64, width: u64, index: u64)",
            assertions=[
                "z.len() as u64 == width",
                "width % 8 == 0",
                "index < height",
            ],
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/arm/generic/bignum_copy_row_from_table_16_neon.S"
    ) as input, open(
        "../../graviola/src/low/aarch64/bignum_copy_row_from_table_16_neon.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_copy_row_from_table_16_neon",
            parameter_map=[
                ("inout", "x0", "z.as_mut_ptr() => _"),
                ("inout", "x1", "table.as_ptr() => _"),
                ("inout", "x2", "height => _"),
                ("inout", "x3", "index => _"),
            ],
            rust_decl="fn bignum_copy_row_from_table_16_neon(z: &mut [u64], table: &[u64], height: u64, index: u64)",
            assertions=[
                "z.len() == 16",
                "index < height",
            ],
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/arm/generic/bignum_copy_row_from_table_32_neon.S"
    ) as input, open(
        "../../graviola/src/low/aarch64/bignum_copy_row_from_table_32_neon.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_copy_row_from_table_32_neon",
            parameter_map=[
                ("inout", "x0", "z.as_mut_ptr() => _"),
                ("inout", "x1", "table.as_ptr() => _"),
                ("inout", "x2", "height => _"),
                ("inout", "x3", "index => _"),
            ],
            rust_decl="fn bignum_copy_row_from_table_32_neon(z: &mut [u64], table: &[u64], height: u64, index: u64)",
            assertions=[
                "z.len() == 32",
                "index < height",
            ],
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/arm/p256/p256_montjadd_alt.S"
    ) as input, open("../../graviola/src/low/aarch64/p256_montjadd.rs", "w") as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "p256_montjadd_alt",
            parameter_map=[
                ("inout", "x0", "p3.as_mut_ptr() => _"),
                ("inout", "x1", "p1.as_ptr() => _"),
                ("inout", "x2", "p2.as_ptr() => _"),
            ],
            rust_decl="fn p256_montjadd(p3: &mut [u64; 12], p1: &[u64; 12], p2: &[u64; 12])",
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/arm/p256/p256_montjmixadd_alt.S"
    ) as input, open(
        "../../graviola/src/low/aarch64/p256_montjmixadd.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "p256_montjmixadd_alt",
            parameter_map=[
                ("inout", "x0", "p3.as_mut_ptr() => _"),
                ("inout", "x1", "p1.as_ptr() => _"),
                ("inout", "x2", "p2.as_ptr() => _"),
            ],
            rust_decl="fn p256_montjmixadd(p3: &mut [u64; 12], p1: &[u64; 12], p2: &[u64; 8])",
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/arm/p256/p256_montjdouble_alt.S"
    ) as input, open(
        "../../graviola/src/low/aarch64/p256_montjdouble.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "p256_montjdouble_alt",
            parameter_map=[
                ("inout", "x0", "p3.as_mut_ptr() => _"),
                ("inout", "x1", "p1.as_ptr() => _"),
            ],
            rust_decl="fn p256_montjdouble(p3: &mut [u64; 12], p1: &[u64; 12])",
        )
        parse_file(input, d)

    with open("../../thirdparty/s2n-bignum/arm/generic/bignum_eq.S") as input, open(
        "../../graviola/src/low/aarch64/bignum_eq.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_eq",
            return_value=("u64", "ret", "ret > 0"),
            parameter_map=[
                ("inout", "x0", "x.len() => ret"),
                ("inout", "x1", "x.as_ptr() => _"),
                ("inout", "x2", "y.len() => _"),
                ("inout", "x3", "y.as_ptr() => _"),
            ],
            rust_decl="fn bignum_eq(x: &[u64], y: &[u64]) -> bool",
        )
        parse_file(input, d)

    with open("../../thirdparty/s2n-bignum/arm/generic/bignum_modadd.S") as input, open(
        "../../graviola/src/low/aarch64/bignum_modadd.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_modadd",
            parameter_map=[
                ("inout", "x0", "m.len() => _"),
                ("inout", "x1", "z.as_mut_ptr() => _"),
                ("inout", "x2", "x.as_ptr() => _"),
                ("inout", "x3", "y.as_ptr() => _"),
                ("inout", "x4", "m.as_ptr() => _"),
            ],
            rust_decl="fn bignum_modadd(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64])",
            assertions=[
                "z.len() == x.len()",
                "z.len() == y.len()",
                "z.len() == m.len()",
            ],
        )
        parse_file(input, d)

    with open("../../thirdparty/s2n-bignum/arm/generic/bignum_modinv.S") as input, open(
        "../../graviola/src/low/aarch64/bignum_modinv.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_modinv",
            parameter_map=[
                ("inout", "x0", "b.len() => _"),
                ("inout", "x1", "z.as_mut_ptr() => _"),
                ("inout", "x2", "a.as_ptr() => _"),
                ("inout", "x3", "b.as_ptr() => _"),
                ("inout", "x4", "t.as_mut_ptr() => _"),
            ],
            rust_decl="fn bignum_modinv(z: &mut [u64], a: &[u64], b: &[u64], t: &mut [u64])",
            assertions=[
                "z.len() == a.len()",
                "z.len() == b.len()",
                "z.len() * 3 <= t.len()",
            ],
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/arm/generic/bignum_montmul.S"
    ) as input, open("../../graviola/src/low/aarch64/bignum_montmul.rs", "w") as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_montmul",
            parameter_map=[
                ("inout", "x0", "m.len() => _"),
                ("inout", "x1", "z.as_mut_ptr() => _"),
                ("inout", "x2", "x.as_ptr() => _"),
                ("inout", "x3", "y.as_ptr() => _"),
                ("inout", "x4", "m.as_ptr() => _"),
            ],
            rust_decl="fn bignum_montmul(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64])",
            assertions=[
                "z.len() == x.len()",
                "z.len() == y.len()",
                "z.len() == m.len()",
            ],
        )
        parse_file(input, d)

    with open("../../thirdparty/s2n-bignum/arm/generic/bignum_demont.S") as input, open(
        "../../graviola/src/low/aarch64/bignum_demont.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_demont",
            parameter_map=[
                ("inout", "x0", "m.len() => _"),
                ("inout", "x1", "z.as_mut_ptr() => _"),
                ("inout", "x2", "x.as_ptr() => _"),
                ("inout", "x3", "m.as_ptr() => _"),
            ],
            rust_decl="fn bignum_demont(z: &mut [u64], x: &[u64], m: &[u64])",
            assertions=[
                "z.len() == x.len()",
                "z.len() == m.len()",
            ],
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/arm/generic/bignum_montifier.S"
    ) as input, open(
        "../../graviola/src/low/aarch64/bignum_montifier.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_montifier",
            parameter_map=[
                ("inout", "x0", "m.len() => _"),
                ("inout", "x1", "z.as_mut_ptr() => _"),
                ("inout", "x2", "m.as_ptr() => _"),
                ("inout", "x3", "t.as_mut_ptr() => _"),
            ],
            rust_decl="fn bignum_montifier(z: &mut [u64], m: &[u64], t: &mut [u64])",
            assertions=[
                "z.len() == m.len()",
                "z.len() <= t.len()",
            ],
        )
        parse_file(input, d)
