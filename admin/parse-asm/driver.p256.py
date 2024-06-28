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
