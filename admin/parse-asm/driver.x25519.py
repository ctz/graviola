from parse import parse_file
from driver import (
    Architecture_amd64,
    RustDriver,
)

if __name__ == "__main__":
    with open("../../s2n-bignum/x86/curve25519/curve25519_x25519.S") as input, open(
        "../curve25519/src/low/x86_64/curve25519_x25519.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.set_label_prefix("curve25519_")
        d.emit_rust_function(
            "curve25519_x25519",
            parameter_map=[
                ("inout", "rdi", "res.as_mut_ptr() => _"),
                ("inout", "rsi", "scalar.as_ptr() => _"),
                ("inout", "rdx", "point.as_ptr() => _"),
            ],
            rust_decl="pub fn curve25519_x25519(res: &mut [u8; 32], scalar: &[u8; 32], point: &[u8; 32])",
        )
        parse_file(input, d)
        d.finish_file()

    with open("../../s2n-bignum/x86/curve25519/curve25519_x25519base.S") as input, open(
        "../curve25519/src/low/x86_64/curve25519_x25519base.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.set_label_prefix("curve25519_")
        d.add_const_symbol("curve25519_x25519base_edwards25519_0g")
        d.add_const_symbol("curve25519_x25519base_edwards25519_8g")
        d.add_const_symbol("curve25519_x25519base_edwards25519_gtable")
        d.emit_rust_function(
            "curve25519_x25519base",
            parameter_map=[
                ("inout", "rdi", "res.as_mut_ptr() => _"),
                ("inout", "rsi", "scalar.as_ptr() => _"),
            ],
            rust_decl="pub fn curve25519_x25519base(res: &mut [u8; 32], scalar: &[u8; 32])",
        )
        parse_file(input, d)
        d.finish_file()
