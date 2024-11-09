from parse import parse_file
from driver import (
    Architecture_aarch64,
    Architecture_amd64,
    RustDriver,
)

if __name__ == "__main__":
    with open(
        "../../thirdparty/s2n-bignum/x86/curve25519/curve25519_x25519.S"
    ) as input, open(
        "../../graviola/src/low/x86_64/curve25519_x25519.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "curve25519_x25519",
            parameter_map=[
                ("inout", "res.as_mut_ptr() => _"),
                ("inout", "scalar.as_ptr() => _"),
                ("inout", "point.as_ptr() => _"),
            ],
            rust_decl="fn curve25519_x25519(res: &mut [u64; 4], scalar: &[u64; 4], point: &[u64; 4])",
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/x86/curve25519/curve25519_x25519base.S"
    ) as input, open(
        "../../graviola/src/low/x86_64/curve25519_x25519base.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.add_const_symbol("curve25519_x25519base_edwards25519_0g")
        d.add_const_symbol("curve25519_x25519base_edwards25519_8g")
        d.add_const_symbol("curve25519_x25519base_edwards25519_gtable")
        d.emit_rust_function(
            "curve25519_x25519base",
            parameter_map=[
                ("inout", "res.as_mut_ptr() => _"),
                ("inout", "scalar.as_ptr() => _"),
            ],
            rust_decl="fn curve25519_x25519base(res: &mut [u64; 4], scalar: &[u64; 4])",
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/arm/curve25519/curve25519_x25519_alt.S"
    ) as input, open(
        "../../graviola/src/low/aarch64/curve25519_x25519.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "curve25519_x25519_alt",
            parameter_map=[
                ("inout", "res.as_mut_ptr() => _"),
                ("inout", "scalar.as_ptr() => _"),
                ("inout", "point.as_ptr() => _"),
            ],
            rust_decl="fn curve25519_x25519(res: &mut [u64; 4], scalar: &[u64; 4], point: &[u64; 4])",
        )
        parse_file(input, d)

    with open(
        "../../thirdparty/s2n-bignum/arm/curve25519/curve25519_x25519base_alt.S"
    ) as input, open(
        "../../graviola/src/low/aarch64/curve25519_x25519base.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.add_const_symbol("curve25519_x25519base_alt_edwards25519_0g")
        d.add_const_symbol("curve25519_x25519base_alt_edwards25519_8g")
        d.add_const_symbol("curve25519_x25519base_alt_edwards25519_gtable")
        d.emit_rust_function(
            "curve25519_x25519base_alt",
            parameter_map=[
                ("inout", "res.as_mut_ptr() => _"),
                ("inout", "scalar.as_ptr() => _"),
            ],
            rust_decl="fn curve25519_x25519base(res: &mut [u64; 4], scalar: &[u64; 4])",
        )
        parse_file(input, d)
