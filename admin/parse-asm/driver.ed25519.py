from parse import parse_file
from driver import (
    Architecture_aarch64,
    Architecture_amd64,
    RustDriver,
)

if __name__ == "__main__":
    # edwards25519_decode (x86_64)
    with open(
        "../../thirdparty/s2n-bignum/x86/curve25519/edwards25519_decode.S"
    ) as input, open(
        "../../graviola/src/low/x86_64/edwards25519_decode.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "edwards25519_decode",
            parameter_map=[
                ("inout", "z.as_mut_ptr() => _"),
                ("inout", "c.as_ptr() => _"),
            ],
            return_value=("u64", "ret", "ret == 0"),
            return_map=("out", "ret"),
            hoist=["proc", "edwards25519_decode_loop", "ret"],
            rust_decl="fn edwards25519_decode(z: &mut [u64; 8], c: &[u8; 32]) -> bool",
        )
        parse_file(input, d)

    # edwards25519_scalarmulbase (x86_64)
    with open(
        "../../thirdparty/s2n-bignum/x86/curve25519/edwards25519_scalarmulbase.S"
    ) as input, open(
        "../../graviola/src/low/x86_64/edwards25519_scalarmulbase.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.add_const_symbol("edwards25519_scalarmulbase_0g")
        d.add_const_symbol("edwards25519_scalarmulbase_251g")
        d.add_const_symbol("edwards25519_scalarmulbase_gtable")
        d.emit_rust_function(
            "edwards25519_scalarmulbase",
            parameter_map=[
                ("inout", "res.as_mut_ptr() => _"),
                ("inout", "scalar.as_ptr() => _"),
            ],
            rust_decl="fn edwards25519_scalarmulbase(res: &mut [u64; 8], scalar: &[u64; 4])",
        )
        parse_file(input, d)

    # bignum_madd_n25519 (x86_64)
    with open(
        "../../thirdparty/s2n-bignum/x86/curve25519/bignum_madd_n25519.S"
    ) as input, open(
        "../../graviola/src/low/x86_64/bignum_madd_n25519.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_madd_n25519",
            parameter_map=[
                ("inout", "z.as_mut_ptr() => _"),
                ("inout", "x.as_ptr() => _"),
                ("inout", "y.as_ptr() => _"),
                ("inout", "c.as_ptr() => _"),
            ],
            rust_decl="fn bignum_madd_n25519(z: &mut [u64; 4], x: &[u64; 4], y: &[u64; 4], c: &[u64; 4])",
        )
        parse_file(input, d)

    # bignum_mod_n25519 (x86_64)
    with open(
        "../../thirdparty/s2n-bignum/x86/curve25519/bignum_mod_n25519.S"
    ) as input, open(
        "../../graviola/src/low/x86_64/bignum_mod_n25519.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_mod_n25519",
            parameter_map=[
                ("inout", "z.as_mut_ptr() => _"),
                ("inout", "x.len() => _"),
                ("inout", "x.as_ptr() => _"),
            ],
            hoist=["linear", "bignum_mod_n25519_shortinput", "jmp"],
            rust_decl="fn bignum_mod_n25519(z: &mut [u64; 4], x: &[u64])",
        )
        parse_file(input, d)

    # edwards25519_decode (aarch64)
    with open(
        "../../thirdparty/s2n-bignum/arm/curve25519/edwards25519_decode_alt.S"
    ) as input, open(
        "../../graviola/src/low/aarch64/edwards25519_decode.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "edwards25519_decode_alt",
            parameter_map=[
                ("inout", "z.as_mut_ptr() => ret"),
                ("inout", "c.as_ptr() => _"),
            ],
            return_value=("u64", "ret", "ret == 0"),
            hoist=["proc", "edwards25519_decode_alt_loop", "ret"],
            rust_decl="fn edwards25519_decode(z: &mut [u64; 8], c: &[u8; 32]) -> bool",
        )
        parse_file(input, d)

    # edwards25519_scalarmulbase (aarch64)
    with open(
        "../../thirdparty/s2n-bignum/arm/curve25519/edwards25519_scalarmulbase_alt.S"
    ) as input, open(
        "../../graviola/src/low/aarch64/edwards25519_scalarmulbase.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.add_const_symbol("edwards25519_scalarmulbase_alt_edwards25519_0g")
        d.add_const_symbol("edwards25519_scalarmulbase_alt_edwards25519_251g")
        d.add_const_symbol("edwards25519_scalarmulbase_alt_edwards25519_gtable")
        d.emit_rust_function(
            "edwards25519_scalarmulbase_alt",
            parameter_map=[
                ("inout", "res.as_mut_ptr() => _"),
                ("inout", "scalar.as_ptr() => _"),
            ],
            rust_decl="fn edwards25519_scalarmulbase(res: &mut [u64; 8], scalar: &[u64; 4])",
        )
        parse_file(input, d)

    # bignum_mod_n25519 (aarch64)
    with open(
        "../../thirdparty/s2n-bignum/arm/curve25519/bignum_mod_n25519.S"
    ) as input, open(
        "../../graviola/src/low/aarch64/bignum_mod_n25519.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_mod_n25519",
            parameter_map=[
                ("inout", "z.as_mut_ptr() => _"),
                ("inout", "x.len() => _"),
                ("inout", "x.as_ptr() => _"),
            ],
            hoist=["linear", "bignum_mod_n25519_short", "b"],
            rust_decl="fn bignum_mod_n25519(z: &mut [u64; 4], x: &[u64])",
        )
        parse_file(input, d)
