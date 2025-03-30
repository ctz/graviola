from parse import parse_file
from driver import (
    Architecture_aarch64,
    Architecture_amd64,
    RustDriver,
)

if __name__ == "__main__":
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
