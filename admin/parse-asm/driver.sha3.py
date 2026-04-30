from driver import (
    Architecture_aarch64,
    Architecture_amd64,
    RustDriver,
)
from parse import parse_file

if __name__ == "__main__":
    with (
        open("../../thirdparty/s2n-bignum/x86/sha3/sha3_keccak_f1600.S") as input,
        open("../../graviola/src/low/x86_64/sha3_keccak_f1600.rs", "w") as output,
    ):
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "sha3_keccak_f1600",
            parameter_map=[
                ("inout", "a.as_mut_ptr() => _"),
                ("inout", "rc.as_ptr() => _"),
            ],
            rust_decl="fn sha3_keccak_f1600(a: &mut [u64; 25], rc: &[u64; 24])",
        )
        parse_file(input, d)

    with (
        open("../../thirdparty/s2n-bignum/arm/sha3/sha3_keccak_f1600.S") as input,
        open("../../graviola/src/low/aarch64/sha3_keccak_f1600.rs", "w") as output,
    ):
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "sha3_keccak_f1600",
            parameter_map=[
                ("inout", "a.as_mut_ptr() => _"),
                ("inout", "rc.as_ptr() => _"),
            ],
            rust_decl="fn sha3_keccak_f1600(a: &mut [u64; 25], rc: &[u64; 24])",
        )
        parse_file(input, d)
