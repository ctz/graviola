from driver import (
    Architecture_aarch64,
    Architecture_amd64,
    RustDriver,
)
from parse import parse_file

if __name__ == "__main__":
    with (
        open("../../thirdparty/s2n-bignum/x86/mlkem/mlkem_ntt.S") as input,
        open("../../graviola/src/low/x86_64/mlkem_ntt.rs", "w") as output,
    ):
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "mlkem_ntt_x86",
            parameter_map=[
                ("inout", "a.as_mut_ptr() => _"),
                ("inout", "qdata.as_ptr() => _"),
            ],
            assertions=[
                "(a.as_mut_ptr() as usize).is_multiple_of(32)",
                "(qdata.as_ptr() as usize).is_multiple_of(32)",
            ],
            rust_decl="fn mlkem_ntt(a: &mut [i16; 256], qdata: &[i16; 624])",
        )
        parse_file(input, d)

    with (
        open("../../thirdparty/s2n-bignum/x86/mlkem/mlkem_intt.S") as input,
        open("../../graviola/src/low/x86_64/mlkem_intt.rs", "w") as output,
    ):
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "mlkem_intt_x86",
            parameter_map=[
                ("inout", "a.as_mut_ptr() => _"),
                ("inout", "qdata.as_ptr() => _"),
            ],
            assertions=[
                "(a.as_mut_ptr() as usize).is_multiple_of(32)",
                "(qdata.as_ptr() as usize).is_multiple_of(32)",
            ],
            rust_decl="fn mlkem_intt(a: &mut [i16; 256], qdata: &[i16; 624])",
        )
        parse_file(input, d)

    with (
        open("../../thirdparty/s2n-bignum/x86/mlkem/mlkem_tobytes.S") as input,
        open("../../graviola/src/low/x86_64/mlkem_tobytes.rs", "w") as output,
    ):
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "mlkem_tobytes",
            parameter_map=[
                ("inout", "r.as_mut_ptr() => _"),
                ("inout", "a.as_ptr() => _"),
            ],
            assertions=[
                "(a.as_ptr() as usize).is_multiple_of(32)",
            ],
            rust_decl="fn mlkem_tobytes(r: &mut [u8; 384], a: &[i16; 256])",
        )
        parse_file(input, d)

    with (
        open("../../thirdparty/s2n-bignum/x86/mlkem/mlkem_frombytes.S") as input,
        open("../../graviola/src/low/x86_64/mlkem_frombytes.rs", "w") as output,
    ):
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "mlkem_frombytes",
            parameter_map=[
                ("inout", "r.as_mut_ptr() => _"),
                ("inout", "a.as_ptr() => _"),
            ],
            rust_decl="fn mlkem_frombytes(r: &mut [i16; 256], a: &[u8; 384])",
        )
        parse_file(input, d)

    with (
        open("../../thirdparty/s2n-bignum/x86/mlkem/mlkem_tomont.S") as input,
        open("../../graviola/src/low/x86_64/mlkem_tomont.rs", "w") as output,
    ):
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "mlkem_tomont",
            parameter_map=[
                ("inout", "a.as_mut_ptr() => _"),
            ],
            rust_decl="fn mlkem_tomont(a: &mut [i16; 256])",
        )
        parse_file(input, d)

    with (
        open("../../thirdparty/s2n-bignum/x86/mlkem/mlkem_unpack.S") as input,
        open("../../graviola/src/low/x86_64/mlkem_unpack.rs", "w") as output,
    ):
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "mlkem_unpack",
            parameter_map=[
                ("inout", "a.as_mut_ptr() => _"),
            ],
            rust_decl="fn mlkem_unpack(a: &mut [i16; 256])",
        )
        parse_file(input, d)

    with (
        open("../../thirdparty/s2n-bignum/x86/mlkem/mlkem_mulcache_compute.S") as input,
        open("../../graviola/src/low/x86_64/mlkem_mulcache_compute.rs", "w") as output,
    ):
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "mlkem_mulcache_compute_x86",
            parameter_map=[
                ("inout", "x.as_mut_ptr() => _"),
                ("inout", "a.as_ptr() => _"),
                ("inout", "qdata.as_ptr() => _"),
            ],
            rust_decl="fn mlkem_mulcache_compute(x: &mut [i16; 128], a: &[i16; 256], qdata: &[i16; 624])",
        )
        parse_file(input, d)

    with (
        open("../../thirdparty/s2n-bignum/x86/mlkem/mlkem_basemul_k3.S") as input,
        open("../../graviola/src/low/x86_64/mlkem_basemul_k3.rs", "w") as output,
    ):
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "mlkem_basemul_k3",
            parameter_map=[
                ("inout", "r.as_mut_ptr() => _"),
                ("inout", "a.as_ptr() => _"),
                ("inout", "b.as_ptr() => _"),
                ("inout", "bt.as_ptr() => _"),
            ],
            rust_decl="fn mlkem_basemul_k3(r: &mut [i16; 256], a: &[i16; 768], b: &[i16; 768], bt: &[i16; 384])",
        )
        parse_file(input, d)

    with (
        open("../../thirdparty/s2n-bignum/x86/mlkem/mlkem_reduce.S") as input,
        open("../../graviola/src/low/x86_64/mlkem_reduce.rs", "w") as output,
    ):
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "mlkem_reduce",
            parameter_map=[
                ("inout", "a.as_mut_ptr() => _"),
            ],
            rust_decl="fn mlkem_reduce(a: &mut [i16; 256])",
        )
        parse_file(input, d)

    with (
        open(
            "../../thirdparty/s2n-bignum/x86/mlkem/mlkem_rej_uniform_VARIABLE_TIME.S"
        ) as input,
        open(
            "../../graviola/src/low/x86_64/mlkem_rej_uniform_vartime.rs", "w"
        ) as output,
    ):
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "mlkem_rej_uniform_VARIABLE_TIME",
            return_value=("u64", "ret", "ret"),
            parameter_map=[
                ("inout", "r.as_mut_ptr() => _"),
                ("inout", "input.as_ptr() => _"),
                ("inout", "input.len() => _"),
                ("inout", "table.as_ptr() => _"),
            ],
            return_map=("out", "ret"),
            rust_decl="fn mlkem_rej_uniform_vartime(r: &mut [i16; 256], input: &[u8], table: &[i8]) -> u64",
        )
        parse_file(input, d)

    with (
        open("../../thirdparty/s2n-bignum/arm/mlkem/mlkem_ntt.S") as input,
        open("../../graviola/src/low/aarch64/mlkem_ntt.rs", "w") as output,
    ):
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "mlkem_ntt",
            parameter_map=[
                ("inout", "a.as_mut_ptr() => _"),
                ("inout", "z_01234.as_ptr() => _"),
                ("inout", "z_56.as_ptr() => _"),
            ],
            assertions=[
                "(a.as_mut_ptr() as usize).is_multiple_of(32)",
                "(z_01234.as_ptr() as usize).is_multiple_of(32)",
                "(z_56.as_ptr() as usize).is_multiple_of(32)",
            ],
            rust_decl="fn mlkem_ntt(a: &mut [i16; 256], z_01234: &[i16; 80], z_56: &[i16; 384])",
        )
        parse_file(input, d)

    with (
        open("../../thirdparty/s2n-bignum/arm/mlkem/mlkem_intt.S") as input,
        open("../../graviola/src/low/aarch64/mlkem_intt.rs", "w") as output,
    ):
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "mlkem_intt",
            parameter_map=[
                ("inout", "a.as_mut_ptr() => _"),
                ("inout", "z_01234.as_ptr() => _"),
                ("inout", "z_56.as_ptr() => _"),
            ],
            assertions=[
                "(a.as_mut_ptr() as usize).is_multiple_of(32)",
                "(z_01234.as_ptr() as usize).is_multiple_of(32)",
                "(z_56.as_ptr() as usize).is_multiple_of(32)",
            ],
            rust_decl="fn mlkem_intt(a: &mut [i16; 256], z_01234: &[i16; 80], z_56: &[i16; 384])",
        )
        parse_file(input, d)

    with (
        open("../../thirdparty/s2n-bignum/arm/mlkem/mlkem_tobytes.S") as input,
        open("../../graviola/src/low/aarch64/mlkem_tobytes.rs", "w") as output,
    ):
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "mlkem_tobytes",
            parameter_map=[
                ("inout", "r.as_mut_ptr() => _"),
                ("inout", "a.as_ptr() => _"),
            ],
            assertions=[
                "(a.as_ptr() as usize).is_multiple_of(32)",
            ],
            rust_decl="fn mlkem_tobytes(r: &mut [u8; 384], a: &[i16; 256])",
        )
        parse_file(input, d)

    with (
        open("../../thirdparty/s2n-bignum/arm/mlkem/mlkem_tomont.S") as input,
        open("../../graviola/src/low/aarch64/mlkem_tomont.rs", "w") as output,
    ):
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "mlkem_tomont",
            parameter_map=[
                ("inout", "a.as_mut_ptr() => _"),
            ],
            rust_decl="fn mlkem_tomont(a: &mut [i16; 256])",
        )
        parse_file(input, d)

    with (
        open("../../thirdparty/s2n-bignum/arm/mlkem/mlkem_mulcache_compute.S") as input,
        open("../../graviola/src/low/aarch64/mlkem_mulcache_compute.rs", "w") as output,
    ):
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "mlkem_mulcache_compute",
            parameter_map=[
                ("inout", "x.as_mut_ptr() => _"),
                ("inout", "a.as_ptr() => _"),
                ("inout", "z.as_ptr() => _"),
                ("inout", "t.as_ptr() => _"),
            ],
            rust_decl="fn mlkem_mulcache_compute(x: &mut [i16; 128], a: &[i16; 256], z: &[i16; 128], t: &[i16; 128])",
        )
        parse_file(input, d)

    with (
        open("../../thirdparty/s2n-bignum/arm/mlkem/mlkem_basemul_k3.S") as input,
        open("../../graviola/src/low/aarch64/mlkem_basemul_k3.rs", "w") as output,
    ):
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "mlkem_basemul_k3",
            parameter_map=[
                ("inout", "r.as_mut_ptr() => _"),
                ("inout", "a.as_ptr() => _"),
                ("inout", "b.as_ptr() => _"),
                ("inout", "bt.as_ptr() => _"),
            ],
            rust_decl="fn mlkem_basemul_k3(r: &mut [i16; 256], a: &[i16; 768], b: &[i16; 768], bt: &[i16; 384])",
        )
        parse_file(input, d)

    with (
        open("../../thirdparty/s2n-bignum/arm/mlkem/mlkem_reduce.S") as input,
        open("../../graviola/src/low/aarch64/mlkem_reduce.rs", "w") as output,
    ):
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "mlkem_reduce",
            parameter_map=[
                ("inout", "a.as_mut_ptr() => _"),
            ],
            rust_decl="fn mlkem_reduce(a: &mut [i16; 256])",
        )
        parse_file(input, d)

    with (
        open(
            "../../thirdparty/s2n-bignum/arm/mlkem/mlkem_rej_uniform_VARIABLE_TIME.S"
        ) as input,
        open(
            "../../graviola/src/low/aarch64/mlkem_rej_uniform_vartime.rs", "w"
        ) as output,
    ):
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "mlkem_rej_uniform_VARIABLE_TIME",
            return_value=("u64", "ret", "ret"),
            parameter_map=[
                ("inout", "r.as_mut_ptr() => ret"),
                ("inout", "input.as_ptr() => _"),
                ("inout", "input.len() => _"),
                ("inout", "table.as_ptr() => _"),
            ],
            rust_decl="fn mlkem_rej_uniform_vartime(r: &mut [i16; 256], input: &[u8], table: &[i8]) -> u64",
        )
        parse_file(input, d)
