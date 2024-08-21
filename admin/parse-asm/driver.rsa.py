from parse import parse_file, assemble_and_disassemble
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
            return_value=("u64", "ret", "ret"),
            hoist=["linear", "ytoploop", "ret"],
            rust_decl="pub fn bignum_cmp_lt(x: &[u64], y: &[u64]) -> u64",
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

    extras = {
        "bignum_ksqr_32_64": dict(hoist=["proc", "local_bignum_sqr_16_32", "ret"]),
        "bignum_kmul_32_64": dict(hoist=["proc", "local_bignum_kmul_16_32", "ret"]),
    }

    for op, inwidth, tmpwidth in (
        ("ksqr", 16, 24),
        ("kmul", 16, 32),
        ("ksqr", 32, 72),
        ("kmul", 32, 96),
    ):
        outwidth = inwidth * 2
        name = "bignum_%s_%d_%d" % (op, inwidth, outwidth)

        with open("../../s2n-bignum/x86/fastmul/%s.S" % name) as input, open(
            "../curve25519/src/low/x86_64/%s.rs" % name, "w"
        ) as output:

            if op == "kmul":
                parameter_map = [
                    ("inout", "rdi", "z.as_mut_ptr() => _"),
                    ("inout", "rsi", "x.as_ptr() => _"),
                    ("inout", "rdx", "y.as_ptr() => _"),
                    ("inout", "rcx", "t.as_mut_ptr() => _"),
                ]
                assertions = [
                    "z.len() == %d" % outwidth,
                    "x.len() == %d" % inwidth,
                    "y.len() == %d" % inwidth,
                    "t.len() >= %d" % tmpwidth,
                ]
                params = "z: &mut [u64], x: &[u64], y: &[u64], t: &mut [u64]"
            elif op == "ksqr":
                parameter_map = [
                    ("inout", "rdi", "z.as_mut_ptr() => _"),
                    ("inout", "rsi", "x.as_ptr() => _"),
                    ("inout", "rdx", "t.as_mut_ptr() => _"),
                ]
                assertions = [
                    "z.len() == %d" % outwidth,
                    "x.len() == %d" % inwidth,
                    "t.len() >= %d" % tmpwidth,
                ]
                params = "z: &mut [u64], x: &[u64], t: &mut [u64]"

            d = RustDriver(output, Architecture_amd64)
            d.emit_rust_function(
                name,
                parameter_map=parameter_map,
                assertions=assertions,
                rust_decl="pub fn %s(%s)" % (name, params),
                **extras.get(name, {})
            )
            input = assemble_and_disassemble(input, tool_prefix="x86_64-linux-gnu-")
            parse_file(input, d)

    with open("../../s2n-bignum/x86/fastmul/bignum_emontredc_8n.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_emontredc_8n.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_emontredc_8n",
            parameter_map=[
                ("inout", "rdi", "m.len() => _"),
                ("inout", "rsi", "z.as_mut_ptr() => _"),
                ("inout", "rdx", "m.as_ptr() => _"),
                ("inout", "rcx", "w => _"),
                ("out", "rax", "ret"),
            ],
            return_value=["u64", "ret", "ret"],
            assertions=["z.len() == m.len() * 2", "z.len() % 8 == 0"],
            rust_decl="pub fn bignum_emontredc_8n(z: &mut [u64], m: &[u64], w: u64) -> u64",
        )

        input = assemble_and_disassemble(input, tool_prefix="x86_64-linux-gnu-")
        parse_file(input, d)

    with open("../../s2n-bignum/x86/generic/bignum_optsub.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_optsub.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_optsub",
            parameter_map=[
                ("inout", "rdi", "z.len() => _"),
                ("inout", "rsi", "z.as_mut_ptr() => _"),
                ("inout", "rdx", "x.as_ptr() => _"),
                ("inout", "rcx", "p => _"),
                ("inout", "r8", "y.as_ptr() => _"),
            ],
            rust_decl="pub fn bignum_optsub(z: &mut [u64], x: &[u64], y: &[u64], p: u64)",
        )
        parse_file(input, d)

    with open("../../s2n-bignum/x86/generic/bignum_negmodinv.S") as input, open(
        "../curve25519/src/low/x86_64/bignum_negmodinv.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_amd64)
        d.emit_rust_function(
            "bignum_negmodinv",
            parameter_map=[
                ("inout", "rdi", "z.len() => _"),
                ("inout", "rsi", "z.as_mut_ptr() => _"),
                ("inout", "rdx", "x.as_ptr() => _"),
            ],
            assertions=["z.len() == x.len()"],
            rust_decl="pub fn bignum_negmodinv(z: &mut [u64], x: &[u64])",
        )
        parse_file(input, d)

    # aarch64
    with open("../../s2n-bignum/arm/generic/bignum_montsqr.S") as input, open(
        "../curve25519/src/low/aarch64/bignum_montsqr.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_montsqr",
            parameter_map=[
                ("inout", "x0", "z.len() => _"),
                ("inout", "x1", "z.as_mut_ptr() => _"),
                ("inout", "x2", "x.as_ptr() => _"),
                ("inout", "x3", "m.as_ptr() => _"),
            ],
            assertions=[
                "z.len() == x.len()",
                "z.len() == m.len()",
            ],
            rust_decl="pub fn bignum_montsqr(z: &mut [u64], x: &[u64], m: &[u64])",
        )
        parse_file(input, d)

    with open("../../s2n-bignum/arm/generic/bignum_bitsize.S") as input, open(
        "../curve25519/src/low/aarch64/bignum_bitsize.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_bitsize",
            parameter_map=[
                ("inout", "x0", "x.len() => ret"),
                ("inout", "x1", "x.as_ptr() => _"),
            ],
            return_value=("u64", "ret", "ret as usize"),
            rust_decl="pub fn bignum_bitsize(x: &[u64]) -> usize",
        )
        parse_file(input, d)

    with open("../../s2n-bignum/arm/generic/bignum_lt.S") as input, open(
        "../curve25519/src/low/aarch64/bignum_cmp_lt.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_lt",
            parameter_map=[
                ("inout", "x0", "x.len() => ret"),
                ("inout", "x1", "x.as_ptr() => _"),
                ("inout", "x2", "y.len() => _"),
                ("inout", "x3", "y.as_ptr() => _"),
            ],
            return_value=("u64", "ret", "ret"),
            hoist=["linear", "ytoploop", "ret"],
            rust_decl="pub fn bignum_cmp_lt(x: &[u64], y: &[u64]) -> u64",
        )
        parse_file(input, d)

    with open("../../s2n-bignum/arm/generic/bignum_mul.S") as input, open(
        "../curve25519/src/low/aarch64/bignum_mul.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_mul",
            parameter_map=[
                ("inout", "x0", "z.len() => _"),
                ("inout", "x1", "z.as_mut_ptr() => _"),
                ("inout", "x2", "x.len() => _"),
                ("inout", "x3", "x.as_ptr() => _"),
                ("inout", "x4", "y.len() => _"),
                ("inout", "x5", "y.as_ptr() => _"),
            ],
            assertions=[
                "z.len() >= x.len() + y.len()",
            ],
            rust_decl="pub fn bignum_mul(z: &mut [u64], x: &[u64], y: &[u64])",
        )
        parse_file(input, d)

    with open("../../s2n-bignum/arm/generic/bignum_add.S") as input, open(
        "../curve25519/src/low/aarch64/bignum_add.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_add",
            parameter_map=[
                ("inout", "x0", "z.len() => _"),
                ("inout", "x1", "z.as_mut_ptr() => _"),
                ("inout", "x2", "x.len() => _"),
                ("inout", "x3", "x.as_ptr() => _"),
                ("inout", "x4", "y.len() => _"),
                ("inout", "x5", "y.as_ptr() => _"),
            ],
            hoist=["linear", "tail", "ret"],
            rust_decl="pub fn bignum_add(z: &mut [u64], x: &[u64], y: &[u64])",
        )
        parse_file(input, d)

    with open("../../s2n-bignum/arm/generic/bignum_modsub.S") as input, open(
        "../curve25519/src/low/aarch64/bignum_modsub.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_modsub",
            parameter_map=[
                ("inout", "x0", "z.len() => _"),
                ("inout", "x1", "z.as_mut_ptr() => _"),
                ("inout", "x2", "x.as_ptr() => _"),
                ("inout", "x3", "y.as_ptr() => _"),
                ("inout", "x4", "m.as_ptr() => _"),
            ],
            assertions=[
                "z.len() == x.len()",
                "z.len() == y.len()",
                "z.len() == m.len()",
            ],
            rust_decl="pub fn bignum_modsub(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64])",
        )
        parse_file(input, d)

    with open("../../s2n-bignum/arm/generic/bignum_montredc.S") as input, open(
        "../curve25519/src/low/aarch64/bignum_montredc.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_montredc",
            parameter_map=[
                ("inout", "x0", "z.len() => _"),
                ("inout", "x1", "z.as_mut_ptr() => _"),
                ("inout", "x2", "x.len() => _"),
                ("inout", "x3", "x.as_ptr() => _"),
                ("inout", "x4", "m.as_ptr() => _"),
                ("inout", "x5", "p => _"),
            ],
            assertions=["z.len() == m.len()"],
            rust_decl="pub fn bignum_montredc(z: &mut [u64], x: &[u64], m: &[u64], p: u64)",
        )
        parse_file(input, d)

    with open("../../s2n-bignum/arm/generic/bignum_digitsize.S") as input, open(
        "../curve25519/src/low/aarch64/bignum_digitsize.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_digitsize",
            parameter_map=[
                ("inout", "x0", "z.len() => ret"),
                ("inout", "x1", "z.as_ptr() => _"),
            ],
            return_value=("u64", "ret", "ret as usize"),
            rust_decl="pub fn bignum_digitsize(z: &[u64]) -> usize",
        )
        parse_file(input, d)

    extras = {
        "bignum_ksqr_32_64": dict(
            hoist=["proc", "bignum_ksqr_32_64_local_sqr_8_16", "ret"]
        ),
        "bignum_kmul_32_64": dict(
            hoist=["proc", "bignum_kmul_32_64_local_mul_8_16", "ret"]
        ),
        "bignum_ksqr_16_32": dict(
            hoist=["proc", "bignum_ksqr_16_32_local_sqr_8_16", "ret"]
        ),
        "bignum_kmul_16_32": dict(
            hoist=["proc", "bignum_kmul_16_32_local_mul_8_16", "ret"]
        ),
    }

    for op, inwidth, tmpwidth in (
        ("ksqr", 16, 24),
        ("kmul", 16, 32),
        ("ksqr", 32, 72),
        ("kmul", 32, 96),
    ):
        outwidth = inwidth * 2
        name = "bignum_%s_%d_%d" % (op, inwidth, outwidth)

        with open("../../s2n-bignum/arm/fastmul/%s.S" % name) as input, open(
            "../curve25519/src/low/aarch64/%s.rs" % name, "w"
        ) as output:

            if op == "kmul":
                parameter_map = [
                    ("inout", "x0", "z.as_mut_ptr() => _"),
                    ("inout", "x1", "x.as_ptr() => _"),
                    ("inout", "x2", "y.as_ptr() => _"),
                    ("inout", "x3", "t.as_mut_ptr() => _"),
                ]
                assertions = [
                    "z.len() == %d" % outwidth,
                    "x.len() == %d" % inwidth,
                    "y.len() == %d" % inwidth,
                    "t.len() >= %d" % tmpwidth,
                ]
                params = "z: &mut [u64], x: &[u64], y: &[u64], t: &mut [u64]"
            elif op == "ksqr":
                parameter_map = [
                    ("inout", "x0", "z.as_mut_ptr() => _"),
                    ("inout", "x1", "x.as_ptr() => _"),
                    ("inout", "x2", "t.as_mut_ptr() => _"),
                ]
                assertions = [
                    "z.len() == %d" % outwidth,
                    "x.len() == %d" % inwidth,
                    "t.len() >= %d" % tmpwidth,
                ]
                params = "z: &mut [u64], x: &[u64], t: &mut [u64]"

            d = RustDriver(output, Architecture_aarch64)
            d.emit_rust_function(
                name,
                parameter_map=parameter_map,
                assertions=assertions,
                rust_decl="pub fn %s(%s)" % (name, params),
                **extras.get(name, {})
            )
            input = assemble_and_disassemble(input, tool_prefix="aarch64-linux-gnu-")
            parse_file(input, d)

    with open("../../s2n-bignum/arm/fastmul/bignum_emontredc_8n.S") as input, open(
        "../curve25519/src/low/aarch64/bignum_emontredc_8n.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_emontredc_8n",
            parameter_map=[
                ("inout", "x0", "m.len() => ret"),
                ("inout", "x1", "z.as_mut_ptr() => _"),
                ("inout", "x2", "m.as_ptr() => _"),
                ("inout", "x3", "w => _"),
            ],
            return_value=["u64", "ret", "ret"],
            assertions=["z.len() == m.len() * 2", "z.len() % 8 == 0"],
            rust_decl="pub fn bignum_emontredc_8n(z: &mut [u64], m: &[u64], w: u64) -> u64",
        )

        input = assemble_and_disassemble(input, tool_prefix="aarch64-linux-gnu-")
        parse_file(input, d)

    with open("../../s2n-bignum/arm/generic/bignum_optsub.S") as input, open(
        "../curve25519/src/low/aarch64/bignum_optsub.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_optsub",
            parameter_map=[
                ("inout", "x0", "z.len() => _"),
                ("inout", "x1", "z.as_mut_ptr() => _"),
                ("inout", "x2", "x.as_ptr() => _"),
                ("inout", "x3", "p => _"),
                ("inout", "x4", "y.as_ptr() => _"),
            ],
            rust_decl="pub fn bignum_optsub(z: &mut [u64], x: &[u64], y: &[u64], p: u64)",
        )
        parse_file(input, d)

    with open("../../s2n-bignum/arm/generic/bignum_negmodinv.S") as input, open(
        "../curve25519/src/low/aarch64/bignum_negmodinv.rs", "w"
    ) as output:
        d = RustDriver(output, Architecture_aarch64)
        d.emit_rust_function(
            "bignum_negmodinv",
            parameter_map=[
                ("inout", "x0", "z.len() => _"),
                ("inout", "x1", "z.as_mut_ptr() => _"),
                ("inout", "x2", "x.as_ptr() => _"),
            ],
            assertions=["z.len() == x.len()"],
            rust_decl="pub fn bignum_negmodinv(z: &mut [u64], x: &[u64])",
        )
        parse_file(input, d)
