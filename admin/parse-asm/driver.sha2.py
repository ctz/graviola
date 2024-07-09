import subprocess

from parse import parse_file, extract_header_comment
from driver import (
    Architecture_aarch64,
    Architecture_amd64,
    RustDriver,
)

if __name__ == "__main__":
    subprocess.check_call(
        ["perl", "x86_64/sha512-x86_64.pl", "sha256.S"], cwd="../../cryptogams"
    )
    subprocess.check_call(
        ["perl", "x86_64/sha512-x86_64.pl", "sha512.S"], cwd="../../cryptogams"
    )

    front_matter = [
        "Copyright (c) 2006, CRYPTOGAMS by <appro@openssl.org> All rights reserved.",
        "SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0-only",
    ]
    front_matter.extend(
        extract_header_comment(open("../../cryptogams/x86_64/sha512-x86_64.pl"))
    )

    with open("../../cryptogams/sha512.S") as input, open(
        "../curve25519/src/low/x86_64/sha512.rs", "w"
    ) as output:
        for line in front_matter:
            print("//! " + line, file=output)

        d = RustDriver(output, Architecture_amd64)
        d.add_const_symbol("K512", align=64)
        d.add_const_symbol("K512_nodup", align=64)
        # we do multiplexing ourselves
        d.discard_rust_function("sha512_block_data_order")
        # XOP: abandoned by AMD
        d.discard_rust_function("sha512_block_data_order_xop")
        # shaext: CPUs supporting this do not currently exist
        d.discard_rust_function("sha512_block_data_order_shaext")
        d.set_att_syntax(True)

        for fn in (
            "sha512_block_data_order_avx",
            "sha512_block_data_order_avx2",
        ):
            d.emit_rust_function(
                fn,
                parameter_map=[
                    ("inout", "rdi", "state.as_mut_ptr() => _"),
                    ("inout", "rsi", "blocks.as_ptr() => _"),
                    ("inout", "rdx", "blocks.len() / 128 => _"),
                ],
                rust_decl="pub fn %s(state: &mut [u64; 8], blocks: &[u8])" % fn,
                allow_inline=False,
            )
        parse_file(input, d)

    with open("../../cryptogams/sha256.S") as input, open(
        "../curve25519/src/low/x86_64/sha256.rs", "w"
    ) as output:
        for line in front_matter:
            print("//! " + line, file=output)

        d = RustDriver(output, Architecture_amd64)
        d.add_const_symbol("K256", align=64)
        d.add_const_symbol("K256_nodup", align=64)
        d.discard_rust_function("sha256_block_data_order")
        d.discard_rust_function("sha256_block_data_order_xop")
        d.set_att_syntax(True)

        for fn in (
            "sha256_block_data_order_ssse3",
            "sha256_block_data_order_shaext",
            "sha256_block_data_order_avx",
            "sha256_block_data_order_avx2",
        ):
            d.emit_rust_function(
                fn,
                parameter_map=[
                    ("inout", "rdi", "state.as_mut_ptr() => _"),
                    ("inout", "rsi", "blocks.as_ptr() => _"),
                    ("inout", "rdx", "blocks.len() / 64 => _"),
                ],
                rust_decl="pub fn %s(state: &mut [u32; 8], blocks: &[u8])" % fn,
                # these functions require an align stack, inlining breaks this
                allow_inline=False,
            )
        parse_file(input, d)
