import subprocess

from parse import parse_file, extract_header_comment
from driver import (
    Architecture_aarch64,
    Architecture_amd64,
    RustDriver,
)

if __name__ == "__main__":
    subprocess.check_call(
        ["perl", "x86_64/aesni-gcm-x86_64.pl", "aesni-gcm.S"], cwd="../../cryptogams"
    )

    front_matter = [
        "Copyright (c) 2006, CRYPTOGAMS by <appro@openssl.org> All rights reserved.",
        "SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0-only",
    ]
    front_matter.extend(
        extract_header_comment(open("../../cryptogams/x86_64/aesni-gcm-x86_64.pl"))
    )

    with open("../../cryptogams/aesni-gcm.S") as input, open(
        "../curve25519/src/low/x86_64/aesni_gcm.rs", "w"
    ) as output:
        for line in front_matter:
            print("//! " + line, file=output)

        d = RustDriver(output, Architecture_amd64)
        d.set_att_syntax(True)

        # internal functions
        d.emit_rust_function("_aesni_ctr32_ghash_6x",
                parameter_map=[],
                rust_decl="pub fn _aesni_ctr32_ghash_6x()",
                allow_inline=False,
        )
        d.emit_rust_function("_aesni_ctr32_6x",
                parameter_map=[],
                rust_decl="pub fn _aesni_ctr32_6x()",
                allow_inline=False,
                hoist=('.Lhandle_ctr32_2', '.Loop_ctr32'),
        )
        d.add_const_symbol("_aesni_ctr32_ghash_6x")
        d.add_const_symbol("_aesni_ctr32_6x")
        d.add_const_symbol(".Lbswap_mask", "bswap_mask", align=64)
        d.add_const_symbol(".Lpoly", "poly", align=64)
        d.add_const_symbol(".Lone_msb", "one_msb", align=64)
        d.add_const_symbol(".Lone_lsb", "one_lsb", align=64)
        d.add_const_symbol(".Ltwo_lsb", "two_lsb", align=64)

        # size_t aesni_gcm_[en|de]crypt(const void *inp, void *out, size_t len,
        #>······>·······const AES_KEY *key, unsigned char iv[16],
        #>······>·······struct { u128 Xi,H,Htbl[9]; } *Xip);
        for direction in ("encrypt", "decrypt"):
            d.emit_rust_function(
                "aesni_gcm_" + direction,
                return_value=("usize", "ret", "ret"),
                parameter_map=[
                    ("inout", "rdi", "inout.as_ptr() => _"),
                    ("inout", "rsi", "inout.as_mut_ptr() => _"),
                    ("inout", "rdx", "inout.len() => _"),
                    ("inout", "rcx", "key => _"),
                    ("inout", "r8", "iv.as_ptr() => _"),
                    ("inout", "r9", "x_i => _"),
                    ("out", "rax", "ret"),
                ],
                rust_decl="pub fn aesni_gcm_%s(inout: &mut [u8], key: &crate::low::AesKey, iv: &[u8; 16], x_i: &crate::low::GcmState) -> usize" % direction,
                allow_inline=False,
            )

        parse_file(input, d)

