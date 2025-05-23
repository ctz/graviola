<h1 align="center">Graviola</h1>
<img width="40%" align="right" src="https://raw.githubusercontent.com/ctz/graviola/main/admin/picture.png">

> **Graviola** is a compendium of **high quality**,
> **fast** and **easy to build** cryptography for Rust, aimed
> at use with [rustls](https://github.com/rustls/rustls).

*High quality*: Graviola incorporates assembler routines
from the [s2n-bignum] project.  These have been formally proven
to correctly implement the desired mathematical operation.

*Fast*: Graviola beats or is competitive with other cryptography
libraries for Rust.  See [performance comparison][performance].

*Easy and fast to build*: no C compiler, assembler or other tooling
needed: just the Rust compiler.  Compiles in less than one second.

## Status

This project is very new, so exercise due caution.  The overriding
goal of this crate is for use with `rustls` via [rustls-graviola][],
but there is also a public API for general-purpose use.

[![Build Status](https://img.shields.io/github/actions/workflow/status/ctz/graviola/build.yml)](https://github.com/ctz/graviola/actions/workflows/build.yml?query=branch%3Amain)
[![Latest release](https://img.shields.io/crates/v/graviola)](https://crates.io/crates/graviola)
[![Coverage Status (codecov.io)](https://img.shields.io/codecov/c/github/ctz/graviola)](https://codecov.io/gh/ctz/graviola/)
[![Documentation](https://img.shields.io/docsrs/graviola)](https://docs.rs/graviola/)

## Goals

- [x] Fast and simple compilation
    - [x] `cargo build` takes less than one second, and requires only rustc
- [x] Competitive performance (with *ring*, aws-lc-rs, and rustcrypto)
- [x] Uses formally-verified assembler from other projects (where available)
- [x] Intended to provide algorithms in wide use on web
- [x] Intended for use as a rustls `CryptoProvider`, via [rustls-graviola][].

## Limitations

`aarch64` and `x86_64` architectures only.

- `aarch64` requires `aes`, `sha2`, `pmull`, and `neon` CPU features.
  (This notably excludes Raspberry PI 4 and earlier, but covers Raspberry Pi 5.)
- `x86_64` requires `aes`, `ssse3` `avx`, `avx2`, `adx`, `bmi2`, and `pclmulqdq` CPU features.
  (This is most x86_64 CPUs made since around ~2014.)

## Acknowledgements and Thanks

Graviola incorporates significant code from other open source projects.
We are grateful to:

- [s2n-bignum]: formally verified assembler for
    - P256, P384, P521 field arithmetic and group operations
    - x25519
    - Big integer arithmetic
- [wycheproof]: collated test vectors for all algorithms.

[s2n-bignum]: https://github.com/awslabs/s2n-bignum
[wycheproof]: https://github.com/C2SP/wycheproof
[SLOTHY]: https://github.com/slothy-optimizer/slothy
[performance]: https://jbp.io/graviola/
[rustls-graviola]: https://crates.io/crates/rustls-graviola

## Algorithms

### Public key signatures

- [x] RSA-PSS signature verification
- [x] RSA-PKCS#1 signature verification
- [x] RSA-PSS signing
- [x] RSA-PKCS#1 signing
- [x] ECDSA on P256 w/ SHA2
- [x] ECDSA on P384 w/ SHA2

### Hashing

- [x] SHA256
- [x] SHA384 & SHA512
- [x] HMAC
- [x] HMAC-DRBG

### Key exchange

- [x] X25519
- [x] P256
- [x] P384

### AEADs

- [x] AES-GCM
- [x] chacha20-poly1305 and xchacha20-poly1305

## Assorted technical details

### RSA
All the arithmetic is provided by s2n-bignum.

The RSA private operation always uses the CRT optimisation.

Modular exponentiation uses 4-bit fixed exponent window, and the term is selected by
the exponent bits from the table of base powers in a side-channel-free way.
The private operation is always followed by the public operation to verify the result
(and the result compared in a side-channel-free way).

Only RSA signing and verification are provided.  Our policy on RSA encryption is:
"These are not made. They should never be made. We will not make them. We will not help make them."

RSA key generation is supported for five fixed key sizes between 2048-8192-bits.
All generated keys have e = 0x10001.  Unlike other private key operations in Graviola,
RSA key generation is currently not side-channel safe.  Avoid doing it in untrusted multi-tenant or
physical environments.

### ECC
All ECC field and scalar arithmetic are provided by s2n-bignum.

P256 base point multiplication uses a 7-bit exponent window with Booth encoding
(this costs a 148KB constant table).
Variable point multiplication uses a 5-bit exponent window with Booth encoding.

P384 base and variable point multiplication both use a 5-bit exponent window with Booth encoding.
(This means we're leaving a some P384 base point performance on the table, in exchange for code space.
P384 performance seems to be less important than P256.)

Both use the same exponent representations for "public" and "secret" exponents --
however the table selection for "public" exponents is specialized at compile-time.

ECDSA follows RFC6979 for generation of `k`, but adds additional non-critical random input.
We do this to avoid the theoretical fragility of RFC6979 under fault conditions.
This is allowed for by RFC6979, and the HMAC-DRBG that it builds on.
The code is structured such that we pass the RFC6979 test vectors.

The code which selects a term from a table of points is non-verified,
and is written in AVX2/Neon intrinsics.

X25519 directly uses the s2n-bignum implementation.

### Symmetric cryptography
SHA256 has straightforward implementations using hashing intrinsics
(aka "SHA-NI" on x86_64, "sha" extension on aarch64) with runtime fallback
on x86_64 to a pure Rust version if needed.

SHA384/SHA512 on x86_64 has an AVX2 by-4 implementation, plus an AVX2 interleaved
single block implementation.

AES and GHASH always use intrinsics (there are no fallbacks).

On x86_64, we have a stitched by-8 AES-CTR and a by-8 GHASH (they are not currently
interleaved; this is future work.)  On aarch64 we have a by-8 AES-CTR
and by-8 GHASH (this is neither interleaved nor stitched).

## Architecture

We have broadly three module layers:

- `low`: low level primitives. private. platform-specific. unsafe allowed. minimal std and alloc.
- `mid`: constructions, protocols and encodings. private. platform agnostic. no unsafe. minimal std and alloc.
- `high`: high level encodings and operations. public. platform agnostic. no unsafe.

`low` code should not refer to `mid`, nor `mid` to `high`.

`low` must present the same interface irrespective of platform.  To this end,
`low::generic` contains pure-rust polyfills for items we don't have assembler-
or intrinsic-based implementations for a certain platform.

## License

Graviola incorporates and redistributes code from:

- [s2n-bignum]: Apache-2.0 OR ISC OR MIT-0

New code written for Graviola is licensed under
Apache-2.0 OR ISC OR MIT-0.

Every file has a `SPDX-License-Identifier` comment.
