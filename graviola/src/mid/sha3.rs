// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! The SHA3 hash function and SHAKE construction.
//!
//! See <https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf>

use crate::low::{Blockwise, sha3_keccak_f1600};

/// A context for incremental computation of SHA3-256.
pub struct Sha3_256Context {
    sponge: Sponge<SHA3_256_R_BYTES, SHA_PAD_BYTE>,
}

impl Sha3_256Context {
    /// Start a new SHA3-256 hash computation.
    pub const fn new() -> Self {
        Self {
            sponge: Sponge::new(),
        }
    }

    /// Add `bytes` to the ongoing hash computation.
    pub fn update(&mut self, bytes: &[u8]) {
        self.sponge.absorb(bytes);
    }

    /// Complete the SHA3-256 computation, returning the hash output.
    pub fn finish(mut self) -> [u8; Self::OUTPUT_SZ] {
        self.sponge.absorb_final();
        let mut digest = [0u8; Self::OUTPUT_SZ];
        self.sponge.into_squeeze(&mut digest);
        digest
    }

    /// The output size of SHA3-256.
    pub const OUTPUT_SZ: usize = 32;
}

/// A context for incremental computation of SHA3-512.
pub struct Sha3_512Context {
    sponge: Sponge<SHA3_512_R_BYTES, SHA_PAD_BYTE>,
}

impl Sha3_512Context {
    /// Start a new SHA3-512 hash computation.
    pub const fn new() -> Self {
        Self {
            sponge: Sponge::new(),
        }
    }

    /// Add `bytes` to the ongoing hash computation.
    pub fn update(&mut self, bytes: &[u8]) {
        self.sponge.absorb(bytes);
    }

    /// Complete the SHA3-512 computation, returning the hash output.
    pub fn finish(mut self) -> [u8; Self::OUTPUT_SZ] {
        self.sponge.absorb_final();
        let mut digest = [0u8; Self::OUTPUT_SZ];
        self.sponge.into_squeeze(&mut digest);
        digest
    }

    /// The output size of SHA3-512.
    pub const OUTPUT_SZ: usize = 64;
}

/// This is SHAKE128.
///
/// This has one-shot input behaviour (all input must be provided to the
/// constructor [`Shake128::new`]) and incremental output behaviour.
pub struct Shake128 {
    sponge: Sponge<SHAKE_128_R_BYTES, SHAKE_PAD_BYTE>,
    buffer: [u8; SHAKE_128_R_BYTES],
    buffer_offset: usize,
}

impl Shake128 {
    /// Create a new SHAKE128 instance using `message` as input.
    pub fn new(message: &[u8]) -> Self {
        let mut sponge = Sponge::new();
        sponge.absorb(message);
        sponge.absorb_final();
        Self {
            sponge,
            buffer: [0u8; SHAKE_128_R_BYTES],
            buffer_offset: SHAKE_128_R_BYTES,
        }
    }

    /// Read data from this instance into `output`.
    ///
    /// This does not fail.  It always fills `output`.
    pub fn read(&mut self, output: &mut [u8]) {
        self.sponge
            .shake_read(output, &mut self.buffer, &mut self.buffer_offset);
    }
}

/// This is SHAKE256.
///
/// This has one-shot input behaviour (all input must be provided to the
/// constructor [`Shake256::new`]) and incremental output behaviour.
pub struct Shake256 {
    sponge: Sponge<SHAKE_256_R_BYTES, SHAKE_PAD_BYTE>,
    buffer: [u8; SHAKE_256_R_BYTES],
    buffer_offset: usize,
}

impl Shake256 {
    /// Create a new SHAKE256 instance using `message` as input.
    pub fn new(message: &[u8]) -> Self {
        let mut sponge = Sponge::new();
        sponge.absorb(message);
        sponge.absorb_final();
        Self {
            sponge,
            buffer: [0u8; SHAKE_256_R_BYTES],
            buffer_offset: SHAKE_256_R_BYTES,
        }
    }

    /// Read data from this instance into `output`.
    ///
    /// This does not fail.  It always fills `output`.
    pub fn read(&mut self, output: &mut [u8]) {
        self.sponge
            .shake_read(output, &mut self.buffer, &mut self.buffer_offset);
    }
}

struct Sponge<const R: usize, const PAD: u8> {
    s: [u64; 25],
    buffer: Blockwise<R>,
}

impl<const R: usize, const PAD: u8> Sponge<R, PAD> {
    const fn new() -> Self {
        Self {
            s: [0; 25],
            buffer: Blockwise::new(),
        }
    }

    fn absorb(&mut self, bytes: &[u8]) {
        let bytes = self.buffer.add_leading(bytes);

        if let Some(block) = self.buffer.take() {
            self.absorb_block(&block);
        }

        let (blocks, remainder) = bytes.as_chunks();
        for block in blocks {
            self.absorb_block(block);
        }

        self.buffer.add_trailing(remainder);
    }

    fn shake_read(&mut self, output: &mut [u8], buffer: &mut [u8; R], buffer_offset: &mut usize) {
        let output = match *buffer_offset == buffer.len() {
            true => output,
            false => {
                let chunk = Ord::min(R - *buffer_offset, output.len());
                let (output, rest) = output.split_at_mut(chunk);
                output.copy_from_slice(&buffer[*buffer_offset..*buffer_offset + chunk]);
                *buffer_offset += chunk;
                rest
            }
        };

        let whole_chunks = output.len() / R;
        let (whole, tail) = output.split_at_mut(whole_chunks * R);
        self.squeeze(whole);

        if !tail.is_empty() {
            self.squeeze(buffer);
            let chunk = Ord::min(R, tail.len());
            tail.copy_from_slice(&buffer[..chunk]);
            *buffer_offset = chunk;
        }
    }

    /// Squeeze into `output`.
    fn squeeze(&mut self, output: &mut [u8]) {
        for chunk in output.chunks_mut(R) {
            self.squeeze_current(chunk);
            sha3_keccak_f1600(&mut self.s, &RC);
        }
    }

    /// Squeeze into `output`.
    ///
    /// This works once, as it omits an unused trailing permutation if possible.
    fn into_squeeze(mut self, output: &mut [u8]) {
        let mut chunks = output.chunks_mut(R).peekable();
        while let Some(chunk) = chunks.next() {
            self.squeeze_current(chunk);
            if chunks.peek().is_some() {
                sha3_keccak_f1600(&mut self.s, &RC);
            }
        }
    }

    fn squeeze_current(&mut self, output: &mut [u8]) {
        for (i, ch) in output.chunks_mut(8).enumerate() {
            ch.copy_from_slice(&self.s[i].swap_bytes().to_be_bytes()[..ch.len()]);
        }
    }

    fn absorb_final(&mut self) {
        match R - self.buffer.used() {
            1 => {
                self.buffer.add_leading(&[PAD | 0x80]);
            }
            2 => {
                self.buffer.add_leading(&[PAD, 0x80]);
            }
            n => {
                self.buffer.add(&[PAD]);
                for _ in 0..n - 2 {
                    self.buffer.add_leading(&[0x00]);
                }
                self.buffer.add_leading(&[0x80]);
            }
        }
        let padded = self.buffer.take().unwrap();
        self.absorb_block(&padded);
    }

    fn absorb_block(&mut self, block: &[u8; R]) {
        for (i, block) in block.chunks_exact(8).enumerate() {
            let x = u64::from_be_bytes(block.try_into().unwrap());
            self.s[i] ^= x.swap_bytes();
        }

        sha3_keccak_f1600(&mut self.s, &RC);
    }
}

const RC: [u64; 24] = [
    0x00000000_00000001,
    0x00000000_00008082,
    0x80000000_0000808A,
    0x80000000_80008000,
    0x00000000_0000808B,
    0x00000000_80000001,
    0x80000000_80008081,
    0x80000000_00008009,
    0x00000000_0000008A,
    0x00000000_00000088,
    0x00000000_80008009,
    0x00000000_8000000A,
    0x00000000_8000808B,
    0x80000000_0000008B,
    0x80000000_00008089,
    0x80000000_00008003,
    0x80000000_00008002,
    0x80000000_00000080,
    0x00000000_0000800A,
    0x80000000_8000000A,
    0x80000000_80008081,
    0x80000000_00008080,
    0x00000000_80000001,
    0x80000000_80008008,
];

const SHAKE_128_R_BYTES: usize = (1600 - 256) / 8;
const SHAKE_256_R_BYTES: usize = (1600 - 512) / 8;

const SHA3_256_R_BYTES: usize = (1600 - 512) / 8;
const SHA3_512_R_BYTES: usize = (1600 - 1024) / 8;

/// This is 0b01_1 in keccak bit ordering.
///
/// `01` is the SHA3 domain separation constant, `1` is the multi-rate
/// padding bit.
const SHA_PAD_BYTE: u8 = 0b0000_0110;

/// This is 0b1111_1 in keccak bit ordering.
///
/// `1111` is the SHAKE domain separation constant, `1` is the multi-rate
/// padding bit.
const SHAKE_PAD_BYTE: u8 = 0b0001_1111;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::*;

    #[test]
    fn hello() {
        let mut ctx = Sha3_256Context::new();
        ctx.update(b"hello");
        assert_eq!(&ctx.finish(),
                   b"\x33\x38\xbe\x69\x4f\x50\xc5\xf3\x38\x81\x49\x86\xcd\xf0\x68\x64\x53\xa8\x88\xb8\x4f\x42\x4d\x79\x2a\xf4\xb9\x20\x23\x98\xf3\x92");

        let mut ctx = Sha3_512Context::new();
        ctx.update(b"hello");
        assert_eq!(&ctx.finish(),
            b"\x75\xd5\x27\xc3\x68\xf2\xef\xe8\x48\xec\xf6\xb0\x73\xa3\x67\x67\x80\x08\x05\xe9\xee\xf2\xb1\x85\x7d\x5f\x98\x4f\x03\x6e\xb6\xdf\x89\x1d\x75\xf7\x2d\x9b\x15\x45\x18\xc1\xcd\x58\x83\x52\x86\xd1\xda\x9a\x38\xde\xba\x3d\xe9\x8b\x5a\x53\xe5\xed\x78\xa8\x49\x76");
    }

    #[test]
    fn sha3_256_all_lengths() {
        // see cifra `vector_length` and associated
        let mut outer = Sha3_256Context::new();

        for len in 0..1024 {
            let mut inner = Sha3_256Context::new();

            for _ in 0..len {
                inner.update(&[len as u8]);
            }

            outer.update(&inner.finish());
        }

        assert_eq!(&outer.finish(),
                   b"\xf7\xed\xf7\x2b\x34\x8c\xb4\xab\x5e\xe7\x4f\x6c\xae\xaf\x11\xad\xe2\x2f\x04\x65\x84\x8e\x5c\xaa\x14\x38\x7f\xd4\xeb\xdb\x9d\x70");
    }

    #[test]
    fn sha3_512_all_lengths() {
        let mut outer = Sha3_512Context::new();

        for len in 0..1024 {
            let mut inner = Sha3_512Context::new();

            for _ in 0..len {
                inner.update(&[len as u8]);
            }

            outer.update(&inner.finish());
        }

        assert_eq!(&outer.finish(),
                   b"\x3a\x98\x11\x17\xbc\x2f\xa3\x3b\x00\x51\x71\xf8\x80\x86\x33\x7f\x4f\x6c\xe9\xd1\x5c\xb7\x38\xc0\x9b\xe2\x8a\xb6\xd5\x38\xba\xbf\
                     \x7b\xc5\x4e\xbf\x3d\xdb\x53\x4a\x9c\x3c\x10\x85\xe7\x18\x3d\x46\xa5\x8c\xbc\xb0\x15\xb0\xdf\x50\x7a\xad\x0e\xdf\xf3\x54\x8e\xfd");
    }

    #[test]
    fn shake_incremental_read() {
        // Read SHAKE output in a big chunk, and then incrementally with a variety
        // of chunk sizes.
        //
        // The outputs must agree.
        let mut long = [0u8; 4096];
        Shake128::new(b"hello").read(&mut long);

        let mut short = [0u8; 511];
        let mut s = Shake128::new(b"hello");
        let mut i = 0;
        let mut len = 1;
        while (i + len) < long.len() {
            s.read(&mut short[..len]);

            assert_eq!(&long[i..i + len], &short[..len]);
            i += len;
            len = ((len + 1) * 2) % short.len();
        }
    }

    #[test]
    fn cavp_sha3() {
        #[derive(Debug)]
        enum Kind {
            None,
            Sha3_256,
            Sha3_512,
        }

        #[derive(Debug)]
        struct Cavp {
            kind: Kind,
            len: usize,
            message: Vec<u8>,
        }

        impl Default for Cavp {
            fn default() -> Self {
                Self {
                    kind: Kind::None,
                    len: 0,
                    message: Vec::new(),
                }
            }
        }

        impl CavpSink for Cavp {
            fn on_meta(&mut self, meta: &str) {
                self.kind = match meta {
                    "L = 256" => Kind::Sha3_256,
                    "L = 512" => Kind::Sha3_512,
                    _ => panic!("unhandled {meta:?}"),
                };
            }

            fn on_value(&mut self, name: &str, value: Value<'_>) {
                match name {
                    "Len" => self.len = (value.int() / 8) as usize,
                    "Msg" => self.message = value.bytes(),
                    "MD" => match self.kind {
                        Kind::None => {}
                        Kind::Sha3_256 => {
                            let mut h = Sha3_256Context::new();
                            h.update(&self.message[..self.len]);
                            assert_eq!(value.bytes(), h.finish());
                        }
                        Kind::Sha3_512 => {
                            let mut h = Sha3_512Context::new();
                            h.update(&self.message[..self.len]);
                            assert_eq!(value.bytes(), h.finish());
                        }
                    },
                    _ => {
                        todo!("{self:?} value {name} = {value:?}");
                    }
                }
            }
        }

        process_cavp(
            "../thirdparty/cavp/sha3/SHA3_256ShortMsg.rsp",
            &mut Cavp::default(),
        );
        process_cavp(
            "../thirdparty/cavp/sha3/SHA3_256LongMsg.rsp",
            &mut Cavp::default(),
        );
        process_cavp(
            "../thirdparty/cavp/sha3/SHA3_512ShortMsg.rsp",
            &mut Cavp::default(),
        );
        process_cavp(
            "../thirdparty/cavp/sha3/SHA3_512LongMsg.rsp",
            &mut Cavp::default(),
        );
    }

    #[test]
    fn cavp_shake() {
        #[derive(Debug)]
        enum Kind {
            None,
            Shake128,
            Shake256,
        }

        #[derive(Debug)]
        struct Cavp {
            kind: Kind,
            len: usize,
            message: Vec<u8>,
        }

        impl Default for Cavp {
            fn default() -> Self {
                Self {
                    kind: Kind::None,
                    len: 0,
                    message: Vec::new(),
                }
            }
        }

        impl CavpSink for Cavp {
            fn on_meta(&mut self, meta: &str) {
                match meta {
                    "Input Length = 128" => self.len = 16,
                    "Input Length = 256" => self.len = 32,
                    _ => {}
                }
            }

            fn on_value(&mut self, name: &str, value: Value<'_>) {
                match name {
                    "COUNT" | "Outputlen" => {}
                    "Msg" => self.message = value.bytes(),
                    "Len" => self.len = (value.int() / 8) as usize,
                    "Output" => match self.kind {
                        Kind::None => {}
                        Kind::Shake128 => {
                            let mut buffer = vec![0; value.bytes().len()];
                            Shake128::new(&self.message[..self.len]).read(&mut buffer);
                            assert_eq!(value.bytes(), buffer);
                        }
                        Kind::Shake256 => {
                            let mut buffer = vec![0; value.bytes().len()];
                            Shake256::new(&self.message[..self.len]).read(&mut buffer);
                            assert_eq!(value.bytes(), buffer);
                        }
                    },
                    _ => {
                        todo!("{self:?} value {name} = {value:?}");
                    }
                }
            }
        }

        process_cavp(
            "../thirdparty/cavp/sha3/SHAKE128ShortMsg.rsp",
            &mut Cavp {
                kind: Kind::Shake128,
                ..Cavp::default()
            },
        );
        process_cavp(
            "../thirdparty/cavp/sha3/SHAKE128LongMsg.rsp",
            &mut Cavp {
                kind: Kind::Shake128,
                ..Cavp::default()
            },
        );
        process_cavp(
            "../thirdparty/cavp/sha3/SHAKE128VariableOut.rsp",
            &mut Cavp {
                kind: Kind::Shake128,
                ..Cavp::default()
            },
        );

        process_cavp(
            "../thirdparty/cavp/sha3/SHAKE256ShortMsg.rsp",
            &mut Cavp {
                kind: Kind::Shake256,
                ..Cavp::default()
            },
        );
        process_cavp(
            "../thirdparty/cavp/sha3/SHAKE256LongMsg.rsp",
            &mut Cavp {
                kind: Kind::Shake256,
                ..Cavp::default()
            },
        );
        process_cavp(
            "../thirdparty/cavp/sha3/SHAKE256VariableOut.rsp",
            &mut Cavp {
                kind: Kind::Shake256,
                ..Cavp::default()
            },
        );
    }
}
