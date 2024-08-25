// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::low::ct_equal;
use crate::mid::sha2::{Sha256Context, Sha384Context, Sha512Context};

use core::cmp;
use core::ops::{Deref, DerefMut};

#[derive(Clone, Debug)]
pub enum HashOutput {
    Sha224([u8; 28]),
    Sha256([u8; 32]),
    Sha384([u8; 48]),
    Sha512([u8; 64]),
}

impl PartialEq for HashOutput {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Sha224(s), Self::Sha224(o)) => ct_equal(s, o),
            (Self::Sha256(s), Self::Sha256(o)) => ct_equal(s, o),
            (Self::Sha384(s), Self::Sha384(o)) => ct_equal(s, o),
            (Self::Sha512(s), Self::Sha512(o)) => ct_equal(s, o),
            _ => false,
        }
    }
}

impl PartialEq<&[u8]> for HashOutput {
    /// Constant-time equality, `other` may be truncated
    fn eq(&self, other: &&[u8]) -> bool {
        let other = *other;
        assert!(!other.is_empty());
        let ours = self.as_ref();
        let size = cmp::min(ours.len(), other.len());
        ct_equal(&ours[..size], other)
    }
}

impl AsRef<[u8]> for HashOutput {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Sha224(v) => v,
            Self::Sha256(v) => v,
            Self::Sha384(v) => v,
            Self::Sha512(v) => v,
        }
    }
}

impl AsMut<[u8]> for HashOutput {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Sha224(v) => v,
            Self::Sha256(v) => v,
            Self::Sha384(v) => v,
            Self::Sha512(v) => v,
        }
    }
}

#[derive(Copy, Clone)]
pub struct HashBlock {
    buf: [u8; 128],
    len: usize,
}

impl HashBlock {
    fn new(len: usize) -> Self {
        Self {
            buf: [0u8; 128],
            len,
        }
    }
}

impl Deref for HashBlock {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.buf[..self.len]
    }
}

impl DerefMut for HashBlock {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf[..self.len]
    }
}

pub trait Hash {
    type Context: HashContext;

    fn new() -> Self::Context;

    fn hash(bytes: &[u8]) -> HashOutput;

    fn zeroed_block() -> HashBlock;

    fn zeroed_output() -> HashOutput;
}

pub trait HashContext: Clone {
    fn update(&mut self, bytes: &[u8]);
    fn finish(self) -> HashOutput;
}

pub struct Sha256;

impl Hash for Sha256 {
    type Context = Sha256Context;

    fn new() -> Self::Context {
        Sha256Context::new()
    }

    fn hash(bytes: &[u8]) -> HashOutput {
        let mut ctx = Self::new();
        ctx.update(bytes);
        HashOutput::Sha256(ctx.finish())
    }

    fn zeroed_block() -> HashBlock {
        HashBlock::new(Sha256Context::BLOCK_SZ)
    }

    fn zeroed_output() -> HashOutput {
        HashOutput::Sha256([0u8; 32])
    }
}

impl HashContext for Sha256Context {
    fn update(&mut self, bytes: &[u8]) {
        self.update(bytes)
    }

    fn finish(self) -> HashOutput {
        HashOutput::Sha256(self.finish())
    }
}

pub struct Sha384;

impl Hash for Sha384 {
    type Context = Sha384Context;

    fn new() -> Self::Context {
        Sha384Context::new()
    }

    fn hash(bytes: &[u8]) -> HashOutput {
        let mut ctx = Self::new();
        ctx.update(bytes);
        HashOutput::Sha384(ctx.finish())
    }

    fn zeroed_block() -> HashBlock {
        HashBlock::new(Sha512Context::BLOCK_SZ)
    }

    fn zeroed_output() -> HashOutput {
        HashOutput::Sha384([0u8; 48])
    }
}

impl HashContext for Sha384Context {
    fn update(&mut self, bytes: &[u8]) {
        self.update(bytes)
    }

    fn finish(self) -> HashOutput {
        HashOutput::Sha384(self.finish())
    }
}

pub struct Sha512;

impl Hash for Sha512 {
    type Context = Sha512Context;

    fn new() -> Self::Context {
        Sha512Context::new()
    }

    fn hash(bytes: &[u8]) -> HashOutput {
        let mut ctx = Self::new();
        ctx.update(bytes);
        HashOutput::Sha512(ctx.finish())
    }

    fn zeroed_block() -> HashBlock {
        HashBlock::new(Sha512Context::BLOCK_SZ)
    }

    fn zeroed_output() -> HashOutput {
        HashOutput::Sha512([0u8; 64])
    }
}

impl HashContext for Sha512Context {
    fn update(&mut self, bytes: &[u8]) {
        self.update(bytes)
    }

    fn finish(self) -> HashOutput {
        HashOutput::Sha512(self.finish())
    }
}
