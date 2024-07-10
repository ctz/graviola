use crate::low::ct_equal;
use crate::mid::sha2::{Sha256Context, Sha512Context};

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

enum HashContextInner {
    Sha256(Sha256Context),
    Sha512(Sha512Context),
}

pub trait Hash {
    type Context: HashContext;

    fn new() -> Self::Context;

    fn hash(bytes: &[u8]) -> HashOutput;

    fn zeroed_block() -> HashBlock;
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
}

impl HashContext for Sha256Context {
    fn update(&mut self, bytes: &[u8]) {
        self.update(bytes)
    }

    fn finish(self) -> HashOutput {
        HashOutput::Sha256(self.finish())
    }
}
