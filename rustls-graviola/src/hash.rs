use rustls::crypto::hash;

use graviola::hashing::sha2;

pub struct Sha256;

impl hash::Hash for Sha256 {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(sha2::Sha256Context::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        let mut ctx = sha2::Sha256Context::new();
        ctx.update(data);

        hash::Output::new(ctx.finish().as_ref())
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA256
    }

    fn output_len(&self) -> usize {
        32
    }
}

struct Sha256Context(sha2::Sha256Context);

impl hash::Context for Sha256Context {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(self.0.clone().finish().as_ref())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Self(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(self.0.finish().as_ref())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

pub struct Sha384;

impl hash::Hash for Sha384 {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Sha384Context(sha2::Sha384Context::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        let mut ctx = sha2::Sha384Context::new();
        ctx.update(data);

        hash::Output::new(ctx.finish().as_ref())
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA384
    }

    fn output_len(&self) -> usize {
        48
    }
}

struct Sha384Context(sha2::Sha384Context);

impl hash::Context for Sha384Context {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(self.0.clone().finish().as_ref())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Self(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(self.0.finish().as_ref())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}
