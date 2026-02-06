use graviola::hashing::sha2;
use rustls::crypto::hash;

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
        sha2::Sha256Context::OUTPUT_SZ
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
        sha2::Sha384Context::OUTPUT_SZ
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

#[cfg(test)]
mod test {
    use rustls::crypto::hash::Hash;

    use super::*;

    #[test]
    fn test_sha256() {
        let hash = Sha256;
        assert_eq!(hash.algorithm(), hash::HashAlgorithm::SHA256);
        assert_eq!(hash.output_len(), 32);
        let input = b"graviola";
        assert_eq!(hash.hash(input).as_ref(),
            b"\x08\xea\xf2\xeb\x21\x07\x25\xb3\x9f\x46\x3a\x45\x0c\xe9\xe2\xe0\x16\x44\x33\x98\x6a\x08\x70\xf6\x9d\x15\x89\xd4\x55\x7d\x76\xbb"
        );
    }

    #[test]
    fn test_sha384() {
        let hash = Sha384;
        assert_eq!(hash.algorithm(), hash::HashAlgorithm::SHA384);
        assert_eq!(hash.output_len(), 48);
        let input = b"graviola";
        assert_eq!(hash.hash(input).as_ref(),
                   b"\x5e\xbd\x63\x2e\xc3\x17\x2c\x56\x36\x99\x32\x0e\xc9\x38\xb2\x24\x8b\xf6\x97\xa5\x55\x52\xe3\x43\x13\xc4\xce\x5b\x1c\x03\x66\x4f\xcb\x2e\x01\x54\x63\xd1\xdd\x23\x50\x23\x19\xf4\x3a\x30\xc8\xad"
        );
    }
}
