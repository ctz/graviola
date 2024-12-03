use graviola::hashing::hmac::Hmac;
use graviola::hashing::{Sha256, Sha384};
use rustls::crypto;

pub struct Sha256Hmac;

impl crypto::hmac::Hmac for Sha256Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(Sha256HmacKey(Hmac::<Sha256>::new(key)))
    }

    fn hash_output_len(&self) -> usize {
        SHA256_OUTPUT
    }
}

struct Sha256HmacKey(Hmac<Sha256>);

impl crypto::hmac::Key for Sha256HmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let mut ctx = self.0.clone();
        ctx.update(first);
        for m in middle {
            ctx.update(m);
        }
        ctx.update(last);
        crypto::hmac::Tag::new(ctx.finish().as_ref())
    }

    fn tag_len(&self) -> usize {
        SHA256_OUTPUT
    }
}

pub struct Sha384Hmac;

impl crypto::hmac::Hmac for Sha384Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(Sha384HmacKey(Hmac::<Sha384>::new(key)))
    }

    fn hash_output_len(&self) -> usize {
        SHA384_OUTPUT
    }
}

struct Sha384HmacKey(Hmac<Sha384>);

impl crypto::hmac::Key for Sha384HmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let mut ctx = self.0.clone();
        ctx.update(first);
        for m in middle {
            ctx.update(m);
        }
        ctx.update(last);
        crypto::hmac::Tag::new(ctx.finish().as_ref())
    }

    fn tag_len(&self) -> usize {
        SHA384_OUTPUT
    }
}

const SHA256_OUTPUT: usize = 32;
const SHA384_OUTPUT: usize = 48;
