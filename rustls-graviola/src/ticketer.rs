use core::sync::atomic::{AtomicUsize, Ordering};
use std::fmt;
use std::sync::Arc;

use graviola::{aead, random};
use rustls::crypto::GetRandomFailed;
use rustls::server::ProducesTickets;
use rustls::{Error, TicketRotator};

/// The default ticketer.
pub struct Ticketer;

impl Ticketer {
    /// Make a new ticketer.
    ///
    /// Tickets are encrypted with XChaCha20Poly1305.
    /// Ticket keys are rotated every 6 hours.
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Result<Arc<dyn ProducesTickets>, Error> {
        Ok(Arc::new(TicketRotator::new(
            ONE_TICKET_LIFETIME_SECS,
            make_ticket_generator,
        )?))
    }
}

fn make_ticket_generator() -> Result<Box<dyn ProducesTickets>, GetRandomFailed> {
    Ok(Box::new(XChaCha20Ticketer::new()?))
}

struct XChaCha20Ticketer {
    key: aead::XChaCha20Poly1305,
    key_name: [u8; 16],
    lifetime: u32,
    maximum_ciphertext_len: AtomicUsize,
}

impl XChaCha20Ticketer {
    fn new() -> Result<Self, GetRandomFailed> {
        let mut key = [0u8; 32];
        let mut key_name = [0u8; 16];

        random::fill(&mut key).map_err(|_| GetRandomFailed)?;
        random::fill(&mut key_name).map_err(|_| GetRandomFailed)?;

        let key = aead::XChaCha20Poly1305::new(key);

        Ok(Self {
            key,
            key_name,
            lifetime: ONE_TICKET_LIFETIME_SECS,
            maximum_ciphertext_len: AtomicUsize::new(0),
        })
    }
}

impl ProducesTickets for XChaCha20Ticketer {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        self.lifetime
    }

    fn encrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
        let mut nonce = [0u8; 24];
        random::fill(&mut nonce).ok()?;

        // wire format is:
        // - key_name [u8; 16]
        // - nonce [u8; 24]
        // - ciphertext [u8; n]
        // - tag [u8; 16]
        //
        // aad is key_name

        let mut tag = [0u8; 16];
        let mut res =
            Vec::with_capacity(self.key_name.len() + nonce.len() + message.len() + tag.len());
        res.extend(&self.key_name);
        res.extend(&nonce);
        res.extend(message);

        self.key.encrypt(
            &nonce,
            &self.key_name,
            &mut res[self.key_name.len() + nonce.len()..],
            &mut tag,
        );
        res.extend(tag);

        self.maximum_ciphertext_len
            .fetch_max(res.len(), Ordering::SeqCst);

        Some(res)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.len() > self.maximum_ciphertext_len.load(Ordering::SeqCst) {
            return None;
        }

        let plain_len = ciphertext
            .len()
            .saturating_sub(self.key_name.len() + 24 + 16);

        if plain_len == 0 {
            return None;
        }

        let (alleged_key_name, rest) = ciphertext.split_at(self.key_name.len());

        // nb. key_name is public data
        if alleged_key_name != self.key_name {
            return None;
        }

        let (nonce, rest) = rest.split_at(24);
        let nonce = nonce.try_into().unwrap();
        let (plain, alleged_tag) = rest.split_at(plain_len);
        let mut plain = plain.to_vec();

        self.key
            .decrypt(&nonce, alleged_key_name, &mut plain, alleged_tag)
            .ok()?;
        Some(plain)
    }
}

impl fmt::Debug for XChaCha20Ticketer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("XChaCha20Ticketer")
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

const ONE_TICKET_LIFETIME_SECS: u32 = 6 * 60 * 60;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let t = Ticketer::new().unwrap();
        let ehello = t.encrypt(b"hello").unwrap();
        assert_eq!(t.decrypt(&ehello).unwrap(), b"hello");

        assert!(t.enabled());
        assert_eq!(t.lifetime(), ONE_TICKET_LIFETIME_SECS * 2);
        println!("{t:?}");
    }

    #[test]
    fn gen() {
        let g = make_ticket_generator().unwrap();
        assert!(g.enabled());
        assert_eq!(g.lifetime(), ONE_TICKET_LIFETIME_SECS);
        println!("{:?}", g);
    }

    #[test]
    fn length_checks() {
        let t = Ticketer::new().unwrap();
        assert_eq!(t.decrypt(b""), None);
        assert_eq!(t.decrypt(b"a"), None);

        let e = t.encrypt(b"a").unwrap();
        assert_eq!(t.decrypt(&e).unwrap(), b"a");
        assert_eq!(t.decrypt(&e[..e.len() - 1]), None);
    }

    #[test]
    fn non_malleable() {
        let t = Ticketer::new().unwrap();
        let ehello = t.encrypt(b"hello").unwrap();

        for i in 0..ehello.len() {
            let mut ehello_tmp = ehello.clone();
            ehello_tmp[i] = ehello_tmp[i] ^ 1;
            assert_eq!(None, t.decrypt(&ehello_tmp));
        }
    }
}
