use crypto::SupportedKxGroup;
use rustls::crypto;
use rustls::ffdhe_groups::FfdheGroup;

use graviola::key_agreement::{p256, p384, x25519};
use graviola::rng::SystemRandom;

/// All key exchange algorithms, in order of preference.
pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    &X25519 as &dyn SupportedKxGroup,
    &P256 as &dyn SupportedKxGroup,
    &P384 as &dyn SupportedKxGroup,
];

/// Key exchange using X25519.
#[derive(Debug)]
pub struct X25519;

impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let priv_key = x25519::PrivateKey::generate(&mut SystemRandom)
            .map_err(|_| rustls::Error::from(crypto::GetRandomFailed))?;
        let pub_key_bytes = priv_key.public_key().as_bytes();

        Ok(Box::new(ActiveX25519 {
            pub_key_bytes,
            priv_key,
        }))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

struct ActiveX25519 {
    priv_key: x25519::PrivateKey,
    pub_key_bytes: [u8; 32],
}

impl crypto::ActiveKeyExchange for ActiveX25519 {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<crypto::SharedSecret, rustls::Error> {
        let their_pub = x25519::PublicKey::try_from_slice(peer)
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        let shared_secret = self.priv_key.diffie_hellman(&their_pub);
        Ok(crypto::SharedSecret::from(&shared_secret.0[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key_bytes
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> rustls::NamedGroup {
        X25519.name()
    }
}

/// Key exchange using P256.
///
/// Also known as secp256r1 or NISTP256.
#[derive(Debug)]
pub struct P256;

impl SupportedKxGroup for P256 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let priv_key = p256::PrivateKey::generate(&mut SystemRandom)
            .map_err(|_| rustls::Error::from(crypto::GetRandomFailed))?;
        let pub_key_bytes = priv_key.public_key_uncompressed();

        Ok(Box::new(ActiveP256 {
            pub_key_bytes,
            priv_key,
        }))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp256r1
    }
}

struct ActiveP256 {
    priv_key: p256::PrivateKey,
    pub_key_bytes: [u8; 65],
}

impl crypto::ActiveKeyExchange for ActiveP256 {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<crypto::SharedSecret, rustls::Error> {
        let their_pub = p256::PublicKey::from_x962_uncompressed(peer)
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        let shared_secret = self
            .priv_key
            .diffie_hellman(&their_pub)
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        Ok(crypto::SharedSecret::from(&shared_secret.0[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key_bytes
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> rustls::NamedGroup {
        P256.name()
    }
}

/// Key exchange using P384.
///
/// Also known as secp384r1 or NISTP384.
#[derive(Debug)]
pub struct P384;

impl SupportedKxGroup for P384 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let priv_key = p384::PrivateKey::generate(&mut SystemRandom)
            .map_err(|_| rustls::Error::from(crypto::GetRandomFailed))?;
        let pub_key_bytes = priv_key.public_key_uncompressed();

        Ok(Box::new(ActiveP384 {
            pub_key_bytes,
            priv_key,
        }))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp384r1
    }
}

struct ActiveP384 {
    priv_key: p384::PrivateKey,
    pub_key_bytes: [u8; 97],
}

impl crypto::ActiveKeyExchange for ActiveP384 {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<crypto::SharedSecret, rustls::Error> {
        let their_pub = p384::PublicKey::from_x962_uncompressed(peer)
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        let shared_secret = self
            .priv_key
            .diffie_hellman(&their_pub)
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        Ok(crypto::SharedSecret::from(&shared_secret.0[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key_bytes
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> rustls::NamedGroup {
        P384.name()
    }
}
