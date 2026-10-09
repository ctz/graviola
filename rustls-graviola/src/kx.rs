use graviola::key_agreement::{p256, p384, x25519};
use rustls::crypto::GetRandomFailed;
use rustls::crypto::kx::{
    ActiveKeyExchange, Hybrid, HybridLayout, NamedGroup, SharedSecret, StartedKeyExchange,
    SupportedKxGroup,
};
use rustls::error::{Error, PeerMisbehaved};

mod mlkem;

/// All key exchange algorithms, in order of preference.
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    X25519MLKEM768,
    &X25519 as &dyn SupportedKxGroup,
    &P256 as &dyn SupportedKxGroup,
    &P384 as &dyn SupportedKxGroup,
];

/// Key exchange using X25519.
#[derive(Debug)]
pub struct X25519;

impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<StartedKeyExchange, Error> {
        let priv_key = x25519::PrivateKey::new_random().map_err(|_| GetRandomFailed)?;
        let pub_key_bytes = priv_key.public_key().as_bytes();

        Ok(StartedKeyExchange::Single(Box::new(ActiveX25519 {
            pub_key_bytes,
            priv_key,
        })))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct ActiveX25519 {
    priv_key: x25519::PrivateKey,
    pub_key_bytes: [u8; 32],
}

impl ActiveKeyExchange for ActiveX25519 {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let shared_secret = x25519::PublicKey::try_from_slice(peer)
            .and_then(|their_pub| self.priv_key.diffie_hellman(&their_pub))
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        Ok(SharedSecret::from(&shared_secret.0[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key_bytes
    }

    fn group(&self) -> NamedGroup {
        X25519.name()
    }
}

/// Key exchange using P256.
///
/// Also known as secp256r1 or NISTP256.
#[derive(Debug)]
pub struct P256;

impl SupportedKxGroup for P256 {
    fn start(&self) -> Result<StartedKeyExchange, Error> {
        let priv_key = p256::PrivateKey::new_random().map_err(|_| GetRandomFailed)?;
        let pub_key_bytes = priv_key.public_key_uncompressed();

        Ok(StartedKeyExchange::Single(Box::new(ActiveP256 {
            pub_key_bytes,
            priv_key,
        })))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

struct ActiveP256 {
    priv_key: p256::PrivateKey,
    pub_key_bytes: [u8; 65],
}

impl ActiveKeyExchange for ActiveP256 {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let their_pub = p256::PublicKey::from_x962_uncompressed(peer)
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let shared_secret = self
            .priv_key
            .diffie_hellman(&their_pub)
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        Ok(SharedSecret::from(&shared_secret.0[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key_bytes
    }

    fn group(&self) -> NamedGroup {
        P256.name()
    }
}

/// Key exchange using P384.
///
/// Also known as secp384r1 or NISTP384.
#[derive(Debug)]
pub struct P384;

impl SupportedKxGroup for P384 {
    fn start(&self) -> Result<StartedKeyExchange, Error> {
        let priv_key = p384::PrivateKey::new_random().map_err(|_| GetRandomFailed)?;
        let pub_key_bytes = priv_key.public_key_uncompressed();

        Ok(StartedKeyExchange::Single(Box::new(ActiveP384 {
            pub_key_bytes,
            priv_key,
        })))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp384r1
    }
}

struct ActiveP384 {
    priv_key: p384::PrivateKey,
    pub_key_bytes: [u8; 97],
}

impl ActiveKeyExchange for ActiveP384 {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let their_pub = p384::PublicKey::from_x962_uncompressed(peer)
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let shared_secret = self
            .priv_key
            .diffie_hellman(&their_pub)
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        Ok(SharedSecret::from(&shared_secret.0[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key_bytes
    }

    fn group(&self) -> NamedGroup {
        P384.name()
    }
}

/// Hybrid key exchange using X25519 and ML-KEM-768.
pub static X25519MLKEM768: &dyn SupportedKxGroup = &Hybrid {
    classical: &X25519,
    post_quantum: &mlkem::MlKem768,
    layout: HybridLayout {
        classical_share_len: 32,
        post_quantum_first: true,
        post_quantum_client_share_len: mlkem::MlKem768::ENCAPS_LEN,
        post_quantum_server_share_len: mlkem::MlKem768::CIPHERTEXT_LEN,
    },
    name: NamedGroup::X25519MLKEM768,
};

#[cfg(test)]
mod tests {
    use rustls::enums::ProtocolVersion;

    use super::*;

    #[test]
    fn test_kx_x25519() {
        // Create a private key and verify its metadata.
        let key = X25519;
        assert_eq!(key.name(), NamedGroup::X25519);
        assert!(key.name().usable_for_version(ProtocolVersion::TLSv1_2));
        assert!(key.name().usable_for_version(ProtocolVersion::TLSv1_3));

        // A key exchange with an invalid peer public key should fail.
        let active = key.start().unwrap().into_single();
        assert!(active.complete(&[0u8]).is_err());

        // A key exchange with a valid peer public key should succeed.
        let active = key.start().unwrap().into_single();
        let peer = x25519::PrivateKey::new_random().unwrap();
        let peer_public_key = peer.public_key().as_bytes();
        assert!(active.complete(&peer_public_key).is_ok());
    }

    #[test]
    fn test_kx_p256() {
        // Create a private key and verify its metadata.
        let key = P256;
        assert_eq!(key.name(), NamedGroup::secp256r1);
        assert!(key.name().usable_for_version(ProtocolVersion::TLSv1_2));
        assert!(key.name().usable_for_version(ProtocolVersion::TLSv1_3));

        // A key exchange with an invalid peer public key should fail.
        let active = key.start().unwrap().into_single();
        assert!(active.complete(&[0u8]).is_err());

        // A key exchange with a valid peer public key should succeed.
        let active = key.start().unwrap().into_single();
        let peer = p256::PrivateKey::new_random().unwrap();
        let peer_public_key = peer.public_key_uncompressed();
        assert!(active.complete(&peer_public_key).is_ok());
    }

    #[test]
    fn test_kx_p384() {
        // Create a private key and verify its metadata.
        let key = P384;
        assert_eq!(key.name(), NamedGroup::secp384r1);
        assert!(key.name().usable_for_version(ProtocolVersion::TLSv1_2));
        assert!(key.name().usable_for_version(ProtocolVersion::TLSv1_3));

        // A key exchange with an invalid peer public key should fail.
        let active = key.start().unwrap().into_single();
        assert!(active.complete(&[0u8]).is_err());

        // A key exchange with a valid peer public key should succeed.
        let active = key.start().unwrap().into_single();
        let peer = p384::PrivateKey::new_random().unwrap();
        let peer_public_key = peer.public_key_uncompressed();
        assert!(active.complete(&peer_public_key).is_ok());
    }
}
