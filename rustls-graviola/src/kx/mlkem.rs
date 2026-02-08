use libcrux_ml_kem::mlkem768;
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

#[derive(Debug)]
pub(super) struct MlKem768;

impl MlKem768 {
    pub(super) const ENCAPS_LEN: usize = 1184;
    pub(super) const CIPHERTEXT_LEN: usize = 1088;
}

impl SupportedKxGroup for MlKem768 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let key_pair = mlkem768::generate_key_pair(random_bytes()?);

        let (decaps_key, encaps_key) = key_pair.into_parts();

        Ok(Box::new(Active {
            decaps_key,
            encaps_key_bytes: encaps_key.as_slice().to_vec(),
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let encaps_key =
            mlkem768::MlKem768PublicKey::try_from(client_share).map_err(|_| INVALID_KEY_SHARE)?;

        let (ciphertext, shared_secret) = mlkem768::encapsulate(&encaps_key, random_bytes()?);

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: Vec::from(ciphertext.as_ref()),
            secret: SharedSecret::from(shared_secret.as_ref()),
        })
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::MLKEM768
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct Active {
    decaps_key: mlkem768::MlKem768PrivateKey,
    encaps_key_bytes: Vec<u8>,
}

impl ActiveKeyExchange for Active {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let ciphertext =
            mlkem768::MlKem768Ciphertext::try_from(peer_pub_key).map_err(|_| INVALID_KEY_SHARE)?;
        let shared_secret = mlkem768::decapsulate(&self.decaps_key, &ciphertext);

        Ok(SharedSecret::from(shared_secret.as_ref()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.encaps_key_bytes
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::MLKEM768
    }
}

fn random_bytes<const L: usize>() -> Result<[u8; L], Error> {
    let mut bytes = [0; L];
    graviola::random::fill(&mut bytes).map_err(|_| rustls::crypto::GetRandomFailed)?;
    Ok(bytes)
}

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

#[cfg(test)]
mod tests {
    use rustls::ProtocolVersion;

    use super::*;

    #[test]
    fn test_kx_mlkem() {
        // Create a private key and verify its metadata.
        let key = MlKem768;
        assert_eq!(key.name(), NamedGroup::MLKEM768);
        assert_eq!(key.ffdhe_group(), None);
        assert!(!key.usable_for_version(ProtocolVersion::TLSv1_2));
        assert!(key.usable_for_version(ProtocolVersion::TLSv1_3));
        assert_eq!(key.start().unwrap().group(), NamedGroup::MLKEM768);

        // A key exchange with an invalid peer public key should fail.
        assert!(key.start_and_complete(&[0u8]).is_err());

        // A key exchange with a valid peer public key should succeed.
        let active = key.start().unwrap();
        assert_eq!(active.ffdhe_group(), None);
        let peer_key_pair = mlkem768::generate_key_pair(random_bytes().unwrap());
        let peer_public_key = peer_key_pair.public_key().as_slice();
        assert!(key.start_and_complete(peer_public_key).is_ok());
    }
}
