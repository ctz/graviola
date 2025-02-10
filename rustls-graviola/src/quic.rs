use rustls::crypto::cipher::{AeadKey, Iv, Nonce};
use rustls::quic;
use rustls::Error;

pub(crate) struct Aes128Gcm;

impl quic::Algorithm for Aes128Gcm {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        Box::new(AesGcmPacketKey::new(key, iv))
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(AesHeaderProtectionKey(
            graviola::aead::quic::AesHeaderProtection::new(key.as_ref()),
        ))
    }

    fn aead_key_len(&self) -> usize {
        16
    }
}

pub(crate) struct Aes256Gcm;

impl quic::Algorithm for Aes256Gcm {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        Box::new(AesGcmPacketKey::new(key, iv))
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(AesHeaderProtectionKey(
            graviola::aead::quic::AesHeaderProtection::new(key.as_ref()),
        ))
    }

    fn aead_key_len(&self) -> usize {
        32
    }
}

struct AesGcmPacketKey {
    key: graviola::aead::AesGcm,
    iv: Iv,
}

impl AesGcmPacketKey {
    fn new(key: AeadKey, iv: Iv) -> Self {
        Self {
            key: graviola::aead::AesGcm::new(key.as_ref()),
            iv,
        }
    }
}

impl quic::PacketKey for AesGcmPacketKey {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        let mut tag = [0u8; 16];
        let nonce = Nonce::new(&self.iv, packet_number);
        self.key.encrypt(&nonce.0, header, payload, &mut tag);
        Ok(quic::Tag::from(&tag[..]))
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let nonce = Nonce::new(&self.iv, packet_number);

        let (cipher, tag) = if payload.len() >= 16 {
            payload.split_at_mut(payload.len() - 16)
        } else {
            return Err(Error::DecryptError);
        };

        self.key
            .decrypt(&nonce.0, header, cipher, tag)
            .map_err(|_| Error::DecryptError)?;

        Ok(cipher)
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn confidentiality_limit(&self) -> u64 {
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.1>
        1 << 23
    }

    fn integrity_limit(&self) -> u64 {
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.2>
        1 << 52
    }
}

struct AesHeaderProtectionKey(graviola::aead::quic::AesHeaderProtection);

impl quic::HeaderProtectionKey for AesHeaderProtectionKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        let sample16 = sample.try_into().map_err(|_| Error::EncryptError)?;
        self.0.encrypt_in_place(sample16, first, packet_number);
        Ok(())
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        let sample16 = sample.try_into().map_err(|_| Error::EncryptError)?;
        self.0.decrypt_in_place(sample16, first, packet_number);
        Ok(())
    }

    fn sample_len(&self) -> usize {
        16
    }
}
