use graviola::aead::{AesGcm, ChaCha20Poly1305};
use rustls::ConnectionTrafficSecrets;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaque, Iv, KeyBlockShape, NONCE_LEN, Nonce, OutboundPlain, Record,
    RecordDecrypter, RecordEncrypter, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
    UnsupportedOperationError, encode_record_header, make_tls12_aad, make_tls13_aad,
};
use rustls::enums::ContentType;

pub struct Chacha20Poly1305;

impl Tls13AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn RecordEncrypter> {
        Box::new(ChaChaTls13Cipher(
            ChaCha20Poly1305::new(key.as_ref().try_into().unwrap()),
            iv,
        ))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn RecordDecrypter> {
        Box::new(ChaChaTls13Cipher(
            ChaCha20Poly1305::new(key.as_ref().try_into().unwrap()),
            iv,
        ))
    }

    fn key_len(&self) -> usize {
        32
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

impl Tls12AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn RecordEncrypter> {
        Box::new(ChaChaTls12Cipher(
            ChaCha20Poly1305::new(key.as_ref().try_into().unwrap()),
            Iv::new(iv).expect("IV length validated by key_block_shape"),
        ))
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn RecordDecrypter> {
        Box::new(ChaChaTls12Cipher(
            ChaCha20Poly1305::new(key.as_ref().try_into().unwrap()),
            Iv::new(iv).expect("IV length validated by key_block_shape"),
        ))
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 12,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        // This should always be true because KeyBlockShape and the Iv nonce len are in agreement.
        debug_assert_eq!(NONCE_LEN, iv.len());
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::new(iv).expect("IV length validated by key_block_shape"),
        })
    }
}

struct ChaChaTls13Cipher(ChaCha20Poly1305, Iv);

impl RecordEncrypter for ChaChaTls13Cipher {
    fn encrypt(
        &mut self,
        record: Record<OutboundPlain<'_>>,
        seq: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), rustls::Error> {
        let total_len = self.encrypted_payload_len(record.payload.len());
        let typ = ContentType::ApplicationData;
        let header = encode_record_header(typ, record.version, total_len as u16);
        out.reserve(header.len() + total_len);
        out.extend_from_slice(&header);

        let nonce = Nonce::new(&self.1, seq).to_array()?;
        let aad = make_tls13_aad(typ, record.version.encode(), total_len);
        let start = out.len();
        record.payload.copy_to_vec(out);
        out.extend_from_slice(&record.typ.to_array());

        let mut tag = [0u8; CHACHAPOLY1305_OVERHEAD];
        self.0.encrypt(&nonce, &aad, &mut out[start..], &mut tag);
        out.extend_from_slice(&tag);
        Ok(())
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + CHACHAPOLY1305_OVERHEAD
    }
}

impl RecordDecrypter for ChaChaTls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut record: Record<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<Record<&'a [u8]>, rustls::Error> {
        let payload = &mut record.payload;
        if payload.len() < CHACHAPOLY1305_OVERHEAD {
            return Err(rustls::Error::DecryptError);
        }

        let nonce = Nonce::new(&self.1, seq).to_array()?;
        let aad = make_tls13_aad(record.typ, record.version.version(), payload.len());
        let cipher_len = payload.len() - CHACHAPOLY1305_OVERHEAD;
        let (cipher, tag) = payload.split_at_mut(cipher_len);

        self.0
            .decrypt(&nonce, &aad, cipher, tag)
            .map_err(|_| rustls::Error::DecryptError)?;

        payload.truncate(cipher_len);
        record.into_tls13_unpadded_record()
    }
}

struct ChaChaTls12Cipher(ChaCha20Poly1305, Iv);

impl RecordEncrypter for ChaChaTls12Cipher {
    fn encrypt(
        &mut self,
        record: Record<OutboundPlain<'_>>,
        seq: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), rustls::Error> {
        let total_len = self.encrypted_payload_len(record.payload.len());
        let header = encode_record_header(record.typ, record.version, total_len as u16);
        out.reserve(header.len() + total_len);
        out.extend_from_slice(&header);

        let nonce = Nonce::new(&self.1, seq).to_array()?;
        let aad = make_tls12_aad(
            seq,
            record.typ,
            record.version.encode(),
            record.payload.len(),
        );
        let start = out.len();
        record.payload.copy_to_vec(out);

        let mut tag = [0u8; CHACHAPOLY1305_OVERHEAD];
        self.0.encrypt(&nonce, &aad, &mut out[start..], &mut tag);
        out.extend_from_slice(&tag);
        Ok(())
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + CHACHAPOLY1305_OVERHEAD
    }
}

impl RecordDecrypter for ChaChaTls12Cipher {
    fn decrypt<'a>(
        &mut self,
        mut record: Record<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<Record<&'a [u8]>, rustls::Error> {
        let payload = &mut record.payload;
        if payload.len() < CHACHAPOLY1305_OVERHEAD {
            return Err(rustls::Error::DecryptError);
        }

        let nonce = Nonce::new(&self.1, seq).to_array()?;
        let cipher_len = payload.len() - CHACHAPOLY1305_OVERHEAD;
        let aad = make_tls12_aad(seq, record.typ, record.version.version(), cipher_len);
        let (cipher, tag) = payload.split_at_mut(cipher_len);

        self.0
            .decrypt(&nonce, &aad, cipher, tag)
            .map_err(|_| rustls::Error::DecryptError)?;

        if cipher_len > MAX_FRAGMENT_LEN {
            return Err(rustls::Error::PeerSentOversizedRecord);
        }

        payload.truncate(cipher_len);
        Ok(record.into_plain_record())
    }
}

pub struct TlsAesGcm(pub usize);

impl Tls13AeadAlgorithm for TlsAesGcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn RecordEncrypter> {
        Box::new(GcmTls13Cipher(AesGcm::new(key.as_ref()), iv))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn RecordDecrypter> {
        Box::new(GcmTls13Cipher(AesGcm::new(key.as_ref()), iv))
    }

    fn key_len(&self) -> usize {
        self.0
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(match self.0 {
            16 => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            32 => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            _ => unreachable!(),
        })
    }
}

impl Tls12AeadAlgorithm for TlsAesGcm {
    fn encrypter(
        &self,
        key: AeadKey,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Box<dyn RecordEncrypter> {
        let iv = gcm_iv(write_iv, explicit);
        Box::new(GcmTls12MessageEncrypter(AesGcm::new(key.as_ref()), iv))
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn RecordDecrypter> {
        Box::new(GcmTls12MessageDecrypter(
            AesGcm::new(key.as_ref()),
            iv.try_into().unwrap(),
        ))
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: self.0,
            fixed_iv_len: 4,
            explicit_nonce_len: 8,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let iv = gcm_iv(iv, explicit);
        Ok(match self.0 {
            16 => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            32 => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            _ => unreachable!(),
        })
    }
}

struct GcmTls12MessageDecrypter(AesGcm, [u8; 4]);

impl RecordDecrypter for GcmTls12MessageDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut record: Record<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<Record<&'a [u8]>, rustls::Error> {
        let payload = &record.payload;
        if payload.len() < AESGCM_OVERHEAD {
            return Err(rustls::Error::DecryptError);
        }

        let nonce = {
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&self.1);
            nonce[4..].copy_from_slice(&payload[..8]);
            nonce
        };

        let plain_len = payload.len() - AESGCM_OVERHEAD;
        let aad = make_tls12_aad(seq, record.typ, record.version.version(), plain_len);

        let payload = &mut record.payload;
        let (_explicit_iv, cipher) = payload.split_at_mut(AESGCM_EXPLICIT_NONCE_LEN);
        let (cipher, tag) = cipher.split_at_mut(cipher.len() - AESGCM_TAG);
        self.0
            .decrypt(&nonce, &aad, cipher, tag)
            .map_err(|_| rustls::Error::DecryptError)?;

        if plain_len > MAX_FRAGMENT_LEN {
            return Err(rustls::Error::PeerSentOversizedRecord);
        }

        Ok(record.into_plain_record_range(
            AESGCM_EXPLICIT_NONCE_LEN..AESGCM_EXPLICIT_NONCE_LEN + plain_len,
        ))
    }
}

struct GcmTls12MessageEncrypter(AesGcm, Iv);

impl RecordEncrypter for GcmTls12MessageEncrypter {
    fn encrypt(
        &mut self,
        record: Record<OutboundPlain<'_>>,
        seq: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), rustls::Error> {
        let total_len = self.encrypted_payload_len(record.payload.len());
        let header = encode_record_header(record.typ, record.version, total_len as u16);
        out.reserve(header.len() + total_len);
        out.extend_from_slice(&header);

        let nonce = Nonce::new(&self.1, seq).to_array()?;
        let aad = make_tls12_aad(
            seq,
            record.typ,
            record.version.encode(),
            record.payload.len(),
        );
        out.extend_from_slice(&nonce[4..]);
        let start = out.len();
        record.payload.copy_to_vec(out);

        let mut tag = [0u8; AESGCM_TAG];
        self.0.encrypt(&nonce, &aad, &mut out[start..], &mut tag);
        out.extend_from_slice(&tag);
        Ok(())
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + AESGCM_EXPLICIT_NONCE_LEN + AESGCM_TAG
    }
}

struct GcmTls13Cipher(AesGcm, Iv);

impl RecordEncrypter for GcmTls13Cipher {
    fn encrypt(
        &mut self,
        record: Record<OutboundPlain<'_>>,
        seq: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), rustls::Error> {
        let total_len = self.encrypted_payload_len(record.payload.len());
        let typ = ContentType::ApplicationData;
        let header = encode_record_header(typ, record.version, total_len as u16);
        out.reserve(header.len() + total_len);
        out.extend_from_slice(&header);

        let nonce = Nonce::new(&self.1, seq).to_array()?;
        let aad = make_tls13_aad(typ, record.version.encode(), total_len);
        let start = out.len();
        record.payload.copy_to_vec(out);
        out.extend_from_slice(&record.typ.to_array());

        let mut tag = [0u8; AESGCM_TAG];
        self.0.encrypt(&nonce, &aad, &mut out[start..], &mut tag);
        out.extend_from_slice(&tag);
        Ok(())
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + AESGCM_TAG
    }
}

impl RecordDecrypter for GcmTls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut record: Record<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<Record<&'a [u8]>, rustls::Error> {
        let payload = &mut record.payload;
        if payload.len() < AESGCM_TAG {
            return Err(rustls::Error::DecryptError);
        }

        let nonce = Nonce::new(&self.1, seq).to_array()?;
        let aad = make_tls13_aad(record.typ, record.version.version(), payload.len());
        let plain_len = payload.len() - AESGCM_TAG;
        let (cipher, tag) = payload.split_at_mut(plain_len);
        self.0
            .decrypt(&nonce, &aad, cipher, tag)
            .map_err(|_| rustls::Error::DecryptError)?;

        payload.truncate(plain_len);
        record.into_tls13_unpadded_record()
    }
}

fn gcm_iv(write_iv: &[u8], explicit: &[u8]) -> Iv {
    debug_assert_eq!(write_iv.len(), 4);
    debug_assert_eq!(explicit.len(), 8);

    // The GCM nonce is constructed from a 32-bit 'salt' derived
    // from the master-secret, and a 64-bit explicit part,
    // with no specified construction.  Thanks for that.
    //
    // We use the same construction as TLS1.3/ChaCha20Poly1305:
    // a starting point extracted from the key block, xored with
    // the sequence number.
    let mut iv = [0; NONCE_LEN];
    iv[..4].copy_from_slice(write_iv);
    iv[4..].copy_from_slice(explicit);

    Iv::from(iv)
}

const CHACHAPOLY1305_OVERHEAD: usize = 16;
const AESGCM_TAG: usize = 16;

const MAX_FRAGMENT_LEN: usize = 16384;

// TLS1.2-specific
const AESGCM_EXPLICIT_NONCE_LEN: usize = 8;
const AESGCM_OVERHEAD: usize = AESGCM_EXPLICIT_NONCE_LEN + AESGCM_TAG;

#[cfg(test)]
mod tests {
    use rustls::Error;

    use super::*;

    fn random_bytes<const L: usize>() -> Result<[u8; L], Error> {
        let mut bytes = [0; L];
        graviola::random::fill(&mut bytes).map_err(|_| rustls::crypto::GetRandomFailed)?;
        Ok(bytes)
    }

    #[test]
    fn test_chacha20_poly1305_tls13() {
        let cipher = Chacha20Poly1305;
        assert_eq!(cipher.key_len(), 32);
        let cipher_key = random_bytes::<32>().unwrap();
        let cipher_iv = random_bytes::<12>().unwrap();
        match rustls::crypto::cipher::Tls13AeadAlgorithm::extract_keys(
            &cipher,
            AeadKey::from(cipher_key),
            Iv::from(cipher_iv),
        )
        .unwrap()
        {
            ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
                assert_eq!(key.as_ref(), cipher_key);
                assert_eq!(iv.as_ref(), cipher_iv);
            }
            _ => panic!("Unexpected secret type extracted from ChaCha20-Poly1305 cipher"),
        }
    }

    #[test]
    fn test_chacha20_poly1305_tls12() {
        let cipher = Chacha20Poly1305;
        assert_eq!(cipher.key_len(), 32);
        let cipher_key = random_bytes::<32>().unwrap();
        let cipher_iv = random_bytes::<12>().unwrap();
        let unused = [0u8; 1];
        match rustls::crypto::cipher::Tls12AeadAlgorithm::extract_keys(
            &cipher,
            AeadKey::from(cipher_key),
            &cipher_iv,
            &unused,
        )
        .unwrap()
        {
            ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
                assert_eq!(key.as_ref(), cipher_key);
                assert_eq!(iv.as_ref(), cipher_iv);
            }
            _ => panic!("Unexpected secret type extracted from ChaCha20-Poly1305 cipher"),
        }
    }

    #[test]
    fn test_aes_gcm_tls13() {
        fn test_aes_gcm_tls13(key_bits: usize) {
            let key_bytes = key_bits / 8;
            let cipher = TlsAesGcm(key_bytes);
            assert_eq!(cipher.key_len(), key_bytes);
            let cipher_key = &random_bytes::<32>().unwrap();
            let cipher_iv = random_bytes::<12>().unwrap();
            match Tls13AeadAlgorithm::extract_keys(
                &cipher,
                AeadKey::from(*cipher_key),
                Iv::from(cipher_iv),
            )
            .unwrap()
            {
                ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                    assert_eq!(key_bits, 128);
                    assert_eq!(key.as_ref(), cipher_key);
                    assert_eq!(iv.as_ref(), cipher_iv);
                }
                ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
                    assert_eq!(key_bits, 256);
                    assert_eq!(key.as_ref(), cipher_key);
                    assert_eq!(iv.as_ref(), cipher_iv);
                }
                _ => panic!(
                    "Unexpected secret type extracted from AES{}-GCM cipher",
                    key_bits
                ),
            }
        }

        test_aes_gcm_tls13(128);
        test_aes_gcm_tls13(256);
    }

    #[test]
    fn test_aes_gcm_tls12() {
        fn test_aes_gcm_tls12(key_bits: usize) {
            let key_bytes = key_bits / 8;
            let cipher = TlsAesGcm(key_bytes);
            assert_eq!(cipher.key_len(), key_bytes);
            let cipher_key = &random_bytes::<32>().unwrap();
            let cipher_iv = random_bytes::<4>().unwrap();
            let cipher_explicit = random_bytes::<8>().unwrap();
            match Tls12AeadAlgorithm::extract_keys(
                &cipher,
                AeadKey::from(*cipher_key),
                &cipher_iv,
                &cipher_explicit,
            )
            .unwrap()
            {
                ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                    assert_eq!(key_bits, 128);
                    assert_eq!(key.as_ref(), cipher_key);
                    assert_eq!(iv.as_ref().len(), 12);
                }
                ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
                    assert_eq!(key_bits, 256);
                    assert_eq!(key.as_ref(), cipher_key);
                    assert_eq!(iv.as_ref().len(), 12);
                }
                _ => panic!(
                    "Unexpected secret type extracted from AES{}-GCM cipher",
                    key_bits
                ),
            }
        }

        test_aes_gcm_tls12(128);
        test_aes_gcm_tls12(256);
    }
}
