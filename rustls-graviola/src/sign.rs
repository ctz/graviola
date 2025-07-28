use core::fmt;
use std::sync::Arc;

use graviola::hashing;
use graviola::signing::{ecdsa, rsa};
use rustls::pki_types::SubjectPublicKeyInfoDer;
use rustls::{SignatureScheme, pki_types, sign};

#[derive(Debug)]
pub(super) struct Provider;

impl rustls::crypto::KeyProvider for Provider {
    fn load_private_key(
        &self,
        key_der: pki_types::PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn sign::SigningKey>, rustls::Error> {
        match key_der {
            pki_types::PrivateKeyDer::Pkcs8(p8) => load_pkcs8(p8),
            pki_types::PrivateKeyDer::Pkcs1(p1) => load_pkcs1(p1),
            pki_types::PrivateKeyDer::Sec1(sec1) => load_sec1(sec1),
            _ => Err(rustls::Error::General("unhandled private key".to_string())),
        }
    }
}

fn load_pkcs8(
    key_der: pki_types::PrivatePkcs8KeyDer<'static>,
) -> Result<Arc<dyn sign::SigningKey>, rustls::Error> {
    if let Ok(rsa) = rsa::SigningKey::from_pkcs8_der(key_der.secret_pkcs8_der()) {
        return Ok(Arc::new(Rsa(Arc::new(rsa))));
    }

    if let Ok(ecp256) = ecdsa::SigningKey::<ecdsa::P256>::from_pkcs8_der(key_der.secret_pkcs8_der())
    {
        return Ok(Arc::new(EcdsaP256(Arc::new(ecp256))));
    }

    if let Ok(ecp384) = ecdsa::SigningKey::<ecdsa::P384>::from_pkcs8_der(key_der.secret_pkcs8_der())
    {
        return Ok(Arc::new(EcdsaP384(Arc::new(ecp384))));
    }

    Err(rustls::Error::General("unhandled pkcs8 format".to_string()))
}

fn load_pkcs1(
    key_der: pki_types::PrivatePkcs1KeyDer<'static>,
) -> Result<Arc<dyn sign::SigningKey>, rustls::Error> {
    let rsa = rsa::SigningKey::from_pkcs1_der(key_der.secret_pkcs1_der())
        .map_err(|err| rustls::Error::General(format!("cannot parse RSA key: {err:?}")))?;

    Ok(Arc::new(Rsa(Arc::new(rsa))))
}

fn load_sec1(
    key_der: pki_types::PrivateSec1KeyDer<'static>,
) -> Result<Arc<dyn sign::SigningKey>, rustls::Error> {
    if let Ok(ecp256) = ecdsa::SigningKey::<ecdsa::P256>::from_sec1_der(key_der.secret_sec1_der()) {
        return Ok(Arc::new(EcdsaP256(Arc::new(ecp256))));
    }

    if let Ok(ecp384) = ecdsa::SigningKey::<ecdsa::P384>::from_sec1_der(key_der.secret_sec1_der()) {
        return Ok(Arc::new(EcdsaP384(Arc::new(ecp384))));
    }

    Err(rustls::Error::General(
        "unhandled sec1 format/curve".to_string(),
    ))
}

struct Rsa(Arc<rsa::SigningKey>);

impl sign::SigningKey for Rsa {
    fn choose_scheme(
        &self,
        schemes: &[SignatureScheme],
    ) -> Option<Box<dyn sign::Signer + 'static>> {
        if schemes.contains(&SignatureScheme::RSA_PSS_SHA512) {
            Some(Box::new(RsaSigner {
                key: Arc::clone(&self.0),
                scheme: SignatureScheme::RSA_PSS_SHA512,
            }))
        } else if schemes.contains(&SignatureScheme::RSA_PSS_SHA384) {
            Some(Box::new(RsaSigner {
                key: Arc::clone(&self.0),
                scheme: SignatureScheme::RSA_PSS_SHA384,
            }))
        } else if schemes.contains(&SignatureScheme::RSA_PSS_SHA256) {
            Some(Box::new(RsaSigner {
                key: Arc::clone(&self.0),
                scheme: SignatureScheme::RSA_PSS_SHA256,
            }))
        } else if schemes.contains(&SignatureScheme::RSA_PKCS1_SHA512) {
            Some(Box::new(RsaSigner {
                key: Arc::clone(&self.0),
                scheme: SignatureScheme::RSA_PKCS1_SHA512,
            }))
        } else if schemes.contains(&SignatureScheme::RSA_PKCS1_SHA384) {
            Some(Box::new(RsaSigner {
                key: Arc::clone(&self.0),
                scheme: SignatureScheme::RSA_PKCS1_SHA384,
            }))
        } else if schemes.contains(&SignatureScheme::RSA_PKCS1_SHA256) {
            Some(Box::new(RsaSigner {
                key: Arc::clone(&self.0),
                scheme: SignatureScheme::RSA_PKCS1_SHA256,
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::RSA
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'static>> {
        let size = self.0.modulus_len_bytes() + 64;
        let mut buffer = vec![0u8; size];

        let pk = self.0.public_key();
        let used = pk.to_spki_der(&mut buffer).ok()?.len();

        buffer.truncate(used);
        Some(SubjectPublicKeyInfoDer::from(buffer))
    }
}

impl fmt::Debug for Rsa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("Rsa").finish_non_exhaustive()
    }
}

struct RsaSigner {
    key: Arc<rsa::SigningKey>,
    scheme: SignatureScheme,
}

impl sign::Signer for RsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut sig = vec![0u8; self.key.modulus_len_bytes()];
        match self.scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => self.key.sign_pkcs1_sha256(&mut sig, message),
            SignatureScheme::RSA_PKCS1_SHA384 => self.key.sign_pkcs1_sha384(&mut sig, message),
            SignatureScheme::RSA_PKCS1_SHA512 => self.key.sign_pkcs1_sha512(&mut sig, message),
            SignatureScheme::RSA_PSS_SHA256 => self.key.sign_pss_sha256(&mut sig, message),
            SignatureScheme::RSA_PSS_SHA384 => self.key.sign_pss_sha384(&mut sig, message),
            SignatureScheme::RSA_PSS_SHA512 => self.key.sign_pss_sha512(&mut sig, message),
            _ => unreachable!(),
        }
        .map_err(|err| rustls::Error::General(format!("signing failed: {err:?}")))?;

        Ok(sig)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl fmt::Debug for RsaSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("RsaSigner").finish_non_exhaustive()
    }
}

struct EcdsaP256(Arc<ecdsa::SigningKey<ecdsa::P256>>);

impl sign::SigningKey for EcdsaP256 {
    fn choose_scheme(
        &self,
        schemes: &[SignatureScheme],
    ) -> Option<Box<dyn sign::Signer + 'static>> {
        if schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256) {
            Some(Box::new(Self(self.0.clone())))
        } else {
            None
        }
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ECDSA
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'static>> {
        let mut buffer = vec![0u8; 128];

        let used = self.0.to_spki_der(&mut buffer).ok()?.len();

        buffer.truncate(used);
        Some(SubjectPublicKeyInfoDer::from(buffer))
    }
}

impl sign::Signer for EcdsaP256 {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut sig_buffer = [0u8; 128];
        let sig = self
            .0
            .sign_asn1::<hashing::Sha256>(&[message], &mut sig_buffer)
            .map_err(|err| rustls::Error::General(format!("signing failed: {err:?}")))?;

        Ok(sig.to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

impl fmt::Debug for EcdsaP256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("EcdsaP256").finish_non_exhaustive()
    }
}

struct EcdsaP384(Arc<ecdsa::SigningKey<ecdsa::P384>>);

impl sign::SigningKey for EcdsaP384 {
    fn choose_scheme(
        &self,
        schemes: &[SignatureScheme],
    ) -> Option<Box<dyn sign::Signer + 'static>> {
        if schemes.contains(&SignatureScheme::ECDSA_NISTP384_SHA384) {
            Some(Box::new(Self(self.0.clone())))
        } else {
            None
        }
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ECDSA
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'static>> {
        let mut buffer = vec![0u8; 128];

        let used = self.0.to_spki_der(&mut buffer).ok()?.len();

        buffer.truncate(used);
        Some(SubjectPublicKeyInfoDer::from(buffer))
    }
}

impl sign::Signer for EcdsaP384 {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut sig_buffer = [0u8; 128];
        let sig = self
            .0
            .sign_asn1::<hashing::Sha384>(&[message], &mut sig_buffer)
            .map_err(|err| rustls::Error::General(format!("signing failed: {err:?}")))?;

        Ok(sig.to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP384_SHA384
    }
}

impl fmt::Debug for EcdsaP384 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("EcdsaP384").finish_non_exhaustive()
    }
}
