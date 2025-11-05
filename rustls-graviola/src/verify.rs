use graviola::hashing;
use graviola::signing::{ecdsa, eddsa, rsa};
use rustls::SignatureScheme;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id,
};

pub(crate) static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA512,
        ECDSA_P256_SHA384,
        ECDSA_P256_SHA256,
        ECDSA_P384_SHA512,
        ECDSA_P384_SHA384,
        ECDSA_P384_SHA256,
        ED25519,
        RSA_PSS_SHA512,
        RSA_PSS_SHA384,
        RSA_PSS_SHA256,
        RSA_PKCS1_SHA512,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA256,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[ECDSA_P256_SHA256, ECDSA_P384_SHA256],
        ),
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[ECDSA_P384_SHA384, ECDSA_P256_SHA384],
        ),
        (SignatureScheme::ED25519, &[ED25519]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[RSA_PKCS1_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
    ],
};

static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &EcdsaP256Verify {
    signature_alg_id: alg_id::ECDSA_SHA256,
    verify: |key, signature, message| key.verify_asn1::<hashing::Sha256>(&[message], signature),
};

static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &EcdsaP256Verify {
    signature_alg_id: alg_id::ECDSA_SHA384,
    verify: |key, signature, message| key.verify_asn1::<hashing::Sha384>(&[message], signature),
};

static ECDSA_P256_SHA512: &dyn SignatureVerificationAlgorithm = &EcdsaP256Verify {
    signature_alg_id: alg_id::ECDSA_SHA512,
    verify: |key, signature, message| key.verify_asn1::<hashing::Sha512>(&[message], signature),
};

static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &EcdsaP384Verify {
    signature_alg_id: alg_id::ECDSA_SHA256,
    verify: |key, signature, message| key.verify_asn1::<hashing::Sha256>(&[message], signature),
};

static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &EcdsaP384Verify {
    signature_alg_id: alg_id::ECDSA_SHA384,
    verify: |key, signature, message| key.verify_asn1::<hashing::Sha384>(&[message], signature),
};

static ECDSA_P384_SHA512: &dyn SignatureVerificationAlgorithm = &EcdsaP384Verify {
    signature_alg_id: alg_id::ECDSA_SHA512,
    verify: |key, signature, message| key.verify_asn1::<hashing::Sha512>(&[message], signature),
};

static ED25519: &dyn SignatureVerificationAlgorithm = &Ed25519Verify;

static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &RsaVerify {
    signature_alg_id: alg_id::RSA_PSS_SHA256,
    verify: |key, signature, message| key.verify_pss_sha256(signature, message),
};

static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &RsaVerify {
    signature_alg_id: alg_id::RSA_PSS_SHA384,
    verify: |key, signature, message| key.verify_pss_sha384(signature, message),
};

static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm = &RsaVerify {
    signature_alg_id: alg_id::RSA_PSS_SHA512,
    verify: |key, signature, message| key.verify_pss_sha512(signature, message),
};

static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &RsaVerify {
    signature_alg_id: alg_id::RSA_PKCS1_SHA256,
    verify: |key, signature, message| key.verify_pkcs1_sha256(signature, message),
};

static RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm = &RsaVerify {
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
    verify: |key, signature, message| key.verify_pkcs1_sha384(signature, message),
};

static RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm = &RsaVerify {
    signature_alg_id: alg_id::RSA_PKCS1_SHA512,
    verify: |key, signature, message| key.verify_pkcs1_sha512(signature, message),
};

#[derive(Debug)]
struct RsaVerify {
    signature_alg_id: AlgorithmIdentifier,
    #[allow(clippy::type_complexity)]
    verify: fn(&rsa::VerifyingKey, &[u8], &[u8]) -> Result<(), graviola::Error>,
}

impl SignatureVerificationAlgorithm for RsaVerify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        rsa::VerifyingKey::from_pkcs1_der(public_key)
            .and_then(|pk| (self.verify)(&pk, signature, message))
            .map_err(|_| InvalidSignature)
    }
}

#[derive(Debug)]
struct EcdsaP256Verify {
    signature_alg_id: AlgorithmIdentifier,
    #[allow(clippy::type_complexity)]
    verify: fn(&ecdsa::VerifyingKey<ecdsa::P256>, &[u8], &[u8]) -> Result<(), graviola::Error>,
}

impl SignatureVerificationAlgorithm for EcdsaP256Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        <ecdsa::P256 as ecdsa::Curve>::PublicKey::from_x962_uncompressed(public_key)
            .and_then(|public_key| {
                (self.verify)(&ecdsa::VerifyingKey { public_key }, signature, message)
            })
            .map_err(|_| InvalidSignature)
    }
}

#[derive(Debug)]
struct EcdsaP384Verify {
    signature_alg_id: AlgorithmIdentifier,
    #[allow(clippy::type_complexity)]
    verify: fn(&ecdsa::VerifyingKey<ecdsa::P384>, &[u8], &[u8]) -> Result<(), graviola::Error>,
}

impl SignatureVerificationAlgorithm for EcdsaP384Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P384
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        <ecdsa::P384 as ecdsa::Curve>::PublicKey::from_x962_uncompressed(public_key)
            .and_then(|public_key| {
                (self.verify)(&ecdsa::VerifyingKey { public_key }, signature, message)
            })
            .map_err(|_| InvalidSignature)
    }
}

#[derive(Debug)]
struct Ed25519Verify;

impl SignatureVerificationAlgorithm for Ed25519Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        eddsa::Ed25519VerifyingKey::from_bytes(public_key)
            .and_then(|public_key| public_key.verify(signature, message))
            .map_err(|_| InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use graviola::random;

    use super::*;

    macro_rules! test_verify {
        ($algorithm:ident, $signature:expr, $signing_key:expr, $hash:ty) => {
            assert_eq!($algorithm.signature_alg_id(), $signature);
            let mut message = [0u8; 64];
            assert!(random::fill(&mut message).is_ok());
            let mut signature = [0u8; 128];
            let signature = $signing_key
                .sign_asn1::<$hash>(&[&message], &mut signature)
                .unwrap();
            assert!(
                $algorithm
                    .verify_signature(
                        &$signing_key.private_key.public_key_uncompressed(),
                        &message,
                        &signature
                    )
                    .is_ok()
            );
        };
    }

    #[test]
    fn test_ecdsap256_verify() {
        let signing_key = Arc::new(
            ecdsa::SigningKey::<ecdsa::P256>::from_pkcs8_der(include_bytes!(
                "../../graviola/src/high/ecdsa/secp256r1.pkcs8.der"
            ))
            .unwrap(),
        );
        test_verify!(
            ECDSA_P256_SHA256,
            alg_id::ECDSA_SHA256,
            signing_key,
            hashing::Sha256
        );
        test_verify!(
            ECDSA_P256_SHA384,
            alg_id::ECDSA_SHA384,
            signing_key,
            hashing::Sha384
        );
        test_verify!(
            ECDSA_P256_SHA512,
            alg_id::ECDSA_SHA512,
            signing_key,
            hashing::Sha512
        );
    }

    #[test]
    fn test_ecdsap384_verify() {
        let signing_key = Arc::new(
            ecdsa::SigningKey::<ecdsa::P384>::from_pkcs8_der(include_bytes!(
                "../../graviola/src/high/ecdsa/secp384r1.pkcs8.der"
            ))
            .unwrap(),
        );
        test_verify!(
            ECDSA_P384_SHA256,
            alg_id::ECDSA_SHA256,
            signing_key,
            hashing::Sha256
        );
        test_verify!(
            ECDSA_P384_SHA384,
            alg_id::ECDSA_SHA384,
            signing_key,
            hashing::Sha384
        );
        test_verify!(
            ECDSA_P384_SHA512,
            alg_id::ECDSA_SHA512,
            signing_key,
            hashing::Sha512
        );
    }
}
