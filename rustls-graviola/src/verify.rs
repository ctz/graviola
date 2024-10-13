use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls::SignatureScheme;
use webpki::alg_id;

use graviola::hash;
use graviola::signing::{ecdsa, rsa};

pub(crate) static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA512,
        ECDSA_P256_SHA384,
        ECDSA_P256_SHA256,
        ECDSA_P384_SHA512,
        ECDSA_P384_SHA384,
        ECDSA_P384_SHA256,
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
    verify: |key, signature, message| key.verify_asn1::<hash::Sha256>(&[message], signature),
};

static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &EcdsaP256Verify {
    signature_alg_id: alg_id::ECDSA_SHA384,
    verify: |key, signature, message| key.verify_asn1::<hash::Sha384>(&[message], signature),
};

static ECDSA_P256_SHA512: &dyn SignatureVerificationAlgorithm = &EcdsaP256Verify {
    signature_alg_id: alg_id::ECDSA_SHA512,
    verify: |key, signature, message| key.verify_asn1::<hash::Sha512>(&[message], signature),
};

static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &EcdsaP384Verify {
    signature_alg_id: alg_id::ECDSA_SHA256,
    verify: |key, signature, message| key.verify_asn1::<hash::Sha256>(&[message], signature),
};

static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &EcdsaP384Verify {
    signature_alg_id: alg_id::ECDSA_SHA384,
    verify: |key, signature, message| key.verify_asn1::<hash::Sha384>(&[message], signature),
};

static ECDSA_P384_SHA512: &dyn SignatureVerificationAlgorithm = &EcdsaP384Verify {
    signature_alg_id: alg_id::ECDSA_SHA512,
    verify: |key, signature, message| key.verify_asn1::<hash::Sha512>(&[message], signature),
};

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
