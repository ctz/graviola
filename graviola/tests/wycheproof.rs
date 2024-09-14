use serde::Deserialize;
use std::fs::File;

use graviola::aes_gcm;
use graviola::chacha20poly1305;
use graviola::ec::{P256, P384};
use graviola::ecdsa::VerifyingKey;
use graviola::high::hash::{Sha256, Sha384, Sha512};
use graviola::high::hmac::Hmac;
use graviola::high::rsa;
use graviola::p256;
use graviola::p384;
use graviola::x25519;
use graviola::Error;

#[derive(Deserialize, Debug)]
struct TestFile {
    #[serde(rename(deserialize = "testGroups"))]
    groups: Vec<TestGroup>,
}

#[derive(Deserialize, Debug)]
struct TestGroup {
    #[serde(rename(deserialize = "type"))]
    typ: String,

    #[serde(default, rename(deserialize = "publicKey"))]
    public_key: PublicKey,

    #[serde(default, rename(deserialize = "publicKeyAsn"), with = "hex::serde")]
    public_key_asn: Vec<u8>,

    #[serde(default)]
    sha: String,

    #[serde(default, rename(deserialize = "mgfSha"))]
    mgf_sha: String,

    #[serde(default, rename(deserialize = "sLen"))]
    salt_len: usize,

    tests: Vec<Test>,
}

#[derive(Deserialize, Debug)]
struct Test {
    #[serde(rename(deserialize = "tcId"))]
    #[allow(unused)] // for Debug
    id: usize,
    #[allow(unused)] // for Debug
    comment: String,
    flags: Vec<String>,
    #[serde(default, with = "hex::serde")]
    key: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    msg: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    tag: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    sig: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    private: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    public: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    shared: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    ct: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    aad: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    iv: Vec<u8>,
    result: ExpectedResult,
}

impl Test {
    fn has_flag(&self, s: &str) -> bool {
        self.flags.contains(&s.to_string())
    }
}

#[derive(Deserialize, Debug, Default)]
struct PublicKey {
    #[serde(default, with = "hex::serde")]
    uncompressed: Vec<u8>,
}

#[derive(Copy, Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
enum ExpectedResult {
    Valid,
    Invalid,
    Acceptable,
}

#[test]
fn hmac_sha256_tests() {
    let data_file = File::open("../thirdparty/wycheproof/testvectors_v1/hmac_sha256_test.json")
        .expect("failed to open data file");

    let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

    for group in tests.groups {
        println!("group: {:?}", group.typ);
        for test in group.tests {
            println!("  test {:?}", test);

            let mut ctx = Hmac::<Sha256>::new(test.key);
            ctx.update(test.msg);
            let result = ctx.verify(&test.tag);

            match (test.result, result) {
                (ExpectedResult::Valid, Ok(())) => {}
                (ExpectedResult::Invalid, Err(Error::BadSignature)) => {}
                _ => panic!("expected {:?} got {:?}", test.result, result),
            }
        }
    }
}

#[test]
fn hmac_sha384_tests() {
    let data_file = File::open("../thirdparty/wycheproof/testvectors_v1/hmac_sha384_test.json")
        .expect("failed to open data file");

    let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

    for group in tests.groups {
        println!("group: {:?}", group.typ);
        for test in group.tests {
            println!("  test {:?}", test);

            let mut ctx = Hmac::<Sha384>::new(test.key);
            ctx.update(test.msg);
            let result = ctx.verify(&test.tag);

            match (test.result, result) {
                (ExpectedResult::Valid, Ok(())) => {}
                (ExpectedResult::Invalid, Err(Error::BadSignature)) => {}
                _ => panic!("expected {:?} got {:?}", test.result, result),
            }
        }
    }
}

#[test]
fn hmac_sha512_tests() {
    let data_file = File::open("../thirdparty/wycheproof/testvectors_v1/hmac_sha512_test.json")
        .expect("failed to open data file");

    let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

    for group in tests.groups {
        println!("group: {:?}", group.typ);
        for test in group.tests {
            println!("  test {:?}", test);

            let mut ctx = Hmac::<Sha512>::new(test.key);
            ctx.update(test.msg);
            let result = ctx.verify(&test.tag);

            match (test.result, result) {
                (ExpectedResult::Valid, Ok(())) => {}
                (ExpectedResult::Invalid, Err(Error::BadSignature)) => {}
                _ => panic!("expected {:?} got {:?}", test.result, result),
            }
        }
    }
}

#[test]
fn test_verify_ecdsa_p256() {
    for file in [
        "ecdsa_secp256r1_sha256_p1363_test.json",
        "ecdsa_secp256r1_sha256_test.json",
        "ecdsa_secp256r1_sha512_p1363_test.json",
        "ecdsa_secp256r1_sha512_test.json",
    ] {
        let data_file = File::open(format!("../thirdparty/wycheproof/testvectors_v1/{file}"))
            .expect("failed to open data file");

        let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

        for group in tests.groups {
            println!("group: {:?}", group.typ);
            let public_key =
                VerifyingKey::<P256>::from_x962_uncompressed(&group.public_key.uncompressed)
                    .unwrap();

            for test in group.tests {
                println!("  test {:?}", test);

                let result = match (group.typ.as_ref(), group.sha.as_ref()) {
                    ("EcdsaP1363Verify", "SHA-256") => {
                        public_key.verify::<Sha256>(&[&test.msg], &test.sig)
                    }
                    ("EcdsaVerify", "SHA-256") => {
                        public_key.verify_asn1::<Sha256>(&[&test.msg], &test.sig)
                    }
                    ("EcdsaP1363Verify", "SHA-512") => {
                        public_key.verify::<Sha512>(&[&test.msg], &test.sig)
                    }
                    ("EcdsaVerify", "SHA-512") => {
                        public_key.verify_asn1::<Sha512>(&[&test.msg], &test.sig)
                    }
                    _ => todo!("other ecdsa hashes"),
                };

                match (test.result, result) {
                    (ExpectedResult::Valid, Ok(())) => {}
                    (
                        ExpectedResult::Invalid,
                        Err(Error::BadSignature) | Err(Error::WrongLength),
                    ) => {}
                    _ => panic!("expected {:?} got {:?}", test.result, result),
                }
            }
        }
    }
}

#[test]
fn test_verify_ecdsa_p384() {
    for file in [
        "ecdsa_secp384r1_sha256_test.json",
        "ecdsa_secp384r1_sha384_p1363_test.json",
        "ecdsa_secp384r1_sha384_test.json",
        "ecdsa_secp384r1_sha512_p1363_test.json",
        "ecdsa_secp384r1_sha512_test.json",
    ] {
        let data_file = File::open(format!("../thirdparty/wycheproof/testvectors_v1/{file}"))
            .expect("failed to open data file");

        let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

        for group in tests.groups {
            println!("group: {:?}", group.typ);
            let public_key =
                VerifyingKey::<P384>::from_x962_uncompressed(&group.public_key.uncompressed)
                    .unwrap();

            for test in group.tests {
                println!("  test {:?}", test);

                let result = match (group.typ.as_ref(), group.sha.as_ref()) {
                    ("EcdsaVerify", "SHA-256") => {
                        public_key.verify_asn1::<Sha256>(&[&test.msg], &test.sig)
                    }
                    ("EcdsaP1363Verify", "SHA-384") => {
                        public_key.verify::<Sha384>(&[&test.msg], &test.sig)
                    }
                    ("EcdsaVerify", "SHA-384") => {
                        public_key.verify_asn1::<Sha384>(&[&test.msg], &test.sig)
                    }
                    ("EcdsaP1363Verify", "SHA-512") => {
                        public_key.verify::<Sha512>(&[&test.msg], &test.sig)
                    }
                    ("EcdsaVerify", "SHA-512") => {
                        public_key.verify_asn1::<Sha512>(&[&test.msg], &test.sig)
                    }
                    _ => todo!("other ecdsa hashes"),
                };

                match (test.result, result) {
                    (ExpectedResult::Valid, Ok(())) => {}
                    (
                        ExpectedResult::Invalid,
                        Err(Error::BadSignature) | Err(Error::WrongLength),
                    ) => {}
                    _ => panic!("expected {:?} got {:?}", test.result, result),
                }
            }
        }
    }
}

#[test]
fn test_ecdh_p256() {
    let data_file =
        File::open("../thirdparty/wycheproof/testvectors_v1/ecdh_secp256r1_ecpoint_test.json")
            .expect("failed to open data file");

    let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

    for group in tests.groups {
        println!("group: {:?}", group.typ);

        for test in group.tests {
            println!("  test {:?}", test);

            let private = p256::PrivateKey::from_bytes(&test.private).unwrap();
            let result = p256::PublicKey::from_x962_uncompressed(&test.public)
                .and_then(|pubkey| private.diffie_hellman(&pubkey));

            // unsupported test cases
            if test.has_flag("CompressedPublic") || test.has_flag("CompressedPoint") {
                assert_eq!(result.err(), Some(Error::NotUncompressed));
                continue;
            }

            match (test.result, &result) {
                (ExpectedResult::Valid, Ok(shared)) => assert_eq!(&shared.0[..], &test.shared),
                (ExpectedResult::Invalid, Err(Error::NotOnCurve))
                    if test.has_flag("InvalidCurveAttack") => {}
                (ExpectedResult::Invalid, Err(Error::WrongLength))
                    if test.has_flag("InvalidEncoding") => {}
                _ => panic!("expected {:?} got {:?}", test.result, result.err()),
            }
        }
    }
}

#[test]
fn test_ecdh_p384() {
    let data_file =
        File::open("../thirdparty/wycheproof/testvectors_v1/ecdh_secp384r1_ecpoint_test.json")
            .expect("failed to open data file");

    let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

    for group in tests.groups {
        println!("group: {:?}", group.typ);

        for test in group.tests {
            println!("  test {:?}", test);

            let private = p384::PrivateKey::from_bytes(&test.private).unwrap();
            let result = p384::PublicKey::from_x962_uncompressed(&test.public)
                .and_then(|pubkey| private.diffie_hellman(&pubkey));

            // unsupported test cases
            if test.has_flag("CompressedPublic") || test.has_flag("CompressedPoint") {
                assert_eq!(result.err(), Some(Error::NotUncompressed));
                continue;
            }

            match (test.result, &result) {
                (ExpectedResult::Valid, Ok(shared)) => assert_eq!(&shared.0[..], &test.shared),
                (ExpectedResult::Invalid, Err(Error::NotOnCurve))
                    if test.has_flag("InvalidCurveAttack") => {}
                (ExpectedResult::Invalid, Err(Error::WrongLength))
                    if test.has_flag("InvalidEncoding") => {}
                _ => panic!("expected {:?} got {:?}", test.result, result.err()),
            }
        }
    }
}

#[test]
fn test_ecdh_x25519() {
    let data_file = File::open("../thirdparty/wycheproof/testvectors_v1/x25519_test.json")
        .expect("failed to open data file");

    let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

    for group in tests.groups {
        println!("group: {:?}", group.typ);

        for test in group.tests {
            println!("  test {:?}", test);

            let private = x25519::PrivateKey::try_from_slice(&test.private).unwrap();
            let result = x25519::PublicKey::try_from_slice(&test.public)
                .and_then(|pubkey| Ok(private.diffie_hellman(&pubkey)));
            match (test.result, &result) {
                (ExpectedResult::Valid | ExpectedResult::Acceptable, Ok(shared)) => {
                    assert_eq!(&shared.0[..], &test.shared)
                }
                _ => panic!("expected {:?} got {:?}", test.result, result.err()),
            }
        }
    }
}

#[test]
fn test_aesgcm() {
    let data_file = File::open("../thirdparty/wycheproof/testvectors_v1/aes_gcm_test.json")
        .expect("failed to open data file");

    let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

    for group in tests.groups {
        println!("group: {:?}", group.typ);

        for test in group.tests {
            println!("  test {:?}", test);

            if test.key.len() == 24 {
                println!("    skipped (unsupported key len)");
                continue;
            }

            let ctx = aes_gcm::AesGcm::new(&test.key);
            let nonce = match test.iv.len() {
                12 => test.iv.try_into().unwrap(),
                _ => {
                    println!("    skipped (unsupported nonce len)");
                    continue;
                }
            };

            // try decrypt
            let mut msg = test.ct.clone();
            let result = ctx.decrypt(&nonce, &test.aad, &mut msg, &test.tag);

            match (test.result, &result) {
                (ExpectedResult::Valid, Ok(())) => {
                    assert_eq!(msg, test.msg);
                }
                (ExpectedResult::Invalid, Err(Error::DecryptFailed)) => {}
                _ => panic!("expected {:?} got {:?}", test.result, result.err()),
            }

            // and encrypt
            let mut ct = test.msg.clone();
            let mut tag = [0u8; 16];

            ctx.encrypt(&nonce, &test.aad, &mut ct, &mut tag);

            if test.result == ExpectedResult::Valid {
                assert_eq!(ct, test.ct);
                assert_eq!(&tag, &test.tag[..]);
            }
        }
    }
}

#[test]
fn test_rsa_pkcs1_verify() {
    for file in &[
        "rsa_signature_2048_sha256_test.json",
        "rsa_signature_2048_sha384_test.json",
        "rsa_signature_2048_sha512_test.json",
        "rsa_signature_3072_sha256_test.json",
        "rsa_signature_3072_sha384_test.json",
        "rsa_signature_3072_sha512_test.json",
        "rsa_signature_4096_sha256_test.json",
        "rsa_signature_4096_sha384_test.json",
        "rsa_signature_4096_sha512_test.json",
        "rsa_signature_8192_sha256_test.json",
        "rsa_signature_8192_sha384_test.json",
        "rsa_signature_8192_sha512_test.json",
    ] {
        let data_file = File::open(&format!("../thirdparty/wycheproof/testvectors_v1/{file}"))
            .expect("failed to open data file");
        println!("file: {data_file:?}");

        let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

        for group in tests.groups {
            println!("group: {:?}", group.typ);

            let key = rsa::RsaPublicVerificationKey::from_pkcs1_der(&group.public_key_asn).unwrap();
            println!("key is {:?}", key);

            for test in group.tests {
                println!("  test {:?}", test);

                let result = match group.sha.as_ref() {
                    "SHA-256" => key.verify_pkcs1_sha256(&test.sig, &test.msg),
                    "SHA-384" => key.verify_pkcs1_sha384(&test.sig, &test.msg),
                    "SHA-512" => key.verify_pkcs1_sha512(&test.sig, &test.msg),
                    other => panic!("unhandled sha {other:?}"),
                };

                match (test.result, &result) {
                    (ExpectedResult::Valid, Ok(())) => {}
                    (
                        ExpectedResult::Invalid | ExpectedResult::Acceptable,
                        Err(Error::BadSignature),
                    ) => {}
                    _ => panic!("expected {:?} got {:?}", test.result, result.err()),
                }
            }
        }
    }
}

#[test]
fn test_rsa_pss_verify() {
    for file in &[
        "rsa_pss_2048_sha256_mgf1_32_test.json",
        "rsa_pss_2048_sha384_mgf1_48_test.json",
        "rsa_pss_3072_sha256_mgf1_32_test.json",
        "rsa_pss_4096_sha256_mgf1_32_test.json",
        "rsa_pss_4096_sha384_mgf1_48_test.json",
        "rsa_pss_4096_sha512_mgf1_64_test.json",
        "rsa_pss_misc_test.json",
    ] {
        let data_file = File::open(&format!("../thirdparty/wycheproof/testvectors_v1/{file}"))
            .expect("failed to open data file");
        println!("file: {data_file:?}");

        let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

        for group in tests.groups {
            println!("group: {:?}", group.typ);

            let key = rsa::RsaPublicVerificationKey::from_pkcs1_der(&group.public_key_asn).unwrap();
            println!("key is {:?}", key);

            match (group.sha.as_ref(), group.mgf_sha.as_ref(), group.salt_len) {
                ("SHA-256", "SHA-256", 32) => {}
                ("SHA-384", "SHA-384", 48) => {}
                ("SHA-512", "SHA-512", 64) => {}
                other => {
                    println!("not supported {other:?}");
                    continue;
                }
            }

            for test in group.tests {
                println!("  test {:?}", test);

                let result = match group.sha.as_ref() {
                    "SHA-256" => key.verify_pss_sha256(&test.sig, &test.msg),
                    "SHA-384" => key.verify_pss_sha384(&test.sig, &test.msg),
                    "SHA-512" => key.verify_pss_sha512(&test.sig, &test.msg),
                    other => panic!("unhandled sha {other:?}"),
                };

                match (test.result, &result) {
                    (ExpectedResult::Valid, Ok(())) => {}
                    (
                        ExpectedResult::Invalid | ExpectedResult::Acceptable,
                        Err(Error::BadSignature),
                    ) => {}
                    _ => panic!("expected {:?} got {:?}", test.result, result.err()),
                }
            }
        }
    }
}

#[test]
fn test_chacha20poly1305() {
    let data_file =
        File::open("../thirdparty/wycheproof/testvectors_v1/chacha20_poly1305_test.json")
            .expect("failed to open data file");

    let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

    for group in tests.groups {
        println!("group: {:?}", group.typ);

        for test in group.tests {
            println!("  test {:?}", test);

            if test.iv.len() != 12 {
                continue;
            }

            let ctx = chacha20poly1305::ChaCha20Poly1305::new(test.key.try_into().unwrap());
            let nonce = test.iv.try_into().unwrap();

            // try decrypt
            let mut msg = test.ct.clone();
            let result = ctx.decrypt(&nonce, &test.aad, &mut msg, &test.tag);

            match (test.result, &result) {
                (ExpectedResult::Valid, Ok(())) => {
                    assert_eq!(msg, test.msg);
                }
                (ExpectedResult::Invalid, Err(Error::DecryptFailed)) => {}
                _ => panic!("expected {:?} got {:?}", test.result, result.err()),
            }

            // and encrypt
            let mut ct = test.msg.clone();
            let mut tag = [0u8; 16];

            ctx.encrypt(&nonce, &test.aad, &mut ct, &mut tag);

            if test.result == ExpectedResult::Valid {
                assert_eq!(ct, test.ct);
                assert_eq!(&tag, &test.tag[..]);
            }
        }
    }
}
