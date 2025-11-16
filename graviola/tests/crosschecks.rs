use aws_lc_rs::{rsa::KeyPair, signature::Ed25519KeyPair};
use graviola::signing::{
    eddsa::Ed25519SigningKey,
    rsa::{KeySize, SigningKey},
};

#[test]
fn rsa_2048_key_generation() {
    check_key_generation(KeySize::Rsa2048);
}

#[test]
fn rsa_2048_key_generation_soak() {
    if std::env::var_os("SLOW_TESTS").is_some() {
        for _ in 0..512 {
            check_key_generation(KeySize::Rsa2048);
        }
    }
}

#[test]
fn rsa_3072_key_generation() {
    check_key_generation(KeySize::Rsa3072);
}

#[test]
fn rsa_4096_key_generation() {
    check_key_generation(KeySize::Rsa4096);
}

#[test]
fn rsa_6144_key_generation() {
    if std::env::var_os("SLOW_TESTS").is_some() {
        check_key_generation(KeySize::Rsa6144);
    }
}

#[test]
fn rsa_8192_key_generation() {
    if std::env::var_os("SLOW_TESTS").is_some() {
        check_key_generation(KeySize::Rsa8192);
    }
}

fn check_key_generation(size: KeySize) {
    let key = SigningKey::generate(size).unwrap();
    let mut buf = [0u8; 8192];
    let key_enc = key.to_pkcs8_der(&mut buf).unwrap();

    KeyPair::from_pkcs8(key_enc).expect("aws-lc-rs rejected a key we generated");
}

#[test]
fn ed25519_key_generation() {
    for _ in 0..100 {
        let key = Ed25519SigningKey::generate().unwrap();

        let mut buf = [0u8; 128];
        let key_enc = key.to_pkcs8_der(&mut buf).unwrap();

        let aws = Ed25519KeyPair::from_pkcs8(key_enc)
            .expect("aws-lc-rs rejected an ed25519 key we generated");
        assert_eq!(
            aws.to_pkcs8().unwrap().as_ref(),
            key_enc,
            "aws-lc-rs varied our ed25519 key encoding"
        );
    }
}
