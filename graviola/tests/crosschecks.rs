use aws_lc_rs::rsa::KeyPair;
use graviola::signing::rsa::{KeySize, SigningKey};

#[test]
fn rsa_2048_key_generation() {
    check_key_generation(KeySize::Rsa2048);
}

#[test]
fn rsa_2048_key_generation_soak() {
    if option_env!("SLOW_TESTS").is_some() {
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
    if option_env!("SLOW_TESTS").is_some() {
        check_key_generation(KeySize::Rsa6144);
    }
}

#[test]
fn rsa_8192_key_generation() {
    if option_env!("SLOW_TESTS").is_some() {
        check_key_generation(KeySize::Rsa8192);
    }
}

fn check_key_generation(size: KeySize) {
    let key = SigningKey::generate(size).unwrap();
    let mut buf = [0u8; 8192];
    let key_enc = key.to_pkcs8_der(&mut buf).unwrap();

    KeyPair::from_pkcs8(key_enc).expect("aws-lc-rs rejected a key we generated");
}
