#![no_main]

use libfuzzer_sys::{arbitrary, arbitrary::Arbitrary, fuzz_target};

fuzz_target!(|op: Operation| {
    match op {
        Operation::ChaCha20Poly1305 {
            key,
            nonce,
            aad,
            plain,
        } => {
            let right = baseline_encrypt(
                &aws_lc_rs::aead::CHACHA20_POLY1305,
                &key,
                &nonce,
                &aad,
                &plain,
            );
            let left = {
                let k = graviola::aead::ChaCha20Poly1305::new(key);
                let mut cipher = plain.clone();
                let mut tag = [0u8; 16];
                k.encrypt(&nonce, &aad, &mut cipher, &mut tag);

                let mut roundtrip = cipher.clone();
                k.decrypt(&nonce, &aad, &mut roundtrip, &tag).unwrap();
                assert_eq!(roundtrip, plain);
                (cipher, tag)
            };

            assert_eq!(left, right);
        }
        Operation::Aes128Gcm {
            key,
            nonce,
            aad,
            plain,
        } => {
            let right = baseline_encrypt(&aws_lc_rs::aead::AES_128_GCM, &key, &nonce, &aad, &plain);
            let left = {
                let k = graviola::aead::AesGcm::new(&key);
                let mut cipher = plain.clone();
                let mut tag = [0u8; 16];
                k.encrypt(&nonce, &aad, &mut cipher, &mut tag);

                let mut roundtrip = cipher.clone();
                k.decrypt(&nonce, &aad, &mut roundtrip, &tag).unwrap();
                assert_eq!(roundtrip, plain);
                (cipher, tag)
            };

            assert_eq!(left, right);
        }
        Operation::Aes256Gcm {
            key,
            nonce,
            aad,
            plain,
        } => {
            let right = baseline_encrypt(&aws_lc_rs::aead::AES_256_GCM, &key, &nonce, &aad, &plain);
            let left = {
                let k = graviola::aead::AesGcm::new(&key);
                let mut cipher = plain.clone();
                let mut tag = [0u8; 16];
                k.encrypt(&nonce, &aad, &mut cipher, &mut tag);

                let mut roundtrip = cipher.clone();
                k.decrypt(&nonce, &aad, &mut roundtrip, &tag).unwrap();
                assert_eq!(roundtrip, plain);
                (cipher, tag)
            };

            assert_eq!(left, right);
        }
    }
});

fn baseline_encrypt(
    alg: &'static aws_lc_rs::aead::Algorithm,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plain: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let k = aws_lc_rs::aead::LessSafeKey::new(aws_lc_rs::aead::UnboundKey::new(alg, key).unwrap());
    let mut cipher = plain.to_vec();
    let tag = k
        .seal_in_place_separate_tag(
            aws_lc_rs::aead::Nonce::assume_unique_for_key(*nonce),
            aws_lc_rs::aead::Aad::from(aad),
            &mut cipher,
        )
        .unwrap();

    let mut tag_array = [0u8; 16];
    tag_array.copy_from_slice(tag.as_ref());
    (cipher, tag_array)
}

#[derive(Arbitrary, Debug)]
enum Operation {
    ChaCha20Poly1305 {
        key: [u8; 32],
        nonce: [u8; 12],
        aad: Vec<u8>,
        plain: Vec<u8>,
    },
    Aes128Gcm {
        key: [u8; 16],
        nonce: [u8; 12],
        aad: Vec<u8>,
        plain: Vec<u8>,
    },
    Aes256Gcm {
        key: [u8; 32],
        nonce: [u8; 12],
        aad: Vec<u8>,
        plain: Vec<u8>,
    },
}
