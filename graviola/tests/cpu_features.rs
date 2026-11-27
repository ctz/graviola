// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

#![cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]

use graviola::aead::AesGcm;
use graviola::key_agreement::x25519::StaticPrivateKey;
use graviola::util::{CpuFeature, is_cpu_feature_supported, is_cpu_supported};

#[test]
fn capability_queries_match_entry_guards() {
    let aes_gcm = is_cpu_feature_supported(CpuFeature::AesGcm);
    let x25519 = is_cpu_feature_supported(CpuFeature::X25519);
    assert_eq!(
        is_cpu_feature_supported(CpuFeature::AesGcm | CpuFeature::X25519),
        aes_gcm && x25519
    );

    // X25519 keeps its existing full-library entry guard.
    assert_eq!(x25519, is_cpu_supported());
    if !x25519 {
        assert!(std::panic::catch_unwind(|| StaticPrivateKey::from_array(&[0; 32])).is_err());
    }

    if !aes_gcm {
        // Missing an AES-GCM requirement must fail before executing intrinsics.
        assert!(std::panic::catch_unwind(|| AesGcm::new(&[0; 16])).is_err());
        assert!(std::panic::catch_unwind(|| AesGcm::new(&[0; 32])).is_err());
        return;
    }

    for key_len in [16, 32] {
        let cipher = AesGcm::new(&[0; 32][..key_len]);
        let mut tag = [0; 16];
        cipher.encrypt(&[0; 12], &[], &mut [], &mut tag);
        let expected = if key_len == 16 {
            "58e2fccefa7e3061367f1d57a4e7455a"
        } else {
            "530f8afbc74536b9a963b4f1c4cb738b"
        };
        assert_eq!(hex::encode(tag), expected);
        cipher.decrypt(&[0; 12], &[], &mut [], &tag).unwrap();

        for size in [1, 15, 16, 17, 127, 128, 129, 4096, 65536] {
            let plaintext = vec![0x42; size];
            let mut ciphertext = plaintext.clone();
            cipher.encrypt(&[1; 12], b"aad", &mut ciphertext, &mut tag);
            let mut decrypted = ciphertext.clone();
            cipher
                .decrypt(&[1; 12], b"aad", &mut decrypted, &tag)
                .unwrap();
            assert_eq!(decrypted, plaintext);

            tag[0] ^= 1;
            assert!(
                cipher
                    .decrypt(&[1; 12], b"aad", &mut ciphertext, &tag)
                    .is_err()
            );
            assert!(ciphertext.iter().all(|byte| *byte == 0));
        }
    }
}
