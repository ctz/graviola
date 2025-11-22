#![no_main]

use libfuzzer_sys::{arbitrary, arbitrary::Arbitrary, fuzz_target};

fuzz_target!(|op: Operation| {
    match op {
        Operation::X25519BaseMul(scalar) => {
            let left = aws_lc_rs::agreement::PrivateKey::from_private_key(
                &aws_lc_rs::agreement::X25519,
                &scalar,
            )
            .unwrap()
            .compute_public_key()
            .unwrap();

            let right =
                graviola::key_agreement::x25519::StaticPrivateKey::from_array(&scalar).public_key();

            assert_eq!(left.as_ref(), right.as_bytes());
        }

        Operation::X25519Agree { scalar, peer } => {
            let left = aws_lc_rs::agreement::agree(
                &aws_lc_rs::agreement::PrivateKey::from_private_key(
                    &aws_lc_rs::agreement::X25519,
                    &scalar,
                )
                .unwrap(),
                aws_lc_rs::agreement::UnparsedPublicKey::new(&aws_lc_rs::agreement::X25519, &peer),
                aws_lc_rs::error::Unspecified,
                |key| Ok(key.to_vec()),
            )
            .map_err(|_| ());

            let right = graviola::key_agreement::x25519::StaticPrivateKey::from_array(&scalar)
                .diffie_hellman(&graviola::key_agreement::x25519::PublicKey::from_array(
                    &peer,
                ))
                .map(|ss| ss.0.to_vec())
                .map_err(|_| ());

            assert_eq!(&left, &right);
        }

        Operation::P256BaseMul(scalar) => {
            let left = aws_lc_rs::agreement::PrivateKey::from_private_key(
                &aws_lc_rs::agreement::ECDH_P256,
                &scalar,
            )
            .map(|private| private.compute_public_key().unwrap().as_ref().to_vec())
            .map_err(|_| ());

            let right = graviola::key_agreement::p256::StaticPrivateKey::from_bytes(&scalar)
                .map(|private| private.public_key_uncompressed().to_vec())
                .map_err(|_| ());

            assert_eq!(left, right);
        }

        Operation::P256Agree { scalar, peer } => {
            let left = aws_lc_rs::agreement::PrivateKey::from_private_key(
                &aws_lc_rs::agreement::ECDH_P256,
                &scalar,
            )
            .map_err(|_| ())
            .and_then(|private| {
                aws_lc_rs::agreement::agree(
                    &private,
                    aws_lc_rs::agreement::UnparsedPublicKey::new(
                        &aws_lc_rs::agreement::ECDH_P256,
                        &peer,
                    ),
                    (),
                    |key| Ok(key.to_vec()),
                )
            })
            .map_err(|_| ());

            let right = graviola::key_agreement::p256::StaticPrivateKey::from_bytes(&scalar)
                .and_then(|private| {
                    graviola::key_agreement::p256::PublicKey::from_x962_uncompressed(&peer)
                        .map(|public| (private, public))
                })
                .and_then(|(private, public)| private.diffie_hellman(&public))
                .map(|ss| ss.0.to_vec())
                .map_err(|_| ());

            assert_eq!(&left, &right);
        }

        Operation::P384BaseMul(scalar) => {
            let left = aws_lc_rs::agreement::PrivateKey::from_private_key(
                &aws_lc_rs::agreement::ECDH_P384,
                &scalar,
            )
            .map(|private| private.compute_public_key().unwrap().as_ref().to_vec())
            .map_err(|_| ());

            let right = graviola::key_agreement::p384::StaticPrivateKey::from_bytes(&scalar)
                .map(|private| private.public_key_uncompressed().to_vec())
                .map_err(|_| ());

            assert_eq!(left, right);
        }

        Operation::P384Agree { scalar, peer } => {
            let left = aws_lc_rs::agreement::PrivateKey::from_private_key(
                &aws_lc_rs::agreement::ECDH_P384,
                &scalar,
            )
            .map_err(|_| ())
            .and_then(|private| {
                aws_lc_rs::agreement::agree(
                    &private,
                    aws_lc_rs::agreement::UnparsedPublicKey::new(
                        &aws_lc_rs::agreement::ECDH_P384,
                        &peer,
                    ),
                    (),
                    |key| Ok(key.to_vec()),
                )
            })
            .map_err(|_| ());

            let right = graviola::key_agreement::p384::StaticPrivateKey::from_bytes(&scalar)
                .and_then(|private| {
                    graviola::key_agreement::p384::PublicKey::from_x962_uncompressed(&peer)
                        .map(|public| (private, public))
                })
                .and_then(|(private, public)| private.diffie_hellman(&public))
                .map(|ss| ss.0.to_vec())
                .map_err(|_| ());

            assert_eq!(&left, &right);
        }
    }
});

#[derive(Arbitrary, Debug)]
enum Operation {
    X25519BaseMul([u8; 32]),
    X25519Agree { scalar: [u8; 32], peer: [u8; 32] },
    P256BaseMul([u8; 32]),
    P256Agree { scalar: [u8; 32], peer: [u8; 65] },
    P384BaseMul([u8; 48]),
    P384Agree { scalar: [u8; 48], peer: [u8; 97] },
}
