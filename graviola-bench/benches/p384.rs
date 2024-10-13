mod criterion;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

const PUBLIC_KEY: &[u8; 97] = &[
    0x04, 0x7a, 0x6e, 0xc8, 0xd3, 0x11, 0xd5, 0xca, 0x58, 0x8b, 0xae, 0xd4, 0x1b, 0xe3, 0xe9, 0x8f,
    0x30, 0xc9, 0x29, 0x48, 0x44, 0xec, 0xbb, 0x62, 0x99, 0x95, 0x65, 0x36, 0x35, 0xdb, 0xc2, 0x2d,
    0xa2, 0xf0, 0x83, 0xf2, 0x97, 0x11, 0xe0, 0xf9, 0xc5, 0x96, 0x3b, 0xc0, 0x21, 0xbd, 0x8c, 0xb2,
    0x10, 0x9d, 0xaf, 0x56, 0xa5, 0x5f, 0x88, 0x3a, 0x72, 0x00, 0xce, 0xa9, 0xc4, 0xde, 0x44, 0x48,
    0x8e, 0x6d, 0xc4, 0x9f, 0xb9, 0xc3, 0x94, 0xf5, 0x1c, 0xb5, 0xa4, 0x9f, 0xc6, 0x9d, 0x7e, 0x8a,
    0x03, 0x47, 0x92, 0x96, 0x3a, 0xe4, 0xea, 0xbc, 0x63, 0x48, 0x3a, 0x2c, 0xf1, 0xa8, 0x99, 0xe8,
    0xc8,
];

fn ecdh(c: &mut Criterion) {
    let mut group = c.benchmark_group("p384-ecdh");
    group.throughput(Throughput::Elements(1));

    group.bench_function("ring", |b| {
        use ring::{agreement, rand};
        let rng = rand::SystemRandom::new();

        b.iter(|| {
            let our_private_key =
                agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P384, &rng).unwrap();
            black_box(our_private_key.compute_public_key().unwrap());

            let peer_public_key =
                agreement::UnparsedPublicKey::new(&agreement::ECDH_P384, PUBLIC_KEY);

            agreement::agree_ephemeral(our_private_key, &peer_public_key, |key_material| {
                black_box(key_material);
            })
            .unwrap();
        })
    });

    group.bench_function("aws-lc-rs", |b| {
        use aws_lc_rs::{agreement, error, rand};
        let rng = rand::SystemRandom::new();

        b.iter(|| {
            let our_private_key =
                agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P384, &rng).unwrap();
            black_box(our_private_key.compute_public_key().unwrap());

            let peer_public_key =
                agreement::UnparsedPublicKey::new(&agreement::ECDH_P384, PUBLIC_KEY);

            agreement::agree_ephemeral(
                our_private_key,
                &peer_public_key,
                error::Unspecified,
                |key_material| {
                    black_box(key_material);
                    Ok(())
                },
            )
            .unwrap();
        })
    });

    group.bench_function("p384-rustcrypto", |b| {
        use p384::ecdh::EphemeralSecret;
        use p384::PublicKey;

        b.iter(|| {
            let our_private_key = EphemeralSecret::random(&mut rand_core::OsRng);
            black_box(our_private_key.public_key());

            let peer = PublicKey::from_sec1_bytes(PUBLIC_KEY).unwrap();
            let secret = our_private_key.diffie_hellman(&peer);
            black_box(secret);
        });
    });

    group.bench_function("graviola", |b| {
        b.iter(|| {
            let our_private_key = graviola::key_agreement::p384::PrivateKey::generate(
                &mut graviola::rng::SystemRandom,
            )
            .unwrap();
            let our_public_key = our_private_key.public_key_uncompressed();
            black_box(our_public_key);

            let peer = graviola::key_agreement::p384::PublicKey::from_x962_uncompressed(PUBLIC_KEY)
                .unwrap();
            let secret = our_private_key.diffie_hellman(&peer).unwrap();
            black_box(secret);
        })
    });
}

fn keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("p384-keygen");
    group.throughput(Throughput::Elements(1));

    group.bench_function("ring", |b| {
        use ring::{agreement, rand};
        let rng = rand::SystemRandom::new();

        b.iter(|| {
            let our_private_key =
                agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P384, &rng).unwrap();
            black_box(our_private_key.compute_public_key().unwrap());
        })
    });

    group.bench_function("aws-lc-rs", |b| {
        use aws_lc_rs::{agreement, rand};
        let rng = rand::SystemRandom::new();

        b.iter(|| {
            let our_private_key =
                agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P384, &rng).unwrap();
            black_box(our_private_key.compute_public_key().unwrap());
        })
    });

    group.bench_function("p384-rustcrypto", |b| {
        use p384::ecdh::EphemeralSecret;

        b.iter(|| {
            let our_private_key = EphemeralSecret::random(&mut rand_core::OsRng);
            black_box(our_private_key.public_key());
        });
    });

    group.bench_function("graviola", |b| {
        b.iter(|| {
            let our_private_key = graviola::key_agreement::p384::PrivateKey::generate(
                &mut graviola::rng::SystemRandom,
            )
            .unwrap();
            black_box(our_private_key.public_key_uncompressed());
        })
    });
}

fn ecdsa_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("p384-ecdsa-verify");
    group.throughput(Throughput::Elements(1));

    let public_key = &[
        0x04, 0x2d, 0xa5, 0x7d, 0xda, 0x10, 0x89, 0x27, 0x6a, 0x54, 0x3f, 0x9f, 0xfd, 0xac, 0x0b,
        0xff, 0x0d, 0x97, 0x6c, 0xad, 0x71, 0xeb, 0x72, 0x80, 0xe7, 0xd9, 0xbf, 0xd9, 0xfe, 0xe4,
        0xbd, 0xb2, 0xf2, 0x0f, 0x47, 0xff, 0x88, 0x82, 0x74, 0x38, 0x97, 0x72, 0xd9, 0x8c, 0xc5,
        0x75, 0x21, 0x38, 0xaa, 0x4b, 0x6d, 0x05, 0x4d, 0x69, 0xdc, 0xf3, 0xe2, 0x5e, 0xc4, 0x9d,
        0xf8, 0x70, 0x71, 0x5e, 0x34, 0x88, 0x3b, 0x18, 0x36, 0x19, 0x7d, 0x76, 0xf8, 0xad, 0x96,
        0x2e, 0x78, 0xf6, 0x57, 0x1b, 0xbc, 0x74, 0x07, 0xb0, 0xd6, 0x09, 0x1f, 0x9e, 0x4d, 0x88,
        0xf0, 0x14, 0x27, 0x44, 0x06, 0x17, 0x4f,
    ];
    let message = b"\x31\x32\x33\x34\x30\x30";
    let signature = &[
        0x12, 0xb3, 0x0a, 0xbe, 0xf6, 0xb5, 0x47, 0x6f, 0xe6, 0xb6, 0x12, 0xae, 0x55, 0x7c, 0x04,
        0x25, 0x66, 0x1e, 0x26, 0xb4, 0x4b, 0x1b, 0xfe, 0x19, 0xda, 0xf2, 0xca, 0x28, 0xe3, 0x11,
        0x30, 0x83, 0xba, 0x8e, 0x4a, 0xe4, 0xcc, 0x45, 0xa0, 0x32, 0x0a, 0xbd, 0x33, 0x94, 0xf1,
        0xc5, 0x48, 0xd7, 0x18, 0x40, 0xda, 0x9f, 0xc1, 0xd2, 0xf8, 0xf8, 0x90, 0x0c, 0xf4, 0x85,
        0xd5, 0x41, 0x3b, 0x8c, 0x25, 0x74, 0xee, 0x3a, 0x8d, 0x4c, 0xa0, 0x39, 0x95, 0xca, 0x30,
        0x24, 0x0e, 0x09, 0x51, 0x38, 0x05, 0xbf, 0x62, 0x09, 0xb5, 0x8a, 0xc7, 0xaa, 0x9c, 0xff,
        0x54, 0xee, 0xcd, 0x82, 0xb9, 0xf1,
    ];

    group.bench_function("ring", |b| {
        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P384_SHA384_FIXED,
            public_key,
        );

        b.iter(|| {
            public_key.verify(message, signature).unwrap();
        })
    });

    group.bench_function("aws-lc-rs", |b| {
        let public_key = aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::ECDSA_P384_SHA384_FIXED,
            public_key,
        );

        b.iter(|| {
            public_key.verify(message, signature).unwrap();
        })
    });

    group.bench_function("rustcrypto", |b| {
        use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key).unwrap();

        b.iter(|| {
            verifying_key
                .verify(message, &Signature::from_slice(signature).unwrap())
                .unwrap();
        });
    });

    group.bench_function("graviola", |b| {
        use graviola::hashing::Sha384;
        use graviola::signing::ecdsa;
        let public_key =
            ecdsa::VerifyingKey::<ecdsa::P384>::from_x962_uncompressed(public_key).unwrap();

        b.iter(|| {
            public_key.verify::<Sha384>(&[message], signature).unwrap();
        })
    });
}

fn ecdsa_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("p384-ecdsa-sign");
    group.throughput(Throughput::Elements(1));
    let message = b"\x31\x32\x33\x34\x30\x30";

    group.bench_function("ring", |b| {
        use ring::{rand, signature};
        let rng = rand::SystemRandom::new();

        let private_key = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let private_key = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            private_key.as_ref(),
            &rng,
        )
        .unwrap();

        b.iter(|| {
            black_box(private_key.sign(&rng, message).unwrap());
        })
    });

    group.bench_function("aws-lc-rs", |b| {
        use aws_lc_rs::{rand, signature};
        let rng = rand::SystemRandom::new();

        let private_key = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let private_key = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            private_key.as_ref(),
        )
        .unwrap();

        b.iter(|| {
            black_box(private_key.sign(&rng, message).unwrap());
        })
    });

    group.bench_function("rustcrypto", |b| {
        use p384::ecdsa::{signature::Signer, Signature, SigningKey};
        let signing_key = SigningKey::random(&mut rand_core::OsRng);

        b.iter(|| {
            let _sig: Signature = signing_key.sign(message);
            black_box(_sig);
        });
    });

    group.bench_function("graviola", |b| {
        use graviola::hashing::Sha384;
        use graviola::signing::ecdsa::{Curve, SigningKey, P384};
        let private_key = P384::generate_random_key(&mut graviola::rng::SystemRandom).unwrap();
        let signing_key = SigningKey::<P384> { private_key };

        b.iter(|| {
            let mut signature = [0u8; 96];
            black_box(
                signing_key
                    .sign::<Sha384>(&[message], &mut signature)
                    .unwrap(),
            );
        });
    });
}

criterion_group!(benches, ecdh, keygen, ecdsa_verify, ecdsa_sign);
criterion_main!(benches);
