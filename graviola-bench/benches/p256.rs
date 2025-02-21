mod criterion;
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

const PUBLIC_KEY: &[u8; 65] = b"\x04\
\x62\xd5\xbd\x33\x72\xaf\x75\xfe\x85\xa0\x40\x71\x5d\x0f\x50\x24\x28\xe0\x70\x46\x86\x8b\x0b\xfd\xfa\x61\xd7\x31\xaf\xe4\x4f\x26\
\xac\x33\x3a\x93\xa9\xe7\x0a\x81\xcd\x5a\x95\xb5\xbf\x8d\x13\x99\x0e\xb7\x41\xc8\xc3\x88\x72\xb4\xa0\x7d\x27\x5a\x01\x4e\x30\xcf";

fn ecdh(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256-ecdh");
    group.throughput(Throughput::Elements(1));

    #[cfg(feature = "__bench_openssl")]
    group.bench_function("openssl", |b| {
        use openssl::bn::BigNumContext;
        use openssl::derive::Deriver;
        use openssl::ec::{EcGroup, EcKey, EcPoint};
        use openssl::nid::Nid;
        use openssl::pkey::PKey;

        let curve = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let mut bn_ctx = BigNumContext::new().unwrap();

        b.iter(|| {
            let priv_key = PKey::ec_gen("prime256v1").unwrap();
            black_box(priv_key.public_key_to_der().unwrap());

            let point = EcPoint::from_bytes(&curve, PUBLIC_KEY, &mut bn_ctx).unwrap();
            let ec_key = EcKey::from_public_key(&curve, &point).unwrap();
            let peer = PKey::from_ec_key(ec_key).unwrap();
            let mut deriver = Deriver::new(&priv_key).unwrap();
            deriver.set_peer(&peer).unwrap();
            let mut secret = [0u8; 32];
            deriver.derive(&mut secret).unwrap();
            black_box(secret);
        });
    });

    group.bench_function("ring", |b| {
        use ring::{agreement, rand};
        let rng = rand::SystemRandom::new();

        b.iter(|| {
            let our_private_key =
                agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
            black_box(our_private_key.compute_public_key().unwrap());

            let peer_public_key =
                agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, PUBLIC_KEY);

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
                agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
            black_box(our_private_key.compute_public_key().unwrap());

            let peer_public_key =
                agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, PUBLIC_KEY);

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

    group.bench_function("p256-rustcrypto", |b| {
        use p256::PublicKey;
        use p256::ecdh::EphemeralSecret;

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
            let our_private_key = graviola::key_agreement::p256::PrivateKey::new_random().unwrap();
            let our_public_key = our_private_key.public_key_uncompressed();
            black_box(our_public_key);

            let peer = graviola::key_agreement::p256::PublicKey::from_x962_uncompressed(PUBLIC_KEY)
                .unwrap();
            let secret = our_private_key.diffie_hellman(&peer).unwrap();
            black_box(secret);
        })
    });
}

fn keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256-keygen");
    group.throughput(Throughput::Elements(1));

    #[cfg(feature = "__bench_openssl")]
    group.bench_function("openssl", |b| {
        use openssl::pkey::PKey;

        b.iter(|| {
            let priv_key = PKey::ec_gen("prime256v1").unwrap();
            black_box(priv_key.public_key_to_der().unwrap());
        });
    });

    group.bench_function("ring", |b| {
        use ring::{agreement, rand};
        let rng = rand::SystemRandom::new();

        b.iter(|| {
            let our_private_key =
                agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
            black_box(our_private_key.compute_public_key().unwrap());
        })
    });

    group.bench_function("aws-lc-rs", |b| {
        use aws_lc_rs::{agreement, rand};
        let rng = rand::SystemRandom::new();

        b.iter(|| {
            let our_private_key =
                agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
            black_box(our_private_key.compute_public_key().unwrap());
        })
    });

    group.bench_function("p256-rustcrypto", |b| {
        use p256::ecdh::EphemeralSecret;

        b.iter(|| {
            let our_private_key = EphemeralSecret::random(&mut rand_core::OsRng);
            black_box(our_private_key.public_key());
        });
    });

    group.bench_function("graviola", |b| {
        b.iter(|| {
            let our_private_key = graviola::key_agreement::p256::PrivateKey::new_random().unwrap();
            black_box(our_private_key.public_key_uncompressed());
        })
    });
}

fn ecdsa_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256-ecdsa-verify");
    group.throughput(Throughput::Elements(1));

    let public_key = b"\x04\
\x29\x27\xb1\x05\x12\xba\xe3\xed\xdc\xfe\x46\x78\x28\x12\x8b\xad\x29\x03\x26\x99\x19\xf7\x08\x60\x69\xc8\xc4\xdf\x6c\x73\x28\x38\
\xc7\x78\x79\x64\xea\xac\x00\xe5\x92\x1f\xb1\x49\x8a\x60\xf4\x60\x67\x66\xb3\xd9\x68\x50\x01\x55\x8d\x1a\x97\x4e\x73\x41\x51\x3e";
    let message = b"\x31\x32\x33\x34\x30\x30";
    let signature = b"\x2b\xa3\xa8\xbe\x6b\x94\xd5\xec\x80\xa6\xd9\xd1\x19\x0a\x43\x6e\xff\xe5\x0d\x85\xa1\xee\xe8\x59\xb8\xcc\x6a\xf9\xbd\x5c\x2e\x18\x4c\xd6\x0b\x85\x5d\x44\x2f\x5b\x3c\x7b\x11\xeb\x6c\x4e\x0a\xe7\x52\x5f\xe7\x10\xfa\xb9\xaa\x7c\x77\xa6\x7f\x79\xe6\xfa\xdd\x76";

    group.bench_function("ring", |b| {
        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            public_key,
        );

        b.iter(|| {
            public_key.verify(message, signature).unwrap();
        })
    });

    group.bench_function("aws-lc-rs", |b| {
        let public_key = aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED,
            public_key,
        );

        b.iter(|| {
            public_key.verify(message, signature).unwrap();
        })
    });

    group.bench_function("rustcrypto", |b| {
        use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key).unwrap();

        b.iter(|| {
            verifying_key
                .verify(message, &Signature::from_slice(signature).unwrap())
                .unwrap();
        });
    });

    group.bench_function("graviola", |b| {
        use graviola::hashing::Sha256;
        use graviola::signing::ecdsa;
        let public_key =
            ecdsa::VerifyingKey::<ecdsa::P256>::from_x962_uncompressed(public_key).unwrap();

        b.iter(|| {
            public_key.verify::<Sha256>(&[message], signature).unwrap();
        })
    });
}

fn ecdsa_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256-ecdsa-sign");
    group.throughput(Throughput::Elements(1));
    let message = b"\x31\x32\x33\x34\x30\x30";

    group.bench_function("ring", |b| {
        use ring::{rand, signature};
        let rng = rand::SystemRandom::new();

        let private_key = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let private_key = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
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
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let private_key = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            private_key.as_ref(),
        )
        .unwrap();

        b.iter(|| {
            black_box(private_key.sign(&rng, message).unwrap());
        })
    });

    group.bench_function("rustcrypto", |b| {
        use p256::ecdsa::{Signature, SigningKey, signature::Signer};
        let signing_key = SigningKey::random(&mut rand_core::OsRng);

        b.iter(|| {
            let _sig: Signature = signing_key.sign(message);
            black_box(_sig);
        });
    });

    group.bench_function("graviola", |b| {
        use graviola::hashing::Sha256;
        use graviola::signing::ecdsa::{Curve, P256, SigningKey};
        let private_key = <P256 as Curve>::PrivateKey::new_random().unwrap();
        let signing_key = SigningKey::<P256> { private_key };

        b.iter(|| {
            let mut signature = [0u8; 64];
            black_box(
                signing_key
                    .sign::<Sha256>(&[message], &mut signature)
                    .unwrap(),
            );
        });
    });
}

criterion_group!(benches, ecdh, keygen, ecdsa_verify, ecdsa_sign);
criterion_main!(benches);
