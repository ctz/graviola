use criterion::{black_box, criterion_group, criterion_main, Criterion};

const PUBLIC_KEY: &[u8; 65] = b"\x04\
\x62\xd5\xbd\x33\x72\xaf\x75\xfe\x85\xa0\x40\x71\x5d\x0f\x50\x24\x28\xe0\x70\x46\x86\x8b\x0b\xfd\xfa\x61\xd7\x31\xaf\xe4\x4f\x26\
\xac\x33\x3a\x93\xa9\xe7\x0a\x81\xcd\x5a\x95\xb5\xbf\x8d\x13\x99\x0e\xb7\x41\xc8\xc3\x88\x72\xb4\xa0\x7d\x27\x5a\x01\x4e\x30\xcf";

fn ecdh(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256-ecdh");

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
        use p256::ecdh::EphemeralSecret;
        use p256::PublicKey;

        b.iter(|| {
            let our_private_key = EphemeralSecret::random(&mut rand_core::OsRng);
            black_box(our_private_key.public_key());

            let peer = PublicKey::from_sec1_bytes(PUBLIC_KEY).unwrap();
            let secret = our_private_key.diffie_hellman(&peer);
            black_box(secret);
        });
    });

    group.bench_function("this", |b| {
        b.iter(|| {
            let our_private_key =
                curve25519::p256::PrivateKey::generate(&mut rand_core::OsRng).unwrap();
            let our_public_key = our_private_key.public_key().unwrap();
            black_box(our_public_key);

            let peer = curve25519::p256::PublicKey::from_x962_uncompressed(PUBLIC_KEY).unwrap();
            let secret = our_private_key.diffie_hellman(&peer).unwrap();
            black_box(secret);
        })
    });
}

fn keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256-keygen");

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

    group.bench_function("this", |b| {
        b.iter(|| {
            let our_private_key =
                curve25519::p256::PrivateKey::generate(&mut rand_core::OsRng).unwrap();
            black_box(our_private_key.public_key().unwrap());
        })
    });
}

criterion_group!(benches, ecdh, keygen);
criterion_main!(benches);
