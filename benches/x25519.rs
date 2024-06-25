use criterion::{black_box, criterion_group, criterion_main, Criterion};

const PUBLIC_KEY: &[u8; 32] = b"\xe6\xdb\x68\x67\x58\x30\x30\xdb\x35\x94\xc1\xa4\x24\xb1\x5f\x7c\x72\x66\x24\xec\x26\xb3\x35\x3b\x10\xa9\x03\xa6\xd0\xab\x1c\x4c";

fn x25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("x25519-ecdh");

    group.bench_function("ring", |b| {
        use ring::{agreement, rand};
        let rng = rand::SystemRandom::new();

        b.iter(|| {
            let our_private_key =
                agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
            black_box(our_private_key.compute_public_key().unwrap());

            let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::X25519, PUBLIC_KEY);

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
                agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
            black_box(our_private_key.compute_public_key().unwrap());

            let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::X25519, PUBLIC_KEY);

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

    group.bench_function("dalek", |b| {
        b.iter(|| {
            let our_priv = x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);
            let our_pub: x25519_dalek::PublicKey = (&our_priv).into();
            black_box(our_pub);

            let their_pub = x25519_dalek::PublicKey::from(*PUBLIC_KEY);

            let shared_secret = our_priv.diffie_hellman(&their_pub);
            black_box(shared_secret.as_bytes());
        });
    });

    group.bench_function("this", |b| {
        use aws_lc_rs::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();

        b.iter(|| {
            let mut our_private_key = [0u8; 32];
            rng.fill(&mut our_private_key).unwrap();
            let mut our_public_key = [0u8; 32];
            curve25519::curve25519_x25519base(&mut our_public_key, &our_private_key);
            black_box(our_public_key);

            let mut res = [0u8; 32];
            curve25519::curve25519_x25519(&mut res, PUBLIC_KEY, &our_private_key);
            black_box(res);
        })
    });
}

criterion_group!(benches, x25519);
criterion_main!(benches);
