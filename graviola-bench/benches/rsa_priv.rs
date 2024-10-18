mod criterion;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

fn rsa2048_pkcs1_sha256_sign(c: &mut Criterion) {
    let private_key = include_bytes!("../../graviola/src/high/rsa/rsa2048.der");
    let message =
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    let mut group = c.benchmark_group("rsa2048-pkcs1-sha256-sign");
    group.throughput(Throughput::Elements(1));

    group.bench_function("ring", |b| {
        use ring::{rand, rsa, signature};

        let key = rsa::KeyPair::from_der(private_key).unwrap();
        let rng = rand::SystemRandom::new();

        b.iter(|| {
            let mut signature = [0u8; 256];
            black_box(
                key.sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut signature)
                    .unwrap(),
            );
        })
    });

    group.bench_function("aws-lc-rs", |b| {
        use aws_lc_rs::{rand, rsa, signature};

        let key = rsa::KeyPair::from_der(private_key).unwrap();
        let rng = rand::SystemRandom::new();

        b.iter(|| {
            let mut signature = [0u8; 256];
            black_box(
                key.sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut signature)
                    .unwrap(),
            );
        })
    });

    group.bench_function("rustcrypto", |b| {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::signature::Signer;
        let key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(
            rsa::RsaPrivateKey::from_pkcs1_der(private_key).unwrap(),
        );

        b.iter(|| {
            black_box(key.sign(message));
        });
    });

    group.bench_function("graviola", |b| {
        let key = graviola::signing::rsa::SigningKey::from_pkcs1_der(private_key).unwrap();

        b.iter(|| {
            black_box(key.sign_pkcs1_sha256(&mut [0u8; 256], message).unwrap());
        })
    });
}

criterion_group!(benches, rsa2048_pkcs1_sha256_sign);
criterion_main!(benches);
