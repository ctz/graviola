mod criterion;
use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

// Generate a fresh key and make a PKCS8 document of it.
fn keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519-keygen");
    group.throughput(Throughput::Elements(1));

    group.bench_function("ring", |b| {
        use ring::{rand, signature};
        let rng = rand::SystemRandom::new();

        b.iter(|| {
            black_box(
                signature::Ed25519KeyPair::generate_pkcs8(&rng)
                    .unwrap()
                    .as_ref(),
            );
        })
    });

    group.bench_function("aws-lc-rs", |b| {
        use aws_lc_rs::{rand, signature};
        let rng = rand::SystemRandom::new();

        b.iter(|| {
            black_box(
                signature::Ed25519KeyPair::generate_pkcs8(&rng)
                    .unwrap()
                    .as_ref(),
            );
        })
    });

    group.bench_function("dalek", |b| {
        use ed25519_dalek::SigningKey;
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        b.iter(|| {
            let key = SigningKey::generate(&mut rand_core::OsRng);
            black_box(key.to_pkcs8_der().unwrap());
        });
    });

    group.bench_function("graviola", |b| {
        let mut buffer = [0; 128];
        b.iter(|| {
            let our_private_key = graviola::signing::eddsa::Ed25519SigningKey::generate().unwrap();
            black_box(our_private_key.to_pkcs8_der(&mut buffer).unwrap());
        })
    });
}

fn verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519-verify");
    group.throughput(Throughput::Elements(1));

    let public_key = b"\x7d\x4d\x0e\x7f\x61\x53\xa6\x9b\x62\x42\xb5\x22\xab\xbe\xe6\x85\xfd\xa4\x42\x0f\x88\x34\xb1\x08\xc3\xbd\xae\x36\x9e\xf5\x49\xfa";
    let message = b"\x54\x65\x73\x74";
    let signature = b"\x7c\x38\xe0\x26\xf2\x9e\x14\xaa\xbd\x05\x9a\x0f\x2d\xb8\xb0\xcd\x78\x30\x40\x60\x9a\x8b\xe6\x84\xdb\x12\xf8\x2a\x27\x77\x4a\xb0\x7a\x91\x55\x71\x1e\xcf\xaf\x7f\x99\xf2\x77\xba\xd0\xc6\xae\x7e\x39\xd4\xee\xf6\x76\x57\x33\x36\xa5\xc5\x1e\xb6\xf9\x46\xb3\x0d";

    group.bench_function("ring", |b| {
        let public_key =
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key);

        b.iter(|| {
            public_key.verify(message, signature).unwrap();
        })
    });

    group.bench_function("aws-lc-rs", |b| {
        let public_key =
            aws_lc_rs::signature::ParsedPublicKey::new(&aws_lc_rs::signature::ED25519, public_key)
                .unwrap();

        b.iter(|| {
            public_key.verify_sig(message, signature).unwrap();
        })
    });

    group.bench_function("dalek", |b| {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let verifying_key = VerifyingKey::from_bytes(public_key).unwrap();

        b.iter(|| {
            verifying_key
                .verify(message, &Signature::from_slice(signature).unwrap())
                .unwrap();
        });
    });

    group.bench_function("graviola", |b| {
        use graviola::signing::eddsa::Ed25519VerifyingKey;
        let public_key = Ed25519VerifyingKey::from_bytes(public_key).unwrap();

        b.iter(|| {
            public_key.verify(signature, message).unwrap();
        })
    });
}

fn sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519-sign");
    group.throughput(Throughput::Elements(1));
    let message = b"\x31\x32\x33\x34\x30\x30";

    group.bench_function("ring", |b| {
        use ring::{rand, signature};
        let rng = rand::SystemRandom::new();

        let private_key = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let private_key = signature::Ed25519KeyPair::from_pkcs8(private_key.as_ref()).unwrap();

        b.iter(|| {
            black_box(private_key.sign(message));
        })
    });

    group.bench_function("aws-lc-rs", |b| {
        use aws_lc_rs::{rand, signature};
        let rng = rand::SystemRandom::new();

        let private_key = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let private_key = signature::Ed25519KeyPair::from_pkcs8(private_key.as_ref()).unwrap();

        b.iter(|| {
            black_box(private_key.sign(message));
        })
    });

    group.bench_function("dalek", |b| {
        use ed25519_dalek::{Signature, Signer, SigningKey};
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);

        b.iter(|| {
            let _sig: Signature = signing_key.sign(message);
            black_box(_sig);
        });
    });

    group.bench_function("graviola", |b| {
        use graviola::signing::eddsa::Ed25519SigningKey;
        let signing_key = Ed25519SigningKey::generate().unwrap();

        b.iter(|| {
            black_box(signing_key.sign(message));
        });
    });
}

criterion_group!(benches, keygen, verify, sign);
criterion_main!(benches);
