mod criterion;
use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

const SALT: &[u8] = &[0x0b; 22];
const IKM: &[u8] = &[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
];
const INFO: &[u8] = &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

fn test_ring(algorithm: ring::hkdf::Algorithm, output: &mut [u8]) {
    struct Length(usize);
    impl ring::hkdf::KeyType for Length {
        fn len(&self) -> usize {
            self.0
        }
    }

    let salt = ring::hkdf::Salt::new(algorithm, SALT);
    let prk = salt.extract(IKM);
    let okm = prk.expand(&[INFO], Length(output.len())).unwrap();
    okm.fill(output).unwrap();
    black_box(output);
}

fn test_aws(algorithm: aws_lc_rs::hkdf::Algorithm, output: &mut [u8]) {
    struct Length(usize);
    impl aws_lc_rs::hkdf::KeyType for Length {
        fn len(&self) -> usize {
            self.0
        }
    }

    let salt = aws_lc_rs::hkdf::Salt::new(algorithm, SALT);
    let prk = salt.extract(IKM);
    let okm = prk.expand(&[INFO], Length(output.len())).unwrap();
    okm.fill(output).unwrap();
    black_box(output);
}

fn test_rc_sha256(okm: &mut [u8]) {
    let (_, hkdf) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(SALT), IKM);
    hkdf.expand(INFO, okm).unwrap();
    black_box(okm);
}

fn test_rc_sha384(okm: &mut [u8]) {
    let (_, hkdf) = hkdf::Hkdf::<sha2::Sha384>::extract(Some(SALT), IKM);
    hkdf.expand(INFO, okm).unwrap();
    black_box(okm);
}

fn test_graviola<H: graviola::hashing::Hash>(okm: &mut [u8]) {
    let prk = graviola::hashing::hkdf::extract::<H>(Some(SALT), IKM);
    graviola::hashing::hkdf::expand::<H>(&prk, INFO, okm);
    black_box(okm);
}

fn sha256(c: &mut Criterion) {
    const HASH_LEN: usize = 32;

    let mut group = c.benchmark_group("hkdf-sha256");

    for (mul, size_name) in [(1, "1 * HashLen"), (255, "255 * HashLen")] {
        group.throughput(Throughput::Elements(1));

        group.bench_function(BenchmarkId::new("ring", size_name), move |b| {
            b.iter_batched_ref(
                || vec![0u8; HASH_LEN * mul],
                |okm| test_ring(ring::hkdf::HKDF_SHA256, okm),
                BatchSize::SmallInput,
            );
        });
        group.bench_function(BenchmarkId::new("aws-lc-rs", size_name), move |b| {
            b.iter_batched_ref(
                || vec![0u8; HASH_LEN * mul],
                |okm| test_aws(aws_lc_rs::hkdf::HKDF_SHA256, okm),
                BatchSize::SmallInput,
            );
        });
        group.bench_function(BenchmarkId::new("rustcrypto", size_name), move |b| {
            b.iter_batched_ref(
                || vec![0u8; HASH_LEN * mul],
                |okm| test_rc_sha256(okm),
                BatchSize::SmallInput,
            );
        });

        group.bench_function(BenchmarkId::new("graviola", size_name), move |b| {
            b.iter_batched_ref(
                || vec![0u8; HASH_LEN * mul],
                |okm| test_graviola::<graviola::hashing::Sha256>(okm),
                BatchSize::SmallInput,
            );
        });
    }
}

fn sha384(c: &mut Criterion) {
    const HASH_LEN: usize = 48;

    let mut group = c.benchmark_group("hkdf-sha384");

    for (mul, size_name) in [(1, "1 * HashLen"), (255, "255 * HashLen")] {
        group.throughput(Throughput::Elements(1));

        group.bench_function(BenchmarkId::new("ring", size_name), move |b| {
            b.iter_batched_ref(
                || vec![0u8; HASH_LEN * mul],
                |okm| test_ring(ring::hkdf::HKDF_SHA384, okm),
                BatchSize::SmallInput,
            );
        });
        group.bench_function(BenchmarkId::new("aws-lc-rs", size_name), move |b| {
            b.iter_batched_ref(
                || vec![0u8; HASH_LEN * mul],
                |okm| test_aws(aws_lc_rs::hkdf::HKDF_SHA384, okm),
                BatchSize::SmallInput,
            );
        });
        group.bench_function(BenchmarkId::new("rustcrypto", size_name), move |b| {
            b.iter_batched_ref(
                || vec![0u8; HASH_LEN * mul],
                |okm| test_rc_sha384(okm),
                BatchSize::SmallInput,
            );
        });

        group.bench_function(BenchmarkId::new("graviola", size_name), move |b| {
            b.iter_batched_ref(
                || vec![0u8; HASH_LEN * mul],
                |okm| test_graviola::<graviola::hashing::Sha384>(okm),
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, sha256, sha384);
criterion_main!(benches);
