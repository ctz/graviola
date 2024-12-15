mod criterion;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hmac::Mac;

fn test_ring_sha256(key: &[u8], data: &[u8]) {
    let mut ctx =
        ring::hmac::Context::with_key(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key));
    ctx.update(&data);
    black_box(ctx.sign());
}

fn test_ring_sha384(key: &[u8], data: &[u8]) {
    let mut ctx =
        ring::hmac::Context::with_key(&ring::hmac::Key::new(ring::hmac::HMAC_SHA384, key));
    ctx.update(&data);
    black_box(ctx.sign());
}

fn test_aws_sha256(key: &[u8], data: &[u8]) {
    let mut ctx = aws_lc_rs::hmac::Context::with_key(&aws_lc_rs::hmac::Key::new(
        aws_lc_rs::hmac::HMAC_SHA256,
        key,
    ));
    ctx.update(&data);
    black_box(ctx.sign());
}

fn test_aws_sha384(key: &[u8], data: &[u8]) {
    let mut ctx = aws_lc_rs::hmac::Context::with_key(&aws_lc_rs::hmac::Key::new(
        aws_lc_rs::hmac::HMAC_SHA384,
        key,
    ));
    ctx.update(&data);
    black_box(ctx.sign());
}

fn test_rc_sha256(key: &[u8], data: &[u8]) {
    let mut ctx = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    ctx.update(data);
    black_box(ctx.finalize());
}

fn test_rc_sha384(key: &[u8], data: &[u8]) {
    let mut ctx = hmac::Hmac::<sha2::Sha384>::new_from_slice(key).unwrap();
    ctx.update(data);
    black_box(ctx.finalize());
}

fn test_graviola_sha256(key: &[u8], data: &[u8]) {
    let mut ctx = graviola::hashing::hmac::Hmac::<graviola::hashing::Sha256>::new(key);
    ctx.update(data);
    black_box(ctx.finish());
}

fn test_graviola_sha384(key: &[u8], data: &[u8]) {
    let mut ctx = graviola::hashing::hmac::Hmac::<graviola::hashing::Sha384>::new(key);
    ctx.update(data);
    black_box(ctx.finish());
}

fn sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac-sha256");
    let key = [0xff; 48];

    for (size, size_name) in [(32, "32B"), (2048, "2KB")] {
        let input = vec![0u8; size];
        group.throughput(Throughput::Elements(1));

        group.bench_with_input(BenchmarkId::new("ring", size_name), &input, |b, input| {
            b.iter(|| test_ring_sha256(&key, input))
        });
        group.bench_with_input(
            BenchmarkId::new("aws-lc-rs", size_name),
            &input,
            |b, input| b.iter(|| test_aws_sha256(&key, input)),
        );
        group.bench_with_input(
            BenchmarkId::new("rustcrypto", size_name),
            &input,
            |b, input| b.iter(|| test_rc_sha256(&key, input)),
        );
        group.bench_with_input(
            BenchmarkId::new("graviola", size_name),
            &input,
            |b, input| b.iter(|| test_graviola_sha256(&key, input)),
        );
    }
}

fn sha384(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac-sha384");
    let key = [0xff; 48];

    for (size, size_name) in [(32, "32B"), (2048, "2KB")] {
        let input = vec![0u8; size];
        group.throughput(Throughput::Elements(1));

        group.bench_with_input(BenchmarkId::new("ring", size_name), &input, |b, input| {
            b.iter(|| test_ring_sha384(&key, input))
        });
        group.bench_with_input(
            BenchmarkId::new("aws-lc-rs", size_name),
            &input,
            |b, input| b.iter(|| test_aws_sha384(&key, input)),
        );
        group.bench_with_input(
            BenchmarkId::new("rustcrypto", size_name),
            &input,
            |b, input| b.iter(|| test_rc_sha384(&key, input)),
        );
        group.bench_with_input(
            BenchmarkId::new("graviola", size_name),
            &input,
            |b, input| b.iter(|| test_graviola_sha384(&key, input)),
        );
    }
}

criterion_group!(benches, sha256, sha384);
criterion_main!(benches);
