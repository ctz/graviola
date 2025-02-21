mod criterion;
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use sha2::Digest;

fn test_ring_sha256(data: &[u8]) {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(&data);
    black_box(ctx.finish());
}

fn test_ring_sha512(data: &[u8]) {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA512);
    ctx.update(&data);
    black_box(ctx.finish());
}

fn test_aws_sha256(data: &[u8]) {
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    ctx.update(data);
    black_box(ctx.finish());
}

fn test_aws_sha512(data: &[u8]) {
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA512);
    ctx.update(data);
    black_box(ctx.finish());
}

fn test_rc_sha256(data: &[u8]) {
    let mut ctx = sha2::Sha256::new();
    ctx.update(data);
    black_box(ctx.finalize());
}

fn test_rc_sha512(data: &[u8]) {
    let mut ctx = sha2::Sha512::new();
    ctx.update(data);
    black_box(ctx.finalize());
}

fn test_graviola_sha256(data: &[u8]) {
    let mut ctx = graviola::hashing::sha2::Sha256Context::new();
    ctx.update(data);
    black_box(ctx.finish());
}

fn test_graviola_sha512(data: &[u8]) {
    let mut ctx = graviola::hashing::sha2::Sha512Context::new();
    ctx.update(data);
    black_box(ctx.finish());
}

fn sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");
    for (size, size_name) in [(32, "32B"), (8192, "8KB"), (65536, "64KB")] {
        let input = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("ring", size_name), &input, |b, input| {
            b.iter(|| test_ring_sha256(input))
        });
        group.bench_with_input(
            BenchmarkId::new("aws-lc-rs", size_name),
            &input,
            |b, input| b.iter(|| test_aws_sha256(input)),
        );
        group.bench_with_input(
            BenchmarkId::new("rustcrypto", size_name),
            &input,
            |b, input| b.iter(|| test_rc_sha256(input)),
        );
        group.bench_with_input(
            BenchmarkId::new("graviola", size_name),
            &input,
            |b, input| b.iter(|| test_graviola_sha256(input)),
        );
    }
}

fn sha512(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha512");
    for (size, size_name) in [(32, "32B"), (8192, "8KB"), (65536, "64KB")] {
        let input = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("ring", size_name), &input, |b, input| {
            b.iter(|| test_ring_sha512(input))
        });
        group.bench_with_input(
            BenchmarkId::new("aws-lc-rs", size_name),
            &input,
            |b, input| b.iter(|| test_aws_sha512(input)),
        );
        group.bench_with_input(
            BenchmarkId::new("rustcrypto", size_name),
            &input,
            |b, input| b.iter(|| test_rc_sha512(input)),
        );
        group.bench_with_input(
            BenchmarkId::new("graviola", size_name),
            &input,
            |b, input| b.iter(|| test_graviola_sha512(input)),
        );
    }
}

criterion_group!(benches, sha256, sha512);
criterion_main!(benches);
