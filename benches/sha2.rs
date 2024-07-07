use criterion::{black_box, criterion_group, criterion_main, Criterion};
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

fn test_this_sha256(data: &[u8]) {
    let mut ctx = curve25519::sha2::Sha256Context::new();
    ctx.update(data);
    black_box(ctx.finish());
}

fn block_32(c: &mut Criterion) {
    let data = [0u8; 32];

    let mut group = c.benchmark_group("sha256-32");
    group.bench_function("ring", |b| b.iter(|| test_ring_sha256(&data)));
    group.bench_function("aws-lc-rs", |b| b.iter(|| test_aws_sha256(&data)));
    group.bench_function("rustcrypto", |b| b.iter(|| test_rc_sha256(&data)));
    group.bench_function("this", |b| b.iter(|| test_this_sha256(&data)));
    drop(group);

    let mut group = c.benchmark_group("sha512-32");
    group.bench_function("ring", |b| b.iter(|| test_ring_sha512(&data)));
    group.bench_function("aws-lc-rs", |b| b.iter(|| test_aws_sha512(&data)));
    group.bench_function("rustcrypto", |b| b.iter(|| test_rc_sha512(&data)));
}

fn block_8k(c: &mut Criterion) {
    let data = vec![0u8; 8192];

    let mut group = c.benchmark_group("sha256-8k");
    group.bench_function("ring", |b| b.iter(|| test_ring_sha256(&data)));
    group.bench_function("aws-lc-rs", |b| b.iter(|| test_aws_sha256(&data)));
    group.bench_function("rustcrypto", |b| b.iter(|| test_rc_sha256(&data)));
    group.bench_function("this", |b| b.iter(|| test_this_sha256(&data)));
    drop(group);

    let mut group = c.benchmark_group("sha512-8k");
    group.bench_function("ring", |b| b.iter(|| test_ring_sha512(&data)));
    group.bench_function("aws-lc-rs", |b| b.iter(|| test_aws_sha512(&data)));
    group.bench_function("rustcrypto", |b| b.iter(|| test_rc_sha512(&data)));
}

fn block_1m(c: &mut Criterion) {
    let data = vec![0u8; 1024 * 1024];

    let mut group = c.benchmark_group("sha256-1m");
    group.bench_function("ring", |b| b.iter(|| test_ring_sha256(&data)));
    group.bench_function("aws-lc-rs", |b| b.iter(|| test_aws_sha256(&data)));
    group.bench_function("rustcrypto", |b| b.iter(|| test_rc_sha256(&data)));
    group.bench_function("this", |b| b.iter(|| test_this_sha256(&data)));
    drop(group);

    let mut group = c.benchmark_group("sha512-1m");
    group.bench_function("ring", |b| b.iter(|| test_ring_sha512(&data)));
    group.bench_function("aws-lc-rs", |b| b.iter(|| test_aws_sha512(&data)));
    group.bench_function("rustcrypto", |b| b.iter(|| test_rc_sha512(&data)));
}

criterion_group!(benches, block_32, block_8k, block_1m);
criterion_main!(benches);
