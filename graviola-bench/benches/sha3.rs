mod criterion;
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use sha3::Digest;
use shake::{ExtendableOutput, XofReader};

fn test_aws_sha3_256(data: &[u8]) {
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA3_256);
    ctx.update(data);
    black_box(ctx.finish());
}

fn test_rc_sha3_256(data: &[u8]) {
    let mut ctx = sha3::Sha3_256::new();
    ctx.update(data);
    black_box(ctx.finalize());
}

fn test_graviola_sha3_256(data: &[u8]) {
    let mut ctx = graviola::hashing::sha3::Sha3_256Context::new();
    ctx.update(data);
    black_box(ctx.finish());
}

fn test_rc_shake128() {
    let mut ctx = shake::Shake128::default();
    shake::Update::update(&mut ctx, SHAKE128_INPUT);
    let mut ctx = ctx.finalize_xof();
    let mut buf = [0u8; SHAKE128_OUTPUT];
    ctx.read(&mut buf);
    black_box(buf);
}

fn test_graviola_shake128() {
    let mut ctx = graviola::hashing::sha3::Shake128::new(&[SHAKE128_INPUT]);
    let mut buf = [0u8; SHAKE128_OUTPUT];
    ctx.read(&mut buf);
    black_box(buf);
}

fn sha3_256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3-256");
    for (size, size_name) in [(32, "32B"), (8192, "8KB"), (65536, "64KB")] {
        let input = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("aws-lc-rs", size_name),
            &input,
            |b, input| b.iter(|| test_aws_sha3_256(input)),
        );
        group.bench_with_input(
            BenchmarkId::new("rustcrypto", size_name),
            &input,
            |b, input| b.iter(|| test_rc_sha3_256(input)),
        );
        group.bench_with_input(
            BenchmarkId::new("graviola", size_name),
            &input,
            |b, input| b.iter(|| test_graviola_sha3_256(input)),
        );
    }
}

fn shake128(c: &mut Criterion) {
    // nb: no SHAKE support in aws-lc-rs or ring
    c.bench_function("shake128/rustcrypto", |b| b.iter(test_rc_shake128));
    c.bench_function("shake128/graviola", |b| b.iter(test_graviola_shake128));
}

criterion_group!(benches, sha3_256, shake128);
criterion_main!(benches);

const SHAKE128_INPUT: &[u8] = &[0u8; 128];
const SHAKE128_OUTPUT: usize = 8192;
