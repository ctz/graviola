mod criterion;
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

fn rsa_key_generation(c: &mut Criterion) {
    // All these are gated under `NOISY_BENCHMARKS` for the benefit of codspeed,
    // which runs each test once and expects deterministic results.  RSA key generation
    // certainly is not that.
    if option_env!("NOISY_BENCHMARKS").is_none() {
        return;
    }

    let mut group = c.benchmark_group("rsa2048-key-generation");
    group.throughput(Throughput::Elements(1));

    group.bench_function("aws-lc-rs", |b| {
        use aws_lc_rs::rsa;

        b.iter(|| {
            black_box(rsa::KeyPair::generate(rsa::KeySize::Rsa2048).unwrap());
        })
    });

    group.bench_function("graviola", |b| {
        use graviola::signing::rsa;

        b.iter(|| {
            black_box(rsa::SigningKey::generate(rsa::KeySize::Rsa2048).unwrap());
        })
    });

    group.bench_function("rustcrypto", |b| {
        use rsa::RsaPrivateKey;

        b.iter(|| {
            black_box(RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap());
        })
    });
}

criterion_group!(benches, rsa_key_generation);
criterion_main!(benches);
