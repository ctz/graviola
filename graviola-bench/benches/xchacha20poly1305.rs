mod criterion;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

fn test_rc_chacha(
    key: &chacha20poly1305::XChaCha20Poly1305,
    nonce: &[u8; 24],
    aad: &[u8],
    plain: &[u8],
) {
    use chacha20poly1305::AeadInPlace;
    let mut ct = plain.to_vec();
    let _tag = key
        .encrypt_in_place_detached(nonce.into(), aad, &mut ct)
        .unwrap();
}

fn test_graviola_chacha(
    key: &graviola::aead::XChaCha20Poly1305,
    nonce: &[u8; 24],
    aad: &[u8],
    plain: &[u8],
) {
    let mut ct = plain.to_vec();
    let mut tag = [0u8; 16];
    key.encrypt(nonce, aad, &mut ct, &mut tag);
}

fn bench_chacha20poly1305(c: &mut Criterion) {
    let key = [0u8; 32];
    let nonce = [0u8; 24];
    let aad = [0u8; 32];

    let mut group = c.benchmark_group("xchacha20poly1305");
    for (size, size_name) in [(32, "32B"), (2048, "2KB"), (16384, "16KB")] {
        let input = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("rustcrypto", size_name),
            &input,
            |b, input| {
                use chacha20poly1305::KeyInit;
                let key = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&key).unwrap();
                b.iter(|| test_rc_chacha(&key, &nonce, &aad, input));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("graviola", size_name),
            &input,
            |b, input| {
                let key = graviola::aead::XChaCha20Poly1305::new(key);
                b.iter(|| test_graviola_chacha(&key, &nonce, &aad, input));
            },
        );
    }
}

criterion_group!(benches, bench_chacha20poly1305);
criterion_main!(benches);
