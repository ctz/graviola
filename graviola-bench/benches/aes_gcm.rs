use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn test_ring_aes_gcm(key: &ring::aead::LessSafeKey, nonce: &[u8; 12], aad: &[u8], plain: &[u8]) {
    let mut ct = plain.to_vec();
    let _tag = key
        .seal_in_place_separate_tag(
            ring::aead::Nonce::assume_unique_for_key(*nonce),
            ring::aead::Aad::from(aad),
            &mut ct,
        )
        .unwrap();
}

fn test_aws_aes_gcm(
    key: &aws_lc_rs::aead::LessSafeKey,
    nonce: &[u8; 12],
    aad: &[u8],
    plain: &[u8],
) {
    let mut ct = plain.to_vec();
    let _tag = key
        .seal_in_place_separate_tag(nonce.into(), aws_lc_rs::aead::Aad::from(aad), &mut ct)
        .unwrap();
}

fn test_rc_aes128_gcm(key: &aes_gcm::Aes128Gcm, nonce: &[u8; 12], aad: &[u8], plain: &[u8]) {
    use aes_gcm::AeadInPlace;
    let mut ct = plain.to_vec();
    let _tag = key
        .encrypt_in_place_detached(nonce.into(), aad, &mut ct)
        .unwrap();
}

fn test_rc_aes256_gcm(key: &aes_gcm::Aes256Gcm, nonce: &[u8; 12], aad: &[u8], plain: &[u8]) {
    use aes_gcm::AeadInPlace;
    let mut ct = plain.to_vec();
    let _tag = key
        .encrypt_in_place_detached(nonce.into(), aad, &mut ct)
        .unwrap();
}

fn test_graviola_aes_gcm(
    key: &graviola::aes_gcm::AesGcm,
    nonce: &[u8; 12],
    aad: &[u8],
    plain: &[u8],
) {
    let mut ct = plain.to_vec();
    let mut tag = [0u8; 16];
    key.encrypt(nonce, aad, &mut ct, &mut tag);
}

fn aes128_gcm(c: &mut Criterion) {
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let aad = [0u8; 32];

    let mut group = c.benchmark_group("aes128-gcm");
    for (size, size_name) in [(32, "32B"), (2048, "2KB"), (8192, "8KB"), (16384, "16KB")] {
        let input = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("ring", size_name), &input, |b, input| {
            use ring::aead::{LessSafeKey, UnboundKey, AES_128_GCM};
            let key = UnboundKey::new(&AES_128_GCM, &key).unwrap();
            let key = LessSafeKey::new(key);
            b.iter(|| test_ring_aes_gcm(&key, &nonce, &aad, input));
        });
        group.bench_with_input(
            BenchmarkId::new("aws-lc-rs", size_name),
            &input,
            |b, input| {
                use aws_lc_rs::aead::{LessSafeKey, UnboundKey, AES_128_GCM};
                let key = UnboundKey::new(&AES_128_GCM, &key).unwrap();
                let key = LessSafeKey::new(key);
                b.iter(|| test_aws_aes_gcm(&key, &nonce, &aad, input));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("rustcrypto", size_name),
            &input,
            |b, input| {
                use aes_gcm::KeyInit;
                let key = aes_gcm::Aes128Gcm::new_from_slice(&key).unwrap();
                b.iter(|| test_rc_aes128_gcm(&key, &nonce, &aad, input));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("graviola", size_name),
            &input,
            |b, input| {
                let key = graviola::aes_gcm::AesGcm::new(&key);
                b.iter(|| test_graviola_aes_gcm(&key, &nonce, &aad, input));
            },
        );
    }
}

fn aes256_gcm(c: &mut Criterion) {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = [0u8; 32];

    let mut group = c.benchmark_group("aes256-gcm");
    for (size, size_name) in [(32, "32B"), (2048, "2KB"), (8192, "8KB"), (16384, "16KB")] {
        let input = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("ring", size_name), &input, |b, input| {
            use ring::aead::{LessSafeKey, UnboundKey, AES_256_GCM};
            let key = UnboundKey::new(&AES_256_GCM, &key).unwrap();
            let key = LessSafeKey::new(key);
            b.iter(|| test_ring_aes_gcm(&key, &nonce, &aad, input));
        });
        group.bench_with_input(
            BenchmarkId::new("aws-lc-rs", size_name),
            &input,
            |b, input| {
                use aws_lc_rs::aead::{LessSafeKey, UnboundKey, AES_256_GCM};
                let key = UnboundKey::new(&AES_256_GCM, &key).unwrap();
                let key = LessSafeKey::new(key);
                b.iter(|| test_aws_aes_gcm(&key, &nonce, &aad, input));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("rustcrypto", size_name),
            &input,
            |b, input| {
                use aes_gcm::KeyInit;
                let key = aes_gcm::Aes256Gcm::new_from_slice(&key).unwrap();
                b.iter(|| test_rc_aes256_gcm(&key, &nonce, &aad, input));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("graviola", size_name),
            &input,
            |b, input| {
                let key = graviola::aes_gcm::AesGcm::new(&key);
                b.iter(|| test_graviola_aes_gcm(&key, &nonce, &aad, input));
            },
        );
    }
}

criterion_group!(benches, aes128_gcm, aes256_gcm);
criterion_main!(benches);
