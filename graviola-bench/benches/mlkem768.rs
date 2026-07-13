mod criterion;
use std::hint::black_box;

use criterion::{Criterion, CustomMeasurement, Throughput, criterion_group, criterion_main};
use rand_core::RngCore;

// client first operation
fn mlkem768_keygen(c: &mut Criterion<CustomMeasurement>) {
    let mut group = c.benchmark_group("mlkem768-keygen");
    group.throughput(Throughput::Elements(1));

    group.bench_function("aws-lc-rs", |b| {
        use aws_lc_rs::kem;

        b.iter(|| {
            let decaps = kem::DecapsulationKey::generate(&kem::ML_KEM_768).unwrap();
            black_box(decaps.encapsulation_key().unwrap())
        })
    });

    group.bench_function("libcrux-ml-kem", |b| {
        use libcrux_ml_kem::mlkem768;

        b.iter(|| {
            let mut rand = [0u8; 64];
            rand_core::OsRng.fill_bytes(&mut rand);
            black_box(mlkem768::generate_key_pair(rand).into_parts());
        });
    });

    group.bench_function("rustcrypto", |b| {
        use ml_kem::{KemCore, MlKem768};

        b.iter(|| {
            black_box(MlKem768::generate(&mut rand_core::OsRng));
        });
    });

    group.bench_function("graviola", |b| {
        use graviola::key_agreement::mlkem768;

        b.iter(|| {
            black_box(mlkem768::DecapKey::generate().unwrap());
        });
    });
}

// server operation
fn mlkem768_encaps(c: &mut Criterion<CustomMeasurement>) {
    let mut group = c.benchmark_group("mlkem768-encaps");
    group.throughput(Throughput::Elements(1));

    group.bench_function("aws-lc-rs", |b| {
        use aws_lc_rs::kem;

        let decaps = kem::DecapsulationKey::generate(&kem::ML_KEM_768).unwrap();
        let encaps_bytes = decaps
            .encapsulation_key()
            .unwrap()
            .key_bytes()
            .unwrap()
            .as_ref()
            .to_vec();

        b.iter(|| {
            let encaps = kem::EncapsulationKey::new(&kem::ML_KEM_768, &encaps_bytes).unwrap();
            black_box(encaps.encapsulate().unwrap());
        })
    });

    group.bench_function("libcrux-ml-kem", |b| {
        use libcrux_ml_kem::mlkem768;

        let mut rand = [0u8; 64];
        rand_core::OsRng.fill_bytes(&mut rand);
        let (_, encaps) = mlkem768::generate_key_pair(rand).into_parts();
        let encaps_bytes = encaps.as_slice().to_vec();

        b.iter(|| {
            let encaps = mlkem768::MlKem768PublicKey::try_from(encaps_bytes.as_slice()).unwrap();
            let mut rand = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut rand);
            black_box(mlkem768::encapsulate(&encaps, rand))
        });
    });

    group.bench_function("rustcrypto", |b| {
        use ml_kem::{
            EncodedSizeUser, KemCore, MlKem768, MlKem768Params, kem::Encapsulate,
            kem::EncapsulationKey,
        };

        let mut rng = rand_core::OsRng;
        let (_decaps, encaps) = MlKem768::generate(&mut rng);
        let encaps_bytes = encaps.as_bytes();

        b.iter(|| {
            let encaps = EncapsulationKey::<MlKem768Params>::from_bytes(&encaps_bytes);
            black_box(encaps.encapsulate(&mut rng).unwrap());
        });
    });

    group.bench_function("graviola", |b| {
        use graviola::key_agreement::mlkem768;

        let encaps_bytes = mlkem768::DecapKey::generate()
            .unwrap()
            .encapsulation_key()
            .as_bytes();

        b.iter(|| {
            let encaps = mlkem768::EncapKey::from_bytes(&encaps_bytes).unwrap();
            black_box(encaps.encaps().unwrap());
        });
    });
}

// client second operation
fn mlkem768_decaps(c: &mut Criterion<CustomMeasurement>) {
    let mut group = c.benchmark_group("mlkem768-decaps");
    group.throughput(Throughput::Elements(1));

    group.bench_function("aws-lc-rs", |b| {
        use aws_lc_rs::kem;

        let decaps = kem::DecapsulationKey::generate(&kem::ML_KEM_768).unwrap();
        let (ciphertext, _secret) = decaps.encapsulation_key().unwrap().encapsulate().unwrap();
        let ciphertext = ciphertext.as_ref().to_vec();

        b.iter(|| {
            let ciphertext = kem::Ciphertext::from(ciphertext.as_slice());
            black_box(decaps.decapsulate(ciphertext).unwrap())
        })
    });

    group.bench_function("libcrux-ml-kem", |b| {
        use libcrux_ml_kem::mlkem768;

        let mut rand = [0u8; 64];
        rand_core::OsRng.fill_bytes(&mut rand);
        let (decaps, encaps) = mlkem768::generate_key_pair(rand).into_parts();

        let mut rand = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut rand);
        let (ciphertext, _secret) = mlkem768::encapsulate(&encaps, rand);
        let ciphertext = ciphertext.as_slice().to_vec();

        b.iter(|| {
            let ciphertext = mlkem768::MlKem768Ciphertext::try_from(ciphertext.as_slice()).unwrap();
            black_box(mlkem768::decapsulate(&decaps, &ciphertext));
        });
    });

    group.bench_function("rustcrypto", |b| {
        use ml_kem::{KemCore, MlKem768, array, kem::Decapsulate, kem::Encapsulate};

        let mut rng = rand_core::OsRng;
        let (decaps, encaps) = MlKem768::generate(&mut rng);
        let (ciphertext, _secret) = encaps.encapsulate(&mut rng).unwrap();
        let ciphertext = ciphertext.as_slice().to_vec();

        b.iter(|| {
            let ciphertext = array::Array::try_from(ciphertext.as_slice()).unwrap();
            black_box(decaps.decapsulate(&ciphertext).unwrap());
        });
    });

    group.bench_function("graviola", |b| {
        use graviola::key_agreement::mlkem768;

        let decap = mlkem768::DecapKey::generate().unwrap();
        let (_ss, ciphertext) = decap.encapsulation_key().encaps().unwrap();

        b.iter(|| {
            black_box(decap.decaps_internal(&ciphertext));
        });
    });
}

// combined operation: keygen, encaps-encode, encaps-decode, encaps, decaps
fn mlkem768_combined(c: &mut Criterion<CustomMeasurement>) {
    let mut group = c.benchmark_group("mlkem768-combined");
    group.throughput(Throughput::Elements(1));

    group.bench_function("aws-lc-rs", |b| {
        use aws_lc_rs::kem;

        b.iter(|| {
            let decaps = kem::DecapsulationKey::generate(&kem::ML_KEM_768).unwrap();
            let encaps_encoded = decaps.encapsulation_key().unwrap().key_bytes().unwrap();
            let encaps =
                kem::EncapsulationKey::new(&kem::ML_KEM_768, encaps_encoded.as_ref()).unwrap();
            let (ciphertext, _secret) = encaps.encapsulate().unwrap();
            black_box(decaps.decapsulate(ciphertext).unwrap())
        })
    });

    group.bench_function("libcrux-ml-kem", |b| {
        use libcrux_ml_kem::mlkem768;

        b.iter(|| {
            let mut rand = [0u8; 64];
            rand_core::OsRng.fill_bytes(&mut rand);
            let (decaps, encaps) = mlkem768::generate_key_pair(rand).into_parts();
            let encaps_encoded = encaps.as_slice();
            let encaps = mlkem768::MlKem768PublicKey::from(encaps_encoded);

            let mut rand = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut rand);
            let (ciphertext, _secret) = mlkem768::encapsulate(&encaps, rand);
            black_box(mlkem768::decapsulate(&decaps, &ciphertext));
        });
    });

    group.bench_function("rustcrypto", |b| {
        use ml_kem::{
            EncodedSizeUser, KemCore, MlKem768, MlKem768Params, array, kem::Decapsulate,
            kem::Encapsulate, kem::EncapsulationKey,
        };

        b.iter(|| {
            let mut rng = rand_core::OsRng;
            let (decaps, encaps) = MlKem768::generate(&mut rng);
            let encaps_encoded = encaps.as_bytes();
            let encaps = EncapsulationKey::<MlKem768Params>::from_bytes(&encaps_encoded);
            let (ciphertext, _secret) = encaps.encapsulate(&mut rng).unwrap();
            let ciphertext = array::Array::try_from(ciphertext.as_slice()).unwrap();
            black_box(decaps.decapsulate(&ciphertext).unwrap());
        });
    });

    group.bench_function("graviola", |b| {
        use graviola::key_agreement::mlkem768;

        b.iter(|| {
            let decap = mlkem768::DecapKey::generate().unwrap();
            let encap_encoded = decap.encapsulation_key().as_bytes();
            let encap = mlkem768::EncapKey::from_bytes(&encap_encoded).unwrap();
            let (_ss, ciphertext) = encap.encaps().unwrap();
            black_box(decap.decaps_internal(&ciphertext));
        });
    });
}

custom_benchmark_group!(
    benches,
    mlkem768_keygen,
    mlkem768_encaps,
    mlkem768_decaps,
    mlkem768_combined,
);
criterion_main!(benches);
