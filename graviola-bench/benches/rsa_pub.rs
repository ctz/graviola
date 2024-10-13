mod criterion;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

fn rsa2048_pkcs1_sha256_verify(c: &mut Criterion) {
    let public_key = b"\x30\x82\x01\x0a\x02\x82\x01\x01\x00\xa2\xb4\x51\xa0\x7d\x0a\xa5\xf9\x6e\x45\x56\x71\x51\x35\x50\x51\x4a\x8a\x5b\x46\x2e\xbe\xf7\x17\x09\x4f\xa1\xfe\xe8\x22\x24\xe6\x37\xf9\x74\x6d\x3f\x7c\xaf\xd3\x18\x78\xd8\x03\x25\xb6\xef\x5a\x17\x00\xf6\x59\x03\xb4\x69\x42\x9e\x89\xd6\xea\xc8\x84\x50\x97\xb5\xab\x39\x31\x89\xdb\x92\x51\x2e\xd8\xa7\x71\x1a\x12\x53\xfa\xcd\x20\xf7\x9c\x15\xe8\x24\x7f\x3d\x3e\x42\xe4\x6e\x48\xc9\x8e\x25\x4a\x2f\xe9\x76\x53\x13\xa0\x3e\xff\x8f\x17\xe1\xa0\x29\x39\x7a\x1f\xa2\x6a\x8d\xce\x26\xf4\x90\xed\x81\x29\x96\x15\xd9\x81\x4c\x22\xda\x61\x04\x28\xe0\x9c\x7d\x96\x58\x59\x42\x66\xf5\xc0\x21\xd0\xfc\xec\xa0\x8d\x94\x5a\x12\xbe\x82\xde\x4d\x1e\xce\x6b\x4c\x03\x14\x5b\x5d\x34\x95\xd4\xed\x54\x11\xeb\x87\x8d\xaf\x05\xfd\x7a\xfc\x3e\x09\xad\xa0\xf1\x12\x64\x22\xf5\x90\x97\x5a\x19\x69\x81\x6f\x48\x69\x8b\xcb\xba\x1b\x4d\x9c\xae\x79\xd4\x60\xd8\xf9\xf8\x5e\x79\x75\x00\x5d\x9b\xc2\x2c\x4e\x5a\xc0\xf7\xc1\xa4\x5d\x12\x56\x9a\x62\x80\x7d\x3b\x9a\x02\xe5\xa5\x30\xe7\x73\x06\x6f\x45\x3d\x1f\x5b\x4c\x2e\x9c\xf7\x82\x02\x83\xf7\x42\xb9\xd5\x02\x03\x01\x00\x01";
    let signature = b"\x8a\x1b\x22\x0c\xb2\xab\x41\x5d\xc7\x60\xeb\x7f\x5b\xb1\x03\x35\xa3\xcc\xa2\x69\xd7\xdb\xbf\x7d\x09\x62\xba\x79\xf9\xcf\x7b\x43\xa5\xfc\x09\xc9\x9a\x15\x84\xf0\x74\x03\x47\x3d\x6c\x18\x9a\x83\x68\x97\xa5\xb6\xf8\xea\x9f\xa2\x2d\x60\x1e\x6b\xa5\xf7\x41\x1f\xe2\x7c\x63\x8b\x81\xb1\xa2\x23\x63\x58\x3a\x80\xfc\xe8\xc7\xdf\x3e\x40\xfb\x51\xbd\x0e\x60\xd0\xa6\x65\x3f\x79\xf3\xbc\xb7\xec\x3e\x9d\xc1\x4c\xfb\x5b\x31\xab\x17\x35\xbc\xa6\x92\xd5\x0a\xc0\x3f\x97\x9d\xda\x92\x74\x7c\x64\x30\xf8\x04\x5e\xfa\x35\x13\xba\x6e\x0c\xe3\xe9\xe3\x55\x70\xe1\xc3\x0c\x8e\xbe\x58\x9b\x44\x19\x2e\x13\x44\xca\x83\xdf\xa5\x76\xfc\x6f\xdc\x7b\xf1\xcd\x7c\xee\x87\x5b\x00\x1c\x8c\x02\xce\x8d\x60\x27\x69\xe4\xbd\x9d\x24\x1c\x48\x57\x18\x2a\x00\x89\xa8\xb6\x76\x44\xe7\x3e\xef\x10\x5c\x55\x0e\xfa\x47\xa4\x08\x74\x28\x93\x95\xac\x0c\x4e\x02\xfd\x4b\xa9\x8e\x13\x0a\x4c\x2d\x1b\x95\x52\x1c\x6a\xf4\xa0\x02\xac\x3b\xdc\x6e\x52\x12\x2a\xe4\xc0\x8c\xc3\xda\x1c\x89\x6e\x05\x9a\xcb\xdd\xec\x57\x4a\xc0\x43\x2f\x61\x03\xdd\x97\x27\x3d\x88\x03\xc1\x02";
    let message =
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    let mut group = c.benchmark_group("rsa2048-pkcs1-sha256-verify");
    group.throughput(Throughput::Elements(1));

    group.bench_function("ring", |b| {
        use ring::signature;
        let peer_public_key =
            signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, public_key);

        b.iter(|| {
            black_box(peer_public_key.verify(message, signature).unwrap());
        })
    });

    group.bench_function("aws-lc-rs", |b| {
        use aws_lc_rs::signature;
        let peer_public_key =
            signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, public_key);

        b.iter(|| {
            black_box(peer_public_key.verify(message, signature).unwrap());
        })
    });

    group.bench_function("rustcrypto", |b| {
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::signature::Verifier;
        let peer_public_key = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(
            rsa::RsaPublicKey::from_pkcs1_der(public_key).unwrap(),
        );

        b.iter(|| {
            let signature = rsa::pkcs1v15::Signature::try_from(&signature[..]).unwrap();
            black_box(peer_public_key.verify(message, &signature).unwrap());
        });
    });

    group.bench_function("graviola", |b| {
        let peer_public_key =
            graviola::signing::rsa::VerifyingKey::from_pkcs1_der(public_key).unwrap();

        b.iter(|| {
            black_box(
                peer_public_key
                    .verify_pkcs1_sha256(signature, message)
                    .unwrap(),
            );
        })
    });
}

criterion_group!(benches, rsa2048_pkcs1_sha256_verify);
criterion_main!(benches);
