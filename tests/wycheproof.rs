use serde::Deserialize;
use std::fs::File;

use graviola::ec::P256;
use graviola::ecdsa::VerifyingKey;
use graviola::high::hash::{Sha256, Sha384, Sha512};
use graviola::high::hmac::Hmac;
use graviola::Error;

#[derive(Deserialize, Debug)]
struct TestFile {
    #[serde(rename(deserialize = "testGroups"))]
    groups: Vec<TestGroup>,
}

#[derive(Deserialize, Debug)]
struct TestGroup {
    #[serde(rename(deserialize = "type"))]
    typ: String,

    #[serde(default, rename(deserialize = "publicKey"))]
    public_key: PublicKey,
    tests: Vec<Test>,
}

#[derive(Deserialize, Debug)]
struct Test {
    #[serde(rename(deserialize = "tcId"))]
    #[allow(unused)] // for Debug
    id: usize,
    #[allow(unused)] // for Debug
    comment: String,
    flags: Vec<String>,
    #[serde(default, with = "hex::serde")]
    key: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    msg: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    tag: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    sig: Vec<u8>,
    result: ExpectedResult,
}

#[derive(Deserialize, Debug, Default)]
struct PublicKey {
    #[serde(with = "hex::serde")]
    uncompressed: Vec<u8>,
}

#[derive(Copy, Clone, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum ExpectedResult {
    Valid,
    Invalid,
}

#[test]
fn hmac_sha256_tests() {
    let data_file = File::open("thirdparty/wycheproof/testvectors_v1/hmac_sha256_test.json")
        .expect("failed to open data file");

    let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

    for group in tests.groups {
        println!("group: {:?}", group.typ);
        for test in group.tests {
            println!("  test {:?}", test);

            let mut ctx = Hmac::<Sha256>::new(test.key);
            ctx.update(test.msg);
            let result = ctx.verify(&test.tag);

            match (test.result, result) {
                (ExpectedResult::Valid, Ok(())) => {}
                (ExpectedResult::Invalid, Err(Error::BadSignature)) => {}
                _ => panic!("expected {:?} got {:?}", test.result, result),
            }
        }
    }
}

#[test]
fn hmac_sha384_tests() {
    let data_file = File::open("thirdparty/wycheproof/testvectors_v1/hmac_sha384_test.json")
        .expect("failed to open data file");

    let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

    for group in tests.groups {
        println!("group: {:?}", group.typ);
        for test in group.tests {
            println!("  test {:?}", test);

            let mut ctx = Hmac::<Sha384>::new(test.key);
            ctx.update(test.msg);
            let result = ctx.verify(&test.tag);

            match (test.result, result) {
                (ExpectedResult::Valid, Ok(())) => {}
                (ExpectedResult::Invalid, Err(Error::BadSignature)) => {}
                _ => panic!("expected {:?} got {:?}", test.result, result),
            }
        }
    }
}

#[test]
fn hmac_sha512_tests() {
    let data_file = File::open("thirdparty/wycheproof/testvectors_v1/hmac_sha512_test.json")
        .expect("failed to open data file");

    let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

    for group in tests.groups {
        println!("group: {:?}", group.typ);
        for test in group.tests {
            println!("  test {:?}", test);

            let mut ctx = Hmac::<Sha512>::new(test.key);
            ctx.update(test.msg);
            let result = ctx.verify(&test.tag);

            match (test.result, result) {
                (ExpectedResult::Valid, Ok(())) => {}
                (ExpectedResult::Invalid, Err(Error::BadSignature)) => {}
                _ => panic!("expected {:?} got {:?}", test.result, result),
            }
        }
    }
}

#[test]
fn test_verify_ecdsa_p256_sha256() {
    let data_file =
        File::open("thirdparty/wycheproof/testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json")
            .expect("failed to open data file");

    let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

    for group in tests.groups {
        println!("group: {:?}", group.typ);
        let public_key =
            VerifyingKey::<P256>::from_x962_uncompressed(&group.public_key.uncompressed).unwrap();

        for test in group.tests {
            println!("  test {:?}", test);

            let result = public_key.verify::<Sha256>(&[&test.msg], &test.sig);

            match (test.result, result) {
                (ExpectedResult::Valid, Ok(())) => {}
                (ExpectedResult::Invalid, Err(Error::BadSignature) | Err(Error::WrongLength)) => {}
                _ => panic!("expected {:?} got {:?}", test.result, result),
            }
        }
    }
}

#[test]
fn test_verify_ecdsa_p256_sha512() {
    let data_file =
        File::open("thirdparty/wycheproof/testvectors_v1/ecdsa_secp256r1_sha512_p1363_test.json")
            .expect("failed to open data file");

    let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

    for group in tests.groups {
        println!("group: {:?}", group.typ);
        let public_key =
            VerifyingKey::<P256>::from_x962_uncompressed(&group.public_key.uncompressed).unwrap();

        for test in group.tests {
            println!("  test {:?}", test);

            let result = public_key.verify::<Sha512>(&[&test.msg], &test.sig);

            match (test.result, result) {
                (ExpectedResult::Valid, Ok(())) => {}
                (ExpectedResult::Invalid, Err(Error::BadSignature) | Err(Error::WrongLength)) => {}
                _ => panic!("expected {:?} got {:?}", test.result, result),
            }
        }
    }
}
