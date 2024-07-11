use serde::Deserialize;
use std::fs::File;

use super::Hmac;
use crate::high::hash::{Sha256, Sha384, Sha512};
use crate::Error;

#[derive(Deserialize, Debug)]
struct TestFile {
    #[serde(rename(deserialize = "testGroups"))]
    groups: Vec<TestGroup>,
}

#[derive(Deserialize, Debug)]
struct TestGroup {
    #[serde(rename(deserialize = "type"))]
    typ: String,
    tests: Vec<Test>,
}

#[derive(Deserialize, Debug)]
struct Test {
    #[serde(rename(deserialize = "tcId"))]
    id: usize,
    comment: String,
    flags: Vec<String>,
    #[serde(with = "hex::serde")]
    key: Vec<u8>,
    #[serde(with = "hex::serde")]
    msg: Vec<u8>,
    #[serde(with = "hex::serde")]
    tag: Vec<u8>,
    result: ExpectedResult,
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
