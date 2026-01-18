//! Verification that long-term key data is zeroed.
//!
//! Some of this is subject to whims of the compiler, and
//! hand-written drop impls, so we test it here.
//!
//! Is this test sound? Well, it's a deliberate use-after-free,
//! so no.
//!
//! Does it work? If you're reading this, it has probably
//! broken, so also no.

#![cfg(target_os = "linux")]

use core::mem::size_of;
use core::ops::Deref;
use core::pin::Pin;
use core::ptr;

#[test]
fn rsa() {
    use graviola::signing::rsa;
    let rsa_priv =
        rsa::SigningKey::from_pkcs1_der(include_bytes!("../src/high/rsa/rsa8192.der")).unwrap();
    let pub_key_size = size_of::<rsa::VerifyingKey>();
    check_zeroed_on_drop_bounded(Box::pin(rsa_priv), Bounds::SkipPrefix(pub_key_size));
}

#[test]
fn ecdsa_p256() {
    use graviola::signing::ecdsa::*;
    let ecdsa =
        SigningKey::<P256>::from_pkcs8_der(include_bytes!("../src/high/ecdsa/secp256r1.pkcs8.der"))
            .unwrap();
    check_zeroed_on_drop(Box::pin(ecdsa));
}

#[test]
fn ecdsa_p384() {
    use graviola::signing::ecdsa::*;
    let ecdsa =
        SigningKey::<P384>::from_pkcs8_der(include_bytes!("../src/high/ecdsa/secp384r1.pkcs8.der"))
            .unwrap();
    check_zeroed_on_drop(Box::pin(ecdsa));
}

#[test]
fn ed25519() {
    use graviola::signing::eddsa::*;
    let ed25519 = Ed25519SigningKey::from_pkcs8_der(include_bytes!(
        "../src/high/asn1/testdata/ed25519-p8v2.bin"
    ))
    .unwrap();
    check_zeroed_on_drop(Box::pin(ed25519));
}

#[test]
fn ecdh_x25519() {
    use graviola::key_agreement::x25519::PrivateKey;
    let x25519 = PrivateKey::new_random().unwrap();
    check_zeroed_on_drop(Box::pin(x25519));
}

#[test]
fn ecdh_static_x25519() {
    use graviola::key_agreement::x25519::StaticPrivateKey;
    let x25519 = StaticPrivateKey::from_array(&[0xffu8; 32]);
    check_zeroed_on_drop(Box::pin(x25519));
}

#[test]
fn ecdh_p256() {
    use graviola::key_agreement::p256::PrivateKey;
    let p256 = PrivateKey::new_random().unwrap();
    check_zeroed_on_drop(Box::pin(p256));
}

#[test]
fn ecdh_p384() {
    use graviola::key_agreement::p384::PrivateKey;
    let p384 = PrivateKey::new_random().unwrap();
    check_zeroed_on_drop(Box::pin(p384));
}

#[test]
fn aes_gcm() {
    use graviola::aead::AesGcm;

    let aes128 = AesGcm::new(&[0xffu8; 16]);
    check_zeroed_on_drop(Box::pin(aes128));

    let aes256 = AesGcm::new(&[0xffu8; 32]);
    check_zeroed_on_drop(Box::pin(aes256));
}

#[test]
fn chacha20_poly1305() {
    use graviola::aead::ChaCha20Poly1305;

    let chacha = ChaCha20Poly1305::new([0xffu8; 32]);
    check_zeroed_on_drop(Box::pin(chacha));
}

#[test]
fn xchacha20_poly1305() {
    use graviola::aead::XChaCha20Poly1305;

    let xchacha = XChaCha20Poly1305::new([0xffu8; 32]);
    check_zeroed_on_drop(Box::pin(xchacha));
}

fn check_zeroed_on_drop<T>(value: Pin<Box<T>>) {
    check_zeroed_on_drop_bounded(value, Bounds::All)
}

fn check_zeroed_on_drop_bounded<T>(value: Pin<Box<T>>, bounds: Bounds) {
    let ptr = value.deref() as *const T as *const u8;
    let len = size_of::<T>();
    assert_ne!(len, 0);
    println!("this value is {len} bytes in length");
    let before_drop = read_into_vec(ptr, len);
    drop(value);
    let after_drop = read_into_vec(ptr, len);

    for i in bounds.start()..bounds.end(len) {
        if after_drop[i] != 0x00 {
            println!("before_drop: {before_drop:02x?}");
            println!("after_drop: {after_drop:02x?}");
            panic!(
                "byte {i} (0x{:x?}) was not cleared after drop",
                after_drop[i]
            );
        }
    }
}

fn read_into_vec(ptr: *const u8, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);

    for i in 0..len {
        // Safety: none
        let byte = unsafe { ptr::read_volatile(ptr.add(i)) };
        out.push(byte);
    }
    out
}

enum Bounds {
    All,
    SkipPrefix(usize),
}

impl Bounds {
    fn start(&self) -> usize {
        match self {
            Bounds::All => HEAP_FREELIST_ZONE.0,
            Bounds::SkipPrefix(prefix) => {
                assert!(HEAP_FREELIST_ZONE.0 <= *prefix);
                *prefix
            }
        }
    }

    fn end(&self, len: usize) -> usize {
        len - HEAP_FREELIST_ZONE.1
    }
}

/// Bytes written by the heap to (probably) keep the freed chunk
/// in the freelist.
///
/// These values from observation; likely very fragile.
const HEAP_FREELIST_ZONE: (usize, usize) = (16, 0);
