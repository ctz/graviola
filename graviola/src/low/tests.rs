// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

fn bignum_mux_equiv(p: u64, x_if_p: &[u64], y_if_not_p: &[u64]) {
    let mut model_z = vec![0; x_if_p.len()];
    let mut real_z = vec![0; x_if_p.len()];
    model::bignum_mux(p, &mut model_z, x_if_p, y_if_not_p);
    super::bignum_mux(p, &mut real_z, x_if_p, y_if_not_p);
    assert_eq!(model_z, real_z);
}

#[test]
fn bignum_mux() {
    bignum_mux_equiv(0, &[0u64; 4], &[1u64; 4]);
    bignum_mux_equiv(1, &[1u64; 4], &[0xff; 4]);
    bignum_mux_equiv(u64::MAX, &[1; 1], &[0; 1]);
}

#[test]
fn zeroise() {
    for n in 0..1024 {
        zeroise_equiv(n);
    }
}

fn zeroise_equiv(len: usize) {
    let expect = vec![0x00u8; len];
    let mut bytes = vec![0xffu8; len];
    super::zeroise(&mut bytes);
    assert_eq!(expect, bytes);
}

#[test]
fn ct_equal() {
    ct_equal_equiv(&[], &[]);

    for n in 1..1024 {
        let a = vec![0u8; n];

        for i in 0..n {
            let mut b = vec![0u8; n];
            b[i] = i as u8;
            ct_equal_equiv(&a, &b);
        }
    }
}

#[test]
fn ct_equal_unaligned() {
    let a = [0u8; 64];
    for offs in 0..8 {
        for n in 0..(64 - offs) {
            ct_equal_equiv(&a[offs..offs + n], &a[..n]);
            for i in 0..n {
                for bit in 0..8 {
                    let mut b = [0u8; 64];
                    b[offs + i] = 1 << bit;
                    ct_equal_equiv(&a[offs..offs + n], &b[offs..offs + n]);
                    ct_equal_equiv(&b[offs..offs + n], &a[..n]);
                }
            }
        }
    }
}

fn ct_equal_equiv(a: &[u8], b: &[u8]) {
    assert_eq!(a == b, super::ct_equal(a, b));
}

fn ct_compare_bytes_equiv(a: &[u8], b: &[u8]) {
    assert_eq!(a.len(), b.len());
    // SAFETY: `a` and `b` are both readable for `a.len()` bytes.
    let real = unsafe { super::ct_compare_bytes(a.as_ptr(), b.as_ptr(), a.len()) };
    let model = model::ct_compare_bytes(a, b);
    assert_eq!(real, model, "a={a:02x?} b={b:02x?}");
}

#[test]
fn ct_compare_bytes_exhaustive_single_bit() {
    // every length/alignment/position/bit for one-bit differences
    let a = [0u8; 80];
    for offs in 0..8 {
        for n in 0..(80 - offs) {
            ct_compare_bytes_equiv(&a[offs..offs + n], &a[..n]);
            for i in 0..n {
                for bit in 0..8 {
                    let mut b = [0u8; 80];
                    b[offs + i] = 1 << bit;
                    ct_compare_bytes_equiv(&a[offs..offs + n], &b[offs..offs + n]);
                    ct_compare_bytes_equiv(&b[offs..offs + n], &a[offs..offs + n]);
                }
            }
        }
    }
}

mod ct_compare_bytes_prop {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn proptest(
            (a, b) in (0usize..300).prop_flat_map(|n| (
                proptest::collection::vec(any::<u8>(), n),
                proptest::collection::vec(any::<u8>(), n),
            )),
            diffs in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..4),
            offs in 0usize..8,
        ) {
            // `a` misaligned by `offs`
            let mut buf = vec![0u8; offs];
            buf.extend_from_slice(&a);
            let a = &buf[offs..];

            // unrelated random inputs
            super::ct_compare_bytes_equiv(a, &b);

            // mostly-equal inputs, with a few sparse differences
            let mut b = a.to_vec();
            if !b.is_empty() {
                let n = b.len();
                for (i, x) in diffs {
                    b[i % n] ^= x;
                }
            }
            super::ct_compare_bytes_equiv(a, &b);
        }
    }
}

mod model {
    /// Pure-Rust model of `ct_compare_bytes`: 0x00 if `a == b`,
    /// otherwise 0xff (on all architectures).
    pub(super) fn ct_compare_bytes(a: &[u8], b: &[u8]) -> u8 {
        assert_eq!(a.len(), b.len());
        match a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) {
            0 => 0x00,
            _ => 0xff,
        }
    }

    pub(super) fn bignum_mux(p: u64, z: &mut [u64], x_if_p: &[u64], y_if_not_p: &[u64]) {
        if p > 0 {
            z.copy_from_slice(x_if_p);
        } else {
            z.copy_from_slice(y_if_not_p);
        }
    }
}

#[test]
fn test_edwards25519_decode() {
    use hex::FromHex;

    // valid pubkey from RFC 8032
    let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let pk = <[u8; 32]>::from_hex(pk_hex).unwrap();
    let mut point = [0u64; 8];
    assert!(super::edwards25519_decode(&mut point, &pk));

    // invalid pubkey
    assert!(!super::edwards25519_decode(&mut point, &[0xffu8; 32]));
}
