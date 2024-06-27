use proptest::{arbitrary, array, proptest};

fn bignum_nonzero_4_witness(a: &[u64; 4]) {
    assert_eq!(model::bignum_nonzero_4(&a), super::bignum_nonzero_4(&a));
}

proptest! {
    #[test]
    fn proptest_bignum_nonzero_4(a in array::uniform4(arbitrary::any::<u64>())) {
        bignum_nonzero_4_witness(&a);
    }
}

#[test]
fn bignum_nonzero_4() {
    bignum_nonzero_4_witness(&[0u64; 4]);
    bignum_nonzero_4_witness(&[1u64; 4]);
    bignum_nonzero_4_witness(&[0x8000_0000_0000_0000u64; 4]);
    bignum_nonzero_4_witness(&[u64::MAX; 4]);
}

mod model {
    pub fn bignum_nonzero_4(v: &[u64; 4]) -> bool {
        match v {
            [0, 0, 0, 0] => false,
            _ => true,
        }
    }
}
