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

mod model {
    pub fn bignum_mux(p: u64, z: &mut [u64], x_if_p: &[u64], y_if_not_p: &[u64]) {
        if p > 0 {
            z.copy_from_slice(x_if_p);
        } else {
            z.copy_from_slice(y_if_not_p);
        }
    }
}
