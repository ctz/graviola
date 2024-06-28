use super::util::Array64x4;
use crate::low;

#[derive(Debug, Clone, Copy)]
pub enum EcError {
    WrongLength,
    NotUncompressed,
    NotOnCurve,
}

#[derive(Debug)]
pub struct AffinePoint {
    x: FieldElement,
    y: FieldElement,
}

impl AffinePoint {
    pub fn from_x962_uncompressed(bytes: &[u8]) -> Result<Self, EcError> {
        match bytes.get(0) {
            Some(&0x04) => (),
            Some(_) => return Err(EcError::NotUncompressed),
            None => return Err(EcError::WrongLength),
        }

        if bytes.len() != 1 + 64 {
            return Err(EcError::WrongLength);
        }

        let x = &bytes[1..33];
        let y = &bytes[33..65];

        let point = AffinePoint {
            x: FieldElement(Array64x4::from_be_bytes(x).unwrap().0),
            y: FieldElement(Array64x4::from_be_bytes(y).unwrap().0),
        };

        if !point.on_curve() {
            return Err(EcError::NotOnCurve);
        }

        Ok(point)
    }

    fn on_curve(&self) -> bool {
        // Compute the curve equation:
        //
        // y ^ 2 === x ^ 3 + ax + b
        //
        // all in GF(p)
        //
        // we do this in single montgomery form (ie,
        // both sides are also multiplied by 2^256 mod p256)

        let x_mont = self.x.to_mont();

        let rhs = x_mont.mont_sqr(); // x ^ 2
        let rhs = rhs.add(&CURVE_A_MONT); // x ^ 2 + a
        let rhs = rhs.mont_mul(&x_mont); // (x ^ 2 + a) * x   equiv  x ^ 3 + ax
        let rhs = rhs.add(&CURVE_B_MONT);

        let lhs = self.y.to_mont().mont_sqr();

        lhs.public_eq(&rhs)
    }
}

struct JacobianPoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
}

#[derive(Debug, Default)]
struct FieldElement([u64; 4]);

impl FieldElement {
    /// Montgomery squaring mod p256
    fn mont_sqr(&self) -> Self {
        let mut r = Self::default();
        low::bignum_montsqr_p256(&mut r.0, &self.0);
        r
    }

    /// Addition mod p256
    fn add(&self, other: &FieldElement) -> Self {
        let mut r = Self::default();
        low::bignum_add_p256(&mut r.0, &self.0, &other.0);
        r
    }

    /// Montgomery multiplication mod p256
    fn mont_mul(&self, other: &FieldElement) -> Self {
        let mut r = Self::default();
        low::bignum_montmul_p256(&mut r.0, &self.0, &other.0);
        r
    }

    /// Remove one montgomery factor
    fn demont(&self) -> Self {
        let mut r = Self::default();
        low::bignum_demont_p256(&mut r.0, &self.0);
        r
    }

    /// Add a montgomery factor
    fn to_mont(&self) -> Self {
        let mut r = Self::default();
        low::bignum_tomont_p256(&mut r.0, &self.0);
        r
    }

    /// Public equality
    fn public_eq(&self, other: &FieldElement) -> bool {
        self.0 == other.0
    }
}

const CURVE_A: FieldElement = FieldElement([
    0xffff_ffff_ffff_fffc,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
]);
const CURVE_B: FieldElement = FieldElement([
    0x3bce_3c3e_27d2_604b,
    0x651d_06b0_cc53_b0f6,
    0xb3eb_bd55_7698_86bc,
    0x5ac6_35d8_aa3a_93e7,
]);

const CURVE_A_MONT: FieldElement = FieldElement([
    0xffff_ffff_ffff_fffc,
    0x0000_0003_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_fffc_0000_0004,
]);
const CURVE_B_MONT: FieldElement = FieldElement([
    0xd89c_df62_29c4_bddf,
    0xacf0_05cd_7884_3090,
    0xe5a2_20ab_f721_2ed6,
    0xdc30_061d_0487_4834,
]);

const CURVE_GENERATOR: AffinePoint = AffinePoint {
    x: FieldElement([
        0xf4a1_3945_d898_c296,
        0x7703_7d81_2deb_33a0,
        0xf8bc_e6e5_63a4_40f2,
        0x6b17_d1f2_e12c_4247,
    ]),
    y: FieldElement([
        0xcbb6_4068_37bf_51f5,
        0x2bce_3357_6b31_5ece,
        0x8ee7_eb4a_7c0f_9e16,
        0x4fe3_42e2_fe1a_7f9b,
    ]),
};

#[test]
fn generator_on_curve() {
    println!("{CURVE_GENERATOR:x?}");
    assert!(CURVE_GENERATOR.on_curve());
}

#[test]
fn curve_field_elements_to_mont() {
    println!("{:x?}", CURVE_A.to_mont());
    println!("{:x?}", CURVE_B.to_mont());
}
