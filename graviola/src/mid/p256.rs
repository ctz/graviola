// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use super::util::Array64x4;
use crate::low;
use crate::mid::rng::RandomSource;
use crate::Error;

use core::fmt;

mod precomp;

#[derive(Clone, Debug)]
pub struct PublicKey {
    point: AffineMontPoint,
    precomp_wnaf_5: [JacobianMontPoint; 16],
}

impl PublicKey {
    pub fn from_x962_uncompressed(bytes: &[u8]) -> Result<Self, Error> {
        let point = AffineMontPoint::from_x962_uncompressed(bytes)?;
        Ok(Self::from_affine(point))
    }

    pub fn as_bytes_uncompressed(&self) -> [u8; 65] {
        self.point.as_bytes_uncompressed()
    }

    fn from_affine(point: AffineMontPoint) -> Self {
        Self {
            precomp_wnaf_5: point.public_precomp_wnaf_5(),
            point,
        }
    }

    pub fn x_scalar(&self) -> Scalar {
        self.point.x_scalar()
    }

    pub fn raw_ecdsa_verify(&self, r: &Scalar, s: &Scalar, e: &Scalar) -> Result<(), Error> {
        // 4. Compute: u1 = e s^-1 mod n and u2 = r s^−1 mod n
        let s_inv = s.inv().as_mont();
        let u1 = s_inv.mont_mul(&e.as_mont()).demont();
        let u2 = s_inv.mont_mul(&r.as_mont()).demont();

        // 5. Compute: R = (xR, yR) = u1 G + u2 QU
        //  If R = O, output "invalid" and stop.
        let lhs = JacobianMontPoint::base_multiply(&u1);
        let rhs = JacobianMontPoint::multiply_wnaf_5(&u2, &self.precomp_wnaf_5);

        // nb. if lhs == rhs, then we need a doubling rather than addition
        // (even complete point addition formula is only defined for P != Q)
        let point = if lhs.public_eq(&rhs) {
            lhs.double()
        } else {
            JacobianMontPoint::add(&lhs, &rhs)
        };

        if point.public_is_infinity() {
            return Err(Error::BadSignature);
        }

        // 6. Convert the field element xR to an integer xR using the conversion routine specified in Section 2.3.9.
        // 7. Set v = xR mod n.
        let v = point.x_scalar();

        // 8. Compare v and r — if v = r, output "valid", and if v != r, output "invalid".
        match v.public_eq(r) {
            true => Ok(()),
            false => Err(Error::BadSignature),
        }
    }
}

pub struct PrivateKey {
    scalar: Scalar,
}

impl PrivateKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Scalar::from_bytes_checked(bytes).map(|scalar| Self { scalar })
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.scalar.as_bytes()
    }

    pub fn public_key_uncompressed(&self) -> [u8; 65] {
        self.public_point().as_bytes_uncompressed()
    }

    pub fn public_key_x_scalar(&self) -> Scalar {
        self.public_point().x_scalar()
    }

    fn public_point(&self) -> AffineMontPoint {
        let point = JacobianMontPoint::base_multiply(&self.scalar).as_affine();
        match point.on_curve() {
            true => point,
            false => panic!("internal fault"),
        }
    }

    pub fn generate(rng: &mut dyn RandomSource) -> Result<Self, Error> {
        for _ in 0..64 {
            let mut r = [0u8; 32];
            rng.fill(&mut r)?;
            if let Ok(p) = Self::from_bytes(&r) {
                return Ok(p);
            }
        }

        Err(Error::RngFailed)
    }

    pub fn diffie_hellman(&self, peer: &PublicKey) -> Result<SharedSecret, Error> {
        let result =
            JacobianMontPoint::multiply_wnaf_5(&self.scalar, &peer.precomp_wnaf_5).as_affine();
        match result.on_curve() {
            true => Ok(SharedSecret(Array64x4(result.x().demont().0).as_be_bytes())),
            false => Err(Error::NotOnCurve),
        }
    }

    pub fn raw_ecdsa_sign(&self, k: &Self, e: &Scalar, r: &Scalar) -> Scalar {
        // this is (e + r * d) / k
        let lhs_mont = self
            .scalar
            .as_mont()
            .mont_mul(&r.as_mont())
            .demont()
            .add(e)
            .as_mont();
        k.scalar.inv().mont_mul(&lhs_mont)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey").finish_non_exhaustive()
    }
}

pub struct SharedSecret(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Default)]
struct AffineMontPoint {
    xy: [u64; 8],
}

impl AffineMontPoint {
    fn from_x962_uncompressed(bytes: &[u8]) -> Result<Self, Error> {
        match bytes.first() {
            Some(&0x04) => (),
            Some(_) => return Err(Error::NotUncompressed),
            None => return Err(Error::WrongLength),
        }

        if bytes.len() != 1 + 64 {
            return Err(Error::WrongLength);
        }

        let x = &bytes[1..33];
        let y = &bytes[33..65];

        let point = Self::from_xy(
            FieldElement(Array64x4::from_be_bytes(x).unwrap().0).as_mont(),
            FieldElement(Array64x4::from_be_bytes(y).unwrap().0).as_mont(),
        );

        if !point.on_curve() {
            return Err(Error::NotOnCurve);
        }

        Ok(point)
    }

    fn x_scalar(&self) -> Scalar {
        let bytes = self.as_bytes_uncompressed();
        Scalar::from_bytes_reduced(&bytes[1..33]).unwrap()
    }

    fn from_xy(x: FieldElement, y: FieldElement) -> Self {
        let mut r = Self::default();
        r.xy[0..4].copy_from_slice(&x.0[..]);
        r.xy[4..8].copy_from_slice(&y.0[..]);
        r
    }

    fn x(&self) -> FieldElement {
        FieldElement(self.xy[0..4].try_into().unwrap())
    }

    fn y(&self) -> FieldElement {
        FieldElement(self.xy[4..8].try_into().unwrap())
    }

    fn on_curve(&self) -> bool {
        // Compute the curve equation:
        //
        // y ^ 2 === x ^ 3 + ax + b
        //
        // all in GF(p)
        //

        let x = self.x();
        let rhs = x.mont_sqr(); // x ^ 2
        let rhs = rhs.add(&CURVE_A_MONT); // x ^ 2 + a
        let rhs = rhs.mont_mul(&x); // (x ^ 2 + a) * x   equiv  x ^ 3 + ax
        let rhs = rhs.add(&CURVE_B_MONT);

        let lhs = self.y().mont_sqr();

        lhs.public_eq(&rhs)
    }

    fn as_bytes_uncompressed(&self) -> [u8; 65] {
        let mut r = [0u8; 65];
        r[0] = 0x04;
        r[1..33].copy_from_slice(&Array64x4(self.x().demont().0).as_be_bytes());
        r[33..65].copy_from_slice(&Array64x4(self.y().demont().0).as_be_bytes());
        r
    }

    fn slow_multiply(&self, scalar: &Scalar) -> Self {
        let mut result = JacobianMontPoint::infinity();

        let mut j = JacobianMontPoint::from_affine(self);
        let zero = JacobianMontPoint::zero();

        for bit in scalar.bits() {
            result.add_inplace(&JacobianMontPoint::select(&zero, &j, bit));
            j = j.double();
        }

        result.as_affine()
    }

    fn maybe_negate_y(&mut self, sign: u8) {
        let y = self.y();
        let neg_y = y.negate_mod_p();
        let result = FieldElement::select(&y, &neg_y, sign);
        self.xy[4..8].copy_from_slice(&result.0);
    }

    /// Precomputes wNAF form (with 𝑤=6) for the point `self`
    ///
    /// 64 is the row size, 2**6.
    /// 37 is the table height, ceil(256/7) (wNAF gives us one bit
    /// extra free, in exchange for a negation to compute a negative
    /// point from the precomputed positive point -- this is ~free).
    ///
    /// This should not be used at runtime, since (for brevity) it
    /// does excessive point representation conversions, and recomputes
    /// items in a given row several times (compare `public_precomp_wnaf_5`).
    #[allow(dead_code)]
    fn public_precomp_wnaf_7_slow(&self) -> [[Self; 64]; 37] {
        let mut r = [[Self::default(); 64]; 37];

        for window in 0..((256 + 6) / 7) {
            let row = &mut r[window];

            // indices into rows are reduced by 1 since 0G does not require
            // storage.  therefore row[0] is 1G << shift.
            let mut first = JacobianMontPoint::from_affine(self);
            first.double_inplace_n(window * 7);
            row[0] = first.as_affine();

            for r in 1..64 {
                row[r] = row[0].slow_multiply(&Scalar([(r + 1) as u64, 0, 0, 0]));
            }
        }

        r
    }

    fn public_precomp_wnaf_5(&self) -> [JacobianMontPoint; 16] {
        let mut r = [JacobianMontPoint::zero(); 16];

        // indices into r are intuitively 1-based; index i contains i * G,
        // and 0 * G is not useful to store.
        macro_rules! index {
            ($i:literal) => {
                $i - 1
            };
        }

        r[index!(1)] = JacobianMontPoint::from_affine(self);
        r[index!(2)] = r[index!(1)].double();
        r[index!(3)] = r[index!(1)].add(&r[index!(2)]);
        r[index!(4)] = r[index!(2)].double();
        r[index!(5)] = r[index!(1)].add(&r[index!(4)]);
        r[index!(6)] = r[index!(3)].double();
        r[index!(7)] = r[index!(1)].add(&r[index!(6)]);
        r[index!(8)] = r[index!(4)].double();
        r[index!(9)] = r[index!(1)].add(&r[index!(8)]);
        r[index!(10)] = r[index!(5)].double();
        r[index!(11)] = r[index!(1)].add(&r[index!(10)]);
        r[index!(12)] = r[index!(6)].double();
        r[index!(13)] = r[index!(1)].add(&r[index!(12)]);
        r[index!(14)] = r[index!(7)].double();
        r[index!(15)] = r[index!(1)].add(&r[index!(14)]);
        r[index!(16)] = r[index!(8)].double();

        r
    }

    /// Returns table[(i - 1) * 8] if index > 1, or else AffineMontPoint::default()
    fn lookup_w7(table: &[u64; 512], index: u8) -> Self {
        let zero = Self::default();
        const MASK6: u8 = (1 << 6) - 1;
        // assumption: wrapping_sub is branch-free
        let index0 = index.wrapping_sub(1) & MASK6;
        let table_point = Self::lookup(table, index0);
        Self::select(&zero, &table_point, index)
    }

    /// Return points[index * 8][..8], but visit every item of `points` along the way
    fn lookup(points: &[u64; 512], index: u8) -> Self {
        let mut r = Self::default();
        let stride = r.xy.len();
        low::bignum_copy_row_from_table(
            &mut r.xy[..],
            points,
            (points.len() / stride) as u64,
            stride as u64,
            index as u64,
        );
        r
    }

    fn select(p0: &Self, p1: &Self, select: u8) -> Self {
        let mut r = Self::default();
        let select = select as u64;
        low::bignum_mux(select, &mut r.xy[..], &p1.xy[..], &p0.xy[..]);
        r
    }

    fn private_eq(&self, other: &Self) -> bool {
        low::bignum_eq(&self.xy, &other.xy)
    }

    fn is_infinity(&self) -> u8 {
        let zero = Self::default();
        self.private_eq(&zero) as u8
    }
}

#[derive(Clone, Copy, Debug)]
struct JacobianMontPoint {
    xyz: [u64; 12],
}

impl JacobianMontPoint {
    fn infinity() -> Self {
        Self {
            xyz: [1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    fn public_is_infinity(&self) -> bool {
        self.z().public_eq(&FieldElement::default())
    }

    fn zero() -> Self {
        Self { xyz: [0; 12] }
    }

    fn x(&self) -> FieldElement {
        FieldElement(self.xyz[0..4].try_into().unwrap())
    }

    fn y(&self) -> FieldElement {
        FieldElement(self.xyz[4..8].try_into().unwrap())
    }

    fn z(&self) -> FieldElement {
        FieldElement(self.xyz[8..12].try_into().unwrap())
    }

    fn set_z(&mut self, fe: &FieldElement) {
        self.xyz[8..12].copy_from_slice(&fe.0);
    }

    fn base_multiply(scalar: &Scalar) -> Self {
        Self::multiply_wnaf_7(scalar, &precomp::CURVE_GENERATOR_PRECOMP_WNAF_7)
    }

    fn multiply_wnaf_7(scalar: &Scalar, precomp: &AffineMontPointTableW7) -> Self {
        let mut terms = scalar.booth_recoded_w7();
        // unwrap: number of terms is constant
        let (digit, sign) = terms.next().unwrap();
        let mut tmp = AffineMontPoint::lookup_w7(&precomp[0], digit);
        tmp.maybe_negate_y(sign);

        let mut result = Self::from_affine(&tmp);
        result.set_z(&FieldElement::select(
            &FieldElement::default(),
            &CURVE_ONE_MONT,
            digit,
        ));

        let mut index = 1;
        for (digit, sign) in terms {
            let mut tmp = AffineMontPoint::lookup_w7(&precomp[index], digit);
            tmp.maybe_negate_y(sign);

            result.add_inplace_affine(&tmp);
            index += 1;
        }

        result
    }

    fn multiply_wnaf_5(scalar: &Scalar, precomp: &[Self; 16]) -> Self {
        let mut terms = scalar.reversed_booth_recoded_w5();

        let (digit, _, _) = terms.next().unwrap();
        let mut result = Self::lookup_w5(precomp, digit);
        result.double_inplace_n(5);

        for (digit, sign, last) in terms {
            let mut tmp = Self::lookup_w5(precomp, digit);
            tmp.maybe_negate_y(sign);
            result.add_inplace(&tmp);

            if !last {
                result.double_inplace_n(5);
            }
        }

        result
    }

    fn from_affine(p: &AffineMontPoint) -> Self {
        let mut xyz: [u64; 12] = Default::default();
        xyz[..8].copy_from_slice(&p.xy);
        xyz[8..12].copy_from_slice(&CURVE_ONE_MONT.0);
        Self { xyz }
    }

    fn as_affine(&self) -> AffineMontPoint {
        // recover (x, y) from (x / z ^ 2, x / z ^ 3, z)
        let z2 = self.z().mont_sqr();
        let z3 = self.z().mont_mul(&z2);

        // inversion calculated outside montgomery domain
        // (benchmarked vs addition chain in montgomery)
        let z2_inv = z2.demont().inv().as_mont();
        let z3_inv = z3.demont().inv().as_mont();

        let x = self.x().mont_mul(&z2_inv);
        let y = self.y().mont_mul(&z3_inv);

        AffineMontPoint::from_xy(x, y)
    }

    fn public_eq(&self, other: &Self) -> bool {
        // we can't compare these directly, because they could be
        // the same point but with different z factors.  instead,
        // convert one to affine, and then bring it back into
        // jacobian using other's z factors.
        let a = self.as_affine();

        let b_z2 = other.z().mont_sqr();
        let b_z3 = other.z().mont_mul(&b_z2);

        let a_x_b_z2 = a.x().mont_mul(&b_z2);
        let a_y_b_z3 = a.y().mont_mul(&b_z3);

        a_x_b_z2.public_eq(&other.x()) && a_y_b_z3.public_eq(&other.y())
    }

    fn x_scalar(&self) -> Scalar {
        // this is a faster version of `as_affine().x_scalar()`
        let z2 = self.z().mont_sqr();
        let z2_inv = z2.demont().inv().as_mont();
        let x = self.x().mont_mul(&z2_inv).demont();
        Scalar::from_bytes_reduced(&Array64x4(x.0).as_be_bytes()).unwrap()
    }

    #[must_use]
    fn double(&self) -> Self {
        let mut tmp = Self::zero();
        low::p256_montjdouble(&mut tmp.xyz, &self.xyz);
        tmp
    }

    fn double_inplace_n(&mut self, n: usize) {
        for _ in 0..n {
            let tmp = *self;
            low::p256_montjdouble(&mut self.xyz, &tmp.xyz);
        }
    }

    fn add_inplace(&mut self, p: &Self) {
        let mut r = Self::infinity();
        low::p256_montjadd(&mut r.xyz, &self.xyz, &p.xyz);
        *self = r;
    }

    fn add_inplace_affine(&mut self, p: &AffineMontPoint) {
        let mut r = Self::infinity();
        low::p256_montjmixadd(&mut r.xyz, &self.xyz, &p.xy);
        // XXX: annoyingly, p256_montjmixadd does not handle point at infinity correctly,
        // so do it here
        *self = Self::select(&r, self, p.is_infinity());
    }

    #[must_use]
    fn add(&self, p: &Self) -> Self {
        let mut r = Self::infinity();
        low::p256_montjadd(&mut r.xyz, &self.xyz, &p.xyz);
        r
    }

    /// Return p0 if select == 0, p1 otherwise
    #[must_use]
    fn select(p0: &Self, p1: &Self, select: u8) -> Self {
        let mut r = Self::zero();
        let select = select as u64;
        low::bignum_mux(select, &mut r.xyz[..], &p1.xyz[..], &p0.xyz[..]);
        r
    }

    /// Return points[index], but visit every item of `points` along the way
    #[must_use]
    fn lookup(points: &[Self], index: u8) -> Self {
        let mut r = Self::zero();
        low::bignum_copy_row_from_table(
            &mut r.xyz[..],
            &points[0].xyz[..],
            points.len() as u64,
            points[0].xyz.len() as u64,
            index as u64,
        );
        r
    }

    /// Returns table[i - 1] if index > 1, or else infinity
    fn lookup_w5(table: &[Self; 16], index: u8) -> Self {
        let zero = Self::infinity();
        const MASK4: u8 = (1 << 4) - 1;
        // assumption: wrapping_sub is branch-free
        let index0 = index.wrapping_sub(1) & MASK4;
        let table_point = Self::lookup(table, index0);
        Self::select(&zero, &table_point, index)
    }

    fn maybe_negate_y(&mut self, sign: u8) {
        let y = self.y();
        let neg_y = y.negate_mod_p();
        let result = FieldElement::select(&y, &neg_y, sign);
        self.xyz[4..8].copy_from_slice(&result.0);
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct FieldElement([u64; 4]);

impl FieldElement {
    fn inv(&self) -> Self {
        let mut r = Self::default();
        low::bignum_inv_p256(&mut r.0, &self.0);
        r
    }

    /// Montgomery squaring mod p256
    fn mont_sqr(&self) -> Self {
        let mut r = Self::default();
        low::bignum_montsqr_p256(&mut r.0, &self.0);
        r
    }

    /// Addition mod p256
    fn add(&self, other: &Self) -> Self {
        let mut r = Self::default();
        low::bignum_add_p256(&mut r.0, &self.0, &other.0);
        r
    }

    /// Montgomery multiplication mod p256
    fn mont_mul(&self, other: &Self) -> Self {
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
    fn as_mont(&self) -> Self {
        let mut r = Self::default();
        low::bignum_tomont_p256(&mut r.0, &self.0);
        r
    }

    fn negate_mod_p(&self) -> Self {
        let mut r = Self::default();
        low::bignum_neg_p256(&mut r.0, &self.0);
        r
    }

    /// Public equality
    fn public_eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    /// Return p0 if select == 0, p1 otherwise
    fn select(p0: &Self, p1: &Self, select: u8) -> Self {
        let mut r = Self::default();
        let select = select as u64;
        low::bignum_mux(select, &mut r.0[..], &p1.0[..], &p0.0[..]);
        r
    }
}

#[derive(Default)]
pub struct Scalar([u64; 4]);

impl Scalar {
    /// Create a scalar from the given slice, which can be any size.
    ///
    /// If it is larger than 32 bytes, the leading bytes must be
    /// zero (this is deemed a non-secret property).
    ///
    /// This returns an error if the scalar is zero or larger than
    /// the curve order.
    ///
    /// Prefer to use `from_array_checked` if you always have 32 bytes.
    pub fn from_bytes_checked(bytes: &[u8]) -> Result<Self, Error> {
        let full = Self(
            Array64x4::from_be_bytes_any_size(bytes)
                .ok_or(Error::WrongLength)?
                .0,
        );

        full.into_range_check()
    }

    /// Create a scalar from the given array.
    ///
    /// This returns an error if the scalar is zero or larger than
    /// the curve order.
    pub fn from_array_checked(array: &[u8; 32]) -> Result<Self, Error> {
        let full = Self(Array64x4::from_be(array).0);

        full.into_range_check()
    }

    pub fn from_bytes_reduced(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(
            Array64x4::from_be_bytes_any_size(bytes)
                .ok_or(Error::WrongLength)?
                .0,
        )
        .reduce_mod_n())
    }

    fn into_range_check(self) -> Result<Self, Error> {
        let reduced = self.reduce_mod_n();

        if !reduced.private_eq(&self) || self.is_zero() {
            Err(Error::OutOfRange)
        } else {
            Ok(self)
        }
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        Array64x4(self.0).as_be_bytes()
    }

    #[cfg(test)]
    fn small_u64(v: u64) -> Self {
        Scalar([v, 0, 0, 0])
    }

    /// Private test for zero
    pub fn is_zero(&self) -> bool {
        self.private_eq(&Self::default())
    }

    /// Private equality
    fn private_eq(&self, other: &Self) -> bool {
        low::bignum_eq(&self.0, &other.0)
    }

    /// Public equality
    fn public_eq(&self, other: &Self) -> bool {
        low::bignum_eq(&self.0, &other.0)
    }

    /// Reduce mod n (curve order)
    fn reduce_mod_n(&self) -> Self {
        let mut r = Self::default();
        low::bignum_mod_n256(&mut r.0, &self.0);
        r
    }

    /// Remove one montgomery factor mod n
    fn demont(&self) -> Self {
        let mut r = Self::default();
        low::bignum_demont(&mut r.0, &self.0, &CURVE_ORDER);
        r
    }

    /// Add a montgomery factor mod n
    fn as_mont(&self) -> Self {
        let mut r = Self::default();
        low::bignum_montmul(&mut r.0, &self.0, &CURVE_ORDER_MM, &CURVE_ORDER);
        r
    }

    /// Return 2^512 mod n, ie MM mod n
    fn montifier() -> Self {
        let mut r = Self::default();
        let mut tmp = Self::default();
        low::bignum_montifier(&mut r.0, &CURVE_ORDER, &mut tmp.0);
        r
    }

    /// Montgomery multiplication mod n
    ///
    /// Assumes `self` and `other` are in montgomery domain.
    /// Result is in montgomery domain.
    fn mont_mul(&self, other: &Self) -> Self {
        let mut r = Self::default();
        low::bignum_montmul(&mut r.0, &self.0, &other.0, &CURVE_ORDER);
        r
    }

    /// Find the multiplicative inverse of `self` mod n
    fn inv(&self) -> Self {
        let mut r = Self::default();
        let mut temp = [0u64; 4 * 3];
        low::bignum_modinv(&mut r.0, &self.0, &CURVE_ORDER, &mut temp);
        r
    }

    /// Add `self` + `other` mod n
    fn add(&self, other: &Self) -> Self {
        let mut r = Self::default();
        low::bignum_modadd(&mut r.0, &self.0, &other.0, &CURVE_ORDER);
        r
    }

    /// Iterator of the bits of the element, lowest first
    fn bits(&self) -> Bits<'_> {
        Bits {
            scalar: self,
            word: 0,
            bit: 0,
        }
    }

    /// Iterator of 37 * 7-bit elements, MSB first, sign bit is separate
    fn booth_recoded_w7(&self) -> BoothRecodeW7 {
        BoothRecodeW7::new(self)
    }

    /// Iterator of 51 * 5-bit elements, LSB first, sign bit and final flag is separate
    fn reversed_booth_recoded_w5(&self) -> BoothRecodeW5 {
        BoothRecodeW5::new(self)
    }
}

struct Bits<'a> {
    scalar: &'a Scalar,
    word: usize,
    bit: usize,
}

impl Iterator for Bits<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.word > 3 {
            return None;
        }

        let v = (self.scalar.0[self.word] >> self.bit) & 1;

        self.bit += 1;
        if self.bit == 64 {
            self.word += 1;
            self.bit = 0;
        }

        Some(v as u8)
    }
}

struct BoothRecodeW7 {
    // little endian
    bytes: [u8; 33],
    index: usize,
}

impl BoothRecodeW7 {
    fn new(scalar: &Scalar) -> Self {
        let mut bytes = [0u8; 33];

        bytes[0..8].copy_from_slice(&scalar.0[0].to_le_bytes());
        bytes[8..16].copy_from_slice(&scalar.0[1].to_le_bytes());
        bytes[16..24].copy_from_slice(&scalar.0[2].to_le_bytes());
        bytes[24..32].copy_from_slice(&scalar.0[3].to_le_bytes());

        Self { bytes, index: 0 }
    }

    fn recode(v: u8) -> (u8, u8) {
        // see the comment above boringssl's `ec_GFp_nistp_recode_scalar_bits` for
        // references
        let sign = !((v >> 7).wrapping_sub(1));

        let d = ((1u16 << 8) - (v as u16) - 1) as u8;
        let d = (d & sign) | (v & !sign);
        let d = (d >> 1) + (d & 1);

        (d, sign & 1)
    }
}

impl Iterator for BoothRecodeW7 {
    type Item = (u8, u8);

    fn next(&mut self) -> Option<Self::Item> {
        match self.index {
            0 => {
                self.index += 7;
                Some(Self::recode(self.bytes[0] << 1))
            }

            7..=252 => {
                let offset = (self.index - 1) / 8;
                let shift = (self.index - 1) % 8;
                let value = (((self.bytes[offset] as u16) | ((self.bytes[offset + 1] as u16) << 8))
                    >> shift) as u8;
                self.index += 7;
                Some(Self::recode(value))
            }

            _ => None,
        }
    }
}

struct BoothRecodeW5 {
    // little endian
    bytes: [u8; 33],
    index: usize,
}

impl BoothRecodeW5 {
    fn new(scalar: &Scalar) -> Self {
        let mut bytes = [0u8; 33];

        bytes[0..8].copy_from_slice(&scalar.0[0].to_le_bytes());
        bytes[8..16].copy_from_slice(&scalar.0[1].to_le_bytes());
        bytes[16..24].copy_from_slice(&scalar.0[2].to_le_bytes());
        bytes[24..32].copy_from_slice(&scalar.0[3].to_le_bytes());

        Self { bytes, index: 255 }
    }

    fn recode(v: u8) -> (u8, u8) {
        // see the comment above boringssl's `ec_GFp_nistp_recode_scalar_bits` for
        // references
        let sign = !((v >> 5).wrapping_sub(1));

        let d = ((1u16 << 6) - (v as u16) - 1) as u8;
        let d = (d & sign) | (v & !sign);
        let d = (d >> 1) + (d & 1);

        (d, sign & 1)
    }
}

impl Iterator for BoothRecodeW5 {
    type Item = (u8, u8, bool);

    fn next(&mut self) -> Option<Self::Item> {
        const MASK: u8 = (1 << (5 + 1)) - 1;

        match self.index {
            5..=255 => {
                let offset = (self.index - 1) / 8;
                let shift = (self.index - 1) % 8;
                let value = (((self.bytes[offset] as u16) | ((self.bytes[offset + 1] as u16) << 8))
                    >> shift) as u8
                    & MASK;
                let (digit, sign) = Self::recode(value);
                self.index -= 5;
                Some((digit, sign, false))
            }

            0 => {
                let value = (self.bytes[0] << 1) & MASK;
                let (digit, sign) = Self::recode(value);
                self.index = usize::MAX;
                Some((digit, sign, true))
            }

            _ => None,
        }
    }
}

/// 37 tables of 6 bits of exponent each.
///
/// 37 := ceil(256 / 7), ie taking 7 bits of exponent at a time.
/// Each 'row' builds in 7 successive doublings.
type AffineMontPointTableW7 = [[u64; 512]; 37];

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

const CURVE_ONE_MONT: FieldElement = FieldElement([
    0x0000_0000_0000_0001,
    0xffff_ffff_0000_0000,
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_fffe,
]);

const CURVE_ORDER: [u64; 4] = [
    0xf3b9_cac2_fc63_2551,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
];

const CURVE_ORDER_MM: [u64; 4] = [
    0x83244c95be79eea2,
    0x4699799c49bd6fa6,
    0x2845b2392b6bec59,
    0x66e12d94f3d95620,
];

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of_val;

    const CURVE_GENERATOR: AffineMontPoint = AffineMontPoint {
        xy: [
            0x79e7_30d4_18a9_143c,
            0x75ba_95fc_5fed_b601,
            0x79fb_732b_7762_2510,
            0x1890_5f76_a537_55c6,
            0xddf2_5357_ce95_560a,
            0x8b4a_b8e4_ba19_e45c,
            0xd2e8_8688_dd21_f325,
            0x8571_ff18_2588_5d85,
        ],
    };

    #[test]
    fn generator_on_curve() {
        println!("{CURVE_GENERATOR:x?}");
        assert!(CURVE_GENERATOR.on_curve());
        println!("demont {:x?}", CURVE_GENERATOR.as_bytes_uncompressed());
    }

    #[test]
    fn generate_key_1() {
        let scalar = Scalar::small_u64(1);
        let r = CURVE_GENERATOR.slow_multiply(&scalar);
        println!("raw {:x?}", r);
        println!("fmt {:x?}", r.as_bytes_uncompressed());
    }

    #[test]
    fn point_double() {
        let mut p = JacobianMontPoint::from_affine(&CURVE_GENERATOR);
        println!("p = {:x?}", p);
        p = p.double();
        println!("p2 = {:x?}", p);
        println!("p2 aff = {:x?}", p.as_affine());
        println!("enc = {:x?}", p.as_affine().as_bytes_uncompressed());
    }

    #[test]
    fn generate_key_2() {
        let scalar = Scalar::small_u64(2);
        let r = CURVE_GENERATOR.slow_multiply(&scalar);
        println!("raw {:x?}", r);
        println!("fmt {:x?}", r.as_bytes_uncompressed());
    }

    #[test]
    fn generate_key_3() {
        let scalar = Scalar::small_u64(3);
        let r = JacobianMontPoint::base_multiply(&scalar).as_affine();
        println!("raw {:x?}", r);
        println!("fmt {:x?}", r.as_bytes_uncompressed());

        let u = CURVE_GENERATOR.slow_multiply(&scalar);
        println!("raw {:x?}", u);
        println!("fmt {:x?}", u.as_bytes_uncompressed());
    }

    #[test]
    fn generate_key_99999999() {
        let scalar = Scalar::small_u64(99999999);
        let r = JacobianMontPoint::base_multiply(&scalar).as_affine();
        println!("raw {:x?}", r);
        println!("fmt {:x?}", r.as_bytes_uncompressed());

        let u = CURVE_GENERATOR.slow_multiply(&scalar);
        println!("raw {:x?}", u);
        println!("fmt {:x?}", u.as_bytes_uncompressed());
    }

    #[test]
    fn generate_key_known_answer() {
        let bytes = b"\x1F\x55\x45\x23\x08\x50\x8C\x6B\x24\x37\x0F\x22\x1E\xF1\xB3\xF9\x54\x46\xBE\x4F\x8A\x4B\x42\x8A\x5B\x51\xB7\x10\xC2\x68\x4C\x03";
        let private = PrivateKey::from_bytes(bytes).unwrap();
        println!("priv = {:x?}", private);
        let public = private.public_key_uncompressed();
        println!("pub = {:x?}", public);
        assert_eq!(&public,
               b"\x04\xcb\x8a\x14\x1c\xd7\xe4\x07\xaf\x69\xa5\x01\x88\xe9\x1c\xe5\x5d\xcc\xfd\x33\x48\xda\xba\x4a\x9c\x46\x64\x33\x2e\x95\x59\xb6\x81\x44\xfc\x1a\x61\xd8\x41\xe4\xdb\x80\x1b\x33\x51\x20\x12\x1d\x0b\xa4\x84\xb3\xc9\x53\xb3\x1d\x35\x1d\x7f\xa2\x13\x97\xd1\x25\x47");
    }

    #[test]
    fn test_raw_ecdsa_sign() {
        let private = PrivateKey::from_bytes(b"\xd1\xf6\xbc\xcc\x3e\x5a\x40\x1b\xcc\x2c\x21\xbe\x34\x90\xed\x38\xde\xf4\x93\x7f\x78\x06\x03\xf5\x2b\x23\xb9\xa6\xfa\x9c\xf6\x0e").unwrap();
        let k = PrivateKey::from_bytes(b"\xe7\x95\x37\xa1\xd7\x55\x45\x1f\x8c\x3c\xbf\xf7\x84\xea\x5c\x1c\xdf\xe1\x6b\x1d\x13\xe7\xbf\xbb\x04\xd7\xfd\x90\x57\xee\xee\xf7").unwrap();
        let e = Scalar::from_bytes_checked(b"\x2c\xf2\x4d\xba\x5f\xb0\xa3\x0e\x26\xe8\x3b\x2a\xc5\xb9\xe2\x9e\x1b\x16\x1e\x5c\x1f\xa7\x42\x5e\x73\x04\x33\x62\x93\x8b\x98\x24").unwrap();
        let r = Scalar::from_bytes_checked(b"\x78\xee\x34\xc8\xb6\x52\x29\x54\x96\x19\x79\x45\x2e\x6e\x0c\xe0\x68\x5d\x40\x42\x38\x41\xef\xeb\x06\xfe\x3e\x3f\xf7\xb6\x5d\xf5").unwrap();
        let s = private.raw_ecdsa_sign(&k, &e, &r);
        assert_eq!(format!("{:02x?}", s.as_bytes()),
               "[5b, c9, 8e, 7d, 28, 74, d0, 9d, e8, fb, da, 22, 34, 83, 24, 4f, a1, ba, a2, 6a, 71, 91, 4e, 8e, d4, 8f, 88, b8, 2d, 17, 0b, 4b]");
    }

    #[test]
    fn test_booth_recoded_w7() {
        let s = Scalar::small_u64(0x3bce_3c3e_27d2_604b);
        for (d, sign) in s.booth_recoded_w7() {
            println!("{d:x} {sign:x}");
        }
    }

    #[test]
    fn private_key_in_range() {
        assert_eq!(
            PrivateKey::from_bytes(&[0u8; 32]).unwrap_err(),
            Error::OutOfRange
        );

        // order rejected
        assert_eq!(PrivateKey::from_bytes(b"\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xbc\xe6\xfa\xad\xa7\x17\x9e\x84\xf3\xb9\xca\xc2\xfc\x63\x25\x51").unwrap_err(), Error::OutOfRange);

        // order + 1 rejected
        assert_eq!(PrivateKey::from_bytes(b"\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xbc\xe6\xfa\xad\xa7\x17\x9e\x84\xf3\xb9\xca\xc2\xfc\x63\x25\x52").unwrap_err(), Error::OutOfRange);

        // order - 1 is ok
        PrivateKey::from_bytes(b"\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xbc\xe6\xfa\xad\xa7\x17\x9e\x84\xf3\xb9\xca\xc2\xfc\x63\x25\x50").unwrap();
    }

    #[test]
    fn curve_field_elements_as_mont() {
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

        println!("G.x = {:x?}", CURVE_GENERATOR.x().as_mont());
        println!("G.y = {:x?}", CURVE_GENERATOR.y().as_mont());
        println!("a = {:x?}", CURVE_A.as_mont());
        println!("b = {:x?}", CURVE_B.as_mont());
        let one = FieldElement([1, 0, 0, 0]);
        println!("R = {:x?}", one.as_mont());
        println!("R * R = {:x?}", one.as_mont().as_mont());

        println!("montify n = {:016x?}", Scalar::montifier().0);
    }

    #[test]
    fn base_point_precomp_wnaf_7() {
        let precomp = CURVE_GENERATOR.public_precomp_wnaf_7_slow();

        println!(
            "pub(super) static CURVE_GENERATOR_PRECOMP_WNAF_7: super::AffineMontPointTableW7 = ["
        );
        for w in 0..37 {
            println!("    // 1G..64G << {}", w * 7);
            println!("    [");
            for p in 0..64 {
                for j in 0..8 {
                    println!("            0x{:016x}, ", precomp[w][p].xy[j]);
                }
            }
            println!("    ],");
        }
        println!("];");

        println!("");
        println!("table size is {} bytes", size_of_val(&precomp));
    }
}
