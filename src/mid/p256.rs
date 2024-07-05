use super::util::Array64x4;
use crate::low;
use core::fmt;
use core::mem;

mod precomp;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EcError {
    WrongLength,
    NotUncompressed,
    NotOnCurve,
    OutOfRange,
    RngFailed,
}

#[derive(Clone, Debug)]
pub struct PublicKey {
    point: AffineMontPoint,
    precomp_wnaf_5: [JacobianMontPoint; 16],
}

impl PublicKey {
    pub fn from_x962_uncompressed(bytes: &[u8]) -> Result<Self, EcError> {
        let point = AffineMontPoint::from_x962_uncompressed(bytes)?;
        Ok(PublicKey::from_affine(point))
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
}

pub struct PrivateKey {
    scalar: Scalar,
}

impl PrivateKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EcError> {
        Scalar::from_bytes_checked(bytes).map(|scalar| PrivateKey { scalar })
    }

    pub fn public_key(&self) -> Result<PublicKey, EcError> {
        let point = AffineMontPoint::base_multiply(&self.scalar);
        match point.on_curve() {
            true => Ok(PublicKey::from_affine(point)),
            false => Err(EcError::NotOnCurve),
        }
    }

    pub fn generate(rng: &mut dyn rand_core::RngCore) -> Result<Self, EcError> {
        for _ in 0..64 {
            let mut r = [0u8; 32];
            rng.try_fill_bytes(&mut r).map_err(|_| EcError::RngFailed)?;
            if let Ok(p) = PrivateKey::from_bytes(&r) {
                return Ok(p);
            }
        }

        Err(EcError::RngFailed)
    }

    pub fn diffie_hellman(&self, peer: &PublicKey) -> Result<SharedSecret, EcError> {
        let result = peer
            .point
            .multiply_wnaf_5(&self.scalar, &peer.precomp_wnaf_5);
        match result.on_curve() {
            true => Ok(SharedSecret(Array64x4(result.x().demont().0).as_be_bytes())),
            false => Err(EcError::NotOnCurve),
        }
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PrivateKey").finish_non_exhaustive()
    }
}

pub struct SharedSecret(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Default)]
struct AffineMontPoint {
    xy: [u64; 8],
}

impl AffineMontPoint {
    fn from_x962_uncompressed(bytes: &[u8]) -> Result<Self, EcError> {
        match bytes.first() {
            Some(&0x04) => (),
            Some(_) => return Err(EcError::NotUncompressed),
            None => return Err(EcError::WrongLength),
        }

        if bytes.len() != 1 + 64 {
            return Err(EcError::WrongLength);
        }

        let x = &bytes[1..33];
        let y = &bytes[33..65];

        let point = AffineMontPoint::from_xy(
            FieldElement(Array64x4::from_be_bytes(x).unwrap().0).as_mont(),
            FieldElement(Array64x4::from_be_bytes(y).unwrap().0).as_mont(),
        );

        if !point.on_curve() {
            return Err(EcError::NotOnCurve);
        }

        Ok(point)
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

    fn multiply(&self, scalar: &Scalar) -> AffineMontPoint {
        let mut result = JacobianMontPoint::infinity();

        let mut j = JacobianMontPoint::from_affine(self);
        let zero = JacobianMontPoint::zero();

        for bit in scalar.bits() {
            result.add_inplace(&JacobianMontPoint::select(&zero, &j, bit));
            j.double_inplace();
        }

        result.into_affine()
    }

    fn multiply_window4(
        &self,
        scalar: &Scalar,
        precomp: &[JacobianMontPoint; 16],
    ) -> AffineMontPoint {
        let mut result = JacobianMontPoint::infinity();

        for (first, val) in scalar.rev_bits().chunks(4) {
            if !first {
                result.double_inplace_n(4);
            }
            result.add_inplace(&JacobianMontPoint::lookup(precomp, val));
        }

        result.into_affine()
    }

    fn multiply_window8(
        &self,
        scalar: &Scalar,
        precomp: &[JacobianMontPoint; 256],
    ) -> AffineMontPoint {
        let mut result = JacobianMontPoint::infinity();

        let mut first = true;
        for val in scalar.rev_bytes() {
            if first {
                first = false;
            } else {
                result.double_inplace_n(8);
            }
            result.add_inplace(&JacobianMontPoint::lookup(precomp, val));
        }

        result.into_affine()
    }

    fn multiply_wnaf_5(
        &self,
        scalar: &Scalar,
        precomp: &[JacobianMontPoint; 16],
    ) -> AffineMontPoint {
        let mut terms = scalar.reversed_booth_recoded_w5();

        let (digit, _, _) = terms.next().unwrap();
        let mut result = JacobianMontPoint::lookup_w5(precomp, digit);
        result.double_inplace_n(5);

        for (digit, sign, last) in terms {
            let mut tmp = JacobianMontPoint::lookup_w5(precomp, digit);
            tmp.maybe_negate_y(sign);
            result.add_inplace(&tmp);

            if !last {
                result.double_inplace_n(5);
            }
        }

        result.into_affine()
    }

    fn multiply_wnaf_7(
        &self,
        scalar: &Scalar,
        precomp: &[[AffineMontPoint; 64]; 37],
    ) -> AffineMontPoint {
        let mut terms = scalar.booth_recoded_w7();
        // unwrap: number of terms is constant
        let (digit, sign) = terms.next().unwrap();
        let mut tmp = AffineMontPoint::lookup_w7(&precomp[0], digit);
        tmp.maybe_negate_y(sign);

        let mut result = JacobianMontPoint::from_affine(&tmp);
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

        result.into_affine()
    }

    fn maybe_negate_y(&mut self, sign: u8) {
        let y = self.y();
        let neg_y = y.negate_mod_p();
        let result = FieldElement::select(&y, &neg_y, sign);
        self.xy[4..8].copy_from_slice(&result.0);
    }

    fn base_multiply(scalar: &Scalar) -> AffineMontPoint {
        //CURVE_GENERATOR.multiply_window4(scalar, &precomp::CURVE_GENERATOR_PRECOMP_4)
        //CURVE_GENERATOR.multiply_window8(scalar, &precomp::CURVE_GENERATOR_PRECOMP_8)
        CURVE_GENERATOR.multiply_wnaf_7(scalar, &precomp::CURVE_GENERATOR_PRECOMP_WNAF_7)
    }

    fn public_precomp4(&self) -> [JacobianMontPoint; 16] {
        let mut j = JacobianMontPoint::from_affine(self);
        let inf = JacobianMontPoint::infinity();

        let mut r = [JacobianMontPoint::zero(); 16];

        // first compute the power two terms
        for i in 0..4 {
            r[1 << i] = inf.add(&j);
            j.double_inplace();
        }

        for i in (3..16).step_by(2) {
            r[i] = r[2].add(&r[i - 2]);
        }

        for i in [6, 10, 12, 14] {
            r[i] = r[2].add(&r[i - 2]);
        }

        r
    }

    fn public_precomp8(&self) -> [JacobianMontPoint; 256] {
        let mut j = JacobianMontPoint::from_affine(self);
        let inf = JacobianMontPoint::infinity();

        let mut r = [JacobianMontPoint::zero(); 256];

        // first compute the power two terms
        for i in 0..8 {
            r[1 << i] = inf.add(&j);
            j.double_inplace();
        }

        for i in (3..256).step_by(2) {
            r[i] = r[2].add(&r[i - 2]);
        }

        for i in (2usize..256).step_by(2) {
            if i.next_power_of_two() != i {
                r[i] = r[2].add(&r[i - 2]);
            }
        }

        r
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
    /// items in a given row several times (compare `public_precomp4`).
    fn public_precomp_wnaf_7_slow(&self) -> [[AffineMontPoint; 64]; 37] {
        let mut r = [[AffineMontPoint::default(); 64]; 37];

        for window in 0..((256 + 6) / 7) {
            let row = &mut r[window];

            // indices into rows are reduced by 1 since 0G does not require
            // storage.  therefore row[0] is 1G << shift.
            let mut first = JacobianMontPoint::from_affine(self);
            first.double_inplace_n(window * 7);
            row[0] = first.into_affine();

            for r in 1..64 {
                row[r] = row[0].multiply(&Scalar([(r + 1) as u64, 0, 0, 0]));
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

    /// Returns table[i - 1] if index > 1, or else AffineMontPoint::default()
    fn lookup_w7(table: &[AffineMontPoint; 64], index: u8) -> Self {
        let zero = AffineMontPoint::default();
        const MASK6: u8 = (1 << 6) - 1;
        // assumption: wrapping_sub is branch-free
        let index0 = index.wrapping_sub(1) & MASK6;
        let table_point = AffineMontPoint::lookup(table, index0);
        Self::select(&zero, &table_point, index)
    }

    /// Return points[index], but visit every item of `points` along the way
    fn lookup(points: &[AffineMontPoint], index: u8) -> AffineMontPoint {
        let mut r = AffineMontPoint::default();
        low::bignum_copy_row_from_table(
            &mut r.xy[..],
            &points[0].xy[..],
            points.len() as u64,
            points[0].xy.len() as u64,
            index as u64,
        );
        r
    }

    fn select(p0: &AffineMontPoint, p1: &AffineMontPoint, select: u8) -> Self {
        let mut r = AffineMontPoint::default();
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

    fn from_affine(p: &AffineMontPoint) -> Self {
        let mut xyz: [u64; 12] = Default::default();
        xyz[..8].copy_from_slice(&p.xy);
        xyz[8..12].copy_from_slice(&CURVE_ONE_MONT.0);
        Self { xyz }
    }

    /*
    fn to_affine_x(&self) -> FieldElement {
        // recover (x, _) from (x / z ^ 2, x / z ^ 3, z)
        let zi = self.z().inv();
        debug_assert!(!zi.public_eq(&FieldElement::default()));


    }
    */

    fn into_affine(self) -> AffineMontPoint {
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

    #[must_use]
    fn double(&self) -> Self {
        let mut tmp = Self::zero();
        low::p256_montjdouble(&mut tmp.xyz, &self.xyz);
        tmp
    }

    fn double_inplace(&mut self) {
        let tmp = *self;
        low::p256_montjdouble(&mut self.xyz, &tmp.xyz);
    }

    fn double_inplace_n(&mut self, n: usize) {
        for _ in 0..n {
            let tmp = *self;
            low::p256_montjdouble(&mut self.xyz, &tmp.xyz);
        }
    }

    fn add_inplace(&mut self, p: &JacobianMontPoint) {
        let mut r = JacobianMontPoint::infinity();
        low::p256_montjadd(&mut r.xyz, &self.xyz, &p.xyz);
        *self = r;
    }

    fn add_inplace_affine(&mut self, p: &AffineMontPoint) {
        let mut r = JacobianMontPoint::infinity();
        low::p256_montjmixadd(&mut r.xyz, &self.xyz, &p.xy);
        // XXX: annoyingly, p256_montjmixadd does not handle point at infinity correctly,
        // so do it here
        *self = Self::select(&r, self, p.is_infinity());
    }

    #[must_use]
    fn add(&self, p: &JacobianMontPoint) -> JacobianMontPoint {
        let mut r = JacobianMontPoint::infinity();
        low::p256_montjadd(&mut r.xyz, &self.xyz, &p.xyz);
        r
    }

    /// Return p0 if select == 0, p1 otherwise
    #[must_use]
    fn select(p0: &JacobianMontPoint, p1: &JacobianMontPoint, select: u8) -> JacobianMontPoint {
        let mut r = JacobianMontPoint::zero();
        let select = select as u64;
        low::bignum_mux(select, &mut r.xyz[..], &p1.xyz[..], &p0.xyz[..]);
        r
    }

    /// Return points[index], but visit every item of `points` along the way
    #[must_use]
    fn lookup(points: &[JacobianMontPoint], index: u8) -> JacobianMontPoint {
        let mut r = JacobianMontPoint::zero();
        low::bignum_copy_row_from_table(
            &mut r.xyz[..],
            &points[0].xyz[..],
            points.len() as u64,
            points[0].xyz.len() as u64,
            index as u64,
        );
        r
    }

    /// Returns table[i - 1] if index > 1, or else JacobianMontPoint::infinity()
    fn lookup_w5(table: &[JacobianMontPoint; 16], index: u8) -> Self {
        let zero = JacobianMontPoint::infinity();
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
    fn zero() -> Self {
        Self::default()
    }

    fn one() -> Self {
        Self::small_u64(1)
    }

    fn small_u64(v: u64) -> Self {
        let mut r = Self::default();
        r.0[0] = v;
        r
    }

    fn inv(&self) -> Self {
        let mut r = Self::default();
        low::bignum_inv_p256(&mut r.0, &self.0);
        r
    }

    fn mont_inv(&self) -> Self {
        // See https://github.com/mmcloughlin/addchain/blob/master/doc/results.md#nist-p-256-field-inversion
        // _10     = 2*1
        // _11     = 1 + _10
        // _1100   = _11 << 2
        // _1111   = _11 + _1100
        // _111100 = _1111 << 2
        // _111111 = _11 + _111100
        // x12     = _111111 << 6 + _111111
        // x24     = x12 << 12 + x12
        // x30     = x24 << 6 + _111111
        // x32     = x30 << 2 + _11
        // i232    = ((x32 << 32 + 1) << 128 + x32) << 32
        // return    ((x32 + i232) << 30 + x30) << 2

        // 	p256Sqr(z, in, 1)
        // 	p256Mul(z, in, z)
        // 	p256Sqr(z, z, 1)
        // 	p256Mul(z, in, z)
        let z = self.mont_sqr();
        let z = self.mont_mul(&z);
        let z = z.mont_sqr();
        let z = self.mont_mul(&z);

        // 	p256Sqr(t0, z, 3)
        // 	p256Mul(t0, z, t0)
        // 	p256Sqr(t1, t0, 6)
        // 	p256Mul(t0, t0, t1)
        let t0 = z.mont_sqr_n(3);
        let t0 = z.mont_mul(&t0);
        let t1 = t0.mont_sqr_n(6);
        let t0 = t0.mont_mul(&t1);

        // 	p256Sqr(t0, t0, 3)
        // 	p256Mul(z, z, t0)
        // 	p256Sqr(t0, z, 1)
        // 	p256Mul(t0, in, t0)
        let t0 = t0.mont_sqr_n(3);
        let z = z.mont_mul(&t0);
        let t0 = z.mont_sqr();
        let t0 = self.mont_mul(&t0);

        // 	p256Sqr(t1, t0, 16)
        // 	p256Mul(t0, t0, t1)
        // 	p256Sqr(t0, t0, 15)
        // 	p256Mul(z, z, t0)
        let t1 = t0.mont_sqr_n(16);
        let t0 = t0.mont_mul(&t1);
        let t0 = t0.mont_sqr_n(15);
        let z = z.mont_mul(&t0);

        // 	p256Sqr(t0, t0, 17)
        // 	p256Mul(t0, in, t0)
        // 	p256Sqr(t0, t0, 143)
        // 	p256Mul(t0, z, t0)
        let t0 = t0.mont_sqr_n(17);
        let t0 = self.mont_mul(&t0);
        let t0 = t0.mont_sqr_n(143);
        let t0 = z.mont_mul(&t0);

        // 	p256Sqr(t0, t0, 47)
        // 	p256Mul(z, z, t0)
        // 	p256Sqr(z, z, 2)
        // 	p256Mul(out, in, z)
        let t0 = t0.mont_sqr_n(47);
        let z = z.mont_mul(&t0);
        let z = z.mont_sqr_n(2);
        self.mont_mul(&z)
    }

    /// Montgomery squaring mod p256
    fn mont_sqr(&self) -> Self {
        let mut r = Self::default();
        low::bignum_montsqr_p256(&mut r.0, &self.0);
        r
    }

    /// Montgomery repeated squaring mod p256
    fn mont_sqr_n(&self, n: usize) -> Self {
        let mut r = Self::default();
        let mut input = *self;
        for _ in 0..n {
            low::bignum_montsqr_p256(&mut r.0, &input.0);
            input = r;
        }
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
    fn public_eq(&self, other: &FieldElement) -> bool {
        self.0 == other.0
    }

    /// Return p0 if select == 0, p1 otherwise
    fn select(p0: &FieldElement, p1: &FieldElement, select: u8) -> Self {
        let mut r = FieldElement::default();
        let select = select as u64;
        low::bignum_mux(select, &mut r.0[..], &p1.0[..], &p0.0[..]);
        r
    }
}

#[derive(Default)]
struct Scalar([u64; 4]);

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
    pub fn from_bytes_checked(bytes: &[u8]) -> Result<Self, EcError> {
        let full = Self(
            Array64x4::from_be_bytes_any_size(bytes)
                .ok_or(EcError::WrongLength)?
                .0,
        );

        full.into_range_check()
    }

    /// Create a scalar from the given array.
    ///
    /// This returns an error if the scalar is zero or larger than
    /// the curve order.
    pub fn from_array_checked(array: &[u8; 32]) -> Result<Self, EcError> {
        let full = Self(Array64x4::from_be(array).0);

        full.into_range_check()
    }

    fn into_range_check(self) -> Result<Self, EcError> {
        let reduced = self.reduce_mod_n();

        if !reduced.private_eq(&self) || self.is_zero() {
            Err(EcError::OutOfRange)
        } else {
            Ok(self)
        }
    }

    #[cfg(test)]
    fn small_u64(v: u64) -> Self {
        Scalar([v, 0, 0, 0])
    }

    /// Private test for zero
    fn is_zero(&self) -> bool {
        self.private_eq(&Scalar::default())
    }

    /// Private equality
    fn private_eq(&self, other: &Self) -> bool {
        low::bignum_eq(&self.0, &other.0)
    }

    /// Reduce mod n (curve order)
    fn reduce_mod_n(&self) -> Self {
        let mut r = Self::default();
        low::bignum_mod_n256(&mut r.0, &self.0);
        r
    }

    /// Iterator of the bits of the element, lowest first
    fn bits(&self) -> Bits {
        Bits {
            scalar: self,
            word: 0,
            bit: 0,
        }
    }

    /// Iterator of the bits of the element, highest first
    fn rev_bits(&self) -> RevBits {
        RevBits {
            scalar: self,
            word: 3,
            bit: 64,
        }
    }

    /// Iterator of the bytes of the element, highest first
    fn rev_bytes(&self) -> RevBytes {
        RevBytes {
            scalar: self,
            byte: 32,
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

struct RevBits<'a> {
    scalar: &'a Scalar,
    word: usize,
    bit: usize,
}

impl<'a> RevBits<'a> {
    fn chunks(self, nbits: u8) -> Chunks<'a> {
        debug_assert!(256usize % (nbits as usize) == 0);
        Chunks {
            bits: self,
            nbits,
            first: true,
        }
    }
}

impl Iterator for RevBits<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.word == 0 && self.bit == 0 {
            return None;
        }

        if self.bit == 0 {
            self.word -= 1;
            self.bit = 64;
        }

        self.bit -= 1;
        let v = (self.scalar.0[self.word] >> self.bit) & 1;

        Some(v as u8)
    }
}

struct Chunks<'a> {
    bits: RevBits<'a>,
    nbits: u8,
    first: bool,
}

impl Iterator for Chunks<'_> {
    type Item = (bool, u8);

    fn next(&mut self) -> Option<Self::Item> {
        let mut val = 0;

        for _ in 0..self.nbits {
            val <<= 1;
            let bit = self.bits.next()?;
            val |= bit;
        }

        let first = mem::take(&mut self.first);
        Some((first, val))
    }
}

struct RevBytes<'a> {
    scalar: &'a Scalar,
    byte: usize,
}

impl Iterator for RevBytes<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.byte == 0 {
            return None;
        }

        self.byte -= 1;

        let word = self.byte >> 3;
        let shift = (self.byte & 7) * 8;
        Some((self.scalar.0[word] >> shift) as u8)
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
/*
const CURVE_P: FieldElement = FieldElement([
    0xffff_ffff_0000_0001,
    0x0000_0000_0000_0000,
    0x0000_0000_ffff_ffff,
    0xffff_ffff_ffff_ffff,
]);
*/

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
const CURVE_RR: FieldElement = FieldElement([
    0x0000_0000_0000_0003,
    0xffff_fffb_ffff_ffff,
    0xffff_ffff_ffff_fffe,
    0x0000_0004_ffff_fffd,
]);

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
    let r = CURVE_GENERATOR.multiply(&scalar);
    println!("raw {:x?}", r);
    println!("fmt {:x?}", r.as_bytes_uncompressed());
}

#[test]
fn point_double() {
    let mut p = JacobianMontPoint::from_affine(&CURVE_GENERATOR);
    println!("p = {:x?}", p);
    p.double_inplace();
    println!("p2 = {:x?}", p);
    println!("p2 aff = {:x?}", p.into_affine());
    println!("enc = {:x?}", p.into_affine().as_bytes_uncompressed());
}

#[test]
fn generate_key_2() {
    let scalar = Scalar::small_u64(2);
    let r = CURVE_GENERATOR.multiply(&scalar);
    println!("raw {:x?}", r);
    println!("fmt {:x?}", r.as_bytes_uncompressed());
}

#[test]
fn generate_key_3() {
    let scalar = Scalar::small_u64(3);
    let r = AffineMontPoint::base_multiply(&scalar);
    println!("raw {:x?}", r);
    println!("fmt {:x?}", r.as_bytes_uncompressed());

    let u = CURVE_GENERATOR.multiply(&scalar);
    println!("raw {:x?}", u);
    println!("fmt {:x?}", u.as_bytes_uncompressed());
}

#[test]
fn generate_key_99999999() {
    let scalar = Scalar::small_u64(99999999);
    let r = AffineMontPoint::base_multiply(&scalar);
    println!("raw {:x?}", r);
    println!("fmt {:x?}", r.as_bytes_uncompressed());

    let u = CURVE_GENERATOR.multiply(&scalar);
    println!("raw {:x?}", u);
    println!("fmt {:x?}", u.as_bytes_uncompressed());
}

#[test]
fn generate_key_known_answer() {
    let bytes = b"\x1F\x55\x45\x23\x08\x50\x8C\x6B\x24\x37\x0F\x22\x1E\xF1\xB3\xF9\x54\x46\xBE\x4F\x8A\x4B\x42\x8A\x5B\x51\xB7\x10\xC2\x68\x4C\x03";
    let private = PrivateKey::from_bytes(bytes).unwrap();
    println!("priv = {:x?}", private);
    let public = private.public_key().unwrap();
    println!("pub = {:x?}", public.as_bytes_uncompressed());
    assert_eq!(&public.as_bytes_uncompressed(),
               b"\x04\xcb\x8a\x14\x1c\xd7\xe4\x07\xaf\x69\xa5\x01\x88\xe9\x1c\xe5\x5d\xcc\xfd\x33\x48\xda\xba\x4a\x9c\x46\x64\x33\x2e\x95\x59\xb6\x81\x44\xfc\x1a\x61\xd8\x41\xe4\xdb\x80\x1b\x33\x51\x20\x12\x1d\x0b\xa4\x84\xb3\xc9\x53\xb3\x1d\x35\x1d\x7f\xa2\x13\x97\xd1\x25\x47");
}

#[test]
fn test_rev_bits() {
    let mut s = Scalar::small_u64(1);
    s.0[3] = 0x55 << 56;
    for b in s.rev_bits() {
        println!("{b:x}");
    }

    println!("chunks:");
    for (first, b) in s.rev_bits().chunks(4) {
        println!("{first} {b:x}");
    }
}

#[test]
fn test_rev_bytes() {
    let mut s = Scalar::small_u64(0x44332211);
    s.0[3] = 0x55 << 56;

    for b in s.rev_bytes() {
        println!("{b:x}");
    }
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
        EcError::OutOfRange
    );

    // order rejected
    assert_eq!(PrivateKey::from_bytes(b"\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xbc\xe6\xfa\xad\xa7\x17\x9e\x84\xf3\xb9\xca\xc2\xfc\x63\x25\x51").unwrap_err(), EcError::OutOfRange);

    // order + 1 rejected
    assert_eq!(PrivateKey::from_bytes(b"\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xbc\xe6\xfa\xad\xa7\x17\x9e\x84\xf3\xb9\xca\xc2\xfc\x63\x25\x52").unwrap_err(), EcError::OutOfRange);

    // order - 1 is ok
    PrivateKey::from_bytes(b"\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xbc\xe6\xfa\xad\xa7\x17\x9e\x84\xf3\xb9\xca\xc2\xfc\x63\x25\x50").unwrap();
}

#[test]
fn curve_field_elements_as_mont() {
    println!("G.x = {:x?}", CURVE_GENERATOR.x().as_mont());
    println!("G.y = {:x?}", CURVE_GENERATOR.y().as_mont());
    println!("a = {:x?}", CURVE_A.as_mont());
    println!("b = {:x?}", CURVE_B.as_mont());
    println!("R = {:x?}", FieldElement::one().as_mont());
    println!("R * R = {:x?}", FieldElement::one().as_mont().as_mont());
}

#[test]
fn base_point_precomp_4() {
    let precomp = CURVE_GENERATOR.public_precomp4();

    println!("pub(super) static CURVE_GENERATOR_PRECOMP_4: [JacobianMontPoint; 16] = [");
    for i in 0..16 {
        println!("    // {}G", i);
        println!("    JacobianMontPoint {{ xyz: [");
        for j in 0..12 {
            println!("0x{:016x}, ", precomp[i].xyz[j]);
        }
        println!("    ]}},");

        // cross-check
        let expect = CURVE_GENERATOR.multiply(&Scalar::small_u64(i as u64));
        assert_eq!(
            expect.as_bytes_uncompressed(),
            precomp[i].into_affine().as_bytes_uncompressed(),
        );
    }
    println!("];");
}

#[test]
fn base_point_precomp_8() {
    let precomp = CURVE_GENERATOR.public_precomp8();

    println!("pub(super) static CURVE_GENERATOR_PRECOMP_8: [JacobianMontPoint; 256] = [");
    for i in 0..256 {
        println!("    // {}G", i);
        println!("    JacobianMontPoint {{ xyz: [");
        for j in 0..12 {
            println!("0x{:016x}, ", precomp[i].xyz[j]);
        }
        println!("    ]}},");

        // cross-check
        let expect = CURVE_GENERATOR.multiply(&Scalar::small_u64(i as u64));
        assert_eq!(
            expect.as_bytes_uncompressed(),
            precomp[i].into_affine().as_bytes_uncompressed(),
        );
    }
    println!("];");
}

#[test]
fn base_point_precomp_wnaf_7() {
    let precomp = CURVE_GENERATOR.public_precomp_wnaf_7_slow();

    println!("pub(super) static CURVE_GENERATOR_PRECOMP_WNAF_7: [[AffineMontPoint; 64]; 37] = [");
    for w in 0..37 {
        println!("    // 1G..64G << {}", w);
        println!("    [");
        for p in 0..64 {
            println!("        AffineMontPoint {{ xy: [");
            for j in 0..8 {
                println!("            0x{:016x}, ", precomp[w][p].xy[j]);
            }
            println!("]}},");
        }
        println!("    ],");
    }
    println!("];");

    println!("");
    // "The pre-computed (fixed) tables require slightly more than 150KB"
    println!("table size is {} bytes", mem::size_of_val(&precomp));
}

/*
// benchmarks for division by Z ^ 2 and Z ^ 3 in projective jacobian -> affine
// conversions

#[bench]
fn bench_mont_inv(b: &mut test::Bencher) {
    let z = FieldElement([
        0xbbe4a6af9d2aac15,
        0x169571c87433c8b9,
        0xa5d10d11ba43e64b,
        0x0ae3fe314b10bb0a,
    ]);
    b.iter(|| {
        let z2 = z.mont_sqr();
        let _z2_inv = test::black_box(z2.mont_inv());
        let _z3_inv = test::black_box(z2.mont_mul(&z).mont_inv());
    });
}

#[bench]
fn bench_inv(b: &mut test::Bencher) {
    let z = FieldElement([
        0xbbe4a6af9d2aac15,
        0x169571c87433c8b9,
        0xa5d10d11ba43e64b,
        0x0ae3fe314b10bb0a,
    ]);
    b.iter(|| {
        let z2 = z.mont_sqr();
        let _z2_inv = test::black_box(z2.demont().inv().as_mont());
        let _z3_inv = test::black_box(z2.mont_mul(&z).demont().inv().as_mont());
    });
}
*/
