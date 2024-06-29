use super::util::Array64x4;
use crate::low;
use core::mem;

mod precomp;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy)]
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
    precomp4: [JacobianMontPoint; 16],
}

impl PublicKey {
    pub fn from_x962_uncompressed(bytes: &[u8]) -> Result<Self, EcError> {
        let point = AffineMontPoint::from_x962_uncompressed(bytes)?;
        Ok(PublicKey::from_affine(point))
    }

    fn from_affine(point: AffineMontPoint) -> Self {
        Self {
            precomp4: point.public_precomp4(),
            point,
        }
    }
}

pub struct PrivateKey {
    scalar: FieldElement,
}

impl PrivateKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EcError> {
        let full = FieldElement(
            Array64x4::from_be_bytes_any_size(bytes)
                .ok_or(EcError::WrongLength)?
                .0,
        );

        let reduced = full.reduce_mod_n();

        if !reduced.private_eq(&full) {
            return Err(EcError::OutOfRange);
        }

        Ok(PrivateKey { scalar: reduced })
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
        let result = peer.point.multiply_window4(&self.scalar, &peer.precomp4);
        match result.on_curve() {
            true => Ok(SharedSecret(Array64x4(result.x.demont().0).as_be_bytes())),
            false => Err(EcError::NotOnCurve),
        }
    }
}

pub struct SharedSecret(pub [u8; 32]);

#[derive(Clone, Debug)]
struct AffineMontPoint {
    x: FieldElement,
    y: FieldElement,
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

        let point = AffineMontPoint {
            x: FieldElement(Array64x4::from_be_bytes(x).unwrap().0).to_mont(),
            y: FieldElement(Array64x4::from_be_bytes(y).unwrap().0).to_mont(),
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

        let rhs = self.x.mont_sqr(); // x ^ 2
        let rhs = rhs.add(&CURVE_A_MONT); // x ^ 2 + a
        let rhs = rhs.mont_mul(&self.x); // (x ^ 2 + a) * x   equiv  x ^ 3 + ax
        let rhs = rhs.add(&CURVE_B_MONT);

        let lhs = self.y.mont_sqr();

        lhs.public_eq(&rhs)
    }

    fn as_bytes_uncompressed(&self) -> [u8; 65] {
        let mut r = [0u8; 65];
        r[0] = 0x04;

        r[1..33].copy_from_slice(&Array64x4(self.x.demont().0).as_be_bytes());
        r[33..65].copy_from_slice(&Array64x4(self.y.demont().0).as_be_bytes());
        r
    }

    fn multiply(&self, scalar: &FieldElement) -> AffineMontPoint {
        let mut result = JacobianMontPoint::infinity();

        let mut j = JacobianMontPoint::from_affine(self);
        let zero = JacobianMontPoint::zero();

        for bit in scalar.bits() {
            result.add_inplace(&JacobianMontPoint::select(&zero, &j, bit));
            j.double();
        }

        result.to_affine()
    }

    fn multiply_window4(
        &self,
        scalar: &FieldElement,
        precomp: &[JacobianMontPoint; 16],
    ) -> AffineMontPoint {
        let mut result = JacobianMontPoint::infinity();

        for (first, val) in scalar.rev_bits().chunks(4) {
            if !first {
                result.double_n(4);
            }
            result.add_inplace(&JacobianMontPoint::lookup(precomp, val));
        }

        result.to_affine()
    }

    fn multiply_window8(
        &self,
        scalar: &FieldElement,
        precomp: &[JacobianMontPoint; 256],
    ) -> AffineMontPoint {
        let mut result = JacobianMontPoint::infinity();

        let mut first = true;
        for val in scalar.rev_bytes() {
            if first {
                first = false;
            } else {
                result.double_n(8);
            }
            result.add_inplace(&JacobianMontPoint::lookup(precomp, val));
        }

        result.to_affine()
    }

    fn base_multiply(scalar: &FieldElement) -> AffineMontPoint {
        //CURVE_GENERATOR.multiply_window4(scalar, &precomp::CURVE_GENERATOR_PRECOMP_4)
        CURVE_GENERATOR.multiply_window8(scalar, &precomp::CURVE_GENERATOR_PRECOMP_8)
    }

    fn public_precomp4(&self) -> [JacobianMontPoint; 16] {
        let mut j = JacobianMontPoint::from_affine(self);
        let inf = JacobianMontPoint::infinity();

        let mut r = [JacobianMontPoint::zero(); 16];

        // first compute the power two terms
        for i in 0..4 {
            r[1 << i] = inf.add(&j);
            j.double();
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
            j.double();
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

    fn view_x(&self) -> &[u64; 4] {
        (&self.xyz[0..4]).try_into().unwrap()
    }

    fn mut_x(&mut self) -> &mut [u64; 4] {
        (&mut self.xyz[0..4]).try_into().unwrap()
    }

    fn view_y(&self) -> &[u64; 4] {
        (&self.xyz[4..8]).try_into().unwrap()
    }

    fn mut_y(&mut self) -> &mut [u64; 4] {
        (&mut self.xyz[4..8]).try_into().unwrap()
    }

    fn view_z(&self) -> &[u64; 4] {
        (&self.xyz[8..12]).try_into().unwrap()
    }

    fn mut_z(&mut self) -> &mut [u64; 4] {
        (&mut self.xyz[8..12]).try_into().unwrap()
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

    fn from_affine(p: &AffineMontPoint) -> Self {
        let mut xyz: [u64; 12] = Default::default();
        xyz[..4].copy_from_slice(&p.x.0);
        xyz[4..8].copy_from_slice(&p.y.0);
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

    fn to_affine(&self) -> AffineMontPoint {
        // recover (x, y) from (x / z ^ 2, x / z ^ 3, z)
        let z2 = self.z().mont_sqr();
        let z3 = self.z().mont_mul(&z2);

        // inversion calculated outside montgomery domain
        // (benchmarked vs addition chain in montgomery)
        let z2_inv = z2.demont().inv().to_mont();
        let z3_inv = z3.demont().inv().to_mont();

        let x = self.x().mont_mul(&z2_inv);
        let y = self.y().mont_mul(&z3_inv);

        AffineMontPoint { x, y }
    }

    fn double(&mut self) {
        let tmp = *self;
        low::p256_montjdouble(&mut self.xyz, &tmp.xyz);
    }

    fn double_n(&mut self, n: usize) {
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

    fn add(&self, p: &JacobianMontPoint) -> JacobianMontPoint {
        let mut r = JacobianMontPoint::infinity();
        low::p256_montjadd(&mut r.xyz, &self.xyz, &p.xyz);
        r
    }

    /// Return p0 if select == 0, p1 otherwise
    fn select(p0: &JacobianMontPoint, p1: &JacobianMontPoint, select: u8) -> JacobianMontPoint {
        let mut r = JacobianMontPoint::zero();
        let select = select as u64;
        low::bignum_mux(select, &mut r.xyz[..], &p1.xyz[..], &p0.xyz[..]);
        r
    }

    /// Return points[index], but visit every item of `points` along the way
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
}

#[derive(Debug, Default, Clone)]
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
        let mut input = self.clone();
        for _ in 0..n {
            low::bignum_montsqr_p256(&mut r.0, &input.0);
            input = r.clone();
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
    fn to_mont(&self) -> Self {
        let mut r = Self::default();
        low::bignum_tomont_p256(&mut r.0, &self.0);
        r
    }

    /// Reduce mod n (curve order)
    fn reduce_mod_n(&self) -> Self {
        let mut r = Self::default();
        low::bignum_mod_n256(&mut r.0, &self.0);
        r
    }

    /// Public equality
    fn public_eq(&self, other: &FieldElement) -> bool {
        self.0 == other.0
    }

    /// Private equality
    fn private_eq(&self, other: &FieldElement) -> bool {
        low::bignum_eq(&self.0, &other.0)
    }

    /// Iterator of the bits of the element, lowest first
    fn bits(&self) -> Bits {
        Bits {
            fe: self,
            word: 0,
            bit: 0,
        }
    }

    /// Iterator of the bits of the element, highest first
    fn rev_bits(&self) -> RevBits {
        RevBits {
            fe: self,
            word: 3,
            bit: 64,
        }
    }

    /// Iterator of the bytes of the element, highest first
    fn rev_bytes(&self) -> RevBytes {
        RevBytes { fe: self, byte: 32 }
    }
}

struct Bits<'a> {
    fe: &'a FieldElement,
    word: usize,
    bit: usize,
}

impl Iterator for Bits<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.word > 3 {
            return None;
        }

        let v = (self.fe.0[self.word] >> self.bit) & 1;

        self.bit += 1;
        if self.bit == 64 {
            self.word += 1;
            self.bit = 0;
        }

        Some(v as u8)
    }
}

struct RevBits<'a> {
    fe: &'a FieldElement,
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
        let v = (self.fe.0[self.word] >> self.bit) & 1;

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
    fe: &'a FieldElement,
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
        Some((self.fe.0[word] >> shift) as u8)
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
    x: FieldElement([
        0x79e7_30d4_18a9_143c,
        0x75ba_95fc_5fed_b601,
        0x79fb_732b_7762_2510,
        0x1890_5f76_a537_55c6,
    ]),
    y: FieldElement([
        0xddf2_5357_ce95_560a,
        0x8b4a_b8e4_ba19_e45c,
        0xd2e8_8688_dd21_f325,
        0x8571_ff18_2588_5d85,
    ]),
};

#[test]
fn generator_on_curve() {
    println!("{CURVE_GENERATOR:x?}");
    assert!(CURVE_GENERATOR.on_curve());
    println!("demont {:x?}", CURVE_GENERATOR.as_bytes_uncompressed());
}

#[test]
fn generate_key_1() {
    let mut scalar = FieldElement::default();
    scalar.0[0] = 1;
    let r = CURVE_GENERATOR.multiply(&scalar);
    println!("raw {:x?}", r);
    println!("fmt {:x?}", r.as_bytes_uncompressed());
}

#[test]
fn point_double() {
    let mut p = JacobianMontPoint::from_affine(&CURVE_GENERATOR);
    println!("p = {:x?}", p);
    p.double();
    println!("p2 = {:x?}", p);
    println!("p2 aff = {:x?}", p.to_affine());
    println!("enc = {:x?}", p.to_affine().as_bytes_uncompressed());
}

#[test]
fn generate_key_2() {
    let mut scalar = FieldElement::default();
    scalar.0[0] = 2;
    let r = CURVE_GENERATOR.multiply(&scalar);
    println!("raw {:x?}", r);
    println!("fmt {:x?}", r.as_bytes_uncompressed());
}

#[test]
fn generate_key_3() {
    let mut scalar = FieldElement::default();
    scalar.0[0] = 3;
    let r = AffineMontPoint::base_multiply(&scalar);
    println!("raw {:x?}", r);
    println!("fmt {:x?}", r.as_bytes_uncompressed());

    let u = CURVE_GENERATOR.multiply(&scalar);
    println!("raw {:x?}", u);
    println!("fmt {:x?}", u.as_bytes_uncompressed());
}

#[test]
fn generate_key_99999999() {
    let scalar = FieldElement::small_u64(99999999);
    let r = AffineMontPoint::base_multiply(&scalar);
    println!("raw {:x?}", r);
    println!("fmt {:x?}", r.as_bytes_uncompressed());

    let u = CURVE_GENERATOR.multiply(&scalar);
    println!("raw {:x?}", u);
    println!("fmt {:x?}", u.as_bytes_uncompressed());
}

#[test]
fn test_rev_bits() {
    let mut fe = FieldElement::small_u64(1);
    fe.0[3] = 0x55 << 56;
    for b in fe.rev_bits() {
        println!("{b:x}");
    }

    println!("chunks:");
    for (first, b) in fe.rev_bits().chunks(4) {
        println!("{first} {b:x}");
    }
}

#[test]
fn test_rev_bytes() {
    let mut fe = FieldElement::small_u64(0x44332211);
    fe.0[3] = 0x55 << 56;

    for b in fe.rev_bytes() {
        println!("{b:x}");
    }
}

#[test]
fn curve_field_elements_to_mont() {
    println!("G.x = {:x?}", CURVE_GENERATOR.x.to_mont());
    println!("G.y = {:x?}", CURVE_GENERATOR.y.to_mont());
    println!("a = {:x?}", CURVE_A.to_mont());
    println!("b = {:x?}", CURVE_B.to_mont());
    println!("R = {:x?}", FieldElement::one().to_mont());
    println!("R * R = {:x?}", FieldElement::one().to_mont().to_mont());
}

#[test]
fn base_point_precomp_4() {
    let precomp = CURVE_GENERATOR.public_precomp4();

    println!("pub(super) const CURVE_GENERATOR_PRECOMP_4: [JacobianMontPoint; 16] = [");
    for i in 0..16 {
        println!("    // {}G", i);
        println!("    JacobianMontPoint {{ xyz: [");
        for j in 0..12 {
            println!("0x{:016x}, ", precomp[i].xyz[j]);
        }
        println!("    ]}},");

        // cross-check
        let expect = CURVE_GENERATOR.multiply(&FieldElement::small_u64(i as u64));
        assert_eq!(
            expect.as_bytes_uncompressed(),
            precomp[i].to_affine().as_bytes_uncompressed(),
        );
    }
    println!("];");
}

#[test]
fn base_point_precomp_8() {
    let precomp = CURVE_GENERATOR.public_precomp8();

    println!("pub(super) const CURVE_GENERATOR_PRECOMP_8: [JacobianMontPoint; 256] = [");
    for i in 0..256 {
        println!("    // {}G", i);
        println!("    JacobianMontPoint {{ xyz: [");
        for j in 0..12 {
            println!("0x{:016x}, ", precomp[i].xyz[j]);
        }
        println!("    ]}},");

        // cross-check
        let expect = CURVE_GENERATOR.multiply(&FieldElement::small_u64(i as u64));
        assert_eq!(
            expect.as_bytes_uncompressed(),
            precomp[i].to_affine().as_bytes_uncompressed(),
        );
    }
    println!("];");
}

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
        let _z2_inv = test::black_box(z2.demont().inv().to_mont());
        let _z3_inv = test::black_box(z2.mont_mul(&z).demont().inv().to_mont());
    });
}
