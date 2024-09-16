// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::low;
use crate::Error;

use core::cmp;

#[derive(Clone, Debug)]
pub(crate) struct PosInt<const N: usize> {
    words: [u64; N],
    used: usize,
}

impl<const N: usize> PosInt<N> {
    /// Makes a minimum-width zero.
    pub(crate) fn zero() -> Self {
        Self {
            words: [0; N],
            used: 0,
        }
    }

    /// Makes a minimum-width one.
    fn one() -> Self {
        let mut r = Self::zero();
        r.words[0] = 1;
        r.used = 1;
        r
    }

    /// Makes a one, but at the width of `self`.
    pub(crate) fn fixed_one(&self) -> Self {
        let mut one = Self::one();
        one.expand(self);
        one
    }

    /// Widen `self` to `other`.
    pub(crate) fn expand(&mut self, other: &Self) {
        // nb, self and other are both of type `Self`, so they have
        // the same size backing store, and `self` has zero words above
        // its used words. inductively that means this is safe.
        // compare this with `widen()`.
        self.used = other.used;
    }

    /// Replaces top word with `word` and increases `used`.
    ///
    /// This means `Self::zero().push_word(1)` == `Self::one()`,
    /// and notably that is not the same as `1 << 64`!
    fn push_word(&mut self, word: u64) -> Result<(), Error> {
        if self.used == N {
            return Err(Error::OutOfRange);
        }

        self.words[self.used] = word;
        self.used += 1;
        Ok(())
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Self::zero();

        let bytes = trim_leading_zeroes(bytes);

        if bytes.len() > N * 8 {
            return Err(Error::OutOfRange);
        }

        let mut words = bytes.rchunks_exact(8);

        for word_bytes in words.by_ref() {
            r.push_word(u64::from_be_bytes(word_bytes.try_into().unwrap()))?;
        }

        let remainder = words.remainder();
        let mut final_word = 0;
        for byte in remainder.iter() {
            final_word = final_word << 8 | (*byte as u64);
        }

        if final_word != 0 {
            r.push_word(final_word)?;
        }

        Ok(r)
    }

    pub(crate) fn to_bytes<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let required_bytes = self.used * 8;

        if out.len() < required_bytes {
            return Err(Error::OutOfRange);
        }

        let out = &mut out[..required_bytes];

        for (chunk, word) in out.chunks_exact_mut(8).rev().zip(self.as_words().iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }

        Ok(out)
    }

    pub(crate) fn debug(&self, why: &str) {
        let mut bytes = [0u8; 512];
        let bytes = self.to_bytes(&mut bytes).unwrap();
        print!("{why} = 0x");
        for b in bytes {
            print!("{b:02x}");
        }
        println!();
    }

    pub(crate) fn len_bytes(&self) -> usize {
        (low::bignum_bitsize(self.as_words()) + 7) / 8
    }

    pub(crate) fn is_even(&self) -> bool {
        self.words[0] & 1 == 0
    }

    fn as_words(&self) -> &[u64] {
        &self.words[..self.used]
    }

    fn as_mut_words(&mut self) -> &mut [u64] {
        &mut self.words[..self.used]
    }

    /// Constant-time equality
    pub(crate) fn equals(&self, other: &Self) -> bool {
        low::bignum_eq(self.as_words(), other.as_words())
    }

    pub(crate) fn pub_equals(&self, other: &Self) -> bool {
        // eliminate trailing zero words, which we can do here
        // because this is a `pub_` function
        let mut s_used = self.used;
        while s_used != 0 {
            if self.words[s_used - 1] == 0 {
                s_used -= 1;
            } else {
                break;
            }
        }

        let mut o_used = other.used;
        while o_used != 0 {
            if other.words[o_used - 1] == 0 {
                o_used -= 1;
            } else {
                break;
            }
        }

        self.words[..s_used] == other.words[..o_used]
    }

    pub(crate) fn less_than(&self, other: &Self) -> bool {
        low::bignum_cmp_lt(self.as_words(), other.as_words()) > 0
    }

    /// Returns the "montifier" for arithmetic mod `self`: M^2 mod self.
    #[must_use]
    pub(crate) fn montifier(&self) -> Self {
        let mut tmp = Self::zero();
        tmp.used = self.used;
        let mut montifier = Self::zero();
        montifier.used = self.used;
        low::bignum_montifier(
            montifier.as_mut_words(),
            self.as_words(),
            tmp.as_mut_words(),
        );
        montifier
    }

    /// Bring `self` into montgomery domain, self * M^2 * M^-1 mod n
    #[must_use]
    pub(crate) fn to_montgomery(&self, montifier: &Self, n: &Self) -> Self {
        let mut mont = Self::zero();
        mont.used = n.used;
        low::bignum_montmul(
            mont.as_mut_words(),
            self.as_words(),
            montifier.as_words(),
            n.as_words(),
        );
        mont
    }

    #[must_use]
    pub(crate) fn mont_neg_inverse(&self) -> u64 {
        let mut tmp = Self::zero();
        tmp.used = self.used;
        low::bignum_negmodinv(tmp.as_mut_words(), self.as_words());
        tmp.words[0]
    }

    /// Return `self` ^ 2 in montgomery domain, self ^ 2 * M^-1 mod n.
    ///
    /// `n0` is `n.mont_neg_inverse()`.
    #[must_use]
    pub(crate) fn mont_sqr(&self, n: &Self, n0: u64) -> Self {
        match (self.used, n.used) {
            (16, 16) => return self.mont_sqr_1024(n, n0),
            (32, 32) => return self.mont_sqr_2048(n, n0),
            _ => {}
        }

        let mut tmp = Self::zero();
        tmp.used = n.used;
        low::bignum_montsqr(tmp.as_mut_words(), self.as_words(), n.as_words());
        tmp
    }

    /// Return `self` * v in montgomery domain, self * v * M^-1 mod n.
    ///
    /// `n0` is `n.mont_neg_inverse()`.
    #[must_use]
    pub(crate) fn mont_mul(&self, v: &Self, n: &Self, n0: u64) -> Self {
        match (self.used, v.used, n.used) {
            (16, 16, 16) => return self.mont_mul_1024(v, n, n0),
            (32, 32, 32) => return self.mont_mul_2048(v, n, n0),
            _ => {}
        }
        let mut tmp = Self::zero();
        tmp.used = n.used;
        low::bignum_montmul(
            tmp.as_mut_words(),
            self.as_words(),
            v.as_words(),
            n.as_words(),
        );
        tmp
    }

    /// Specialisation of `mont_mul`, using 1024-bit karatsuba multiplier
    fn mont_mul_1024(&self, v: &Self, n: &Self, n0: u64) -> Self {
        let mut tmp = [0u64; 32];
        let mut res = [0u64; 32];
        low::bignum_kmul_16_32(&mut res, self.as_words(), v.as_words(), &mut tmp);

        Self::mont_reduce8(&mut res, n, n0)
    }

    /// Specialisation of `mont_mul`, using 2048-bit karatsuba multiplier
    fn mont_mul_2048(&self, v: &Self, n: &Self, n0: u64) -> Self {
        let mut tmp = [0u64; 96];
        let mut res = [0u64; 64];
        low::bignum_kmul_32_64(&mut res, self.as_words(), v.as_words(), &mut tmp);

        Self::mont_reduce8(&mut res, n, n0)
    }

    /// Specialisation of `mont_sqr`, using 1024-bit karatsuba squaring
    fn mont_sqr_1024(&self, n: &Self, n0: u64) -> Self {
        let mut tmp = [0u64; 24];
        let mut res = [0u64; 32];
        low::bignum_ksqr_16_32(&mut res, self.as_words(), &mut tmp);

        Self::mont_reduce8(&mut res, n, n0)
    }

    /// Specialisation of `mont_sqr`, using 2048-bit karatsuba squaring
    fn mont_sqr_2048(&self, n: &Self, n0: u64) -> Self {
        let mut tmp = [0u64; 72];
        let mut res = [0u64; 64];
        low::bignum_ksqr_32_64(&mut res, self.as_words(), &mut tmp);

        Self::mont_reduce8(&mut res, n, n0)
    }

    /// Full montgomery reduction, specialised for multiples of 8 word reductions.
    ///
    /// `n0` is `n.mont_neg_inverse()`.
    fn mont_reduce8(product: &mut [u64], n: &Self, n0: u64) -> Self {
        let carry = low::bignum_emontredc_8n(product, n.as_words(), n0);
        let (_, reduced) = product.split_at(product.len() / 2);
        let carry = carry | low::bignum_cmp_lt(n.as_words(), reduced);

        let mut result = Self::zero();
        result.used = n.used;
        low::bignum_optsub(result.as_mut_words(), reduced, n.as_words(), carry);

        result
    }

    #[must_use]
    fn mont_redc<const M: usize>(&self, n: &PosInt<M>) -> PosInt<M> {
        let mut tmp = PosInt::<M>::zero();
        tmp.used = n.used;
        low::bignum_montredc(
            tmp.as_mut_words(),
            self.as_words(),
            n.as_words(),
            n.as_words().len() as u64,
        );
        tmp
    }

    /// Reduce `self` mod `n`.
    ///
    /// `n` must be odd.
    /// `n_montifier` is `n.montifier()`.
    #[must_use]
    pub(crate) fn reduce<const M: usize>(
        &self,
        n: &PosInt<M>,
        n_montifier: &PosInt<M>,
    ) -> PosInt<M> {
        assert!(M < N);
        // do this by montgomery reduction (leaving one inverse-M term) then multiply out M
        self.mont_redc(n).to_montgomery(n_montifier, n)
    }

    /// Bring `self` out of montgomery domain, self * M^-1 mod n.
    #[must_use]
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn from_montgomery(self, n: &Self) -> Self {
        let mut demont = Self::zero();
        demont.used = n.used;
        low::bignum_demont(demont.as_mut_words(), self.as_words(), n.as_words());
        demont
    }

    /// Returns a * b
    #[must_use]
    pub(crate) fn mul<const M: usize>(a: &Self, b: &Self) -> PosInt<M> {
        assert!(M >= N + N);
        let mut r = PosInt::<M>::zero();
        r.used = a.used + b.used;
        low::bignum_mul(r.as_mut_words(), a.as_words(), b.as_words());
        r
    }

    /// Computes `self` ^ `e` mod `n`.
    ///
    /// `n_montifier` is `n.montifier()`.
    /// `n_0` is `n.mont_neg_inverse()`.
    ///
    /// This is done in a side-channel-free way, with respect to the values of `self`, `e`,
    /// `n` and `n_0`.  The instruction trace depends only on `e.used` and `n.used`.
    pub(crate) fn mont_exp(&self, e: &Self, n: &Self, n_montifier: &Self, n_0: u64) -> Self {
        let mut accum = n.fixed_one().mont_mul(n_montifier, n, n_0);

        // our window size is 4 bits, so precompute a table of 2**4 multiples of self
        //
        // the window size also evenly divides our 64-bit word size, so there is no
        // need to have a degenerate case at the end of the loop
        //
        // put this on the heap, so only n.used * 16 entries are needed (rather than
        // N * 16, which is not possible to express with half-finished const generics)

        let mut table = Vec::with_capacity(n.used * 16);

        // 0: identity in montgomery domain
        table.extend_from_slice(accum.as_words());

        // 1: self
        let t1 = self.to_montgomery(n_montifier, n);
        table.extend_from_slice(t1.as_words());

        // 2: self ^ 2
        let t2 = t1.mont_sqr(n, n_0);
        table.extend_from_slice(t2.as_words());

        // 3: self ^ 2 * self
        let t3 = t2.mont_mul(&t1, n, n_0);
        table.extend_from_slice(t3.as_words());

        // 4: self ^ 2 ^ 2
        let t4 = t2.mont_sqr(n, n_0);
        table.extend_from_slice(t4.as_words());

        // (and so on)
        let t5 = t4.mont_mul(&t1, n, n_0);
        table.extend_from_slice(t5.as_words());

        let t6 = t3.mont_sqr(n, n_0);
        table.extend_from_slice(t6.as_words());

        let t7 = t6.mont_mul(&t1, n, n_0);
        table.extend_from_slice(t7.as_words());

        let t8 = t4.mont_sqr(n, n_0);
        table.extend_from_slice(t8.as_words());

        let t9 = t8.mont_mul(&t1, n, n_0);
        table.extend_from_slice(t9.as_words());

        let t10 = t5.mont_sqr(n, n_0);
        table.extend_from_slice(t10.as_words());

        let t11 = t10.mont_mul(&t1, n, n_0);
        table.extend_from_slice(t11.as_words());

        let t12 = t6.mont_sqr(n, n_0);
        table.extend_from_slice(t12.as_words());

        let t13 = t12.mont_mul(&t1, n, n_0);
        table.extend_from_slice(t13.as_words());

        let t14 = t7.mont_sqr(n, n_0);
        table.extend_from_slice(t14.as_words());

        let t15 = t14.mont_mul(&t1, n, n_0);
        table.extend_from_slice(t15.as_words());

        let mut first = true;
        let mut wcount = 0;
        let mut window = 0;

        let mut term = Self::zero();
        term.used = n.used;

        for bit in BitsMsbFirstIter::new(e.as_words()) {
            // for the first exponent bit, `accum` is 1M;
            // squaring this would be a waste of effort.
            let tmp = if first {
                first = false;
                accum.clone()
            } else {
                accum.mont_sqr(n, n_0)
            };

            // accumulate exponent bits into the window.
            window = (window << 1) | bit;
            wcount += 1;

            // until we have a full window of bits
            if wcount == 4 {
                // and then use that to select the term from `table`;
                // relying on `bignum_copy_row_from_table` being side-channel
                // silent.
                low::bignum_copy_row_from_table(
                    term.as_mut_words(),
                    table.as_slice(),
                    16,
                    n.used as u64,
                    window,
                );

                // then multiply that in, mod n.
                accum = tmp.mont_mul(&term, n, n_0);
                wcount = 0;
                window = 0;
            } else {
                accum = tmp;
            }
        }

        accum.from_montgomery(n)
    }

    /// Computes `self` + `b`
    #[must_use]
    pub(crate) fn add(&self, b: &Self) -> Self {
        let mut r = Self::zero();
        low::bignum_add(&mut r.words, self.as_words(), b.as_words());
        r.used = low::bignum_digitsize(&r.words);
        r
    }

    /// Computes `self` - `b` mod `p`
    #[must_use]
    pub(crate) fn sub_mod(&self, b: &Self, p: &Self) -> Self {
        let mut r = Self::zero();
        r.used = p.used;
        low::bignum_modsub(
            r.as_mut_words(),
            self.as_words(),
            b.as_words(),
            p.as_words(),
        );
        r
    }

    /// Zero extends `self` to have a larger representation.
    #[must_use]
    pub(crate) fn widen<const M: usize>(&self) -> PosInt<M> {
        assert!(M >= N);
        let mut r = PosInt::<M>::zero();
        r.words[..self.used].copy_from_slice(self.as_words());
        r.used = self.used;
        r
    }

    /// Truncates `self` to have a shorter representation.
    ///
    /// Discards unused words; does not check they are zero.
    #[must_use]
    pub(crate) fn narrow<const M: usize>(&self) -> PosInt<M> {
        assert!(M <= N);
        let mut r = PosInt::<M>::zero();
        r.words.copy_from_slice(&self.words[..M]);
        r.used = cmp::min(self.used, N);
        r
    }
}

#[derive(Debug)]
struct BitsMsbFirstIter<'a> {
    words: &'a [u64],
    bit: usize,
    word: usize,
}

impl<'a> BitsMsbFirstIter<'a> {
    fn new(words: &'a [u64]) -> Self {
        debug_assert!(!words.is_empty());
        Self {
            words,
            bit: 64,
            word: words.len() - 1,
        }
    }
}

impl Iterator for BitsMsbFirstIter<'_> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bit == 0 && self.word == 0 {
            return None;
        }

        if self.bit == 0 {
            self.bit = 63;
            self.word -= 1;
        } else {
            self.bit -= 1;
        }

        Some((self.words[self.word] >> self.bit) & 1)
    }
}

fn trim_leading_zeroes(mut bytes: &[u8]) -> &[u8] {
    while let Some((first, rest)) = bytes.split_first() {
        if *first == 0x00 {
            bytes = rest;
        } else {
            return bytes;
        }
    }

    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes() {
        // no bytes -> zero
        assert!(PosInt::<1>::from_bytes(&[])
            .unwrap()
            .pub_equals(&PosInt::<1>::zero()));

        // from single zero byte
        assert!(PosInt::<1>::from_bytes(&[0])
            .unwrap()
            .pub_equals(&PosInt::<1>::zero()));

        // can parse exactly 8N bytes
        assert!(PosInt::<1>::from_bytes(&[0; 8])
            .unwrap()
            .pub_equals(&PosInt::<1>::zero()));

        // cannot parse > 8N bytes (excluding leading zeroes)
        assert_eq!(
            PosInt::<1>::from_bytes(&[1; 9]).unwrap_err(),
            Error::OutOfRange
        );
        PosInt::<1>::from_bytes(&[0; 9]).unwrap();

        // can parse both entire words and remaining bytes
        assert_eq!(
            PosInt::<2>::from_bytes(&[1, 0, 0, 0, 0, 0, 0, 0, 2])
                .unwrap()
                .as_words(),
            &[2, 1]
        );

        // and remaining bytes that require combining
        assert_eq!(
            PosInt::<1>::from_bytes(&[0x11, 0x22, 0x33, 0x44])
                .unwrap()
                .as_words(),
            &[0x11223344]
        );
    }

    #[test]
    fn to_bytes() {
        let mut buf = [0xff; 8];
        assert_eq!(PosInt::<2>::zero().to_bytes(&mut buf).unwrap(), &[]);

        let all_bits_set = PosInt::<2>::from_bytes(&[0xff; 16]).unwrap();
        assert_eq!(
            all_bits_set.to_bytes(&mut buf).unwrap_err(),
            Error::OutOfRange
        );

        let mut buf16 = [0; 16];
        all_bits_set.to_bytes(&mut buf16).unwrap();
        assert_eq!(buf16, [0xff; 16]);
    }

    #[test]
    fn mul() {
        // identities
        let zero_1 = PosInt::<1>::zero();
        let zero_2 = PosInt::<2>::zero();
        let one_1 = PosInt::<1>::one();
        let one_2 = PosInt::<2>::one();

        let r = PosInt::mul(&one_1, &one_1);
        println!("r = {:?}", r);
        assert!(r.pub_equals(&one_2));

        let r = PosInt::mul(&zero_1, &one_1);
        println!("r = {:?}", r);
        assert!(r.pub_equals(&zero_2));

        let r = PosInt::mul(&zero_1, &zero_1);
        println!("r = {:?}", r);
        assert!(r.pub_equals(&zero_2));

        let x_4 = PosInt::<4>::from_bytes(b"\xed\x1f\xde\xb5\xc6\x39\x43\x8f\xea\x1d\x05\x9c\xba\xa8\xd3\x7c\x13\x96\xf4\x96\x1c\x8e\x5f\x52\x8f\x3c\x4c\x3c\x45\xe5\x75\xa2").unwrap();
        let y_4 = PosInt::<4>::from_bytes(b"\x38\x8f\xb5\xd8\xbd\xad\x46\xfd\xe2\x8e\x33\x11\xe4\xdd\xef\x79\x70\xfe\x4a\xb9\xef\x24\x85\xbe\x4f\xde\x81\x79\x36\x0c\x9c\x86").unwrap();
        let xy_8: PosInt<8> = PosInt::mul(&x_4, &y_4);
        println!("{xy_8:x?}");

        let expect_8 = PosInt::<8>::from_bytes(b"\x34\x64\x15\xf5\x75\xf1\xb7\x01\x8b\x1d\xc4\x68\xde\x4b\xf7\x6e\x6f\x62\x87\xa1\x44\x08\x6f\xb1\x85\x9c\xf3\x84\x41\x64\x48\x9d\x16\xe7\xb0\xd0\xd3\x56\x13\xba\xa2\xb9\xa6\x12\x1a\x6c\x2f\x93\xcd\xe4\x20\xfa\x41\xa4\xef\xa2\xab\xcd\x8b\x48\x19\x62\x4a\xcc").unwrap();
        assert!(xy_8.pub_equals(&expect_8));
    }
}
