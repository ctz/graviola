// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use super::rsa_pub::RsaPublicKey;
use crate::error::Error;
use crate::low;

pub(crate) struct RsaPrivateKey {
    public: RsaPublicKey,

    p: RsaPosIntModP,
    q: RsaPosIntModP,
    dp: RsaPosIntModP,
    dq: RsaPosIntModP,

    iqmp_mont: RsaPosIntModP,
    p_montifier: RsaPosIntModP,
    q_montifier: RsaPosIntModP,
    p0: u64,
    q0: u64,
}

impl RsaPrivateKey {
    pub(crate) fn new(
        p: RsaPosIntModP,
        q: RsaPosIntModP,
        dp: RsaPosIntModP,
        dq: RsaPosIntModP,
        iqmp: RsaPosIntModP,
        n: RsaPosIntModN,
        e: u32,
    ) -> Result<Self, Error> {
        let p_len = p.len_bytes();
        if p.is_even()
            || q.is_even()
            || dp.is_even()
            || dq.is_even()
            || !(MIN_PRIVATE_MODULUS_BYTES..=MAX_PRIVATE_MODULUS_BYTES).contains(&p_len)
        {
            return Err(Error::OutOfRange);
        }

        let public = RsaPublicKey::new(n, e)?;
        let p_montifier: RsaPosIntModP = p.montifier().into();
        let q_montifier = q.montifier().into();
        let iqmp_mont = iqmp.to_montgomery(&p_montifier, &p).into();
        let p0 = p.mont_neg_inverse();
        let q0 = q.mont_neg_inverse();

        Ok(Self {
            public,
            p,
            q,
            dp,
            dq,
            iqmp_mont,
            p_montifier,
            q_montifier,
            p0,
            q0,
        })
    }

    pub(crate) fn public_key(&self) -> RsaPublicKey {
        self.public.clone()
    }

    pub(crate) fn modulus_len_bytes(&self) -> usize {
        self.public.modulus_len_bytes()
    }

    /// returns c ^ d mod n
    ///
    /// (albeit via CRT)
    pub(crate) fn private_op(&self, c: &RsaPosIntModN) -> Result<RsaPosIntModN, Error> {
        if !c.less_than(&self.public.n) {
            return Err(Error::OutOfRange);
        }

        // A note about blinding:
        //
        // In this library, we only perform RSA signatures, where `c` is
        // public information, there is little use for base blinding.
        //
        // Exponent and modulus blinding are _also_ relatively unnecessary,
        // since our `PosInt::mont_exp` is side-channel silent.
        // See the commentary there for why I think that is the case.

        // i.   Let m_1 = c^dP mod p and m_2 = c^dQ mod q.
        // (do reductions of c first, so the mod exp can be done at
        // width of p or q rather than pq.)
        let cmp = c.reduce(&self.p, &self.p_montifier);
        let m_1 = cmp.mont_exp(&self.dp, &self.p, &self.p_montifier, self.p0);
        let cmq = c.reduce(&self.q, &self.q_montifier);
        let m_2 = cmq.mont_exp(&self.dq, &self.q, &self.q_montifier, self.q0);

        // ii. If u > 2, let m_i = c^(d_i) mod r_i, i = 3, ..., u.
        // (we don't support multiprime rsa)

        // iii. Let h = (m_1 - m_2) * qInv mod p.
        let h = m_1
            .sub_mod(&m_2, &self.p)
            .mont_mul(&self.iqmp_mont, &self.p, self.p0);

        // iv.  Let m = m_2 + q * h.
        let m = m_2.widen().add(&low::PosInt::mul(&self.q, &h));

        // validate the result as a fault attack countermeasure,
        // at the same time it validates our working above, and
        // the key halves against each other
        let c2 = self.public.public_op(m.clone())?;
        if c2.equals(c) {
            Ok(m)
        } else {
            Err(Error::DecryptFailed)
        }
    }
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        low::zeroise_value(&mut self.p0);
        low::zeroise_value(&mut self.q0);
    }
}

const MAX_PRIVATE_MODULUS_BITS: usize = 4096;
const MAX_PRIVATE_MODULUS_WORDS: usize = MAX_PRIVATE_MODULUS_BITS / 64;
pub(crate) const MAX_PRIVATE_MODULUS_BYTES: usize = MAX_PRIVATE_MODULUS_BITS / 8;

const MIN_PRIVATE_MODULUS_BITS: usize = 1024;
const MIN_PRIVATE_MODULUS_BYTES: usize = MIN_PRIVATE_MODULUS_BITS / 8;

type RsaPosIntModP = low::SecretPosInt<MAX_PRIVATE_MODULUS_WORDS>;
type RsaPosIntModN = low::PosInt<{ MAX_PRIVATE_MODULUS_WORDS * 2 }>;
