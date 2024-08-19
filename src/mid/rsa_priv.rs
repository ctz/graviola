use super::rsa_pub::RsaPublicKey;
use crate::error::Error;
use crate::low;

#[derive(Debug)]
pub(crate) struct RsaPrivateKey {
    p: RsaPosIntModP,
    q: RsaPosIntModP,
    dp: RsaPosIntModP,
    dq: RsaPosIntModP,
    iqmp: RsaPosIntModP,
    public: RsaPublicKey,

    iqmp_mont: RsaPosIntModP,
    p_montifier: RsaPosIntModP,
    q_montifier: RsaPosIntModP,
    p0: u64,
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
        let p_montifier = p.montifier();
        let q_montifier = q.montifier();
        let iqmp_mont = iqmp.to_montgomery(&p_montifier, &p);
        let p0 = p.mont_neg_inverse();

        Ok(Self {
            p,
            q,
            dp,
            dq,
            iqmp,
            public,
            iqmp_mont,
            p_montifier,
            q_montifier,
            p0,
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

        // i.   Let m_1 = c^dP mod p and m_2 = c^dQ mod q.
        // (do reductions of c first, so the mod exp can be done at
        // width of p or q rather than pq.)
        let mut tmp = low::PosInt::<{ MAX_PRIVATE_MODULUS_WORDS * 3 }>::zero();
        let cmp = c.reduce(&self.p, &self.p_montifier);
        let m_1 = cmp.mod_exp(&self.dp, &self.p, &mut tmp);
        let cmq = c.reduce(&self.q, &self.q_montifier);
        let m_2 = cmq.mod_exp(&self.dq, &self.q, &mut tmp);

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
        let c2 = self.public.public_op(&m)?;
        if c2.equals(c) {
            Ok(m)
        } else {
            Err(Error::DecryptFailed)
        }
    }
}

const MAX_PRIVATE_MODULUS_BITS: usize = 4096;
const MAX_PRIVATE_MODULUS_WORDS: usize = MAX_PRIVATE_MODULUS_BITS / 64;
pub(crate) const MAX_PRIVATE_MODULUS_BYTES: usize = MAX_PRIVATE_MODULUS_BITS / 8;

const MIN_PRIVATE_MODULUS_BITS: usize = 1024;
const MIN_PRIVATE_MODULUS_BYTES: usize = MIN_PRIVATE_MODULUS_BITS / 8;

type RsaPosIntModP = low::PosInt<MAX_PRIVATE_MODULUS_WORDS>;
type RsaPosIntModN = low::PosInt<{ MAX_PRIVATE_MODULUS_WORDS * 2 }>;
