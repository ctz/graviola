// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

pub(crate) struct Array64x4(pub(crate) [u64; 4]);

impl Array64x4 {
    pub(crate) fn as_le_bytes(&self) -> [u8; 32] {
        let a = self.0[0].to_le_bytes();
        let b = self.0[1].to_le_bytes();
        let c = self.0[2].to_le_bytes();
        let d = self.0[3].to_le_bytes();

        let mut r = [0u8; 32];
        r[0..8].copy_from_slice(&a);
        r[8..16].copy_from_slice(&b);
        r[16..24].copy_from_slice(&c);
        r[24..32].copy_from_slice(&d);
        r
    }

    pub(crate) fn from_le_bytes(bytes: &[u8]) -> Option<Self> {
        let as_array: [u8; 32] = bytes.try_into().ok()?;
        Some(Self::from_le(&as_array))
    }

    pub(crate) fn from_le(v: &[u8; 32]) -> Self {
        let a = v[0..8].try_into().unwrap();
        let b = v[8..16].try_into().unwrap();
        let c = v[16..24].try_into().unwrap();
        let d = v[24..32].try_into().unwrap();
        Self([
            u64::from_le_bytes(a),
            u64::from_le_bytes(b),
            u64::from_le_bytes(c),
            u64::from_le_bytes(d),
        ])
    }

    pub(crate) fn as_be_bytes(&self) -> [u8; 32] {
        let a = self.0[0].to_be_bytes();
        let b = self.0[1].to_be_bytes();
        let c = self.0[2].to_be_bytes();
        let d = self.0[3].to_be_bytes();

        let mut r = [0u8; 32];
        r[0..8].copy_from_slice(&d);
        r[8..16].copy_from_slice(&c);
        r[16..24].copy_from_slice(&b);
        r[24..32].copy_from_slice(&a);
        r
    }

    pub(crate) fn from_be_bytes(bytes: &[u8]) -> Option<Self> {
        let as_array: [u8; 32] = bytes.try_into().ok()?;
        Some(Self::from_be(&as_array))
    }

    /// This should avoid looking at values of `bytes` that
    /// comprise the value.
    pub(crate) fn from_be_bytes_any_size(bytes: &[u8]) -> Option<Self> {
        // short circuit for correct lengths
        if let Ok(array) = bytes.try_into() {
            return Some(Self::from_be(array));
        }

        // shift in bytes, starting with the LSB
        let mut word = 0;
        let mut shift = 0;
        let mut leading_bytes = false;

        let mut r = Self([0; 4]);

        for val in bytes.iter().rev() {
            if leading_bytes {
                if *val != 0 {
                    return None;
                }
                continue;
            }

            r.0[word] |= (*val as u64) << shift;

            shift += 8;
            if shift == 64 {
                word += 1;
                shift = 0;
            }

            if word == 4 {
                leading_bytes = true;
            }
        }

        Some(r)
    }

    pub(crate) fn from_be(v: &[u8; 32]) -> Self {
        let a = v[0..8].try_into().unwrap();
        let b = v[8..16].try_into().unwrap();
        let c = v[16..24].try_into().unwrap();
        let d = v[24..32].try_into().unwrap();
        Self([
            u64::from_be_bytes(d),
            u64::from_be_bytes(c),
            u64::from_be_bytes(b),
            u64::from_be_bytes(a),
        ])
    }
}

pub(crate) struct Array64x6(pub(crate) [u64; 6]);

impl Array64x6 {
    pub(crate) fn as_be_bytes(&self) -> [u8; 48] {
        let a = self.0[0].to_be_bytes();
        let b = self.0[1].to_be_bytes();
        let c = self.0[2].to_be_bytes();
        let d = self.0[3].to_be_bytes();
        let e = self.0[4].to_be_bytes();
        let f = self.0[5].to_be_bytes();

        let mut r = [0u8; 48];
        r[0..8].copy_from_slice(&f);
        r[8..16].copy_from_slice(&e);
        r[16..24].copy_from_slice(&d);
        r[24..32].copy_from_slice(&c);
        r[32..40].copy_from_slice(&b);
        r[40..48].copy_from_slice(&a);
        r
    }

    pub(crate) fn from_be_bytes(bytes: &[u8]) -> Option<Self> {
        let as_array: [u8; 48] = bytes.try_into().ok()?;
        Some(Self::from_be(&as_array))
    }

    /// This should avoid looking at values of `bytes` that
    /// comprise the value.
    pub(crate) fn from_be_bytes_any_size(bytes: &[u8]) -> Option<Self> {
        // short circuit for correct lengths
        if let Ok(array) = bytes.try_into() {
            return Some(Self::from_be(array));
        }

        // shift in bytes, starting with the LSB
        let mut word = 0;
        let mut shift = 0;
        let mut leading_bytes = false;

        let mut r = Self([0; 6]);

        for val in bytes.iter().rev() {
            if leading_bytes {
                if *val != 0 {
                    return None;
                }
                continue;
            }

            r.0[word] |= (*val as u64) << shift;

            shift += 8;
            if shift == 64 {
                word += 1;
                shift = 0;
            }

            if word == 6 {
                leading_bytes = true;
            }
        }

        Some(r)
    }

    pub(crate) fn from_be(v: &[u8; 48]) -> Self {
        let a = v[0..8].try_into().unwrap();
        let b = v[8..16].try_into().unwrap();
        let c = v[16..24].try_into().unwrap();
        let d = v[24..32].try_into().unwrap();
        let e = v[32..40].try_into().unwrap();
        let f = v[40..48].try_into().unwrap();
        Self([
            u64::from_be_bytes(f),
            u64::from_be_bytes(e),
            u64::from_be_bytes(d),
            u64::from_be_bytes(c),
            u64::from_be_bytes(b),
            u64::from_be_bytes(a),
        ])
    }
}
