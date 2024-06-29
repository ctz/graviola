pub struct Array64x4(pub [u64; 4]);

impl Array64x4 {
    pub fn as_le_bytes(&self) -> [u8; 32] {
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

    pub fn from_le_bytes(bytes: &[u8]) -> Option<Array64x4> {
        let as_array: [u8; 32] = bytes.try_into().ok()?;
        Some(Self::from_le(&as_array))
    }

    pub fn from_le(v: &[u8; 32]) -> Array64x4 {
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

    pub fn as_be_bytes(&self) -> [u8; 32] {
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

    pub fn from_be_bytes(bytes: &[u8]) -> Option<Array64x4> {
        let as_array: [u8; 32] = bytes.try_into().ok()?;
        Some(Self::from_be(&as_array))
    }

    pub fn from_be_bytes_any_size(mut bytes: &[u8]) -> Option<Array64x4> {
        let mut r = Array64x4([0; 4]);

        // remove leading zeroes
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes = &bytes[1..];
        }

        if bytes.len() > 32 {
            return None;
        }

        let mut word = 0;
        let mut shift = 0;

        for val in bytes.iter().rev() {
            r.0[word] |= (*val as u64) << shift;

            shift += 8;
            if shift == 64 {
                word += 1;
                shift = 0;
            }
        }

        Some(r)
    }

    pub fn from_be(v: &[u8; 32]) -> Array64x4 {
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
