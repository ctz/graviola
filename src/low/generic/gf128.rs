/// An extremely slow, by-the-book implementation.
///
/// Useful as a test model for faster implementations.

pub(crate) fn mul(x: u128, y: u128) -> u128 {
    let mut z = 0;
    let mut v = x;

    for i in 0..128 {
        let bit = 127 - i;
        let mask = ((y >> bit) & 1).wrapping_neg();
        let sum = z ^ v;
        z = (z & !mask) | (sum & mask);
        v = double(v);
    }

    z
}

fn double(a: u128) -> u128 {
    let mask = (a & 1).wrapping_neg();
    let b = a >> 1;
    b ^ (mask & R)
}

const R: u128 = 0xe1000000_00000000_00000000_00000000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double() {
        assert_eq!(0, double(0));
        assert_eq!(R, double(1));
        assert_eq!(1, double(2));
        assert_eq!(R + 1, double(3));

        let e = u128::from_be_bytes(
            *b"\x5e\x2e\xc7\x46\x91\x70\x62\x88\x2c\x85\xb0\x68\x53\x53\xde\xb7",
        );
        let e2 = double(e);
        assert_eq!(
            &e2.to_be_bytes(),
            b"\xce\x17\x63\xa3\x48\xb8\x31\x44\x16\x42\xd8\x34\x29\xa9\xef\x5b"
        );
    }

    #[test]
    fn test_mul() {
        assert_eq!(0, mul(1, 0));

        let x = u128::from_be_bytes(
            *b"\x03\x88\xda\xce\x60\xb6\xa3\x92\xf3\x28\xc2\xb9\x71\xb2\xfe\x78",
        );
        let y = u128::from_be_bytes(
            *b"\x66\xe9\x4b\xd4\xef\x8a\x2c\x3b\x88\x4c\xfa\x59\xca\x34\x2b\x2e",
        );
        assert_eq!(
            b"\x5e\x2e\xc7\x46\x91\x70\x62\x88\x2c\x85\xb0\x68\x53\x53\xde\xb7",
            &mul(x, y).to_be_bytes()
        );
    }
}