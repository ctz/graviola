// References:
// - https://iacr.org/archive/fse2009/56650054/56650054.pdf (or)
// - https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf

use crate::low::generic::aes::{AesKey, AES_MAX_ROUNDS};

use std::arch::x86_64::*;

/// Does AES key expansion.
///
/// `key` must be 16 or 32 bytes in length (AES-192 not supported).
pub(crate) fn aes_expand_key(key: &[u8]) -> AesKey {
    let rounds = match key.len() {
        16 => 10,
        32 => 14,
        _ => unreachable!(),
    };

    let mut round_keys = [0u32; 4 * (AES_MAX_ROUNDS + 1)];

    // First words are just the key
    for (i, word) in key.chunks(4).enumerate() {
        round_keys[i] = u32::from_le_bytes(word.try_into().unwrap());
    }

    match rounds {
        10 => {
            let (key, rk) = round_keys.split_at_mut(4);
            unsafe {
                aes128_expand(key, rk);
            }
        }
        14 => {
            let (key, rk) = round_keys.split_at_mut(8);
            unsafe {
                aes256_expand(key, rk);
            }
        }
        _ => unreachable!(),
    };

    AesKey { round_keys, rounds }
}

impl AesKey {
    pub(crate) fn encrypt_block(&self, inout: &mut [u8]) {
        debug_assert_eq!(inout.len(), 16);

        match self.rounds {
            10 => unsafe { aes128_block(&self.round_keys, inout) },
            14 => unsafe { aes256_block(&self.round_keys, inout) },
            _ => unreachable!(),
        }
    }
}

macro_rules! expand_128 {
    ($rcon:literal, $t1:ident, $out:ident) => {
        // with [X3, _, X1,  _] = t1
        // t2 := [RotWord (SubWord (X3)) XOR RCON, SubWord (X3),
        //        RotWord (SubWord (X1)) XOR RCON, SubWord (X1)]
        let t2 = _mm_aeskeygenassist_si128($t1, $rcon);

        // select just high dqword, distribute to other dqwords
        let t2 = _mm_shuffle_epi32(t2, 0b11_11_11_11);

        let t3 = _mm_slli_si128($t1, 0x4); // nb. 4 bytes shift
        $t1 = _mm_xor_si128($t1, t3);

        let t3 = _mm_slli_si128(t3, 0x4);
        $t1 = _mm_xor_si128($t1, t3);

        let t3 = _mm_slli_si128(t3, 0x4);
        $t1 = _mm_xor_si128($t1, t3);

        $t1 = _mm_xor_si128($t1, t2);

        _mm_store_si128($out.as_mut_ptr() as *mut _, $t1);
        let (_, rest) = $out.split_at_mut(4);
        $out = rest;
    };
}

#[target_feature(enable = "aes")]
unsafe fn aes128_expand(key: &[u32], mut out: &mut [u32]) {
    unsafe {
        let mut t1 = _mm_lddqu_si128(key.as_ptr() as *const _);

        expand_128!(0x01, t1, out);
        expand_128!(0x02, t1, out);
        expand_128!(0x04, t1, out);
        expand_128!(0x08, t1, out);
        expand_128!(0x10, t1, out);
        expand_128!(0x20, t1, out);
        expand_128!(0x40, t1, out);
        expand_128!(0x80, t1, out);
        expand_128!(0x1b, t1, out);
        expand_128!(0x36, t1, out);
    }
}

macro_rules! expand_256 {
    (Odd, $rcon:literal, $t1:ident, $t3:ident, $out:ident) => {
        let t2 = _mm_aeskeygenassist_si128($t3, $rcon);
        let t2 = _mm_shuffle_epi32(t2, 0b11_11_11_11);

        let t3 = _mm_slli_si128($t1, 0x4); // nb. 4 bytes shift
        $t1 = _mm_xor_si128($t1, t3);

        let t3 = _mm_slli_si128(t3, 0x4);
        $t1 = _mm_xor_si128($t1, t3);

        let t3 = _mm_slli_si128(t3, 0x4);
        $t1 = _mm_xor_si128($t1, t3);

        $t1 = _mm_xor_si128($t1, t2);

        _mm_store_si128($out.as_mut_ptr() as *mut _, $t1);
        let (_, rest) = $out.split_at_mut(4);
        $out = rest;
    };
    (Even, $t1:ident, $t3:ident, $out:ident) => {
        let t4 = _mm_aeskeygenassist_si128($t1, 0);
        let t2 = _mm_shuffle_epi32(t4, 0b10_10_10_10); // choose SubWord(X3) term

        let t4 = _mm_slli_si128($t3, 0x4);
        $t3 = _mm_xor_si128($t3, t4);

        let t4 = _mm_slli_si128(t4, 0x4);
        $t3 = _mm_xor_si128($t3, t4);

        let t4 = _mm_slli_si128(t4, 0x4);
        $t3 = _mm_xor_si128($t3, t4);
        $t3 = _mm_xor_si128($t3, t2);

        _mm_store_si128($out.as_mut_ptr() as *mut _, $t3);
        let (_, rest) = $out.split_at_mut(4);
        $out = rest;
    };
}

#[target_feature(enable = "aes")]
unsafe fn aes256_expand(key: &[u32], mut out: &mut [u32]) {
    let mut t1 = _mm_lddqu_si128(key.as_ptr() as *const _);
    let mut t3 = _mm_lddqu_si128(key[4..].as_ptr() as *const _);

    // nb. 'odd' rounds in units of Nk have an rcon term (equivalent
    // to all rounds of 128-bit key expansion), 'even' rounds do not
    expand_256!(Odd, 0x01, t1, t3, out);
    expand_256!(Even, t1, t3, out);
    expand_256!(Odd, 0x02, t1, t3, out);
    expand_256!(Even, t1, t3, out);
    expand_256!(Odd, 0x04, t1, t3, out);
    expand_256!(Even, t1, t3, out);
    expand_256!(Odd, 0x08, t1, t3, out);
    expand_256!(Even, t1, t3, out);
    expand_256!(Odd, 0x10, t1, t3, out);
    expand_256!(Even, t1, t3, out);
    expand_256!(Odd, 0x20, t1, t3, out);
    expand_256!(Even, t1, t3, out);
    expand_256!(Odd, 0x40, t1, t3, out);
}

#[target_feature(enable = "aes")]
unsafe fn aes128_block(round_keys: &[u32], block_inout: &mut [u8]) {
    let block = _mm_lddqu_si128(block_inout.as_ptr() as *const _);
    let block = _mm_xor_si128(block, _mm_lddqu_si128(round_keys[0..].as_ptr() as *const _));
    let block = _mm_aesenc_si128(block, _mm_lddqu_si128(round_keys[4..].as_ptr() as *const _));
    let block = _mm_aesenc_si128(block, _mm_lddqu_si128(round_keys[8..].as_ptr() as *const _));
    let block = _mm_aesenc_si128(
        block,
        _mm_lddqu_si128(round_keys[12..].as_ptr() as *const _),
    );
    let block = _mm_aesenc_si128(
        block,
        _mm_lddqu_si128(round_keys[16..].as_ptr() as *const _),
    );
    let block = _mm_aesenc_si128(
        block,
        _mm_lddqu_si128(round_keys[20..].as_ptr() as *const _),
    );
    let block = _mm_aesenc_si128(
        block,
        _mm_lddqu_si128(round_keys[24..].as_ptr() as *const _),
    );
    let block = _mm_aesenc_si128(
        block,
        _mm_lddqu_si128(round_keys[28..].as_ptr() as *const _),
    );
    let block = _mm_aesenc_si128(
        block,
        _mm_lddqu_si128(round_keys[32..].as_ptr() as *const _),
    );
    let block = _mm_aesenc_si128(
        block,
        _mm_lddqu_si128(round_keys[36..].as_ptr() as *const _),
    );
    let block = _mm_aesenclast_si128(
        block,
        _mm_lddqu_si128(round_keys[40..].as_ptr() as *const _),
    );
    _mm_storeu_si128(block_inout.as_mut_ptr() as *mut _, block);
}

#[target_feature(enable = "aes")]
unsafe fn aes256_block(round_keys: &[u32], block_inout: &mut [u8]) {
    let block = _mm_lddqu_si128(block_inout.as_ptr() as *const _);
    let block = _mm_xor_si128(block, _mm_lddqu_si128(round_keys[0..].as_ptr() as *const _));
    let block = _mm_aesenc_si128(block, _mm_lddqu_si128(round_keys[4..].as_ptr() as *const _));
    let block = _mm_aesenc_si128(block, _mm_lddqu_si128(round_keys[8..].as_ptr() as *const _));
    let block = _mm_aesenc_si128(
        block,
        _mm_lddqu_si128(round_keys[12..].as_ptr() as *const _),
    );
    let block = _mm_aesenc_si128(
        block,
        _mm_lddqu_si128(round_keys[16..].as_ptr() as *const _),
    );
    let block = _mm_aesenc_si128(
        block,
        _mm_lddqu_si128(round_keys[20..].as_ptr() as *const _),
    );
    let block = _mm_aesenc_si128(
        block,
        _mm_lddqu_si128(round_keys[24..].as_ptr() as *const _),
    );
    let block = _mm_aesenc_si128(
        block,
        _mm_lddqu_si128(round_keys[28..].as_ptr() as *const _),
    );
    let block = _mm_aesenc_si128(
        block,
        _mm_lddqu_si128(round_keys[32..].as_ptr() as *const _),
    );
    let block = _mm_aesenc_si128(
        block,
        _mm_lddqu_si128(round_keys[36..].as_ptr() as *const _),
    );
    let block = _mm_aesenc_si128(
        block,
        _mm_lddqu_si128(round_keys[40..].as_ptr() as *const _),
    );
    let block = _mm_aesenc_si128(
        block,
        _mm_lddqu_si128(round_keys[44..].as_ptr() as *const _),
    );
    let block = _mm_aesenc_si128(
        block,
        _mm_lddqu_si128(round_keys[48..].as_ptr() as *const _),
    );
    let block = _mm_aesenc_si128(
        block,
        _mm_lddqu_si128(round_keys[52..].as_ptr() as *const _),
    );
    let block = _mm_aesenclast_si128(
        block,
        _mm_lddqu_si128(round_keys[56..].as_ptr() as *const _),
    );
    _mm_storeu_si128(block_inout.as_mut_ptr() as *mut _, block);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_u128(v: __m128i) -> u128 {
        let mut u = 0;
        unsafe {
            _mm_store_si128(&mut u as *mut u128 as *mut _, v);
        }
        u
    }

    // these test vectors from FIPS-197 appendices A.1 - A.3.

    #[test]
    fn test_key_expansion_128() {
        let context = aes_expand_key(&[
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ]);

        let expected: Vec<u32> = [
            0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c, 0xa0fafe17, 0x88542cb1, 0x23a33939,
            0x2a6c7605, 0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f, 0x3d80477d, 0x4716fe3e,
            0x1e237e44, 0x6d7a883b, 0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00, 0xd4d1c6f8,
            0x7c839d87, 0xcaf2b8bc, 0x11f915bc, 0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
            0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f, 0xead27321, 0xb58dbad2, 0x312bf560,
            0x7f8d292f, 0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, 0xd014f9a8, 0xc9ee2589,
            0xe13f0cc8, 0xb6630ca6,
        ]
        .into_iter()
        .map(|item: u32| item.swap_bytes())
        .collect();

        println!("round_keys = {:#010x?}", context.round_keys);
        println!("expected   = {:#010x?}", expected);

        assert_eq!(context.rounds, 10);
        assert_eq!(&context.round_keys[..44], &expected,);
    }

    #[test]
    fn test_key_expansion_256() {
        let context = aes_expand_key(&[
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ]);

        let expected: Vec<u32> = [
            0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3,
            0x0914dff4, 0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde, 0xa8b09c1a, 0x93d194cd,
            0xbe49846e, 0xb75d5b9a, 0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96, 0xb5a9328a,
            0x2678a647, 0x98312229, 0x2f6c79b3, 0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464,
            0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214, 0x68007bac, 0xb2df3316, 0x96e939e4,
            0x6c518d80, 0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239, 0xde136967, 0x6ccc5a71,
            0xfa256395, 0x9674ee15, 0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3, 0x749c47ab,
            0x18501dda, 0xe2757e4f, 0x7401905a, 0xcafaaae3, 0xe4d59b34, 0x9adf6ace, 0xbd10190d,
            0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e,
        ]
        .into_iter()
        .map(|item: u32| item.swap_bytes())
        .collect();

        println!("round_keys = {:#010x?}", context.round_keys);
        println!("expected   = {:#010x?}", expected);

        assert_eq!(context.rounds, 14);
        assert_eq!(&context.round_keys[..], &expected,);
    }

    #[test]
    fn test_block_128() {
        let context = aes_expand_key(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]);
        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        context.encrypt_block(&mut block);
        assert_eq!(
            block,
            [
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
                0xc5, 0x5a
            ]
        );
    }

    #[test]
    fn test_block_256() {
        let context = aes_expand_key(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);
        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        context.encrypt_block(&mut block);
        assert_eq!(
            block,
            [
                0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
                0x60, 0x89
            ]
        );
    }
}
