use crate::low::ghash::Ghash;
use crate::low::AesKey;

pub(crate) fn encrypt(
    key: &AesKey,
    ghash: &mut Ghash<'_>,
    initial_counter: &[u8; 16],
    aad: &[u8],
    cipher_inout: &mut [u8],
) {
    ghash.add(aad);
    cipher(key, initial_counter, cipher_inout);
    ghash.add(cipher_inout);
}

fn cipher(key: &AesKey, initial_counter: &[u8; 16], cipher_inout: &mut [u8]) {
    let mut counter = *initial_counter;
    let mut exact = cipher_inout.chunks_exact_mut(16);

    for block in exact.by_ref() {
        inc_counter(&mut counter);
        ctr(key, &counter, block);
    }

    let cipher_inout = exact.into_remainder();
    if !cipher_inout.is_empty() {
        let mut block = [0u8; 16];
        let len = cipher_inout.len();
        debug_assert!(len < 16);
        block[..len].copy_from_slice(cipher_inout);

        inc_counter(&mut counter);
        ctr(key, &counter, &mut block);

        cipher_inout.copy_from_slice(&block[..len]);
    }
}

#[inline]
fn ctr(key: &AesKey, counter: &[u8; 16], cipher_inout: &mut [u8]) {
    let mut block = *counter;
    key.encrypt_block(&mut block);
    for (x, y) in cipher_inout.iter_mut().zip(block.iter()) {
        *x ^= *y;
    }
}

#[inline]
fn inc_counter(block: &mut [u8; 16]) {
    let c = u32::from_be_bytes(block[12..].try_into().unwrap());
    let c = c.wrapping_add(1);
    block[12..].copy_from_slice(&c.to_be_bytes());
}
