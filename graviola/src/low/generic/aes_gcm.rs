// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

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

pub(crate) fn decrypt(
    key: &AesKey,
    ghash: &mut Ghash<'_>,
    initial_counter: &[u8; 16],
    aad: &[u8],
    cipher_inout: &mut [u8],
) {
    ghash.add(aad);
    ghash.add(cipher_inout);
    cipher(key, initial_counter, cipher_inout);
}

fn cipher(key: &AesKey, initial_counter: &[u8; 16], cipher_inout: &mut [u8]) {
    let mut counter = *initial_counter;

    let mut by8 = cipher_inout.chunks_exact_mut(128);

    for block8 in by8.by_ref() {
        let mut counter_block = inc_counter_x8(&mut counter);
        key.encrypt_8_blocks(&mut counter_block);
        for (x, y) in block8.iter_mut().zip(counter_block.iter()) {
            *x ^= *y;
        }
    }

    let mut by1 = by8.into_remainder().chunks_exact_mut(16);

    for block in by1.by_ref() {
        inc_counter(&mut counter);
        ctr(key, &counter, block);
    }

    let cipher_inout = by1.into_remainder();
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

#[inline]
fn inc_counter_x8(block: &mut [u8; 16]) -> [u8; 128] {
    let mut ret = [0u8; 128];
    ret[0..16].copy_from_slice(block);
    ret[16..32].copy_from_slice(block);
    ret[32..48].copy_from_slice(block);
    ret[48..64].copy_from_slice(block);
    ret[64..80].copy_from_slice(block);
    ret[80..96].copy_from_slice(block);
    ret[96..112].copy_from_slice(block);
    ret[112..128].copy_from_slice(block);

    let c = u32::from_be_bytes(block[12..].try_into().unwrap());
    ret[12..16].copy_from_slice(&c.wrapping_add(1).to_be_bytes());
    ret[28..32].copy_from_slice(&c.wrapping_add(2).to_be_bytes());
    ret[44..48].copy_from_slice(&c.wrapping_add(3).to_be_bytes());
    ret[60..64].copy_from_slice(&c.wrapping_add(4).to_be_bytes());
    ret[76..80].copy_from_slice(&c.wrapping_add(5).to_be_bytes());
    ret[92..96].copy_from_slice(&c.wrapping_add(6).to_be_bytes());
    ret[108..112].copy_from_slice(&c.wrapping_add(7).to_be_bytes());
    ret[124..128].copy_from_slice(&c.wrapping_add(8).to_be_bytes());

    block[12..].copy_from_slice(&c.wrapping_add(8).to_be_bytes());
    ret
}
