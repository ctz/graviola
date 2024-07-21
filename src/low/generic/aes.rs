/// An expanded AES encryption key.
///
/// This is in the layout expected by cryptogams.
#[repr(C)]
pub struct AesKey {
    pub(crate) round_keys: [u32; 4 * (AES_MAX_ROUNDS + 1)],
    pub(crate) rounds: u32,
}

#[repr(C)]
pub struct GcmTable {
    pub(crate) h: u128,
    pub(crate) h_table: [u128; 9],
}

#[repr(C)]
pub struct GcmState {
    pub(crate) xi: u128,
    pub(crate) tab: GcmTable,
}

pub(crate) const AES_MAX_ROUNDS: usize = 14;
