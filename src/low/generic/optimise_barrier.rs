use core::ptr::read_volatile;

pub fn optimise_barrier_u8(v: u8) -> u8 {
    unsafe { read_volatile(&v) }
}
