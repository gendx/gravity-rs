/* Can modify */
const K: usize = 24;
const C: usize = 10;
const D: usize = 1;
const H: usize = 5; // 5 is often good


/* Don't modify */
pub const HASH_SIZE: usize = 32; // Only implemented for 32

pub const WOTS_W: usize = 16; // Only implemented for 16
pub const WOTS_LOG_ELL1: usize = 6; // Implicitly depends on HASH_SIZE and W
pub const WOTS_ELL1: usize = 1 << WOTS_LOG_ELL1;
pub const WOTS_CHKSUM: usize = 3; // Implicitly depends on W and ELL1
pub const WOTS_ELL: usize = WOTS_ELL1 + WOTS_CHKSUM;

pub const PORS_TAU: usize = 16; // Only implemented for 16
pub const PORS_T: usize = 1 << PORS_TAU;
pub const PORS_K: usize = K;

// Implicit constraint: GRAVITY_C + MERKLE_H * GRAVITY_D <= 64
pub const MERKLE_H: usize = H;
pub const MERKLE_HHH: usize = 1 << MERKLE_H;

pub const GRAVITY_C: usize = C;
pub const GRAVITY_CCC: usize = 1 << GRAVITY_C;
pub const GRAVITY_D: usize = D;
pub const GRAVITY_H: usize = MERKLE_H * GRAVITY_D + GRAVITY_C;
pub static GRAVITY_MASK: u64 = 0xFFFF_FFFF_FFFF_FFFF_u64 ^ (0xFFFF_FFFF_FFFF_FFFF_u64 << GRAVITY_H);
