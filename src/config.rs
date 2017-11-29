pub const HASH_SIZE: usize = 32; // Only implemented for 32

pub const WOTS_W: usize = 16; // Only implemented for 16
pub const WOTS_LOG_ELL1: usize = 6; // Implicitly depends on HASH_SIZE and W
pub const WOTS_ELL1: usize = 1 << WOTS_LOG_ELL1;
pub const WOTS_CHKSUM: usize = 3; // Implicitly depends on W and ELL1
pub const WOTS_ELL: usize = WOTS_ELL1 + WOTS_CHKSUM;

pub const PORS_TAU: usize = 16; // Only implemented for 16
pub const PORS_T: usize = 1 << PORS_TAU;
pub const PORS_K: usize = 32; // Can be modified

// Implicit constraint: GRAVITY_C + MERKLE_H * GRAVITY_D <= 64
pub const MERKLE_H: usize = 5; // Can be modified
pub const MERKLE_HHH: usize = 1 << MERKLE_H;

pub const GRAVITY_C: usize = 10; // Can be modified
pub const GRAVITY_CCC: usize = 1 << GRAVITY_C;
pub const GRAVITY_D: usize = 8; // Can be modified
pub const GRAVITY_DDD: usize = 1 << GRAVITY_D;
pub const GRAVITY_H: usize = MERKLE_H * GRAVITY_D + GRAVITY_C;
pub static GRAVITY_MASK: u64 = 0xFFFF_FFFF_FFFF_FFFF_u64 ^ (0xFFFF_FFFF_FFFF_FFFF_u64 << GRAVITY_H);
