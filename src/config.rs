/* Can modify */
const TAU: usize = 16; // 16 is often good
const K: usize = 24;
const H: usize = 5; // 5 is often good
const D: usize = 1;
const C: usize = 10;


/* Don't modify */
pub const HASH_SIZE: usize = 32; // Only implemented for 32

pub const WOTS_W: usize = 16; // Only implemented for 16
pub const WOTS_LOG_ELL1: usize = 6; // Implicitly depends on HASH_SIZE and W
pub const WOTS_ELL1: usize = 1 << WOTS_LOG_ELL1;
pub const WOTS_CHKSUM: usize = 3; // Implicitly depends on W and ELL1
pub const WOTS_ELL: usize = WOTS_ELL1 + WOTS_CHKSUM;

pub const PORS_TAU: usize = TAU;
pub const PORS_T: usize = 1 << PORS_TAU;
pub const PORS_K: usize = K;

// Implicit constraint: GRAVITY_C + MERKLE_H * GRAVITY_D <= 64
pub const MERKLE_H: usize = H;
pub const MERKLE_H_MASK: usize = (1 << MERKLE_H) - 1;

pub const GRAVITY_C: usize = C;
pub const GRAVITY_D: usize = D;
const GRAVITY_HD: usize = MERKLE_H * GRAVITY_D;
// Note: dirty hack to avoid shift overflow when GRAVITY_H = 64
pub const GRAVITY_MASK: u64 = 0xFFFF_FFFF_FFFF_FFFF_u64 ^
    ((0xFFFF_FFFF_FFFF_FFFF_u64 << GRAVITY_HD) << GRAVITY_C);


#[cfg(test)]
#[derive(Debug, PartialEq)]
pub enum ConfigType {
    S,
    M,
    L,
    Unknown,
}

#[cfg(test)]
pub fn get_config_type() -> ConfigType {
    match (PORS_TAU, PORS_K, MERKLE_H, GRAVITY_D, GRAVITY_C) {
        (16, 24, 5, 1, 10) => ConfigType::S,
        (16, 32, 5, 7, 15) => ConfigType::M,
        (16, 28, 5, 10, 14) => ConfigType::L,
        _ => ConfigType::Unknown,
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_type() {
        assert_ne!(get_config_type(), ConfigType::Unknown);
    }

    #[test]
    fn test_fixed() {
        assert_eq!(HASH_SIZE, 32);
        assert_eq!(WOTS_W, 16);
    }

    fn is_power_of_two(x: usize) -> bool {
        1 << x.trailing_zeros() == x
    }

    #[test]
    fn test_winternitz() {
        assert!(is_power_of_two(WOTS_W));
        assert_eq!(
            WOTS_ELL1 * (WOTS_W.trailing_zeros() as usize),
            HASH_SIZE * 8
        );
    }

    #[test]
    fn test_pors() {
        assert!(PORS_K > 0);
        assert!(PORS_K <= PORS_T);
    }

    #[test]
    fn test_gravity() {
        assert!(GRAVITY_C + MERKLE_H * GRAVITY_D <= 64);
    }
}
