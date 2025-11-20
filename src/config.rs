use std::fmt::Debug;

pub trait GravityParams: Debug + PartialEq {
    #[cfg(test)]
    fn config_type() -> ConfigType;
    fn check_params();

    /// 16 is often good.
    const TAU: usize;
    const K: usize;
    /// 5 is often good.
    const H: usize;
    const D: usize;
    const C: usize;

    /* Don't modify */
    const PORS_TAU: usize = Self::TAU;
    const PORS_T: usize = 1 << Self::PORS_TAU;
    const PORS_K: usize = Self::K;

    // Implicit constraint: GRAVITY_C + MERKLE_H * GRAVITY_D <= 64
    const MERKLE_H: usize = Self::H;
    const MERKLE_H_MASK: usize = (1 << Self::MERKLE_H) - 1;

    const GRAVITY_C: usize = Self::C;
    const GRAVITY_D: usize = Self::D;
    const GRAVITY_HD: usize = Self::MERKLE_H * Self::GRAVITY_D;
    // Note: dirty hack to avoid shift overflow when GRAVITY_H = 64
    const GRAVITY_MASK: u64 = 0xFFFF_FFFF_FFFF_FFFF_u64
        ^ ((0xFFFF_FFFF_FFFF_FFFF_u64 << Self::GRAVITY_HD) << Self::GRAVITY_C);
}

#[derive(Debug, PartialEq)]
pub struct GravitySmall;

impl GravityParams for GravitySmall {
    #[cfg(test)]
    fn config_type() -> ConfigType {
        ConfigType::S
    }

    fn check_params() {
        // TODO: Move this implementation to the trait when supported.
        const {
            assert!(Self::PORS_K > 0);
            assert!(Self::PORS_K <= Self::PORS_T);
            assert!(Self::GRAVITY_C + Self::MERKLE_H * Self::GRAVITY_D <= 64);
        };
    }

    const TAU: usize = 16;
    const K: usize = 24;
    const H: usize = 5;
    const D: usize = 1;
    const C: usize = 10;
}

#[derive(Debug, PartialEq)]
pub struct GravityMedium;

impl GravityParams for GravityMedium {
    #[cfg(test)]
    fn config_type() -> ConfigType {
        ConfigType::M
    }

    fn check_params() {
        // TODO: Move this implementation to the trait when supported.
        const {
            assert!(Self::PORS_K > 0);
            assert!(Self::PORS_K <= Self::PORS_T);
            assert!(Self::GRAVITY_C + Self::MERKLE_H * Self::GRAVITY_D <= 64);
        };
    }

    const TAU: usize = 16;
    const K: usize = 32;
    const H: usize = 5;
    const D: usize = 7;
    const C: usize = 15;
}

#[derive(Debug, PartialEq)]
pub struct GravityLarge;

impl GravityParams for GravityLarge {
    #[cfg(test)]
    fn config_type() -> ConfigType {
        ConfigType::L
    }

    fn check_params() {
        // TODO: Move this implementation to the trait when supported.
        const {
            assert!(Self::PORS_K > 0);
            assert!(Self::PORS_K <= Self::PORS_T);
            assert!(Self::GRAVITY_C + Self::MERKLE_H * Self::GRAVITY_D <= 64);
        };
    }

    const TAU: usize = 16;
    const K: usize = 28;
    const H: usize = 5;
    const D: usize = 10;
    const C: usize = 14;
}

/* Don't modify */
pub const HASH_SIZE: usize = 32; // Only implemented for 32

pub const WOTS_W: usize = 16; // Only implemented for 16
pub const WOTS_LOG_ELL1: usize = 6; // Implicitly depends on HASH_SIZE and W
pub const WOTS_ELL1: usize = 1 << WOTS_LOG_ELL1;
pub const WOTS_CHKSUM: usize = 3; // Implicitly depends on W and ELL1
pub const WOTS_ELL: usize = WOTS_ELL1 + WOTS_CHKSUM;

#[cfg(test)]
#[derive(Debug, PartialEq)]
pub enum ConfigType {
    S,
    M,
    L,
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
