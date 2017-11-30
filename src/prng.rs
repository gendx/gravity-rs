use hash::Hash;
use primitives::aes256;
use address;

pub struct Prng {
    seed: Hash,
    // TODO: precompute AES round keys
}

impl Prng {
    pub fn new(seed: &Hash) -> Self {
        Self { seed: *seed }
    }

    pub fn genblock(&self, dst: &mut Hash, address: &address::Address, counter: u32) {
        let h = &mut dst.h;
        aes256::aes256(
            array_mut_ref![h, 0, 16],
            &address.to_block(2 * counter),
            &self.seed.h,
        );
        aes256::aes256(
            array_mut_ref![h, 16, 16],
            &address.to_block(2 * counter + 1),
            &self.seed.h,
        );
    }

    pub fn genblocks(&self, dst: &mut [Hash], address: &address::Address) {
        let count = dst.len();
        for i in 0..count {
            self.genblock(&mut dst[i], address, i as u32);
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genblock_zero() {
        use hash;

        let prng = Prng::new(&hash::tests::HASH_ELEMENT);
        let mut dst = Default::default();
        prng.genblock(&mut dst, &address::Address::new(0, 0), 0);

        assert_eq!(
            *array_ref![dst.h, 0, 16],
            aes256::aes256_ret(&[0; 16], &hash::tests::HASH_ELEMENT.h)
        );
        assert_eq!(
            *array_ref![dst.h, 16, 16],
            aes256::aes256_ret(
                &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                &hash::tests::HASH_ELEMENT.h,
            )
        );
    }

    // TODO: test vectors
}
