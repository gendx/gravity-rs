use crate::address;
use crate::hash::Hash;
use crate::primitives::aes256;
use arrayref::array_mut_ref;

#[derive(Default)]
pub struct Prng {
    rkeys: [[u8; 16]; 15],
}

impl Prng {
    pub fn new(seed: &Hash) -> Self {
        let mut prng: Prng = Default::default();
        aes256::expand256_slice(&seed.h, &mut prng.rkeys);
        prng
    }

    pub fn genblock(&self, dst: &mut Hash, address: &address::Address, counter: u32) {
        let h = &mut dst.h;
        aes256::aes256_rkeys_slice(
            array_mut_ref![h, 0, 16],
            &address.to_block(2 * counter),
            &self.rkeys,
        );
        aes256::aes256_rkeys_slice(
            array_mut_ref![h, 16, 16],
            &address.to_block(2 * counter + 1),
            &self.rkeys,
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
    use super::super::hash;
    use super::*;
    use arrayref::array_ref;

    #[test]
    fn test_genblock_zero() {
        let prng = Prng::new(&hash::tests::HASH_ELEMENT);
        let mut dst = Default::default();
        prng.genblock(&mut dst, &address::Address::new(0, 0), 0);

        assert_eq!(
            *array_ref![dst.h, 0, 16],
            aes256::aes256_ret(
                &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                &hash::tests::HASH_ELEMENT.h,
            )
        );
        assert_eq!(
            *array_ref![dst.h, 16, 16],
            aes256::aes256_ret(
                &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                &hash::tests::HASH_ELEMENT.h,
            )
        );
    }

    #[test]
    fn test_genblocks() {
        let prng = Prng::new(&hash::tests::HASH_ELEMENT);
        let mut dst = [Default::default(); 3];
        prng.genblocks(&mut dst, &address::Address::new(0, 0));

        for i in 0..3 {
            let j = 2 * i as u8;
            assert_eq!(
                *array_ref![dst[i].h, 0, 16],
                aes256::aes256_ret(
                    &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, j],
                    &hash::tests::HASH_ELEMENT.h,
                )
            );
            let j = (2 * i + 1) as u8;
            assert_eq!(
                *array_ref![dst[i].h, 16, 16],
                aes256::aes256_ret(
                    &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, j],
                    &hash::tests::HASH_ELEMENT.h,
                )
            );
        }
    }

    #[test]
    fn test_kat() {
        use hex;

        let prng = Prng::new(&hash::tests::HASH_ELEMENT);
        let mut dst = [Default::default(); 3];
        prng.genblocks(
            &mut dst,
            &address::Address::new(0x01020304, 0x05060708090a0b0c),
        );

        let expect = hex::decode(
            "b53cb99417a048bb15cfd6736804f6af990ff34be63fc19cb626381935d550ca\
             983118485ada760182fb24cc2899158bb44ca576ec99a8a9775897a34d62cc4c\
             bd4071f05445d2eb4922114e2f847347a63ea10249474f55f9d6ca81cf66a3ca",
        )
        .unwrap();

        assert_eq!(dst[0].h, *array_ref![expect, 0, 32]);
        assert_eq!(dst[1].h, *array_ref![expect, 32, 32]);
        assert_eq!(dst[2].h, *array_ref![expect, 64, 32]);
    }

    use super::super::config;
    use test::Bencher;

    #[bench]
    fn bench_genblock(b: &mut Bencher) {
        let prng = Prng::new(&hash::tests::HASH_ELEMENT);
        let mut dst = Default::default();
        b.iter(|| prng.genblock(&mut dst, &address::Address::new(0, 0), 0));
    }

    #[bench]
    fn bench_genblocks_5(b: &mut Bencher) {
        let prng = Prng::new(&hash::tests::HASH_ELEMENT);
        let mut dst = [Default::default(); 5];
        b.iter(|| prng.genblocks(&mut dst, &address::Address::new(0, 0)));
    }

    #[bench]
    fn bench_genblocks_20(b: &mut Bencher) {
        let prng = Prng::new(&hash::tests::HASH_ELEMENT);
        let mut dst = [Default::default(); 20];
        b.iter(|| prng.genblocks(&mut dst, &address::Address::new(0, 0)));
    }

    #[bench]
    fn bench_genblocks_pors(b: &mut Bencher) {
        let prng = Prng::new(&hash::tests::HASH_ELEMENT);
        let mut dst = vec![Default::default(); config::PORS_T];
        b.iter(|| prng.genblocks(&mut dst, &address::Address::new(0, 0)));
    }

    #[bench]
    fn bench_genblocks_wots(b: &mut Bencher) {
        let prng = Prng::new(&hash::tests::HASH_ELEMENT);
        let mut dst = [Default::default(); config::WOTS_ELL];
        b.iter(|| prng.genblocks(&mut dst, &address::Address::new(0, 0)));
    }
}
