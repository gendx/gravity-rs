use crate::config;
use crate::primitives::haraka256;
use crate::primitives::haraka512;
use arrayref::array_ref;
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Clone, Copy, Default, PartialEq)]
pub struct Hash {
    pub h: [u8; config::HASH_SIZE],
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for x in self.h.iter() {
            write!(f, "{:02x}", x)?;
        }
        Ok(())
    }
}

impl Hash {
    pub fn serialize(&self, output: &mut Vec<u8>) {
        output.extend(self.h.iter());
    }

    pub fn deserialize<'a, I>(it: &mut I) -> Option<Self>
    where
        I: Iterator<Item = &'a u8>,
    {
        let mut hash: Hash = Default::default();
        for x in hash.h.iter_mut() {
            *x = *it.next()?;
        }
        Some(hash)
    }
}

pub fn long_hash(src: &[u8]) -> Hash {
    let digest = Sha256::digest(src);
    Hash {
        h: *array_ref![digest, 0, config::HASH_SIZE],
    }
}

pub fn hash_n_to_n(dst: &mut Hash, src: &Hash) {
    haraka256::haraka256::<6>(&mut dst.h, &src.h)
}

#[cfg(test)]
pub fn hash_n_to_n_ret(src: &Hash) -> Hash {
    let mut dst = Default::default();
    hash_n_to_n(&mut dst, src);
    dst
}

pub fn hash_2n_to_n(dst: &mut Hash, src0: &Hash, src1: &Hash) {
    haraka512::haraka512::<6>(&mut dst.h, &src0.h, &src1.h)
}

#[inline(always)]
pub fn hash_2n_to_n_ret(src0: &Hash, src1: &Hash) -> Hash {
    let mut dst = Default::default();
    hash_2n_to_n(&mut dst, src0, src1);
    dst
}

#[inline(always)]
pub fn hash_n_to_n_chain(dst: &mut Hash, src: &Hash, count: usize) {
    *dst = *src;
    for _ in 0..count {
        let tmp = *dst;
        hash_n_to_n(dst, &tmp);
    }
}

#[cfg(test)]
pub fn hash_n_to_n_chain_ret(src: &Hash, count: usize) -> Hash {
    let mut dst = Default::default();
    hash_n_to_n_chain(&mut dst, src, count);
    dst
}

#[inline(always)]
pub fn hash_parallel(dst: &mut [Hash], src: &[Hash], count: usize) {
    for i in 0..count {
        hash_n_to_n(&mut dst[i], &src[i]);
    }
}

#[inline(always)]
pub fn hash_parallel_all(dst: &mut [Hash], src: &[Hash]) {
    let count = dst.len();
    hash_parallel(dst, src, count);
}

#[inline(always)]
fn hash_parallel_chains(dst: &mut [Hash], src: &[Hash], count: usize, chainlen: usize) {
    dst[..count].copy_from_slice(&src[..count]);
    for _ in 0..chainlen {
        for i in 0..count {
            let tmp = dst[i];
            hash_n_to_n(&mut dst[i], &tmp);
        }
    }
}

#[inline(always)]
pub fn hash_parallel_chains_all(dst: &mut [Hash], src: &[Hash], chainlen: usize) {
    let count = dst.len();
    hash_parallel_chains(dst, src, count, chainlen);
}

#[inline(always)]
pub fn hash_compress_pairs(dst: &mut [Hash], src: &[Hash], count: usize) {
    for i in 0..count {
        hash_2n_to_n(&mut dst[i], &src[2 * i], &src[2 * i + 1]);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    // Tests must pass whatever this value is.
    pub const HASH_ELEMENT: Hash = Hash {
        h: *b"\x00\x01\x02\x03\x04\x05\x06\x07\
              \x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
              \x10\x11\x12\x13\x14\x15\x16\x17\
              \x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
    };

    #[test]
    fn test_chain_0() {
        let src = HASH_ELEMENT;
        let dst = hash_n_to_n_chain_ret(&src, 0);
        assert_eq!(dst, src);
    }

    #[test]
    fn test_chain_1() {
        let src = HASH_ELEMENT;
        let expect = hash_n_to_n_ret(&src);
        let dst = hash_n_to_n_chain_ret(&src, 1);
        assert_eq!(dst, expect);
    }

    #[test]
    fn test_chain_5() {
        let src = Hash {
            h: *b"\x00\x01\x02\x03\x04\x05\x06\x07\
                  \x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
                  \x10\x11\x12\x13\x14\x15\x16\x17\
                  \x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
        };
        let expect = Hash {
            h: *b"\xae\x13\x7b\x6f\x07\x3c\xa8\x60\
                  \x2d\x6c\xa2\x06\x6a\x64\xb4\x5f\
                  \x8f\xe9\x76\xbe\xa2\xee\xb5\xce\
                  \x1c\x2e\xeb\xaa\xf7\x00\x46\x36",
        };
        let dst = hash_n_to_n_chain_ret(&src, 5);
        assert_eq!(dst, expect);
    }

    #[test]
    fn test_parallel() {
        let src = [HASH_ELEMENT; 5];
        let expect = hash_n_to_n_ret(&HASH_ELEMENT);
        let mut dst = [Default::default(); 5];
        hash_parallel_all(&mut dst, &src);
        assert_eq!(dst, [expect; 5]);
    }

    #[test]
    fn test_parallel_mix() {
        let h0 = HASH_ELEMENT;
        let h1 = hash_n_to_n_ret(&h0);
        let h2 = hash_n_to_n_ret(&h1);
        let h3 = hash_n_to_n_ret(&h2);
        let h4 = hash_n_to_n_ret(&h3);
        let h5 = hash_n_to_n_ret(&h4);

        let src = [h0, h1, h2, h3, h4];
        let expect = [h1, h2, h3, h4, h5];
        let mut dst = [Default::default(); 5];
        hash_parallel_all(&mut dst, &src);
        assert_eq!(dst, expect);
    }

    #[test]
    fn test_parallel_chains_0() {
        let src = [HASH_ELEMENT; 5];
        let mut dst = [Default::default(); 5];
        hash_parallel_chains_all(&mut dst, &src, 0);
        assert_eq!(dst, src);
    }

    #[test]
    fn test_parallel_chains_1() {
        let src = [HASH_ELEMENT; 5];
        let expect = hash_n_to_n_ret(&HASH_ELEMENT);
        let mut dst = [Default::default(); 5];
        hash_parallel_chains_all(&mut dst, &src, 1);
        assert_eq!(dst, [expect; 5]);
    }

    #[test]
    fn test_parallel_chains_3() {
        let src = [HASH_ELEMENT; 5];
        let expect = hash_n_to_n_ret(&hash_n_to_n_ret(&hash_n_to_n_ret(&HASH_ELEMENT)));
        let mut dst = [Default::default(); 5];
        hash_parallel_chains_all(&mut dst, &src, 3);
        assert_eq!(dst, [expect; 5]);
    }

    #[test]
    fn test_compress_pairs_1() {
        let src = [HASH_ELEMENT; 2];
        let expect = hash_2n_to_n_ret(&HASH_ELEMENT, &HASH_ELEMENT);

        let mut dst = [Default::default(); 1];
        hash_compress_pairs(&mut dst, &src, 1);

        assert_eq!(dst, [expect]);
    }

    #[test]
    fn test_compress_pairs_2() {
        let src = [HASH_ELEMENT; 4];
        let expect = hash_2n_to_n_ret(&HASH_ELEMENT, &HASH_ELEMENT);

        let mut dst = [Default::default(); 2];
        hash_compress_pairs(&mut dst, &src, 2);

        assert_eq!(dst, [expect, expect]);
    }

    use std::hint::black_box;
    use test::Bencher;

    #[bench]
    fn bench_chain_1(b: &mut Bencher) {
        let src = HASH_ELEMENT;
        b.iter(|| hash_n_to_n_chain_ret(black_box(&src), 1));
    }

    #[bench]
    fn bench_chain_5(b: &mut Bencher) {
        let src = HASH_ELEMENT;
        b.iter(|| hash_n_to_n_chain_ret(black_box(&src), 5));
    }

    #[bench]
    fn bench_parallel_5(b: &mut Bencher) {
        let src = [HASH_ELEMENT; 5];
        b.iter(|| {
            let mut dst = [Default::default(); 5];
            hash_parallel_all(&mut dst, black_box(&src));
            dst
        });
    }

    #[bench]
    fn bench_parallel_chains_5x5(b: &mut Bencher) {
        let src = [HASH_ELEMENT; 5];
        b.iter(|| {
            let mut dst = [Default::default(); 5];
            hash_parallel_chains_all(&mut dst, black_box(&src), 5);
            dst
        });
    }

    #[bench]
    fn bench_parallel_columns_5x5(b: &mut Bencher) {
        let src = [HASH_ELEMENT; 5];
        b.iter(|| {
            let mut dst = [Default::default(); 5];
            for i in 0..5 {
                hash_n_to_n_chain(&mut dst[i], black_box(&src[i]), 5);
            }
            dst
        });
    }

    #[bench]
    fn bench_parallel_rows_5x5(b: &mut Bencher) {
        let src = [HASH_ELEMENT; 5];
        b.iter(|| {
            let mut dst = black_box(src);
            for _ in 0..5 {
                let tmp = dst;
                hash_parallel_all(&mut dst, &tmp);
            }
            dst
        });
    }

    #[bench]
    fn bench_parallel_mix_5(b: &mut Bencher) {
        let h0 = HASH_ELEMENT;
        let h1 = hash_n_to_n_ret(&h0);
        let h2 = hash_n_to_n_ret(&h1);
        let h3 = hash_n_to_n_ret(&h2);
        let h4 = hash_n_to_n_ret(&h3);

        let src = [h0, h1, h2, h3, h4];
        b.iter(|| {
            let mut dst = [Default::default(); 5];
            hash_parallel_all(&mut dst, black_box(&src));
            dst
        });
    }
}
