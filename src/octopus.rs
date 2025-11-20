use crate::config::*;
use crate::hash;
use crate::hash::Hash;
use crate::merkle;
use arrayref::array_mut_ref;
use byteorder::{ByteOrder, LittleEndian};
use std::marker::PhantomData;
use std::mem;

#[derive(Debug, PartialEq, Eq)]
pub struct Octopus<P: GravityParams> {
    pub oct: Vec<Hash>,
    _phantom: PhantomData<P>,
}

impl<P: GravityParams> Octopus<P> {
    pub fn serialize(&self, output: &mut Vec<u8>) {
        for x in self.oct.iter() {
            x.serialize(output);
        }
        // TODO: improve this!
        let empty = Hash { h: [0; HASH_SIZE] };
        let count = self.oct.len();
        for _ in count..(P::PORS_K * P::PORS_TAU) {
            empty.serialize(output);
        }

        let mut block = [0u8; 16];
        LittleEndian::write_u32(array_mut_ref![&mut block, 0, 4], count as u32);
        output.extend(block.iter());
    }

    pub fn deserialize<'a, I>(it: &mut I) -> Option<Self>
    where
        I: Iterator<Item = &'a u8>,
    {
        let mut oct = Vec::new();
        for _ in 0..(P::PORS_K * P::PORS_TAU) {
            oct.push(Hash::deserialize(it)?);
        }

        let mut block = [0u8; 4];
        for x in block.iter_mut() {
            *x = *it.next()?;
        }
        let count = LittleEndian::read_u32(&block) as usize;

        for _ in 0..12 {
            if *it.next()? != 0 {
                return None;
            }
        }

        if count > P::PORS_K * P::PORS_TAU {
            return None;
        }
        let empty = Hash { h: [0; HASH_SIZE] };

        if oct[count..].iter().any(|x| *x != empty) {
            return None;
        }
        oct.resize(count, empty);

        Some(Self {
            oct,
            _phantom: PhantomData,
        })
    }
}

pub fn merkle_gen_octopus<P: GravityParams>(
    buf: &mut merkle::MerkleBuf,
    indices: &mut [usize],
) -> (Hash, Octopus<P>) {
    let height = buf.height();
    let mut n = 1 << height;
    let (mut dst, mut src) = buf.split_half_mut();
    let mut count = indices.len();

    let mut oct = Vec::new();
    for _ in 0..height {
        // Copy auth octopus
        let mut i = 0;
        let mut j = 0;
        while i < count {
            let index = indices[i];
            let sibling = index ^ 1;

            // Check redundancy with sibling
            if i + 1 < count && indices[i + 1] == sibling {
                i += 1;
            } else {
                oct.push(dst[sibling]);
            }

            indices[j] = indices[i] >> 1;

            i += 1;
            j += 1;
        }
        count = j;

        // Compute next layer
        mem::swap(&mut dst, &mut src);
        n >>= 1;
        hash::hash_compress_pairs(dst, src, n);
    }

    let root = dst[0];
    let octopus = Octopus {
        oct,
        _phantom: PhantomData,
    };
    (root, octopus)
}

pub fn merkle_compress_octopus<P: GravityParams>(
    nodes: &mut [Hash],
    octopus: &Octopus<P>,
    height: usize,
    indices: &mut [usize],
) -> Option<Hash> {
    let octolen = octopus.oct.len();
    let mut len = 0;
    let mut count = indices.len();

    for _ in 0..height {
        let mut i = 0;
        let mut j = 0;
        while i < count {
            let index = indices[i];

            if index & 1 == 0 {
                let sibling = index ^ 1;
                if i + 1 < count && indices[i + 1] == sibling {
                    nodes[j] = hash::hash_2n_to_n_ret(&nodes[i], &nodes[i + 1]);
                    i += 1;
                } else {
                    if len == octolen {
                        return None;
                    }
                    nodes[j] = hash::hash_2n_to_n_ret(&nodes[i], &octopus.oct[len]);
                    len += 1;
                }
            } else {
                if len == octolen {
                    return None;
                }
                nodes[j] = hash::hash_2n_to_n_ret(&octopus.oct[len], &nodes[i]);
                len += 1;
            }

            indices[j] = indices[i] >> 1;

            i += 1;
            j += 1;
        }
        count = j;
    }

    if len == octolen { Some(nodes[0]) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! all_tests {
        ( $mod:ident, $params:ty ) => {
            crate::tests::param_tests!(
                $mod,
                $params,
                test_merkle_gen_octopus,
                test_merkle_gen_compress_octopus,
            );
        };
    }

    all_tests!(small, GravitySmall);
    all_tests!(medium, GravityMedium);
    all_tests!(large, GravityLarge);

    fn merkle_gen_octopus_leaves<P: GravityParams>(
        leaves: &[Hash],
        height: usize,
        indices: &mut [usize],
    ) -> (Hash, Octopus<P>) {
        let count = leaves.len();
        assert_eq!(count, 1 << height);

        let mut buf = merkle::MerkleBuf::new(height);
        buf.fill_leaves(leaves);

        merkle_gen_octopus(&mut buf, indices)
    }

    fn test_merkle_gen_octopus<P: GravityParams>() {
        let h0 = hash::tests::HASH_ELEMENT;
        let h1 = hash::hash_n_to_n_ret(&h0);
        let h2 = hash::hash_n_to_n_ret(&h1);
        let h3 = hash::hash_n_to_n_ret(&h2);
        let h4 = hash::hash_n_to_n_ret(&h3);
        let h5 = hash::hash_n_to_n_ret(&h4);
        let h6 = hash::hash_n_to_n_ret(&h5);
        let h7 = hash::hash_n_to_n_ret(&h6);

        let h8 = hash::hash_2n_to_n_ret(&h0, &h1);
        let h9 = hash::hash_2n_to_n_ret(&h2, &h3);
        let h10 = hash::hash_2n_to_n_ret(&h4, &h5);
        let h11 = hash::hash_2n_to_n_ret(&h6, &h7);

        let h12 = hash::hash_2n_to_n_ret(&h8, &h9);
        let h13 = hash::hash_2n_to_n_ret(&h10, &h11);

        let h14 = hash::hash_2n_to_n_ret(&h12, &h13);

        let src = [h0, h1, h2, h3, h4, h5, h6, h7];
        let (root, octopus) = merkle_gen_octopus_leaves::<P>(&src, 3, &mut [0, 2, 3, 6]);
        assert_eq!(
            octopus,
            Octopus {
                oct: vec![h1, h7, h10],
                _phantom: PhantomData,
            }
        );
        assert_eq!(root, h14);
    }

    fn test_merkle_gen_compress_octopus<P: GravityParams>() {
        let h0 = hash::tests::HASH_ELEMENT;
        let h1 = hash::hash_n_to_n_ret(&h0);
        let h2 = hash::hash_n_to_n_ret(&h1);
        let h3 = hash::hash_n_to_n_ret(&h2);
        let h4 = hash::hash_n_to_n_ret(&h3);
        let h5 = hash::hash_n_to_n_ret(&h4);
        let h6 = hash::hash_n_to_n_ret(&h5);
        let h7 = hash::hash_n_to_n_ret(&h6);
        let src = [h0, h1, h2, h3, h4, h5, h6, h7];

        // Test all combinations of 3 indices
        for i in 0..6 {
            for j in (i + 1)..7 {
                for k in (j + 1)..8 {
                    let (root, octopus) = merkle_gen_octopus_leaves::<P>(&src, 3, &mut [i, j, k]);
                    let mut nodes = [src[i], src[j], src[k]];
                    let compressed =
                        merkle_compress_octopus(&mut nodes, &octopus, 3, &mut [i, j, k]);
                    assert_eq!(compressed, Some(root));
                }
            }
        }
    }

    macro_rules! all_benches {
        ( $mod:ident, $params:ty ) => {
            crate::tests::param_benches!(
                $mod,
                $params,
                bench_merkle_gen_octopus_pors,
                bench_merkle_compress_octopus_pors,
            );
        };
    }

    all_benches!(benches_small, GravitySmall);
    all_benches!(benches_medium, GravityMedium);
    all_benches!(benches_large, GravityLarge);

    use super::super::{address, prng};
    use arrayref::array_ref;
    use byteorder::{BigEndian, ByteOrder};
    use std::hint::black_box;
    use test::Bencher;

    #[derive(Debug, PartialEq)]
    struct Octopus8;

    impl GravityParams for Octopus8 {
        #[cfg(test)]
        fn config_type() -> ConfigType {
            ConfigType::Unknown
        }

        #[allow(clippy::absurd_extreme_comparisons)]
        fn check_params() {
            // TODO: Move this implementation to the trait when supported.
            const {
                assert!(Self::PORS_K > 0);
                assert!(Self::PORS_K <= Self::PORS_T);
                assert!(Self::GRAVITY_C + Self::MERKLE_H * Self::GRAVITY_D <= 64);
            };
        }

        const TAU: usize = 3;
        // Irrelevant here.
        const K: usize = 1;
        const H: usize = 0;
        const D: usize = 0;
        const C: usize = 0;
    }

    #[bench]
    fn bench_merkle_gen_octopus_8(b: &mut Bencher) {
        const HEIGHT: usize = 3;
        let src = [hash::tests::HASH_ELEMENT; 1 << HEIGHT];
        let mut indices = [0, 2, 3, 6];
        b.iter(|| merkle_gen_octopus_leaves::<Octopus8>(black_box(&src), HEIGHT, &mut indices));
    }

    #[bench]
    fn bench_merkle_compress_octopus_8(b: &mut Bencher) {
        const HEIGHT: usize = 3;
        let src = [hash::tests::HASH_ELEMENT; 1 << HEIGHT];
        let mut indices = [0, 2, 3];

        let (_, octopus) =
            merkle_gen_octopus_leaves::<Octopus8>(&src, HEIGHT, &mut indices.clone());

        let mut nodes = indices.map(|i| src[i]);
        b.iter(|| {
            merkle_compress_octopus(
                black_box(&mut nodes),
                black_box(&octopus),
                HEIGHT,
                &mut indices,
            )
        })
    }

    fn bench_merkle_gen_octopus_pors<P: GravityParams>(b: &mut Bencher)
    where
        [(); P::PORS_K]:,
    {
        let src = vec![hash::tests::HASH_ELEMENT; P::PORS_T];
        let mut buf = merkle::MerkleBuf::new(P::PORS_TAU);
        hash::hash_parallel(buf.slice_leaves_mut(), &src, P::PORS_T);

        let mut subset = fake_pors_subset::<P>();
        b.iter(|| merkle_gen_octopus::<P>(black_box(&mut buf), &mut subset));
    }

    fn bench_merkle_compress_octopus_pors<P: GravityParams>(b: &mut Bencher)
    where
        [(); P::PORS_K]:,
    {
        let src = vec![hash::tests::HASH_ELEMENT; P::PORS_T];
        let mut buf = merkle::MerkleBuf::new(P::PORS_TAU);
        hash::hash_parallel(buf.slice_leaves_mut(), &src, P::PORS_T);

        let mut subset = fake_pors_subset::<P>();
        let (_, octopus) = merkle_gen_octopus::<P>(&mut buf, &mut subset.clone());

        let mut nodes = subset.map(|i| src[i]);
        b.iter(|| {
            merkle_compress_octopus(
                black_box(&mut nodes),
                black_box(&octopus),
                P::PORS_TAU,
                &mut subset,
            )
        });
    }

    fn fake_pors_subset<P: GravityParams>() -> [usize; P::PORS_K] {
        let seed = hash::tests::HASH_ELEMENT;
        let prng = prng::Prng::new(&seed);
        let address = address::Address::new(0, 0);

        let mut subset: [usize; P::PORS_K] = [0; P::PORS_K];
        let mut count = 0;
        let mut counter = 1;
        let mut block = Default::default();

        'outer: while count < P::PORS_K {
            prng.genblock(&mut block, &address, counter);
            'inner: for i in 0..8 {
                let x = BigEndian::read_u32(array_ref![block.h, 4 * i, 4]) as usize;
                let x = x % P::PORS_T;

                if subset[..count].contains(&x) {
                    continue 'inner;
                }

                subset[count] = x;
                count += 1;
                if count == P::PORS_K {
                    break 'outer;
                }
            }
            counter += 1;
        }

        subset.sort();
        subset
    }
}
