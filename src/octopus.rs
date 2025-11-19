use crate::config::*;
use crate::hash;
use crate::hash::Hash;
use crate::merkle;
use arrayref::array_mut_ref;
use byteorder::{ByteOrder, LittleEndian};
use std::mem;

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Octopus {
    pub oct: Vec<Hash>,
}

impl Octopus {
    pub fn serialize(&self, output: &mut Vec<u8>) {
        for x in self.oct.iter() {
            x.serialize(output);
        }
        // TODO: improve this!
        let empty = Hash { h: [0; HASH_SIZE] };
        let count = self.oct.len();
        for _ in count..(PORS_K * PORS_TAU) {
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
        let mut octopus: Octopus = Default::default();
        for _ in 0..(PORS_K * PORS_TAU) {
            octopus.oct.push(Hash::deserialize(it)?);
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

        if count > PORS_K * PORS_TAU {
            return None;
        }
        let empty = Hash { h: [0; HASH_SIZE] };
        for i in count..(PORS_K * PORS_TAU) {
            if octopus.oct[i] != empty {
                return None;
            }
        }
        octopus.oct.resize(count, empty);

        Some(octopus)
    }
}

pub fn merkle_gen_octopus(
    octopus: &mut Octopus,
    buf: &mut merkle::MerkleBuf,
    indices: &mut [usize],
) -> Hash {
    let height = buf.height();
    let mut n = 1 << height;
    let (mut dst, mut src) = buf.split_half_mut();
    let mut count = indices.len();

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
                octopus.oct.push(dst[sibling]);
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

    dst[0]
}

pub fn merkle_compress_octopus(
    nodes: &mut [Hash],
    octopus: &Octopus,
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
    use arrayref::array_ref;

    fn merkle_gen_octopus_leaves(
        octopus: &mut Octopus,
        leaves: &[Hash],
        height: usize,
        indices: &mut [usize],
    ) -> Hash {
        let count = leaves.len();
        assert_eq!(count, 1 << height);

        let mut buf = merkle::MerkleBuf::new(height);
        buf.fill_leaves(leaves);

        merkle_gen_octopus(octopus, &mut buf, indices)
    }

    #[test]
    fn test_merkle_gen_octopus() {
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
        let mut octopus = Default::default();
        let root = merkle_gen_octopus_leaves(&mut octopus, &src, 3, &mut [0, 2, 3, 6]);
        assert_eq!(
            octopus,
            Octopus {
                oct: vec![h1, h7, h10]
            }
        );
        assert_eq!(root, h14);
    }

    #[test]
    fn test_merkle_gen_compress_octopus() {
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
                    let mut octopus = Default::default();
                    let root = merkle_gen_octopus_leaves(&mut octopus, &src, 3, &mut [i, j, k]);
                    let mut nodes = [src[i], src[j], src[k]];
                    let compressed =
                        merkle_compress_octopus(&mut nodes, &octopus, 3, &mut [i, j, k]);
                    assert_eq!(compressed, Some(root));
                }
            }
        }
    }

    use super::super::{address, prng};
    use byteorder::{BigEndian, ByteOrder};
    use std::hint::black_box;
    use test::Bencher;

    #[bench]
    fn bench_merkle_gen_octopus_8(b: &mut Bencher) {
        const HEIGHT: usize = 3;
        let src = [hash::tests::HASH_ELEMENT; 1 << HEIGHT];
        let mut indices = [0, 2, 3, 6];
        b.iter(|| {
            let mut octopus = Default::default();
            let hash =
                merkle_gen_octopus_leaves(&mut octopus, black_box(&src), HEIGHT, &mut indices);
            (hash, octopus)
        });
    }

    #[bench]
    fn bench_merkle_gen_octopus_pors(b: &mut Bencher) {
        let src = vec![hash::tests::HASH_ELEMENT; PORS_T];
        let mut buf = merkle::MerkleBuf::new(PORS_TAU);
        hash::hash_parallel(buf.slice_leaves_mut(), &src, PORS_T);

        let mut subset = fake_pors_subset();
        b.iter(|| {
            let mut octopus = Default::default();
            let hash = merkle_gen_octopus(&mut octopus, black_box(&mut buf), &mut subset);
            (hash, octopus)
        });
    }

    #[bench]
    fn bench_merkle_compress_octopus_8(b: &mut Bencher) {
        const HEIGHT: usize = 3;
        let src = [hash::tests::HASH_ELEMENT; 1 << HEIGHT];
        let mut indices = [0, 2, 3];

        let mut octopus = Default::default();
        let _ = merkle_gen_octopus_leaves(&mut octopus, &src, HEIGHT, &mut indices.clone());

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

    #[bench]
    fn bench_merkle_compress_octopus_pors(b: &mut Bencher) {
        let src = vec![hash::tests::HASH_ELEMENT; PORS_T];
        let mut buf = merkle::MerkleBuf::new(PORS_TAU);
        hash::hash_parallel(buf.slice_leaves_mut(), &src, PORS_T);

        let mut subset = fake_pors_subset();
        let mut octopus = Default::default();
        merkle_gen_octopus(&mut octopus, &mut buf, &mut subset.clone());

        let mut nodes = subset.map(|i| src[i]);
        b.iter(|| {
            merkle_compress_octopus(
                black_box(&mut nodes),
                black_box(&octopus),
                PORS_TAU,
                &mut subset,
            )
        });
    }

    fn fake_pors_subset() -> [usize; PORS_K] {
        let seed = hash::tests::HASH_ELEMENT;
        let prng = prng::Prng::new(&seed);
        let address = address::Address::new(0, 0);

        let mut subset: [usize; PORS_K] = [0; PORS_K];
        let mut count = 0;
        let mut counter = 1;
        let mut block = Default::default();

        'outer: while count < PORS_K {
            prng.genblock(&mut block, &address, counter);
            'inner: for i in 0..8 {
                let x = BigEndian::read_u32(array_ref![block.h, 4 * i, 4]) as usize;
                let x = x % PORS_T;

                if subset[..count].contains(&x) {
                    continue 'inner;
                }

                subset[count] = x;
                count += 1;
                if count == PORS_K {
                    break 'outer;
                }
            }
            counter += 1;
        }

        subset.sort();
        subset
    }
}
