use crate::hash;
use crate::hash::Hash;
use std::mem;

pub struct MerkleBuf {
    height: usize,
    buf: Vec<Hash>,
}

impl MerkleBuf {
    pub fn new(height: usize) -> Self {
        Self {
            height,
            buf: vec![Default::default(); 1 << (height + 1)],
        }
    }

    pub fn height(&self) -> usize {
        self.height
    }

    pub fn split_half_mut(&mut self) -> (&mut [Hash], &mut [Hash]) {
        self.buf.as_mut_slice().split_at_mut(1 << self.height)
    }

    pub fn slice_leaves_mut(&mut self) -> &mut [Hash] {
        &mut self.buf[..(1 << self.height)]
    }

    #[cfg(test)]
    pub fn fill_leaves(&mut self, leaves: &[Hash]) {
        for i in 0..leaves.len() {
            self.buf[i] = leaves[i];
        }
    }
}

pub struct MerkleTree {
    height: usize,
    nodes: Vec<Hash>,
}

impl MerkleTree {
    pub fn new(height: usize) -> Self {
        Self {
            height,
            nodes: vec![Default::default(); 1 << (height + 1)],
        }
    }

    pub fn leaves(&mut self) -> &mut [Hash] {
        let n = 1 << self.height;
        &mut self.nodes[n..(2 * n)]
    }

    pub fn generate(&mut self) {
        for i in 0..self.height {
            let n = 1 << (self.height - 1 - i);
            {
                let (dst, src) = self.nodes.split_at_mut(2 * n);
                hash::hash_compress_pairs(&mut dst[n..(2 * n)], src, n);
            }
        }
    }

    pub fn root(&self) -> Hash {
        self.nodes[1]
    }

    pub fn gen_auth(&self, auth: &mut [Hash], mut index: usize) {
        let mut n = 1 << self.height;
        for l in 0..self.height {
            // Copy auth path
            let sibling = index ^ 1;
            auth[l] = self.nodes[n + sibling];
            index >>= 1;
            n >>= 1;
        }
    }
}

pub fn merkle_compress_all(root: &mut Hash, buf: &mut MerkleBuf) {
    let height = buf.height();
    let mut n = 1 << height;
    let (mut dst, mut src) = buf.split_half_mut();

    for _ in 0..height {
        mem::swap(&mut dst, &mut src);
        n >>= 1;
        hash::hash_compress_pairs(dst, src, n);
    }

    *root = dst[0]
}

#[cfg(test)]
pub fn merkle_compress_all_leaves(leaves: &[Hash], height: usize) -> Hash {
    let count = leaves.len();
    assert_eq!(count, 1 << height);

    let mut buf = MerkleBuf::new(height);
    buf.fill_leaves(leaves);

    let mut root = Default::default();
    merkle_compress_all(&mut root, &mut buf);
    root
}

pub fn merkle_gen_auth(auth: &mut [Hash], buf: &mut MerkleBuf, mut index: usize) -> Hash {
    let height = buf.height();
    let mut n = 1 << height;
    let (mut dst, mut src) = buf.split_half_mut();

    for l in 0..height {
        // Copy auth path
        let sibling = index ^ 1;
        auth[l] = dst[sibling];
        index >>= 1;

        // Compute next layer
        mem::swap(&mut dst, &mut src);
        n >>= 1;
        hash::hash_compress_pairs(dst, src, n);
    }

    dst[0]
}

pub fn merkle_compress_auth(
    node: &mut Hash,
    auth: &[Hash],
    height_diff: usize,
    mut index: usize,
) -> usize {
    for l in 0..height_diff {
        if index & 1 == 0 {
            *node = hash::hash_2n_to_n_ret(node, &auth[l])
        } else {
            *node = hash::hash_2n_to_n_ret(&auth[l], node)
        }
        index >>= 1;
    }

    index
}

#[cfg(test)]
mod tests {
    use super::*;

    fn merkle_gen_auth_leaves(
        auth: &mut [Hash],
        leaves: &[Hash],
        height: usize,
        index: usize,
    ) -> Hash {
        let count = leaves.len();
        assert_eq!(count, 1 << height);

        let mut buf = MerkleBuf::new(height);
        buf.fill_leaves(leaves);

        merkle_gen_auth(auth, &mut buf, index)
    }

    // Notation for these tests: H(h_i, h_i) = h_{i+1}
    #[test]
    fn test_merkle_compress_all_0() {
        let h0 = hash::tests::HASH_ELEMENT;

        let src = [h0; 1];
        let dst = merkle_compress_all_leaves(&src, 0);
        assert_eq!(dst, h0);
    }

    #[test]
    fn test_merkle_compress_all_1() {
        let h0 = hash::tests::HASH_ELEMENT;
        let h1 = hash::hash_2n_to_n_ret(&h0, &h0);

        let src = [h0; 2];
        let dst = merkle_compress_all_leaves(&src, 1);
        assert_eq!(dst, h1);
    }

    #[test]
    fn test_merkle_compress_all_2() {
        let h0 = hash::tests::HASH_ELEMENT;
        let h1 = hash::hash_2n_to_n_ret(&h0, &h0);
        let h2 = hash::hash_2n_to_n_ret(&h1, &h1);

        let src = [h0; 4];
        let dst = merkle_compress_all_leaves(&src, 2);
        assert_eq!(dst, h2);
    }

    #[test]
    fn test_merkle_compress_all_3() {
        let h0 = hash::tests::HASH_ELEMENT;
        let h1 = hash::hash_2n_to_n_ret(&h0, &h0);
        let h2 = hash::hash_2n_to_n_ret(&h1, &h1);
        let h3 = hash::hash_2n_to_n_ret(&h2, &h2);

        let src = [h0; 8];
        let dst = merkle_compress_all_leaves(&src, 3);
        assert_eq!(dst, h3);
    }

    #[test]
    fn test_merkle_compress_all_mixed() {
        let h0 = hash::tests::HASH_ELEMENT;
        let h1 = hash::hash_n_to_n_ret(&h0);
        let h2 = hash::hash_n_to_n_ret(&h1);
        let h3 = hash::hash_n_to_n_ret(&h2);

        let h4 = hash::hash_2n_to_n_ret(&h0, &h1);
        let h5 = hash::hash_2n_to_n_ret(&h2, &h3);

        let h6 = hash::hash_2n_to_n_ret(&h4, &h5);

        let src = [h0, h1, h2, h3];
        let dst = merkle_compress_all_leaves(&src, 2);
        assert_eq!(dst, h6);
    }

    #[test]
    fn test_merkle_gen_auth_0() {
        let h0 = hash::tests::HASH_ELEMENT;
        let h1 = hash::hash_n_to_n_ret(&h0);
        let h2 = hash::hash_n_to_n_ret(&h1);
        let h3 = hash::hash_n_to_n_ret(&h2);

        let h4 = hash::hash_2n_to_n_ret(&h0, &h1);
        let h5 = hash::hash_2n_to_n_ret(&h2, &h3);

        let h6 = hash::hash_2n_to_n_ret(&h4, &h5);

        let src = [h0, h1, h2, h3];
        let mut auth = [Default::default(); 2];
        let root = merkle_gen_auth_leaves(&mut auth, &src, 2, 0);
        assert_eq!(auth, [h1, h5]);
        assert_eq!(root, h6);
    }

    #[test]
    fn test_merkle_gen_auth_1() {
        let h0 = hash::tests::HASH_ELEMENT;
        let h1 = hash::hash_n_to_n_ret(&h0);
        let h2 = hash::hash_n_to_n_ret(&h1);
        let h3 = hash::hash_n_to_n_ret(&h2);

        let h4 = hash::hash_2n_to_n_ret(&h0, &h1);
        let h5 = hash::hash_2n_to_n_ret(&h2, &h3);

        let h6 = hash::hash_2n_to_n_ret(&h4, &h5);

        let src = [h0, h1, h2, h3];
        let mut auth = [Default::default(); 2];
        let root = merkle_gen_auth_leaves(&mut auth, &src, 2, 1);
        assert_eq!(auth, [h0, h5]);
        assert_eq!(root, h6);
    }

    #[test]
    fn test_merkle_gen_auth_2() {
        let h0 = hash::tests::HASH_ELEMENT;
        let h1 = hash::hash_n_to_n_ret(&h0);
        let h2 = hash::hash_n_to_n_ret(&h1);
        let h3 = hash::hash_n_to_n_ret(&h2);

        let h4 = hash::hash_2n_to_n_ret(&h0, &h1);
        let h5 = hash::hash_2n_to_n_ret(&h2, &h3);

        let h6 = hash::hash_2n_to_n_ret(&h4, &h5);

        let src = [h0, h1, h2, h3];
        let mut auth = [Default::default(); 2];
        let root = merkle_gen_auth_leaves(&mut auth, &src, 2, 2);
        assert_eq!(auth, [h3, h4]);
        assert_eq!(root, h6);
    }

    #[test]
    fn test_merkle_gen_compress_auth() {
        let h0 = hash::tests::HASH_ELEMENT;
        let h1 = hash::hash_n_to_n_ret(&h0);
        let h2 = hash::hash_n_to_n_ret(&h1);
        let h3 = hash::hash_n_to_n_ret(&h2);
        let src = [h0, h1, h2, h3];

        for i in 0..4 {
            let mut auth = [Default::default(); 2];
            let root = merkle_gen_auth_leaves(&mut auth, &src, 2, i);
            let mut node = src[i];
            let index = merkle_compress_auth(&mut node, &auth, 2, i);
            assert_eq!(index, 0);
            assert_eq!(node, root);
        }
    }

    #[test]
    fn test_merkle_compress_auth() {
        let h0 = hash::tests::HASH_ELEMENT;
        let a1 = hash::hash_n_to_n_ret(&h0);
        let a2 = hash::hash_n_to_n_ret(&a1);
        let a3 = hash::hash_n_to_n_ret(&a2);
        let auth = [a1, a2, a3];

        let h1 = hash::hash_2n_to_n_ret(&h0, &a1);
        let h2 = hash::hash_2n_to_n_ret(&a2, &h1);
        let h3 = hash::hash_2n_to_n_ret(&h2, &a3);

        let mut node = h0;
        let index = merkle_compress_auth(&mut node, &auth, 3, 2);
        assert_eq!(index, 0);
        assert_eq!(node, h3);
    }

    #[test]
    fn test_merkle_compress_auth_partial() {
        let h0 = hash::tests::HASH_ELEMENT;
        let a1 = hash::hash_n_to_n_ret(&h0);
        let a2 = hash::hash_n_to_n_ret(&a1);
        let a3 = hash::hash_n_to_n_ret(&a2);
        let auth = [a1, a2, a3];

        let h1 = hash::hash_2n_to_n_ret(&a1, &h0);
        let h2 = hash::hash_2n_to_n_ret(&a2, &h1);

        let mut node = h0;
        let index = merkle_compress_auth(&mut node, &auth, 2, 7);
        assert_eq!(index, 1);
        assert_eq!(node, h2);
    }

    #[test]
    fn test_merkle_tree_root() {
        let h0 = hash::tests::HASH_ELEMENT;
        let h1 = hash::hash_n_to_n_ret(&h0);
        let h2 = hash::hash_n_to_n_ret(&h1);
        let h3 = hash::hash_n_to_n_ret(&h2);
        let src = [h0, h1, h2, h3];
        let expect = merkle_compress_all_leaves(&src, 2);

        let mut mt = MerkleTree::new(2);
        {
            let leaves = mt.leaves();
            leaves[0] = h0;
            leaves[1] = h1;
            leaves[2] = h2;
            leaves[3] = h3;
        }
        mt.generate();
        let root = mt.root();

        assert_eq!(root, expect);
    }

    #[test]
    fn test_merkle_tree_gen_auth() {
        let h0 = hash::tests::HASH_ELEMENT;
        let h1 = hash::hash_n_to_n_ret(&h0);
        let h2 = hash::hash_n_to_n_ret(&h1);
        let h3 = hash::hash_n_to_n_ret(&h2);
        let src = [h0, h1, h2, h3];

        let mut mt = MerkleTree::new(2);
        {
            let leaves = mt.leaves();
            leaves[0] = h0;
            leaves[1] = h1;
            leaves[2] = h2;
            leaves[3] = h3;
        }
        mt.generate();

        for index in 0..4 {
            let mut expect = [Default::default(); 2];
            merkle_gen_auth_leaves(&mut expect, &src, 2, index);
            let mut auth = [Default::default(); 2];
            mt.gen_auth(&mut auth, index);
            assert_eq!(auth, expect);
        }
    }

    use super::super::config;
    use std::hint::black_box;
    use test::Bencher;

    fn bench_merkle_compress_all(b: &mut Bencher, height: usize) {
        let mut buf = MerkleBuf::new(height);
        for leaf in buf.slice_leaves_mut() {
            *leaf = hash::tests::HASH_ELEMENT;
        }

        b.iter(|| {
            let mut root = Default::default();
            merkle_compress_all(&mut root, black_box(&mut buf));
            root
        });
    }

    fn bench_merkle_gen_auth(b: &mut Bencher, height: usize, index: usize) {
        let mut buf = MerkleBuf::new(height);
        b.iter(|| {
            // TODO: use const generic height once it's available.
            let mut auth = vec![Default::default(); height];
            let hash = merkle_gen_auth(&mut auth, black_box(&mut buf), index);
            (hash, auth)
        });
    }

    fn bench_merkle_gen_auth_first(b: &mut Bencher, height: usize) {
        bench_merkle_gen_auth(b, height, 0);
    }

    fn bench_merkle_gen_auth_last(b: &mut Bencher, height: usize) {
        bench_merkle_gen_auth(b, height, (1 << height) - 1);
    }

    fn bench_merkle_gen_auth_middle(b: &mut Bencher, height: usize) {
        let mut index = 0;
        for i in 0..height {
            index <<= 1;
            index |= i & 1;
        }
        bench_merkle_gen_auth(b, height, index);
    }

    fn bench_merkle_compress_auth(b: &mut Bencher, height: usize, index: usize) {
        // TODO: use const generic height once it's available.
        let auth = vec![hash::tests::HASH_ELEMENT; height];
        b.iter(|| {
            let mut node = black_box(hash::tests::HASH_ELEMENT);
            merkle_compress_auth(&mut node, black_box(&auth), height, index);
            node
        });
    }

    fn bench_merkle_compress_auth_first(b: &mut Bencher, height: usize) {
        bench_merkle_compress_auth(b, height, 0);
    }

    fn bench_merkle_compress_auth_last(b: &mut Bencher, height: usize) {
        bench_merkle_compress_auth(b, height, (1 << height) - 1);
    }

    fn bench_merkle_compress_auth_middle(b: &mut Bencher, height: usize) {
        let mut index = 0;
        for i in 0..height {
            index <<= 1;
            index |= i & 1;
        }
        bench_merkle_compress_auth(b, height, index);
    }

    // SPHINCS subtree
    #[bench]
    fn bench_merkle_compress_all_subtree(b: &mut Bencher) {
        bench_merkle_compress_all(b, config::MERKLE_H);
    }

    #[bench]
    fn bench_merkle_gen_auth_subtree_first(b: &mut Bencher) {
        bench_merkle_gen_auth_first(b, config::MERKLE_H);
    }

    #[bench]
    fn bench_merkle_gen_auth_subtree_last(b: &mut Bencher) {
        bench_merkle_gen_auth_last(b, config::MERKLE_H);
    }

    #[bench]
    fn bench_merkle_gen_auth_subtree_middle(b: &mut Bencher) {
        bench_merkle_gen_auth_middle(b, config::MERKLE_H);
    }

    #[bench]
    fn bench_merkle_compress_auth_subtree_first(b: &mut Bencher) {
        bench_merkle_compress_auth_first(b, config::MERKLE_H);
    }

    #[bench]
    fn bench_merkle_compress_auth_subtree_last(b: &mut Bencher) {
        bench_merkle_compress_auth_last(b, config::MERKLE_H);
    }

    #[bench]
    fn bench_merkle_compress_auth_subtree_middle(b: &mut Bencher) {
        bench_merkle_compress_auth_middle(b, config::MERKLE_H);
    }

    // PORS tree
    #[bench]
    fn bench_merkle_compress_all_pors(b: &mut Bencher) {
        bench_merkle_compress_all(b, config::PORS_TAU);
    }

    #[bench]
    fn bench_merkle_gen_auth_pors_first(b: &mut Bencher) {
        bench_merkle_gen_auth_first(b, config::PORS_TAU);
    }

    #[bench]
    fn bench_merkle_gen_auth_pors_last(b: &mut Bencher) {
        bench_merkle_gen_auth_last(b, config::PORS_TAU);
    }

    #[bench]
    fn bench_merkle_gen_auth_pors_middle(b: &mut Bencher) {
        bench_merkle_gen_auth_middle(b, config::PORS_TAU);
    }

    #[bench]
    fn bench_merkle_compress_auth_pors_first(b: &mut Bencher) {
        bench_merkle_compress_auth_first(b, config::PORS_TAU);
    }

    #[bench]
    fn bench_merkle_compress_auth_pors_last(b: &mut Bencher) {
        bench_merkle_compress_auth_last(b, config::PORS_TAU);
    }

    #[bench]
    fn bench_merkle_compress_auth_pors_middle(b: &mut Bencher) {
        bench_merkle_compress_auth_middle(b, config::PORS_TAU);
    }
}
