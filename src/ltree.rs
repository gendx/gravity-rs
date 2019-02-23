use hash;
use hash::Hash;
use std::mem;

fn ltree(root: &mut Hash, buf: &mut [Hash], mut count: usize) {
    let (mut dst, mut src) = buf.split_at_mut(count);

    while count > 1 {
        mem::swap(&mut dst, &mut src);

        let mut newcount = count >> 1;
        hash::hash_compress_pairs(dst, src, newcount);
        if count & 1 != 0 {
            dst[newcount] = src[count - 1];
            newcount += 1;
        }

        count = newcount;
    }

    *root = dst[0]
}

pub fn ltree_leaves(root: &mut Hash, leaves: &[Hash]) {
    let count = leaves.len();
    let mut buf = vec![Default::default(); 2 * count];
    for i in 0..count {
        buf[i] = leaves[i];
    }

    ltree(root, buf.as_mut_slice(), count)
}

pub fn ltree_leaves_ret(leaves: &[Hash]) -> Hash {
    let mut root = Default::default();
    ltree_leaves(&mut root, leaves);
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    // Notation for these tests: H(h_i, h_j) = h_{2^i*3^j}
    #[test]
    fn test_ltree_1() {
        let h0 = hash::tests::HASH_ELEMENT;

        let dst = ltree_leaves_ret(&[h0; 1]);
        assert_eq!(dst, h0);
    }

    #[test]
    fn test_ltree_2() {
        let h0 = hash::tests::HASH_ELEMENT;
        let h1 = hash::hash_2n_to_n_ret(&h0, &h0);

        let dst = ltree_leaves_ret(&[h0; 2]);
        assert_eq!(dst, h1);
    }

    #[test]
    fn test_ltree_3() {
        let h0 = hash::tests::HASH_ELEMENT;
        let h1 = hash::hash_2n_to_n_ret(&h0, &h0);
        let h2 = hash::hash_2n_to_n_ret(&h1, &h0);

        let dst = ltree_leaves_ret(&[h0; 3]);
        assert_eq!(dst, h2);
    }

    #[test]
    fn test_ltree_4() {
        let h0 = hash::tests::HASH_ELEMENT;
        let h1 = hash::hash_2n_to_n_ret(&h0, &h0);
        let h6 = hash::hash_2n_to_n_ret(&h1, &h1);

        let dst = ltree_leaves_ret(&[h0; 4]);
        assert_eq!(dst, h6);
    }

    #[test]
    fn test_ltree_5() {
        let h0 = hash::tests::HASH_ELEMENT;
        let h1 = hash::hash_2n_to_n_ret(&h0, &h0);
        let h6 = hash::hash_2n_to_n_ret(&h1, &h1);
        let h64 = hash::hash_2n_to_n_ret(&h6, &h0);

        let dst = ltree_leaves_ret(&[h0; 5]);
        assert_eq!(dst, h64);
    }

    #[test]
    fn test_ltree_6() {
        let h0 = hash::tests::HASH_ELEMENT;
        let h1 = hash::hash_2n_to_n_ret(&h0, &h0);
        let h6 = hash::hash_2n_to_n_ret(&h1, &h1);
        let h192 = hash::hash_2n_to_n_ret(&h6, &h1);

        let dst = ltree_leaves_ret(&[h0; 6]);
        assert_eq!(dst, h192);
    }
}
