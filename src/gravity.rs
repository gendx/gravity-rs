use hash::Hash;
use address;
use prng;
use merkle;
use pors;
use subtree;
use config::*;

pub struct SecKey {
    seed: Hash,
    salt: Hash,
    cache: merkle::MerkleTree,
}
pub struct PubKey {
    pub h: Hash,
}
#[derive(Default)]
pub struct Signature {
    pors_sign: pors::Signature,
    subtrees: [subtree::Signature; GRAVITY_D],
    auth_c: [Hash; GRAVITY_C],
}

impl SecKey {
    pub fn new(random: &[u8; 64]) -> Self {
        let mut sk = SecKey {
            seed: Hash { h: *array_ref![random, 0, 32] },
            salt: Hash { h: *array_ref![random, 32, 32] },
            cache: merkle::MerkleTree::new(GRAVITY_C),
        };

        {
            let leaves = sk.cache.leaves();
            let layer = 0u32;

            let prng = prng::Prng::new(&sk.seed);
            let subtree_sk = subtree::SecKey::new(&prng);
            for i in 0..GRAVITY_CCC {
                let address = address::Address::new(layer, (MERKLE_HHH * i) as u64);
                let pk = subtree_sk.genpk(&address);
                leaves[i] = pk.h;
            }
        }

        sk.cache.generate();
        sk
    }

    pub fn genpk(&self) -> PubKey {
        PubKey { h: self.cache.root() }
    }

    pub fn sign(&self, msg: &Hash) -> Signature {
        let mut sign: Signature = Default::default();

        let prng = prng::Prng::new(&self.seed);
        let (mut address, mut h, pors_sign) = pors::sign(&prng, &self.salt, msg);
        sign.pors_sign = pors_sign;

        let subtree_sk = subtree::SecKey::new(&prng);
        for i in 0..GRAVITY_D {
            address.next_layer();
            let (root, subtree_sign) = subtree_sk.sign(&address, &h);
            h = root;
            sign.subtrees[i] = subtree_sign;
            address.shift(MERKLE_H); // Update instance
        }

        let index = address.get_instance();
        self.cache.gen_auth(&mut sign.auth_c, index);

        sign
    }
}

impl PubKey {
    pub fn verify(&self, sign: &Signature, msg: &Hash) -> bool {
        if let Some(h) = sign.extract(msg) {
            self.h == h
        } else {
            false
        }
    }
}

impl Signature {
    pub fn extract(&self, msg: &Hash) -> Option<Hash> {
        if let Some((mut address, mut h)) = self.pors_sign.extract(msg) {
            for i in 0..GRAVITY_D {
                address.next_layer();
                h = self.subtrees[i].extract(&address, &h);
                address.shift(MERKLE_H);
            }

            let index = address.get_instance();
            merkle::merkle_compress_auth(&mut h, &self.auth_c, GRAVITY_C, index);
            Some(h)
        } else {
            None
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        use hash;

        let mut random = [0u8; 64];
        for i in 0..64 {
            random[i] = i as u8;
        }

        let sk = SecKey::new(&random);
        let pk = sk.genpk();
        let msg = hash::tests::HASH_ELEMENT;
        let sign = sk.sign(&msg);
        assert!(pk.verify(&sign, &msg));
    }

    // TODO: test vectors
}
