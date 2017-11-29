use hash;
use hash::Hash;
use ltree::ltree_leaves_ret;
use address;
use prng;
use config::*;
use std::default;

pub struct SecKey([Hash; WOTS_ELL]);
pub struct PubKey {
    pub h: Hash,
}
pub struct Signature([Hash; WOTS_ELL]);

impl default::Default for Signature {
    fn default() -> Self {
        Signature([Default::default(); WOTS_ELL])
    }
}

// Split a message into a list of Winternitz indices (with checksum)
fn split_msg(msg: &Hash) -> [usize; WOTS_ELL] {
    // TODO: use some kind of static_assert instead
    assert_eq!(
        WOTS_W,
        16,
        "Winternitz OTS is only implemented for WOTS_W = 16"
    );

    let mut result = [0; WOTS_ELL];
    let mut checksum: usize = 0;

    for j in 0..HASH_SIZE {
        let v = msg.h[j];
        let a = (v >> 4) as usize;
        let b = (v & 0xF) as usize;
        checksum += (WOTS_W - 1 - a) + (WOTS_W - 1 - b);

        result[2 * j] = a;
        result[2 * j + 1] = b;
    }

    for i in WOTS_ELL1..WOTS_ELL {
        result[i] = checksum & 0xF;
        checksum >>= 4;
    }

    result
}

impl SecKey {
    pub fn new(prng: &prng::Prng, address: &address::Address) -> Self {
        let mut sk = SecKey([Default::default(); WOTS_ELL]);
        prng.genblocks(&mut sk.0, address);
        sk
    }

    pub fn genpk(&self) -> PubKey {
        let mut buf = [Default::default(); WOTS_ELL];
        hash::hash_parallel_chains_all(&mut buf, &self.0, WOTS_W - 1);
        PubKey { h: ltree_leaves_ret(&buf) }
    }

    pub fn sign(&self, msg: &Hash) -> Signature {
        let mut sign = Signature([Default::default(); WOTS_ELL]);
        let lengths = split_msg(msg);

        for i in 0..WOTS_ELL {
            hash::hash_n_to_n_chain(&mut sign.0[i], &self.0[i], lengths[i]);
        }

        sign
    }
}

impl PubKey {
    pub fn verify(&self, sign: &Signature, msg: &Hash) -> bool {
        let h = sign.extract(msg);
        self.h == h
    }
}

impl Signature {
    pub fn extract(&self, msg: &Hash) -> Hash {
        let mut buf = [Default::default(); WOTS_ELL];
        let lengths = split_msg(msg);

        for i in 0..WOTS_ELL {
            hash::hash_n_to_n_chain(&mut buf[i], &self.0[i], WOTS_W - 1 - lengths[i]);
        }

        ltree_leaves_ret(&buf)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let seed = hash::tests::HASH_ELEMENT;
        let layer: u32 = 0;
        let instance: u64 = 0;

        let prng = prng::Prng::new(&seed);
        let address = address::Address::new(layer, instance);
        let sk = SecKey::new(&prng, &address);
        let pk = sk.genpk();
        let msg = hash::tests::HASH_ELEMENT;
        let sign = sk.sign(&msg);
        assert!(pk.verify(&sign, &msg));
    }

    // TODO: test vectors
}
