use crate::address;
use crate::config::*;
use crate::hash;
use crate::hash::Hash;
use crate::ltree::ltree_leaves_ret;
use crate::prng;
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
#[allow(clippy::needless_range_loop)]
fn split_msg(msg: &Hash) -> [usize; WOTS_ELL] {
    const {
        assert!(
            WOTS_W == 16,
            "Winternitz OTS is only implemented for WOTS_W = 16"
        );
    }

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
        PubKey {
            h: ltree_leaves_ret(&buf),
        }
    }

    #[allow(clippy::needless_range_loop)]
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
    #[cfg(test)]
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

    #[cfg(test)]
    pub fn size_hashes() -> usize {
        WOTS_ELL
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        for x in self.0.iter() {
            x.serialize(output);
        }
    }

    pub fn deserialize<'a, I>(it: &mut I) -> Option<Self>
    where
        I: Iterator<Item = &'a u8>,
    {
        let mut sign: Signature = Default::default();
        for x in sign.0.iter_mut() {
            *x = Hash::deserialize(it)?;
        }
        Some(sign)
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

    #[test]
    fn test_split_msg_0() {
        let msg = Hash { h: [0; HASH_SIZE] };
        let lengths = split_msg(&msg);
        let mut expect: [usize; WOTS_ELL] = [0; WOTS_ELL];
        expect[64] = 0x0;
        expect[65] = 0xC;
        expect[66] = 0x3;
        assert_eq!(
            expect[64] + expect[65] * WOTS_W + expect[66] * WOTS_W * WOTS_W,
            WOTS_ELL1 * (WOTS_W - 1)
        );
        assert_eq!(lengths, expect);
    }

    #[test]
    fn test_split_msg_1() {
        let msg = Hash {
            h: *b"\x00\x01\x02\x03\x04\x05\x06\x07\
                  \x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
                  \x10\x11\x12\x13\x14\x15\x16\x17\
                  \x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
        };
        let lengths = split_msg(&msg);
        let expect: [usize; WOTS_ELL] = [
            0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0, 13,
            0, 14, 0, 15, 1, 0, 1, 1, 1, 2, 1, 3, 1, 4, 1, 5, 1, 6, 1, 7, 1, 8, 1, 9, 1, 10, 1, 11,
            1, 12, 1, 13, 1, 14, 1, 15, 0, 12, 2,
        ];
        let checksum = 16 * 15 // zeros
            + 16 * 14 // ones
            + 15 * 16; // sequence
        assert_eq!(
            expect[64] + expect[65] * WOTS_W + expect[66] * WOTS_W * WOTS_W,
            checksum
        );
        assert_eq!(lengths, expect);
    }

    use std::hint::black_box;
    use test::Bencher;

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        let seed = hash::tests::HASH_ELEMENT;
        let layer: u32 = 0;
        let instance: u64 = 0;

        let prng = prng::Prng::new(&seed);
        b.iter(|| {
            let address = black_box(address::Address::new(layer, instance));
            let sk = SecKey::new(&prng, &address);
            sk.genpk()
        });
    }

    #[bench]
    fn bench_gensk(b: &mut Bencher) {
        let seed = hash::tests::HASH_ELEMENT;
        let layer: u32 = 0;
        let instance: u64 = 0;

        let prng = prng::Prng::new(&seed);
        b.iter(|| {
            let address = black_box(address::Address::new(layer, instance));
            SecKey::new(&prng, &address)
        });
    }

    #[bench]
    fn bench_genpk(b: &mut Bencher) {
        let seed = hash::tests::HASH_ELEMENT;
        let layer: u32 = 0;
        let instance: u64 = 0;

        let prng = prng::Prng::new(&seed);
        let address = address::Address::new(layer, instance);
        let sk = SecKey::new(&prng, &address);
        b.iter(|| sk.genpk());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let seed = hash::tests::HASH_ELEMENT;
        let layer: u32 = 0;
        let instance: u64 = 0;

        let prng = prng::Prng::new(&seed);
        let address = address::Address::new(layer, instance);
        let sk = SecKey::new(&prng, &address);
        let msg = hash::tests::HASH_ELEMENT;
        b.iter(|| sk.sign(black_box(&msg)));
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let seed = hash::tests::HASH_ELEMENT;
        let layer: u32 = 0;
        let instance: u64 = 0;

        let prng = prng::Prng::new(&seed);
        let address = address::Address::new(layer, instance);
        let sk = SecKey::new(&prng, &address);
        let pk = sk.genpk();
        let msg = hash::tests::HASH_ELEMENT;
        let sign = sk.sign(&msg);
        b.iter(|| pk.verify(black_box(&sign), black_box(&msg)));
    }

    #[bench]
    fn bench_split_msg(b: &mut Bencher) {
        let msg = Hash { h: [0; HASH_SIZE] };
        b.iter(|| split_msg(black_box(&msg)));
    }

    // TODO: test vectors
}
