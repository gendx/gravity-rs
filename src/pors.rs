use crate::address;
use crate::config::*;
use crate::hash;
use crate::hash::Hash;
use crate::merkle;
use crate::octopus;
use crate::prng;
use arrayref::array_ref;
use byteorder::{BigEndian, ByteOrder};

pub struct SecKey {
    values: Vec<Hash>,
}
#[cfg(test)]
pub struct PubKey(Hash);
#[derive(Default)]
pub struct Signature {
    pepper: Hash,
    values: [Hash; PORS_K],
    octopus: octopus::Octopus,
}

impl SecKey {
    pub fn new(prng: &prng::Prng, address: &address::Address) -> Self {
        let mut sk = SecKey {
            values: vec![Default::default(); PORS_T],
        };
        prng.genblocks(sk.values.as_mut_slice(), address);
        sk
    }

    #[cfg(test)]
    pub fn genpk(&self) -> PubKey {
        let mut buf = vec![Default::default(); PORS_T];
        hash::hash_parallel_all(buf.as_mut_slice(), self.values.as_slice());
        PubKey(merkle::merkle_compress_all_leaves(buf.as_slice(), PORS_TAU))
    }

    pub fn sign_subset(&self, pepper: Hash, mut subset: [usize; PORS_K]) -> (Hash, Signature) {
        let mut sign = Signature {
            pepper,
            values: [Default::default(); PORS_K],
            octopus: Default::default(),
        };

        for i in 0..PORS_K {
            sign.values[i] = self.values[subset[i]];
        }

        let mut buf = merkle::MerkleBuf::new(PORS_TAU);
        hash::hash_parallel(buf.slice_leaves_mut(), self.values.as_slice(), PORS_T);
        let root = octopus::merkle_gen_octopus(&mut sign.octopus, &mut buf, &mut subset);

        (root, sign)
    }
}

#[cfg(test)]
impl PubKey {
    pub fn verify(&self, sign: &Signature, msg: &Hash) -> bool {
        if let Some((_, h)) = sign.extract(msg) {
            self.0 == h
        } else {
            false
        }
    }
}

impl Signature {
    pub fn extract(&self, msg: &Hash) -> Option<(address::Address, Hash)> {
        let (address, mut subset) = obtain_address_subset(&self.pepper, msg);
        let mut nodes = [Default::default(); PORS_K];
        hash::hash_parallel_all(&mut nodes, &self.values);
        let root =
            octopus::merkle_compress_octopus(&mut nodes, &self.octopus, PORS_TAU, &mut subset);
        if let Some(h) = root {
            Some((address, h))
        } else {
            None
        }
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        self.pepper.serialize(output);
        for x in self.values.iter() {
            x.serialize(output);
        }
        self.octopus.serialize(output);
    }

    pub fn deserialize<'a, I>(it: &mut I) -> Option<Self>
    where
        I: Iterator<Item = &'a u8>,
    {
        let mut sign: Signature = Default::default();
        sign.pepper = Hash::deserialize(it)?;
        for x in sign.values.iter_mut() {
            *x = Hash::deserialize(it)?;
        }
        sign.octopus = octopus::Octopus::deserialize(it)?;
        Some(sign)
    }
}

pub fn sign(prng: &prng::Prng, salt: &Hash, msg: &Hash) -> (address::Address, Hash, Signature) {
    let pepper = hash::hash_2n_to_n_ret(&salt, &msg);
    let (address, subset) = obtain_address_subset(&pepper, &msg);

    let sk = SecKey::new(&prng, &address);
    let (root, sign) = sk.sign_subset(pepper, subset);
    (address, root, sign)
}

fn obtain_address_subset(pepper: &Hash, msg: &Hash) -> (address::Address, [usize; PORS_K]) {
    // TODO: use some kind of static_assert instead
    assert!(PORS_K > 0, "PORS is only implemented for PORS_K > 0");
    assert!(
        PORS_K <= PORS_T,
        "PORS is only implemented for PORS_K <= PORS_T"
    );

    let seed = hash::hash_2n_to_n_ret(pepper, msg);
    let prng = prng::Prng::new(&seed);
    let address = address::Address::new(0, 0);

    let mut block = Default::default();
    prng.genblock(&mut block, &address, 0);
    let instance: u64 = BigEndian::read_u64(array_ref![block.h, 24, 8]);
    let instance = instance & GRAVITY_MASK;

    let mut subset: [usize; PORS_K] = [0; PORS_K];
    let mut count = 0;
    let mut counter = 1;

    'outer: while count < PORS_K {
        prng.genblock(&mut block, &address, counter);
        'inner: for i in 0..8 {
            let x = BigEndian::read_u32(array_ref![block.h, 4 * i, 4]) as usize;
            let x = x % PORS_T;

            for i in 0..count {
                if subset[i] == x {
                    continue 'inner;
                }
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
    (address::Address::new(GRAVITY_D as u32, instance), subset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let seed = hash::tests::HASH_ELEMENT;
        let salt = hash::tests::HASH_ELEMENT;
        let msg = hash::tests::HASH_ELEMENT;

        let prng = prng::Prng::new(&seed);
        let pepper = hash::hash_2n_to_n_ret(&salt, &msg);
        let (address, subset) = obtain_address_subset(&pepper, &msg);

        let sk = SecKey::new(&prng, &address);
        let pk = sk.genpk();
        let (_, sign) = sk.sign_subset(pepper, subset);

        assert!(pk.verify(&sign, &msg));
    }

    use test::Bencher;

    #[bench]
    fn bench_obtain_address_subset(b: &mut Bencher) {
        let salt = hash::tests::HASH_ELEMENT;
        let msg = hash::tests::HASH_ELEMENT;

        let pepper = hash::hash_2n_to_n_ret(&salt, &msg);
        b.iter(|| obtain_address_subset(&pepper, &msg));
    }

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        let seed = hash::tests::HASH_ELEMENT;
        let salt = hash::tests::HASH_ELEMENT;
        let msg = hash::tests::HASH_ELEMENT;

        let prng = prng::Prng::new(&seed);
        b.iter(|| {
            let pepper = hash::hash_2n_to_n_ret(&salt, &msg);
            let (address, _) = obtain_address_subset(&pepper, &msg);

            let sk = SecKey::new(&prng, &address);
            sk.genpk()
        });
    }

    #[bench]
    fn bench_gensk(b: &mut Bencher) {
        let seed = hash::tests::HASH_ELEMENT;
        let salt = hash::tests::HASH_ELEMENT;
        let msg = hash::tests::HASH_ELEMENT;

        let prng = prng::Prng::new(&seed);
        b.iter(|| {
            let pepper = hash::hash_2n_to_n_ret(&salt, &msg);
            let (address, _) = obtain_address_subset(&pepper, &msg);

            SecKey::new(&prng, &address)
        });
    }

    #[bench]
    fn bench_genpk(b: &mut Bencher) {
        let seed = hash::tests::HASH_ELEMENT;
        let salt = hash::tests::HASH_ELEMENT;
        let msg = hash::tests::HASH_ELEMENT;

        let prng = prng::Prng::new(&seed);
        let pepper = hash::hash_2n_to_n_ret(&salt, &msg);
        let (address, _) = obtain_address_subset(&pepper, &msg);

        let sk = SecKey::new(&prng, &address);
        b.iter(|| sk.genpk());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let seed = hash::tests::HASH_ELEMENT;
        let salt = hash::tests::HASH_ELEMENT;
        let msg = hash::tests::HASH_ELEMENT;

        let prng = prng::Prng::new(&seed);
        let pepper = hash::hash_2n_to_n_ret(&salt, &msg);
        let (address, subset) = obtain_address_subset(&pepper, &msg);

        let sk = SecKey::new(&prng, &address);
        b.iter(|| sk.sign_subset(pepper, subset));
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let seed = hash::tests::HASH_ELEMENT;
        let salt = hash::tests::HASH_ELEMENT;
        let msg = hash::tests::HASH_ELEMENT;

        let prng = prng::Prng::new(&seed);
        let pepper = hash::hash_2n_to_n_ret(&salt, &msg);
        let (address, subset) = obtain_address_subset(&pepper, &msg);

        let sk = SecKey::new(&prng, &address);
        let pk = sk.genpk();
        let (_, sign) = sk.sign_subset(pepper, subset);
        b.iter(|| pk.verify(&sign, &msg));
    }

    // TODO: test vectors
}
