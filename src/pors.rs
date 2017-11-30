use byteorder::{ByteOrder, BigEndian};
use hash;
use hash::Hash;
use merkle;
use octopus;
use address;
use prng;
use config::*;

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
        let mut sk = SecKey { values: vec![Default::default(); PORS_T] };
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
        {
            let (tmp, _) = buf.split_at_mut(PORS_T);
            hash::hash_parallel(tmp, self.values.as_slice(), PORS_T);
        }
        let root = octopus::merkle_gen_octopus(&mut sign.octopus, &mut buf, PORS_TAU, &mut subset);

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
        for i in 0..PORS_K {
            sign.values[i] = Hash::deserialize(it)?;
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
    assert_eq!(PORS_TAU, 16, "PORS is only implemented for PORS_TAU = 16");
    assert!(PORS_K > 0, "PORS is only implemented for PORS_K > 0");

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
            println!("pors x = {}", x);

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

        //let h1 = hash::hash_n_to_n_ret(&msg);
        assert!(pk.verify(&sign, &msg));
    }

    // TODO: test vectors
}
