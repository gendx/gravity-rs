use hash::Hash;
use address;
use prng;
use merkle;
use wots;
use config::*;

pub struct SecKey<'a> {
    prng: &'a prng::Prng,
}
pub struct PubKey {
    pub h: Hash,
}
#[derive(Default)]
pub struct Signature {
    wots_sign: wots::Signature,
    auth: [Hash; MERKLE_H],
}

impl<'a> SecKey<'a> {
    pub fn new(prng: &'a prng::Prng) -> Self {
        Self { prng }
    }

    pub fn genpk(&self, address: &address::Address) -> PubKey {
        let mut buf = merkle::MerkleBuf::new(MERKLE_H);
        let (mut address, _) = address.normalize_index((MERKLE_HHH - 1) as u64);

        {
            let (tmp, _) = buf.split_at_mut(MERKLE_HHH);
            for i in 0..MERKLE_HHH {
                let sk = wots::SecKey::new(self.prng, &address);
                let pk = sk.genpk();
                tmp[i] = pk.h;
                address.incr_instance();
            }
        }

        let mut dst = Default::default();
        merkle::merkle_compress_all(&mut dst, &mut buf, MERKLE_H);
        PubKey { h: dst }
    }

    pub fn sign(&self, address: &address::Address, msg: &Hash) -> (Hash, Signature) {
        let mut sign: Signature = Default::default();

        let mut buf = merkle::MerkleBuf::new(MERKLE_H);
        let (mut address, index) = address.normalize_index((MERKLE_HHH - 1) as u64);

        {
            let (tmp, _) = buf.split_at_mut(MERKLE_HHH);
            for i in 0..MERKLE_HHH {
                let sk = wots::SecKey::new(self.prng, &address);
                let pk = sk.genpk();
                tmp[i] = pk.h;
                if i == index {
                    sign.wots_sign = sk.sign(msg);
                }
                address.incr_instance();
            }
        }

        let root = merkle::merkle_gen_auth(&mut sign.auth, &mut buf, MERKLE_H, index);
        (root, sign)
    }
}

impl PubKey {
    #[cfg(test)]
    pub fn verify(&self, address: &address::Address, sign: &Signature, msg: &Hash) -> bool {
        let h = sign.extract(&address, msg);
        self.h == h
    }
}

impl Signature {
    pub fn extract(&self, address: &address::Address, msg: &Hash) -> Hash {
        let (_, index) = address.normalize_index((MERKLE_HHH - 1) as u64);
        let mut h = self.wots_sign.extract(msg);
        merkle::merkle_compress_auth(&mut h, &self.auth, MERKLE_H, index);
        h
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        self.wots_sign.serialize(output);
        for x in self.auth.iter() {
            x.serialize(output);
        }
    }

    pub fn deserialize<'a, I>(it: &mut I) -> Option<Self>
    where
        I: Iterator<Item = &'a u8>,
    {
        let mut sign: Signature = Default::default();
        sign.wots_sign = wots::Signature::deserialize(it)?;
        for i in 0..MERKLE_H {
            sign.auth[i] = Hash::deserialize(it)?;
        }
        Some(sign)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        use hash;

        let seed = hash::tests::HASH_ELEMENT;
        let layer: u32 = 0x01020304;
        let instance: u64 = 0x05060708090a0b0c;

        let prng = prng::Prng::new(&seed);
        let address = address::Address::new(layer, instance);

        let sk = SecKey::new(&prng);
        let pk = sk.genpk(&address);
        let msg = hash::tests::HASH_ELEMENT;
        let (root, sign) = sk.sign(&address, &msg);
        assert_eq!(root, pk.h);
        assert!(pk.verify(&address, &sign, &msg));
    }

    // TODO: test vectors
}