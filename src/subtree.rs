use crate::address;
use crate::config::*;
use crate::hash::Hash;
use crate::merkle;
use crate::prng;
use crate::wots;
use std::array;
use std::marker::PhantomData;

pub struct SecKey<'a, P: GravityParams> {
    prng: &'a prng::Prng,
    _phantom: PhantomData<P>,
}

pub struct PubKey<P: GravityParams> {
    pub h: Hash,
    _phantom: PhantomData<P>,
}

pub struct Signature<P: GravityParams>
where
    [(); P::MERKLE_H]:,
{
    wots_sign: wots::Signature,
    auth: [Hash; P::MERKLE_H],
}

impl<'a, P: GravityParams> SecKey<'a, P> {
    pub fn new(prng: &'a prng::Prng) -> Self {
        Self {
            prng,
            _phantom: PhantomData,
        }
    }

    pub fn genpk(&self, address: &address::Address) -> PubKey<P> {
        let mut buf = merkle::MerkleBuf::new(P::MERKLE_H);
        let (mut address, _) = address.normalize_index(P::MERKLE_H_MASK as u64);

        for leaf in buf.slice_leaves_mut() {
            let sk = wots::SecKey::new(self.prng, &address);
            let pk = sk.genpk();
            *leaf = pk.h;
            address.incr_instance();
        }

        let mut dst = Default::default();
        merkle::merkle_compress_all(&mut dst, &mut buf);
        PubKey {
            h: dst,
            _phantom: PhantomData,
        }
    }

    pub fn sign(&self, address: &address::Address, msg: &Hash) -> (Hash, Signature<P>)
    where
        [(); P::MERKLE_H]:,
    {
        let mut buf = merkle::MerkleBuf::new(P::MERKLE_H);
        let (mut address, index) = address.normalize_index(P::MERKLE_H_MASK as u64);

        let mut wots_sign = None;
        for (i, leaf) in buf.slice_leaves_mut().iter_mut().enumerate() {
            let sk = wots::SecKey::new(self.prng, &address);
            let pk = sk.genpk();
            *leaf = pk.h;
            if i == index {
                wots_sign = Some(sk.sign(msg));
            }
            address.incr_instance();
        }

        let mut auth = [Default::default(); P::MERKLE_H];
        let root = merkle::merkle_gen_auth(&mut auth, &mut buf, index);

        let sign = Signature {
            wots_sign: wots_sign.unwrap(),
            auth,
        };
        (root, sign)
    }
}

impl<P: GravityParams> PubKey<P> {
    #[cfg(test)]
    pub fn verify(&self, address: &address::Address, sign: &Signature<P>, msg: &Hash) -> bool
    where
        [(); P::MERKLE_H]:,
    {
        let h = sign.extract(address, msg);
        self.h == h
    }
}

impl<P: GravityParams> Signature<P>
where
    [(); P::MERKLE_H]:,
{
    pub fn extract(&self, address: &address::Address, msg: &Hash) -> Hash {
        let (_, index) = address.normalize_index(P::MERKLE_H_MASK as u64);
        let mut h = self.wots_sign.extract(msg);
        merkle::merkle_compress_auth(&mut h, &self.auth, P::MERKLE_H, index);
        h
    }

    #[cfg(test)]
    pub fn size_hashes() -> usize {
        wots::Signature::size_hashes() + P::MERKLE_H
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
        let wots_sign = wots::Signature::deserialize(it)?;
        let auth = array::try_from_fn(|_| Hash::deserialize(it))?;

        Some(Signature { wots_sign, auth })
    }
}

#[cfg(test)]
mod tests {
    use super::super::hash;
    use super::*;

    macro_rules! all_tests {
        ( $mod:ident, $params:ty ) => {
            crate::tests::param_tests!($mod, $params, test_signature_size, test_sign_verify,);
        };
    }

    all_tests!(small, GravitySmall);
    all_tests!(medium, GravityMedium);
    all_tests!(large, GravityLarge);

    fn test_signature_size<P: GravityParams>()
    where
        [(); P::MERKLE_H]:,
    {
        let expected_hashes = match P::config_type() {
            ConfigType::S | ConfigType::M | ConfigType::L => 72,
            ConfigType::Unknown => unimplemented!(),
        };
        assert_eq!(Signature::<P>::size_hashes(), expected_hashes);
    }

    fn test_sign_verify<P: GravityParams>()
    where
        [(); P::MERKLE_H]:,
    {
        let seed = hash::tests::HASH_ELEMENT;
        let layer: u32 = 0x01020304;
        let instance: u64 = 0x05060708090a0b0c;

        let prng = prng::Prng::new(&seed);
        let address = address::Address::new(layer, instance);

        let sk = SecKey::<P>::new(&prng);
        let pk = sk.genpk(&address);
        let msg = hash::tests::HASH_ELEMENT;
        let (root, sign) = sk.sign(&address, &msg);
        assert_eq!(root, pk.h);
        assert!(pk.verify(&address, &sign, &msg));
    }

    macro_rules! all_benches {
        ( $mod:ident, $params:ty ) => {
            crate::tests::param_benches!($mod, $params, bench_genpk, bench_sign, bench_verify,);
        };
    }

    all_benches!(benches_small, GravitySmall);
    all_benches!(benches_medium, GravityMedium);
    all_benches!(benches_large, GravityLarge);

    use std::hint::black_box;
    use test::Bencher;

    fn bench_genpk<P: GravityParams>(b: &mut Bencher) {
        let seed = hash::tests::HASH_ELEMENT;
        let layer: u32 = 0x01020304;
        let instance: u64 = 0x05060708090a0b0c;

        let prng = prng::Prng::new(&seed);
        let address = address::Address::new(layer, instance);

        let sk = SecKey::<P>::new(&prng);
        b.iter(|| sk.genpk(black_box(&address)));
    }

    fn bench_sign<P: GravityParams>(b: &mut Bencher)
    where
        [(); P::MERKLE_H]:,
    {
        let seed = hash::tests::HASH_ELEMENT;
        let layer: u32 = 0x01020304;
        let instance: u64 = 0x05060708090a0b0c;

        let prng = prng::Prng::new(&seed);
        let address = address::Address::new(layer, instance);

        let sk = SecKey::<P>::new(&prng);
        let msg = hash::tests::HASH_ELEMENT;
        b.iter(|| sk.sign(black_box(&address), black_box(&msg)));
    }

    fn bench_verify<P: GravityParams>(b: &mut Bencher)
    where
        [(); P::MERKLE_H]:,
    {
        let seed = hash::tests::HASH_ELEMENT;
        let layer: u32 = 0x01020304;
        let instance: u64 = 0x05060708090a0b0c;

        let prng = prng::Prng::new(&seed);
        let address = address::Address::new(layer, instance);

        let sk = SecKey::<P>::new(&prng);
        let pk = sk.genpk(&address);
        let msg = hash::tests::HASH_ELEMENT;
        let (_, sign) = sk.sign(&address, &msg);
        b.iter(|| pk.verify(black_box(&address), black_box(&sign), black_box(&msg)));
    }

    // TODO: test vectors
}
