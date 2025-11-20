use crate::address;
use crate::config::*;
use crate::hash;
use crate::hash::Hash;
use crate::merkle;
use crate::octopus;
use crate::prng;
use arrayref::array_ref;
use byteorder::{BigEndian, ByteOrder};
use std::array;
use std::marker::PhantomData;

pub struct SecKey<P: GravityParams> {
    values: Vec<Hash>,
    _phantom: PhantomData<P>,
}

#[cfg(test)]
pub struct PubKey<P: GravityParams> {
    h: Hash,
    _phantom: PhantomData<P>,
}

pub struct Signature<P: GravityParams>
where
    [(); P::PORS_K]:,
{
    pepper: Hash,
    values: [Hash; P::PORS_K],
    octopus: octopus::Octopus<P>,
}

impl<P: GravityParams> SecKey<P> {
    pub fn new(prng: &prng::Prng, address: &address::Address) -> Self {
        let mut values = vec![Default::default(); P::PORS_T];
        prng.genblocks(values.as_mut_slice(), address);
        Self {
            values,
            _phantom: PhantomData,
        }
    }

    #[cfg(test)]
    pub fn genpk(&self) -> PubKey<P> {
        let mut buf = vec![Default::default(); P::PORS_T];
        hash::hash_parallel_all(buf.as_mut_slice(), self.values.as_slice());
        PubKey {
            h: merkle::merkle_compress_all_leaves(buf.as_slice(), P::PORS_TAU),
            _phantom: PhantomData,
        }
    }

    #[allow(clippy::needless_range_loop)]
    pub fn sign_subset(&self, pepper: Hash, subset: [usize; P::PORS_K]) -> (Hash, Signature<P>)
    where
        [(); P::PORS_K]:,
    {
        let values = array::from_fn(|i| self.values[subset[i]]);

        let mut buf = merkle::MerkleBuf::new(P::PORS_TAU);
        hash::hash_parallel(buf.slice_leaves_mut(), self.values.as_slice(), P::PORS_T);
        let (root, octopus) = octopus::merkle_gen_octopus(&mut buf, subset);

        let sign = Signature {
            pepper,
            values,
            octopus,
        };
        (root, sign)
    }
}

#[cfg(test)]
impl<P: GravityParams> PubKey<P> {
    pub fn verify(&self, sign: &Signature<P>, msg: &Hash) -> bool
    where
        [(); P::PORS_K]:,
    {
        if let Some((_, h)) = sign.extract(msg) {
            self.h == h
        } else {
            false
        }
    }
}

impl<P: GravityParams> Signature<P>
where
    [(); P::PORS_K]:,
{
    pub fn extract(&self, msg: &Hash) -> Option<(address::Address, Hash)> {
        let (address, subset) = obtain_address_subset(&self.pepper, msg);
        let mut nodes = [Default::default(); P::PORS_K];
        hash::hash_parallel_all(&mut nodes, &self.values);
        let root = octopus::merkle_compress_octopus(&mut nodes, &self.octopus, P::PORS_TAU, subset);
        root.map(|h| (address, h))
    }

    #[cfg(test)]
    pub fn min_size_hashes() -> usize {
        1 + P::PORS_K + octopus::Octopus::<P>::min_size_hashes()
    }

    #[cfg(test)]
    pub fn max_size_hashes() -> usize {
        1 + P::PORS_K + octopus::Octopus::<P>::max_size_hashes()
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
        let pepper = Hash::deserialize(it)?;
        let values = array::try_from_fn(|_| Hash::deserialize(it))?;
        let octopus = octopus::Octopus::deserialize(it)?;

        Some(Signature {
            pepper,
            values,
            octopus,
        })
    }
}

pub fn sign<P: GravityParams>(
    prng: &prng::Prng,
    salt: &Hash,
    msg: &Hash,
) -> (address::Address, Hash, Signature<P>)
where
    [(); P::PORS_K]:,
{
    let pepper = hash::hash_2n_to_n_ret(salt, msg);
    let (address, subset) = obtain_address_subset(&pepper, msg);

    let sk = SecKey::new(prng, &address);
    let (root, sign) = sk.sign_subset(pepper, subset);
    (address, root, sign)
}

#[allow(clippy::needless_range_loop)]
fn obtain_address_subset<P: GravityParams>(
    pepper: &Hash,
    msg: &Hash,
) -> (address::Address, [usize; P::PORS_K]) {
    // TODO: Make this const when supported.
    assert!(P::PORS_K > 0, "PORS is only implemented for PORS_K > 0");
    assert!(
        P::PORS_K <= P::PORS_T,
        "PORS is only implemented for PORS_K <= PORS_T"
    );

    let seed = hash::hash_2n_to_n_ret(pepper, msg);
    let prng = prng::Prng::new(&seed);
    let address = address::Address::new(0, 0);

    let mut block = Default::default();
    prng.genblock(&mut block, &address, 0);
    let instance: u64 = BigEndian::read_u64(array_ref![block.h, 24, 8]);
    let instance = instance & P::GRAVITY_MASK;

    let mut subset: [usize; P::PORS_K] = [0; P::PORS_K];
    let mut count = 0;
    let mut counter = 1;

    'outer: while count < P::PORS_K {
        prng.genblock(&mut block, &address, counter);
        'inner: for i in 0..8 {
            let x = BigEndian::read_u32(array_ref![block.h, 4 * i, 4]) as usize;
            let x = x % P::PORS_T;

            for i in 0..count {
                if subset[i] == x {
                    continue 'inner;
                }
            }

            subset[count] = x;
            count += 1;
            if count == P::PORS_K {
                break 'outer;
            }
        }
        counter += 1;
    }

    subset.sort();
    (address::Address::new(P::GRAVITY_D as u32, instance), subset)
}

#[cfg(test)]
mod tests {
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
        [(); P::PORS_K]:,
    {
        let (expected_min_hashes, expected_max_hashes) = match P::config_type() {
            ConfigType::S => (36, 313),
            ConfigType::M => (44, 385),
            ConfigType::L => (40, 365),
            ConfigType::Unknown => unimplemented!(),
        };
        assert_eq!(Signature::<P>::min_size_hashes(), expected_min_hashes);
        assert_eq!(Signature::<P>::max_size_hashes(), expected_max_hashes);
    }

    fn test_sign_verify<P: GravityParams>()
    where
        [(); P::PORS_K]:,
    {
        let seed = hash::tests::HASH_ELEMENT;
        let salt = hash::tests::HASH_ELEMENT;
        let msg = hash::tests::HASH_ELEMENT;

        let prng = prng::Prng::new(&seed);
        let pepper = hash::hash_2n_to_n_ret(&salt, &msg);
        let (address, subset) = obtain_address_subset(&pepper, &msg);

        let sk = SecKey::<P>::new(&prng, &address);
        let pk = sk.genpk();
        let (_, sign) = sk.sign_subset(pepper, subset);

        assert!(pk.verify(&sign, &msg));
    }

    macro_rules! all_benches {
        ( $mod:ident, $params:ty ) => {
            crate::tests::param_benches!(
                $mod,
                $params,
                bench_obtain_address_subset,
                bench_keypair,
                bench_gensk,
                bench_genpk,
                bench_sign,
                bench_verify,
            );
        };
    }

    all_benches!(benches_small, GravitySmall);
    all_benches!(benches_medium, GravityMedium);
    all_benches!(benches_large, GravityLarge);

    use std::hint::black_box;
    use test::Bencher;

    fn bench_obtain_address_subset<P: GravityParams>(b: &mut Bencher)
    where
        [(); P::PORS_K]:,
    {
        let salt = hash::tests::HASH_ELEMENT;
        let msg = hash::tests::HASH_ELEMENT;

        let pepper = hash::hash_2n_to_n_ret(&salt, &msg);
        b.iter(|| obtain_address_subset::<P>(black_box(&pepper), black_box(&msg)));
    }

    fn bench_keypair<P: GravityParams>(b: &mut Bencher)
    where
        [(); P::PORS_K]:,
    {
        let seed = hash::tests::HASH_ELEMENT;
        let salt = hash::tests::HASH_ELEMENT;
        let msg = hash::tests::HASH_ELEMENT;

        let prng = prng::Prng::new(&seed);
        b.iter(|| {
            let pepper = hash::hash_2n_to_n_ret(black_box(&salt), black_box(&msg));
            let (address, _) = obtain_address_subset::<P>(&pepper, &msg);

            let sk = SecKey::<P>::new(black_box(&prng), &address);
            sk.genpk()
        });
    }

    fn bench_gensk<P: GravityParams>(b: &mut Bencher)
    where
        [(); P::PORS_K]:,
    {
        let seed = hash::tests::HASH_ELEMENT;
        let salt = hash::tests::HASH_ELEMENT;
        let msg = hash::tests::HASH_ELEMENT;

        let prng = prng::Prng::new(&seed);
        b.iter(|| {
            let pepper = hash::hash_2n_to_n_ret(black_box(&salt), black_box(&msg));
            let (address, _) = obtain_address_subset::<P>(&pepper, &msg);

            SecKey::<P>::new(black_box(&prng), &address)
        });
    }

    fn bench_genpk<P: GravityParams>(b: &mut Bencher)
    where
        [(); P::PORS_K]:,
    {
        let seed = hash::tests::HASH_ELEMENT;
        let salt = hash::tests::HASH_ELEMENT;
        let msg = hash::tests::HASH_ELEMENT;

        let prng = prng::Prng::new(&seed);
        let pepper = hash::hash_2n_to_n_ret(&salt, &msg);
        let (address, _) = obtain_address_subset::<P>(&pepper, &msg);

        let sk = SecKey::<P>::new(&prng, &address);
        b.iter(|| sk.genpk());
    }

    fn bench_sign<P: GravityParams>(b: &mut Bencher)
    where
        [(); P::PORS_K]:,
    {
        let seed = hash::tests::HASH_ELEMENT;
        let salt = hash::tests::HASH_ELEMENT;
        let msg = hash::tests::HASH_ELEMENT;

        let prng = prng::Prng::new(&seed);
        let pepper = hash::hash_2n_to_n_ret(&salt, &msg);
        let (address, subset) = obtain_address_subset(&pepper, &msg);

        let sk = SecKey::<P>::new(&prng, &address);
        b.iter(|| sk.sign_subset(black_box(pepper), black_box(subset)));
    }

    fn bench_verify<P: GravityParams>(b: &mut Bencher)
    where
        [(); P::PORS_K]:,
    {
        let seed = hash::tests::HASH_ELEMENT;
        let salt = hash::tests::HASH_ELEMENT;
        let msg = hash::tests::HASH_ELEMENT;

        let prng = prng::Prng::new(&seed);
        let pepper = hash::hash_2n_to_n_ret(&salt, &msg);
        let (address, subset) = obtain_address_subset(&pepper, &msg);

        let sk = SecKey::<P>::new(&prng, &address);
        let pk = sk.genpk();
        let (_, sign) = sk.sign_subset(pepper, subset);
        b.iter(|| pk.verify(black_box(&sign), black_box(&msg)));
    }

    // TODO: test vectors
}
