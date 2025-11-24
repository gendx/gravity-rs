use crate::config::*;
use crate::hash::Hash;
use crate::{address, hash, merkle, octopus, prng};
use arrayref::array_ref;
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
        assert_eq!(
            octopus.oct.len(),
            octopus::octopus_size_hashes(P::PORS_TAU, subset)
        );

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
    pub fn limited_size_hashes() -> usize {
        1 + P::PORS_K + octopus::Octopus::<P>::limited_size_hashes()
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
    let mut pepper = hash::hash_2n_to_n_ret(salt, msg);
    let (address, subset) = obtain_address_subset_under_limit(&mut pepper, msg);

    let sk = SecKey::new(prng, &address);
    let (root, sign) = sk.sign_subset(pepper, subset);
    (address, root, sign)
}

fn obtain_address_subset_under_limit<P: GravityParams>(
    pepper: &mut Hash,
    msg: &Hash,
) -> (address::Address, [usize; P::PORS_K]) {
    loop {
        let (address, subset) = obtain_address_subset(pepper, msg);
        if P::OCTOPUS_LIMIT
            .is_none_or(|limit| octopus::octopus_size_hashes(P::PORS_TAU, subset) <= limit)
        {
            return (address, subset);
        }
        pepper.increment();
    }
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
    let instance = u64::from_be_bytes(*array_ref![block.h, 24, 8]);
    let instance = instance & P::GRAVITY_MASK;

    let mut subset: [usize; P::PORS_K] = [0; P::PORS_K];
    let mut count = 0;
    let mut counter = 1;

    'outer: while count < P::PORS_K {
        prng.genblock(&mut block, &address, counter);
        'inner: for i in 0..8 {
            let x = u32::from_be_bytes(*array_ref![block.h, 4 * i, 4]) as usize;
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

    #[derive(Debug, PartialEq)]
    pub struct Octopus1316;

    impl GravityParams for Octopus1316 {
        #[cfg(test)]
        fn config_type() -> ConfigType {
            ConfigType::Unknown
        }

        fn check_params() {
            // TODO: Move this implementation to the trait when supported.
            const {
                assert!(Self::PORS_K > 0);
                assert!(Self::PORS_K <= Self::PORS_T);
            };
        }

        const TAU: usize = 13;
        const K: usize = 16;
        // Irrelevant here.
        const H: usize = 0;
        const D: usize = 0;
        const C: usize = 0;

        const OCTOPUS_LIMIT: Option<usize> = Some(107);
    }

    macro_rules! all_tests {
        ( $mod:ident, $params:ty ) => {
            crate::tests::param_tests!(
                $mod,
                $params,
                test_signature_size,
                test_sign_verify,
                test_obtain_address_subset,
                test_obtain_address_subset_under_limit,
            );
        };
    }

    all_tests!(pors1316, Octopus1316);
    all_tests!(small, GravitySmall);
    all_tests!(medium, GravityMedium);
    all_tests!(large, GravityLarge);

    fn test_signature_size<P: GravityParams>()
    where
        [(); P::PORS_K]:,
    {
        let expected = match P::config_type() {
            ConfigType::S => (36, 255, 313),
            ConfigType::M => (44, 323, 385),
            ConfigType::L => (40, 289, 365),
            ConfigType::Unknown => (26, 124, 161),
        };
        assert_eq!(
            (
                Signature::<P>::min_size_hashes(),
                Signature::<P>::limited_size_hashes(),
                Signature::<P>::max_size_hashes()
            ),
            expected
        );
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

    fn test_obtain_address_subset<P: GravityParams>()
    where
        [(); P::PORS_K]:,
    {
        let salt = hash::tests::HASH_ELEMENT;
        let msg = hash::tests::HASH_ELEMENT;

        let pepper = hash::hash_2n_to_n_ret(&salt, &msg);
        let (_, subset) = obtain_address_subset(&pepper, &msg);

        println!("subset: {subset:#x?}");
        match P::config_type() {
            ConfigType::S => assert_eq!(
                &subset[..],
                &[
                    0x0f93, 0x30b0, 0x325c, 0x344a, 0x40f3, 0x529d, 0x6758, 0x6764, 0x6dd7, 0x9615,
                    0xae87, 0xb6ea, 0xbb00, 0xbdb1, 0xc1ed, 0xc77b, 0xd379, 0xd849, 0xdc78, 0xe00e,
                    0xeeca, 0xf41a, 0xf6ee, 0xff4b,
                ]
            ),
            ConfigType::M => assert_eq!(
                &subset[..],
                &[
                    0x0f93, 0x206f, 0x26ba, 0x28f0, 0x30b0, 0x325c, 0x344a, 0x40f3, 0x410e, 0x529d,
                    0x6758, 0x6764, 0x69fa, 0x6dd7, 0x868f, 0x8c2f, 0x9615, 0xae87, 0xb6ea, 0xbb00,
                    0xbdb1, 0xc1ed, 0xc77b, 0xd33f, 0xd379, 0xd849, 0xdc78, 0xe00e, 0xeeca, 0xf41a,
                    0xf6ee, 0xff4b,
                ]
            ),
            ConfigType::L => assert_eq!(
                &subset[..],
                &[
                    0x0f93, 0x206f, 0x26ba, 0x30b0, 0x325c, 0x344a, 0x40f3, 0x410e, 0x529d, 0x6758,
                    0x6764, 0x6dd7, 0x8c2f, 0x9615, 0xae87, 0xb6ea, 0xbb00, 0xbdb1, 0xc1ed, 0xc77b,
                    0xd379, 0xd849, 0xdc78, 0xe00e, 0xeeca, 0xf41a, 0xf6ee, 0xff4b,
                ]
            ),
            _ => assert_eq!(
                &subset[..],
                &[
                    0x00f3, 0x01ed, 0x0758, 0x0764, 0x077b, 0x0dd7, 0x0e87, 0x0eca, 0x0f93, 0x10b0,
                    0x1615, 0x16ea, 0x16ee, 0x1b00, 0x1c78, 0x1db1,
                ]
            ),
        }
    }

    fn test_obtain_address_subset_under_limit<P: GravityParams>()
    where
        [(); P::PORS_K]:,
    {
        let salt = hash::tests::HASH_ELEMENT;
        let msg = hash::tests::HASH_ELEMENT;

        let mut pepper = hash::hash_2n_to_n_ret(&salt, &msg);
        let (_, subset) = obtain_address_subset_under_limit(&mut pepper, &msg);

        println!("subset: {subset:#x?}");
        match P::config_type() {
            ConfigType::S => assert_eq!(
                &subset[..],
                &[
                    0x1897, 0x1cd4, 0x3ed4, 0x48de, 0x49ea, 0x4a21, 0x4a67, 0x78b4, 0xa697, 0xaaf0,
                    0xb153, 0xb3e3, 0xb862, 0xbdab, 0xc548, 0xc720, 0xcd1b, 0xd053, 0xd379, 0xf53f,
                    0xf566, 0xf56b, 0xf5b4, 0xfa66,
                ]
            ),
            ConfigType::M => assert_eq!(
                &subset[..],
                &[
                    0x3415, 0x3585, 0x3da1, 0x3db2, 0x44d1, 0x455d, 0x4a04, 0x4a09, 0x6d4d, 0x708a,
                    0x70cb, 0x767b, 0x7b70, 0x8400, 0x892a, 0x9c7a, 0xa4dd, 0xa910, 0xa9ba, 0xba80,
                    0xccb3, 0xccc2, 0xccf3, 0xcd89, 0xcde8, 0xd164, 0xd184, 0xd263, 0xddae, 0xe3db,
                    0xe4b3, 0xf3b7,
                ]
            ),
            ConfigType::L => assert_eq!(
                &subset[..],
                &[
                    0x12c8, 0x1649, 0x165f, 0x485d, 0x506a, 0x6cf3, 0x6e7f, 0x6f0d, 0x7287, 0x781b,
                    0x78bc, 0x9455, 0x9ad8, 0x9afd, 0x9e3e, 0x9e7b, 0xa561, 0xa578, 0xa870, 0xac23,
                    0xac77, 0xae67, 0xc069, 0xc3d8, 0xcd02, 0xdfdb, 0xe8e9, 0xf27a,
                ]
            ),
            _ => assert_eq!(
                &subset[..],
                &[
                    0x031a, 0x031b, 0x03f1, 0x059b, 0x09d6, 0x0eb1, 0x0fc1, 0x1233, 0x1242, 0x13e6,
                    0x13eb, 0x150c, 0x1556, 0x1ddb, 0x1de5, 0x1de6,
                ]
            ),
        }
    }
}

#[cfg(all(test, not(coverage)))]
mod bench {
    use super::tests::Octopus1316;
    use super::*;

    macro_rules! all_benches {
        ( $mod:ident, $params:ty ) => {
            crate::tests::param_benches!(
                $mod,
                $params,
                bench_obtain_address_subset,
                bench_obtain_address_subset_under_limit,
                bench_keypair,
                bench_gensk,
                bench_genpk,
                bench_sign,
                bench_verify,
            );
        };
    }

    all_benches!(benches_pors1316, Octopus1316);
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

    fn bench_obtain_address_subset_under_limit<P: GravityParams>(b: &mut Bencher)
    where
        [(); P::PORS_K]:,
    {
        let mut salt = hash::tests::HASH_ELEMENT;
        let msg = hash::tests::HASH_ELEMENT;

        b.iter(|| {
            salt.increment();
            let mut pepper = hash::hash_2n_to_n_ret(&salt, black_box(&msg));
            obtain_address_subset_under_limit::<P>(&mut pepper, black_box(&msg))
        });
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
