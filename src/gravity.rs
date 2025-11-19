use crate::address;
use crate::config::*;
use crate::hash;
use crate::hash::Hash;
use crate::merkle;
use crate::pors;
use crate::prng;
use crate::subtree;
use arrayref::array_ref;

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
            seed: Hash {
                h: *array_ref![random, 0, 32],
            },
            salt: Hash {
                h: *array_ref![random, 32, 32],
            },
            cache: merkle::MerkleTree::new(GRAVITY_C),
        };

        let layer = 0u32;
        let prng = prng::Prng::new(&sk.seed);
        let subtree_sk = subtree::SecKey::new(&prng);

        for (i, leaf) in sk.cache.leaves().iter_mut().enumerate() {
            let address = address::Address::new(layer, (i << MERKLE_H) as u64);
            let pk = subtree_sk.genpk(&address);
            *leaf = pk.h;
        }

        sk.cache.generate();
        sk
    }

    pub fn genpk(&self) -> PubKey {
        PubKey {
            h: self.cache.root(),
        }
    }

    pub fn sign_hash(&self, msg: &Hash) -> Signature {
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

    pub fn sign_bytes(&self, msg: &[u8]) -> Signature {
        let h = hash::long_hash(msg);
        self.sign_hash(&h)
    }
}

impl PubKey {
    fn verify_hash(&self, sign: &Signature, msg: &Hash) -> bool {
        if let Some(h) = sign.extract_hash(msg) {
            self.h == h
        } else {
            false
        }
    }

    pub fn verify_bytes(&self, sign: &Signature, msg: &[u8]) -> bool {
        let h = hash::long_hash(msg);
        self.verify_hash(sign, &h)
    }
}

impl Signature {
    fn extract_hash(&self, msg: &Hash) -> Option<Hash> {
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

    pub fn serialize(&self, output: &mut Vec<u8>) {
        self.pors_sign.serialize(output);
        for t in self.subtrees.iter() {
            t.serialize(output);
        }
        for x in self.auth_c.iter() {
            x.serialize(output);
        }
    }

    pub fn deserialize<'a, I>(it: &mut I) -> Option<Self>
    where
        I: Iterator<Item = &'a u8>,
    {
        let mut sign = Signature {
            pors_sign: pors::Signature::deserialize(it)?,
            ..Default::default()
        };
        for t in sign.subtrees.iter_mut() {
            *t = subtree::Signature::deserialize(it)?;
        }
        for x in sign.auth_c.iter_mut() {
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
        let random: [u8; 64] = std::array::from_fn(|i| i as u8);

        let sk = SecKey::new(&random);
        let pk = sk.genpk();
        let msg = hash::tests::HASH_ELEMENT;
        let sign = sk.sign_hash(&msg);
        assert!(pk.verify_hash(&sign, &msg));
    }

    #[test]
    fn test_genkey_zeros() {
        let random: [u8; 64] = [0u8; 64];
        let pkh: [u8; 32] = match get_config_type() {
            ConfigType::S => {
                *b"\x57\x03\x58\x87\x1a\x7a\x2c\xfe\
                   \x1e\xab\xf1\x3b\x4c\x11\x3a\x81\
                   \xce\x08\x9a\x2c\x02\x04\xa3\xbb\
                   \xc4\x4d\xd7\xb6\x94\x07\x94\x2a"
            }
            ConfigType::M => {
                *b"\x33\xbd\x9a\x33\x3d\x5f\x88\xc6\
                   \x0a\xca\x08\x42\x3e\xe3\xbc\xcf\
                   \x02\xe1\xc7\xd2\x74\xa8\xec\xf4\
                   \xd7\x4e\xfe\x34\x05\xb9\x24\x04"
            }
            ConfigType::L => {
                *b"\xcb\xf7\x04\xd6\xe0\xf5\x2e\xb7\
                   \xaa\xad\xee\xd8\xf9\xad\x8c\xde\
                   \x84\x68\x1c\xa8\x03\x75\x4c\xc2\
                   \x1f\x50\x69\x68\x41\xc1\xb3\x03"
            }
            ConfigType::Unknown => unimplemented!(),
        };

        let sk = SecKey::new(&random);
        let pk = sk.genpk();
        assert_eq!(pk.h.h, pkh);
    }

    #[test]
    fn test_sign_zeros() {
        use hex;

        let random: [u8; 64] = [0u8; 64];
        let msg: [u8; 32] = *b"\x00\x01\x02\x03\x04\x05\x06\x07\
                               \x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
                               \x10\x11\x12\x13\x14\x15\x16\x17\
                               \x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
        let hex_file = match get_config_type() {
            ConfigType::S => {
                let hex_file = include_str!("../test_files/test_sign_zero_S.hex");
                hex_file
            }
            ConfigType::M => {
                let hex_file = include_str!("../test_files/test_sign_zero_M.hex");
                hex_file
            }
            ConfigType::L => {
                let hex_file = include_str!("../test_files/test_sign_zero_L.hex");
                hex_file
            }
            ConfigType::Unknown => unimplemented!(),
        };

        let mut hex: Vec<u8> = vec![];
        for x in hex_file.split_whitespace() {
            hex.extend(x.bytes())
        }
        let expect: Vec<u8> = hex::decode(hex).unwrap();

        let sk = SecKey::new(&random);
        let sign = sk.sign_bytes(&msg);
        let mut sign_bytes = Vec::<u8>::new();
        sign.serialize(&mut sign_bytes);
        assert_eq!(sign_bytes, expect);
    }

    #[test]
    fn test_genkey_kat() {
        let random: [u8; 64] = *b"\x7C\x99\x35\xA0\xB0\x76\x94\xAA\
                                  \x0C\x6D\x10\xE4\xDB\x6B\x1A\xDD\
                                  \x2F\xD8\x1A\x25\xCC\xB1\x48\x03\
                                  \x2D\xCD\x73\x99\x36\x73\x7F\x2D\
                                  \x86\x26\xED\x79\xD4\x51\x14\x08\
                                  \x00\xE0\x3B\x59\xB9\x56\xF8\x21\
                                  \x0E\x55\x60\x67\x40\x7D\x13\xDC\
                                  \x90\xFA\x9E\x8B\x87\x2B\xFB\x8F";
        let pkh: [u8; 32] = match get_config_type() {
            ConfigType::S => {
                *b"\xDB\x9E\xBB\x0D\xB2\xB1\xD2\x31\
                   \x9E\xFB\x26\xCD\xA6\x5C\x0F\x50\
                   \xFD\xA6\xD0\x4F\x60\x9E\xF0\x30\
                   \xE9\x38\xF1\x92\xF6\xF9\xAB\x77"
            }
            ConfigType::M => {
                *b"\xDA\x70\xD0\x51\x6F\xBC\xEE\x17\
                   \x4A\x68\xE4\xC5\x6F\xBF\x7A\x1C\
                   \x0E\x9A\x04\x84\x2E\x95\x78\xD9\
                   \xB6\xE2\x19\x5A\xCD\xF2\x69\x7B"
            }
            ConfigType::L => {
                *b"\x30\x33\xC3\xA5\x79\x09\x6C\x92\
                   \x4E\x99\x87\x61\xE8\x7E\x42\x60\
                   \xF0\xF7\xC3\xC5\x3D\x0E\x21\xFE\
                   \xD8\xDF\x4C\xD6\xCB\x20\x69\xD9"
            }
            ConfigType::Unknown => unimplemented!(),
        };

        let sk = SecKey::new(&random);
        let pk = sk.genpk();
        assert_eq!(pk.h.h, pkh);
    }

    #[test]
    fn test_sign_kat() {
        use hex;

        let random: [u8; 64] = *b"\x7C\x99\x35\xA0\xB0\x76\x94\xAA\
                                  \x0C\x6D\x10\xE4\xDB\x6B\x1A\xDD\
                                  \x2F\xD8\x1A\x25\xCC\xB1\x48\x03\
                                  \x2D\xCD\x73\x99\x36\x73\x7F\x2D\
                                  \x86\x26\xED\x79\xD4\x51\x14\x08\
                                  \x00\xE0\x3B\x59\xB9\x56\xF8\x21\
                                  \x0E\x55\x60\x67\x40\x7D\x13\xDC\
                                  \x90\xFA\x9E\x8B\x87\x2B\xFB\x8F";
        let msg = hex::decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8")
            .unwrap();
        let hex_file = match get_config_type() {
            ConfigType::S => include_str!("../test_files/test_sign_kat_S.hex"),
            ConfigType::M => include_str!("../test_files/test_sign_kat_M.hex"),
            ConfigType::L => include_str!("../test_files/test_sign_kat_L.hex"),
            ConfigType::Unknown => unimplemented!(),
        };

        let mut hex: Vec<u8> = vec![];
        for x in hex_file.split_whitespace() {
            hex.extend(x.bytes())
        }
        let expect: Vec<u8> = hex::decode(hex).unwrap();

        let sk = SecKey::new(&random);
        let sign = sk.sign_bytes(&msg);
        let mut sign_bytes = Vec::<u8>::new();
        sign.serialize(&mut sign_bytes);

        assert_eq!(sign_bytes, expect);
    }

    use std::hint::black_box;
    use test::Bencher;

    #[cfg(feature = "bigbench")]
    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        let seed = [0u8; 64];
        b.iter(|| {
            let sk = SecKey::new(black_box(&seed));
            sk.genpk()
        });
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let seed = [0u8; 64];
        let sk = SecKey::new(&seed);
        let msg = hash::tests::HASH_ELEMENT;
        b.iter(|| sk.sign_hash(black_box(&msg)));
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let seed = [0u8; 64];
        let sk = SecKey::new(&seed);
        let pk = sk.genpk();
        let msg = hash::tests::HASH_ELEMENT;
        let sign = sk.sign_hash(&msg);
        b.iter(|| pk.verify_hash(black_box(&sign), black_box(&msg)));
    }
}
