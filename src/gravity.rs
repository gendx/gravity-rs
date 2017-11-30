use hash;
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
        PubKey { h: self.cache.root() }
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
        let mut sign: Signature = Default::default();
        sign.pors_sign = pors::Signature::deserialize(it)?;
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
        let mut random = [0u8; 64];
        for i in 0..64 {
            random[i] = i as u8;
        }

        let sk = SecKey::new(&random);
        let pk = sk.genpk();
        let msg = hash::tests::HASH_ELEMENT;
        let sign = sk.sign_hash(&msg);
        assert!(pk.verify_hash(&sign, &msg));
    }

    #[test]
    fn test_genkey_zeros() {
        let random: [u8; 64] = [0u8; 64];
        let pkh = match get_config_type() {
            ConfigType::S => {
                let pkh: [u8; 32] = *b"\x57\x03\x58\x87\x1a\x7a\x2c\xfe\
                                       \x1e\xab\xf1\x3b\x4c\x11\x3a\x81\
                                       \xce\x08\x9a\x2c\x02\x04\xa3\xbb\
                                       \xc4\x4d\xd7\xb6\x94\x07\x94\x2a";
                pkh
            }
            ConfigType::M => {
                let pkh: [u8; 32] = *b"\x33\xbd\x9a\x33\x3d\x5f\x88\xc6\
                                       \x0a\xca\x08\x42\x3e\xe3\xbc\xcf\
                                       \x02\xe1\xc7\xd2\x74\xa8\xec\xf4\
                                       \xd7\x4e\xfe\x34\x05\xb9\x24\x04";
                pkh
            }
            ConfigType::L => {
                let pkh: [u8; 32] = *b"\xcb\xf7\x04\xd6\xe0\xf5\x2e\xb7\
                                       \xaa\xad\xee\xd8\xf9\xad\x8c\xde\
                                       \x84\x68\x1c\xa8\x03\x75\x4c\xc2\
                                       \x1f\x50\x69\x68\x41\xc1\xb3\x03";
                pkh
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
        let (random, pkh) = match get_config_type() {
            ConfigType::S => {
                let random: [u8; 64] = *b"\x5E\x97\x5E\x8F\xAC\x3E\x0E\x56\
                                          \x7B\x4E\xD0\x23\x86\xFB\x6A\x58\
                                          \xBE\x85\xE6\x30\x37\x3F\x1C\x7D\
                                          \x35\xF2\xBD\x8F\x3D\x4E\xBB\x3E\
                                          \x4A\xA5\x08\x42\x0C\xAF\xED\xC8\
                                          \x02\x46\x87\x0B\x96\xF8\xDB\xFE\
                                          \xB4\x18\x0B\xD1\x55\xCE\xFD\x08\
                                          \x2E\x13\xAC\xE4\x7F\x39\xB0\x0E";
                let pkh: [u8; 32] = *b"\xF3\x6C\xD0\xE8\x4D\x6B\xE4\x13\
                                       \x30\x65\x00\x88\xA6\x48\x0B\x38\
                                       \x91\x68\x9C\x18\xB0\x20\xE2\xD3\
                                       \x21\xF9\xD0\xB4\x69\x98\x3D\xC7";
                (random, pkh)
            }
            ConfigType::M => {
                let random: [u8; 64] = *b"\x82\xD0\x0C\x6C\x85\x57\x72\xBF\
                                          \x95\x0F\x54\x07\x1D\xF6\xCE\x12\
                                          \x2E\xE3\xFE\xCE\x15\x7F\xFA\xA0\
                                          \x55\xA1\x17\x09\x6F\xC1\xC5\xA0\
                                          \x47\x5D\xA7\xEB\x7C\xE1\xF0\xDC\
                                          \xBA\x49\xE8\xC9\xB4\x6F\x78\x6C\
                                          \xC4\xD6\x9A\x3E\xCD\x96\x78\xFB\
                                          \xB9\x58\x85\x66\x49\xE2\x24\x6C";
                let pkh: [u8; 32] = *b"\x15\x88\xAB\x53\x4D\xF9\xD4\xE1\
                                       \x17\x0F\x8A\x7F\xB4\x38\x55\x5B\
                                       \x3E\x02\xEB\x5F\x1D\x00\xC3\x4F\
                                       \x2B\x86\x6D\x5D\x25\x64\x55\xC8";
                (random, pkh)
            }
            ConfigType::L => {
                let random: [u8; 64] = *b"\x8C\x6A\xEC\xA7\x87\xF8\x42\xC3\
                                          \x7A\x0F\xA7\xBB\x59\x7B\xBF\xB2\
                                          \x5B\xF1\x53\xD8\x0C\x30\xE5\x62\
                                          \xFF\x99\xC9\x61\xC5\x63\x50\x63\
                                          \xEF\x90\x3D\x2E\x3F\xDE\xA3\x97\
                                          \xE1\x9A\xF8\xC8\xF2\x7E\x81\x25\
                                          \xC1\xC1\x64\x79\x82\xFD\x98\x68\
                                          \x61\x89\x4E\xD9\x29\xE5\x5E\x41";
                let pkh: [u8; 32] = *b"\xBD\x6F\x26\xD0\x87\xFE\xA3\x4F\
                                       \x75\xEA\x24\x71\x9C\x0D\xA2\x80\
                                       \x67\x71\xEE\x84\x8B\x8D\x9D\xEE\
                                       \xD8\xA4\x47\x4D\xDB\x85\xA2\x9B";
                (random, pkh)
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

        let (random, msg, hex_file) = match get_config_type() {
            ConfigType::S => {
                let random: [u8; 64] = *b"\x5E\x97\x5E\x8F\xAC\x3E\x0E\x56\
                                          \x7B\x4E\xD0\x23\x86\xFB\x6A\x58\
                                          \xBE\x85\xE6\x30\x37\x3F\x1C\x7D\
                                          \x35\xF2\xBD\x8F\x3D\x4E\xBB\x3E\
                                          \x4A\xA5\x08\x42\x0C\xAF\xED\xC8\
                                          \x02\x46\x87\x0B\x96\xF8\xDB\xFE\
                                          \xB4\x18\x0B\xD1\x55\xCE\xFD\x08\
                                          \x2E\x13\xAC\xE4\x7F\x39\xB0\x0E";
                let msg = hex::decode(
                    "D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8",
                ).unwrap();
                let hex_file = include_str!("../test_files/test_sign_kat_S.hex");
                (random, msg, hex_file)
            }
            ConfigType::M => {
                let random: [u8; 64] = *b"\x82\xD0\x0C\x6C\x85\x57\x72\xBF\
                                          \x95\x0F\x54\x07\x1D\xF6\xCE\x12\
                                          \x2E\xE3\xFE\xCE\x15\x7F\xFA\xA0\
                                          \x55\xA1\x17\x09\x6F\xC1\xC5\xA0\
                                          \x47\x5D\xA7\xEB\x7C\xE1\xF0\xDC\
                                          \xBA\x49\xE8\xC9\xB4\x6F\x78\x6C\
                                          \xC4\xD6\x9A\x3E\xCD\x96\x78\xFB\
                                          \xB9\x58\x85\x66\x49\xE2\x24\x6C";
                let msg = hex::decode(
                    "D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8",
                ).unwrap();
                let hex_file = include_str!("../test_files/test_sign_kat_M.hex");
                (random, msg, hex_file)
            }
            ConfigType::L => {
                let random: [u8; 64] = *b"\x8C\x6A\xEC\xA7\x87\xF8\x42\xC3\
                                          \x7A\x0F\xA7\xBB\x59\x7B\xBF\xB2\
                                          \x5B\xF1\x53\xD8\x0C\x30\xE5\x62\
                                          \xFF\x99\xC9\x61\xC5\x63\x50\x63\
                                          \xEF\x90\x3D\x2E\x3F\xDE\xA3\x97\
                                          \xE1\x9A\xF8\xC8\xF2\x7E\x81\x25\
                                          \xC1\xC1\x64\x79\x82\xFD\x98\x68\
                                          \x61\x89\x4E\xD9\x29\xE5\x5E\x41";
                let msg = hex::decode(
                    "D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8",
                ).unwrap();
                let hex_file = include_str!("../test_files/test_sign_kat_L.hex");
                (random, msg, hex_file)
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
}
