#![allow(incomplete_features)]
#![feature(array_try_from_fn, generic_const_exprs)]
#![cfg_attr(test, feature(test))]

#[cfg(test)]
extern crate test;

mod address;
mod config;
mod gravity;
mod hash;
mod ltree;
mod merkle;
mod octopus;
mod pors;
mod primitives;
mod prng;
mod subtree;
mod wots;

pub use config::{GravityLarge, GravityMedium, GravityParams, GravitySmall};

pub fn gravity_genpk<P: GravityParams>(public: &mut [u8; 32], secret: &[u8; 64])
where
    [(); P::GRAVITY_D]:,
    [(); P::GRAVITY_C]:,
    [(); P::MERKLE_H]:,
    [(); P::PORS_K]:,
{
    let sk = gravity::SecKey::<P>::new(secret);
    let pk = sk.genpk();
    *public = pk.get_bytes();
}

pub fn gravity_sign<P: GravityParams>(secret: &[u8; 64], msg: &[u8]) -> Vec<u8>
where
    [(); P::GRAVITY_D]:,
    [(); P::GRAVITY_C]:,
    [(); P::MERKLE_H]:,
    [(); P::PORS_K]:,
{
    let sk = gravity::SecKey::<P>::new(secret);
    let sign = sk.sign_bytes(msg);
    let mut sign_bytes = Vec::<u8>::new();
    sign.serialize(&mut sign_bytes);
    sign_bytes
}

pub fn gravity_verify<P: GravityParams>(public: &[u8; 32], msg: &[u8], sign_bytes: Vec<u8>) -> bool
where
    [(); P::GRAVITY_D]:,
    [(); P::GRAVITY_C]:,
    [(); P::MERKLE_H]:,
    [(); P::PORS_K]:,
{
    let pk = gravity::PubKey::<P>::new(*public);
    if let Some(sign) = gravity::Signature::<P>::deserialize(&mut sign_bytes.iter()) {
        pk.verify_bytes(&sign, msg)
    } else {
        false
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    macro_rules! param_tests {
        (
            $mod:ident,
            $params:ty,
            $( $( #[ $attrs:meta ] )* $case:ident ,)*
        ) => {
            mod $mod {
                use super::*;

                $(
                    $( #[$attrs] )*
                    #[test]
                    fn $case() {
                        super::$case::<$params>()
                    }
                )*
            }
        };
    }

    macro_rules! param_benches {
        (
            $mod:ident,
            $params:ty,
            $( $( #[ $attrs:meta ] )* $case:ident ,)*
        ) => {
            mod $mod {
                use super::*;

                $(
                    $( #[$attrs] )*
                    #[bench]
                    fn $case(b: &mut Bencher) {
                        super::$case::<$params>(b)
                    }
                )*
            }
        };
    }

    pub(crate) use {param_benches, param_tests};

    macro_rules! all_tests {
        ( $mod:ident, $params:ty ) => {
            crate::tests::param_tests!($mod, $params, test_sign_verify,);
        };
    }

    all_tests!(small, GravitySmall);
    all_tests!(medium, GravityMedium);
    all_tests!(large, GravityLarge);

    fn test_sign_verify<P: GravityParams>()
    where
        [(); P::GRAVITY_D]:,
        [(); P::GRAVITY_C]:,
        [(); P::MERKLE_H]:,
        [(); P::PORS_K]:,
    {
        let secret: &[u8; 64] = b"\x00\x01\x02\x03\x04\x05\x06\x07\
                                  \x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
                                  \x10\x11\x12\x13\x14\x15\x16\x17\
                                  \x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\
                                  \x20\x21\x22\x23\x24\x25\x26\x27\
                                  \x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\
                                  \x30\x31\x32\x33\x34\x35\x36\x37\
                                  \x38\x39\x3a\x3b\x3c\x3d\x3e\x3f";
        let msg: &[u8] = b"Hello world";

        let mut public = [0; 32];
        gravity_genpk::<P>(&mut public, secret);
        let sign = gravity_sign(secret, msg);
        assert!(gravity_verify(&public, msg, sign));
    }
}
