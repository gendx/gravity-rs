#![feature(asm)]
#![feature(repr_simd)]

#[macro_use]
extern crate arrayref;
extern crate byteorder;

mod config;
mod primitives;
mod hash;
mod address;
mod prng;
mod ltree;
mod merkle;
mod octopus;
mod wots;
mod pors;
mod subtree;
mod gravity;

use primitives::haraka256;
use primitives::haraka512;
use primitives::aes256;

pub fn haraka256_5round(dst: &mut [u8; 32], src: &[u8; 32]) {
    haraka256::haraka256_5round(dst, src)
}

pub fn haraka512_5round(dst: &mut [u8; 32], src: &[u8; 64]) {
    haraka512::haraka512_5round_bis(dst, src)
}

pub fn haraka256_6round(dst: &mut [u8; 32], src: &[u8; 32]) {
    haraka256::haraka256_6round(dst, src)
}

pub fn haraka512_6round(dst: &mut [u8; 32], src: &[u8; 64]) {
    haraka512::haraka512_6round_bis(dst, src)
}

pub fn aes256(dst: &mut [u8; 16], src: &[u8; 16], key: &[u8; 32]) {
    aes256::aes256(dst, src, key)
}
