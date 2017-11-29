use hash::Hash;
use primitives::aes256::aes256;
use address;

pub struct Prng {
    seed: Hash,
    // TODO: precompute AES round keys
}

impl Prng {
    pub fn new(seed: &Hash) -> Self {
        Self { seed: *seed }
    }

    pub fn genblock(&self, dst: &mut [u8; 16], address: &address::Address, counter: u32) {
        let src = address.to_block(counter);
        aes256(dst, &src, &self.seed.h);
    }

    pub fn genblocks(&self, dst: &mut [Hash], address: &address::Address) {
        let count = dst.len();
        for i in 0..count {
            let h = &mut dst[i].h;
            let counter = (2 * i) as u32;
            self.genblock(array_mut_ref![h, 0, 16], &address, counter);
            let counter = (2 * i + 1) as u32;
            self.genblock(array_mut_ref![h, 16, 16], &address, counter);
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    // TODO: test vectors
}
