use primitives::intrinsics;
use primitives::u64x2::u64x2;

#[inline(always)]
fn assist256_1(a: &mut u64x2, mut b: u64x2) {
    b = intrinsics::pshufd_0xff(&b);
    let mut y: u64x2 = *a;
    intrinsics::pslldq_0x04(&mut y);
    intrinsics::pxor(a, &y);
    intrinsics::pslldq_0x04(&mut y);
    intrinsics::pxor(a, &y);
    intrinsics::pslldq_0x04(&mut y);
    intrinsics::pxor(a, &y);
    intrinsics::pxor(a, &b);
}

#[inline(always)]
fn assist256_2(mut a: u64x2, b: &mut u64x2) {
    a = intrinsics::pshufd_0xaa(&a);
    let mut y: u64x2 = *b;
    intrinsics::pslldq_0x04(&mut y);
    intrinsics::pxor(b, &y);
    intrinsics::pslldq_0x04(&mut y);
    intrinsics::pxor(b, &y);
    intrinsics::pslldq_0x04(&mut y);
    intrinsics::pxor(b, &y);
    intrinsics::pxor(b, &a);
}

#[inline(always)]
fn expand256(key: &[u8; 32], rkeys: &mut [u64x2; 15]) {
    let mut key0_xmm = u64x2::read(array_ref![key, 0, 16]);
    let mut key1_xmm = u64x2::read(array_ref![key, 16, 16]);

    // 0
    rkeys[0] = key0_xmm;
    rkeys[1] = key1_xmm;

    // 2
    assist256_1(&mut key0_xmm, intrinsics::aeskeygenassist_0x01(&key1_xmm));
    assist256_2(intrinsics::aeskeygenassist_0x00(&key0_xmm), &mut key1_xmm);
    rkeys[2] = key0_xmm;
    rkeys[3] = key1_xmm;

    // 4
    assist256_1(&mut key0_xmm, intrinsics::aeskeygenassist_0x02(&key1_xmm));
    assist256_2(intrinsics::aeskeygenassist_0x00(&key0_xmm), &mut key1_xmm);
    rkeys[4] = key0_xmm;
    rkeys[5] = key1_xmm;

    // 6
    assist256_1(&mut key0_xmm, intrinsics::aeskeygenassist_0x04(&key1_xmm));
    assist256_2(intrinsics::aeskeygenassist_0x00(&key0_xmm), &mut key1_xmm);
    rkeys[6] = key0_xmm;
    rkeys[7] = key1_xmm;

    // 8
    assist256_1(&mut key0_xmm, intrinsics::aeskeygenassist_0x08(&key1_xmm));
    assist256_2(intrinsics::aeskeygenassist_0x00(&key0_xmm), &mut key1_xmm);
    rkeys[8] = key0_xmm;
    rkeys[9] = key1_xmm;

    // 10
    assist256_1(&mut key0_xmm, intrinsics::aeskeygenassist_0x10(&key1_xmm));
    assist256_2(intrinsics::aeskeygenassist_0x00(&key0_xmm), &mut key1_xmm);
    rkeys[10] = key0_xmm;
    rkeys[11] = key1_xmm;

    // 12
    assist256_1(&mut key0_xmm, intrinsics::aeskeygenassist_0x20(&key1_xmm));
    assist256_2(intrinsics::aeskeygenassist_0x00(&key0_xmm), &mut key1_xmm);
    rkeys[12] = key0_xmm;
    rkeys[13] = key1_xmm;

    // 14
    assist256_1(&mut key0_xmm, intrinsics::aeskeygenassist_0x40(&key1_xmm));
    rkeys[14] = key0_xmm;
}

pub fn expand256_slice(key: &[u8; 32], rkeys: &mut [[u8; 16]; 15]) {
    let mut rkeys_xmm = [u64x2(0, 0); 15];
    expand256(key, &mut rkeys_xmm);
    for i in 0..15 {
        rkeys_xmm[i].write(&mut rkeys[i])
    }
}

fn aes256_rkeys_xmm(dst: &mut [u8; 16], src: &[u8; 16], rkeys: &[u64x2; 15]) {
    let mut state_xmm = u64x2::read(src);

    intrinsics::pxor(&mut state_xmm, &rkeys[0]);
    for i in 1..14 {
        intrinsics::aesenc(&mut state_xmm, &rkeys[i]);
    }
    intrinsics::aesenclast(&mut state_xmm, &rkeys[14]);

    state_xmm.write(dst);
}

pub fn aes256_rkeys_slice(dst: &mut [u8; 16], src: &[u8; 16], rkeys: &[[u8; 16]; 15]) {
    let mut rkeys_xmm = [u64x2(0, 0); 15];
    for i in 0..15 {
        rkeys_xmm[i] = u64x2::read(&rkeys[i]);
    }

    aes256_rkeys_xmm(dst, src, &rkeys_xmm);
}

#[cfg(test)]
pub fn aes256_ret(src: &[u8; 16], key: &[u8; 32]) -> [u8; 16] {
    let mut rkeys = [u64x2(0, 0); 15];
    expand256(key, &mut rkeys);

    let mut dst = [0u8; 16];
    aes256_rkeys_xmm(&mut dst, src, &rkeys);
    dst
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256() {
        let src = b"\x00\x01\x02\x03\x04\x05\x06\x07\
                    \x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
        let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\
                    \x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
                    \x10\x11\x12\x13\x14\x15\x16\x17\
                    \x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
        let expect = b"\x5a\x6e\x04\x57\x08\xfb\x71\x96\
                       \xf0\x2e\x55\x3d\x02\xc3\xa6\x92";
        let dst = aes256_ret(src, key);
        assert_eq!(&dst, expect);
    }

    #[test]
    fn test_aes256_nist() {
        let src = b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\
                    \xe9\x3d\x7e\x11\x73\x93\x17\x2a";
        let key = b"\x60\x3d\xeb\x10\x15\xca\x71\xbe\
                    \x2b\x73\xae\xf0\x85\x7d\x77\x81\
                    \x1f\x35\x2c\x07\x3b\x61\x08\xd7\
                    \x2d\x98\x10\xa3\x09\x14\xdf\xf4";
        let expect = b"\xf3\xee\xd1\xbd\xb5\xd2\xa0\x3c\
                       \x06\x4b\x5a\x7e\x3d\xb1\x81\xf8";
        let dst = aes256_ret(src, key);
        assert_eq!(&dst, expect);
    }

    fn subbytes(state: &mut [u8; 16]) {
        use primitives::constants;

        for x in state.iter_mut() {
            *x = constants::AES_SBOX[*x as usize];
        }
    }

    #[test]
    fn test_subbytes() {
        let mut state = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let expect = [
            99,
            124,
            119,
            123,
            242,
            107,
            111,
            197,
            48,
            1,
            103,
            43,
            254,
            215,
            171,
            118,
        ];
        subbytes(&mut state);
        assert_eq!(state, expect);
    }

    fn shiftrows(state: &mut [u8; 16]) {
        let tmp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = tmp;

        let tmp = state[2];
        state[2] = state[10];
        state[10] = tmp;
        let tmp = state[6];
        state[6] = state[14];
        state[14] = tmp;

        let tmp = state[3];
        state[3] = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = tmp;
    }

    #[test]
    fn test_shiftrows() {
        let mut state = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let expect = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
        shiftrows(&mut state);
        assert_eq!(state, expect);
    }

    // multiplication by 2 in GF(2^256)
    fn mul2(x: u8) -> u8 {
        (x << 1) ^ (((x >> 7) & 1) * 0x1b)
    }

    fn mixcolumns(state: &mut [u8; 16]) {
        for i in 0..4 {
            let x0 = state[4 * i];
            let x1 = state[4 * i + 1];
            let x2 = state[4 * i + 2];
            let x3 = state[4 * i + 3];
            let x = x0 ^ x1 ^ x2 ^ x3;
            state[4 * i] ^= mul2(x0 ^ x1) ^ x;
            state[4 * i + 1] ^= mul2(x1 ^ x2) ^ x;
            state[4 * i + 2] ^= mul2(x2 ^ x3) ^ x;
            state[4 * i + 3] ^= mul2(x3 ^ x0) ^ x;
        }
    }

    #[test]
    fn test_mixcolumns() {
        let mut state = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let expect = [2, 7, 0, 5, 6, 3, 4, 1, 10, 15, 8, 13, 14, 11, 12, 9];
        mixcolumns(&mut state);
        assert_eq!(state, expect);
    }

    // multiplication by 3 in GF(2^256)
    fn mul3(x: u8) -> u8 {
        mul2(x) ^ x
    }

    fn mixcolumns_bis(state: &mut [u8; 16]) {
        for i in 0..4 {
            let x0 = state[4 * i];
            let x1 = state[4 * i + 1];
            let x2 = state[4 * i + 2];
            let x3 = state[4 * i + 3];
            state[4 * i] = mul2(x0) ^ mul3(x1) ^ x2 ^ x3;
            state[4 * i + 1] = x0 ^ mul2(x1) ^ mul3(x2) ^ x3;
            state[4 * i + 2] = x0 ^ x1 ^ mul2(x2) ^ mul3(x3);
            state[4 * i + 3] = mul3(x0) ^ x1 ^ x2 ^ mul2(x3);
        }
    }

    #[test]
    fn test_mixcolums_bis() {
        let mut state = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut state_bis = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        mixcolumns(&mut state);
        mixcolumns_bis(&mut state_bis);
        assert_eq!(state, state_bis);
    }

    #[test]
    fn test_aesenc_nokey() {
        use primitives::intrinsics;

        let mut state = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let rkey = [0u8; 16];
        intrinsics::tests::aesenc_slice(&mut state, &rkey);

        let mut state_manual = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        subbytes(&mut state_manual);
        shiftrows(&mut state_manual);
        mixcolumns(&mut state_manual);

        assert_eq!(state, state_manual);
    }

    #[test]
    fn test_aesenclast_nokey() {
        use primitives::intrinsics;

        let mut state = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let rkey = [0u8; 16];
        intrinsics::tests::aesenclast_slice(&mut state, &rkey);

        let mut state_manual = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        subbytes(&mut state_manual);
        shiftrows(&mut state_manual);

        assert_eq!(state, state_manual);
    }

    fn addroundkey(state: &mut [u8; 16], rkey: &[u8; 16]) {
        for i in 0..16 {
            state[i] ^= rkey[i];
        }
    }

    #[test]
    fn test_aesenc() {
        use primitives::intrinsics;

        let mut state = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let rkey = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        intrinsics::tests::aesenc_slice(&mut state, &rkey);

        let mut state_manual = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        subbytes(&mut state_manual);
        shiftrows(&mut state_manual);
        mixcolumns(&mut state_manual);
        addroundkey(&mut state_manual, &rkey);

        assert_eq!(state, state_manual);
    }

    #[test]
    fn test_aesenclast() {
        use primitives::intrinsics;

        let mut state = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let rkey = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        intrinsics::tests::aesenclast_slice(&mut state, &rkey);

        let mut state_manual = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        subbytes(&mut state_manual);
        shiftrows(&mut state_manual);
        addroundkey(&mut state_manual, &rkey);

        assert_eq!(state, state_manual);
    }

    fn rotword(word: &mut [u8; 4]) {
        let tmp = word[0];
        word[0] = word[1];
        word[1] = word[2];
        word[2] = word[3];
        word[3] = tmp;
    }

    fn subword(word: &mut [u8; 4]) {
        use primitives::constants;

        for x in word.iter_mut() {
            *x = constants::AES_SBOX[*x as usize];
        }
    }

    fn xorword(word: &mut [u8; 4], src: &[u8; 4]) {
        for i in 0..4 {
            word[i] ^= src[i];
        }
    }

    fn expand256_bis(key: &[u8; 32], rkeys: &mut [[u8; 16]; 15]) {
        use primitives::constants;

        rkeys[0] = *array_ref![key, 0, 16];
        rkeys[1] = *array_ref![key, 16, 16];

        let mut word: [u8; 4] = *array_ref![rkeys[1], 12, 4];
        for i in 2..15 {
            if i % 2 == 0 {
                rotword(&mut word);
                subword(&mut word);
                word[0] ^= constants::AES_RCON[i / 2 - 1];
            } else {
                subword(&mut word);
            }

            for j in 0..4 {
                xorword(&mut word, array_ref![rkeys[i - 2], 4 * j, 4]);
                *array_mut_ref![rkeys[i], 4 * j, 4] = word;
            }
        }
    }

    #[test]
    fn test_expand256() {
        let key = [0u8; 32];
        let mut rkeys = [[0u8; 16]; 15];
        expand256_slice(&key, &mut rkeys);
        let mut rkeys_bis = [[0u8; 16]; 15];
        expand256_bis(&key, &mut rkeys_bis);
        assert_eq!(rkeys, rkeys_bis);
    }
}
