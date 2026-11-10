#[cfg(target_arch = "x86")]
use std::arch::x86::{
    __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_aeskeygenassist_si128, _mm_loadu_si128,
    _mm_shuffle_epi32, _mm_slli_si128, _mm_storeu_si128, _mm_unpackhi_epi32, _mm_unpackhi_epi64,
    _mm_unpacklo_epi32, _mm_unpacklo_epi64, _mm_xor_si128,
};
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{
    __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_aeskeygenassist_si128, _mm_loadu_si128,
    _mm_shuffle_epi32, _mm_slli_si128, _mm_storeu_si128, _mm_unpackhi_epi32, _mm_unpackhi_epi64,
    _mm_unpacklo_epi32, _mm_unpacklo_epi64, _mm_xor_si128,
};
use std::mem::transmute;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[derive(Clone, Copy)]
pub(crate) struct Simd128(__m128i);

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl Simd128 {
    pub const fn from(x: u128) -> Self {
        Self(unsafe { transmute::<u128, __m128i>(x) })
    }

    /// Read from array pointer (potentially unaligned)
    #[inline(always)]
    pub fn read(src: &[u8; 16]) -> Self {
        let x = unsafe { _mm_loadu_si128(src.as_ptr() as *const _ as *const __m128i) };
        Self(x)
    }

    /// Write into array pointer (potentially unaligned)
    #[inline(always)]
    pub fn write(self, dst: &mut [u8; 16]) {
        unsafe {
            _mm_storeu_si128(dst.as_mut_ptr() as *mut _ as *mut __m128i, self.0);
        }
    }

    #[inline(always)]
    pub(crate) fn aesenc(block: &mut Self, key: &Self) {
        unsafe {
            block.0 = _mm_aesenc_si128(block.0, key.0);
        }
    }

    #[inline(always)]
    pub(crate) fn aesenclast(block: &mut Self, key: &Self) {
        unsafe {
            block.0 = _mm_aesenclast_si128(block.0, key.0);
        }
    }

    #[inline(always)]
    pub(crate) fn aeskeygenassist<const ROUND_CONSTANT: i32>(block: &Self) -> Self {
        unsafe { Self(_mm_aeskeygenassist_si128::<ROUND_CONSTANT>(block.0)) }
    }

    #[inline(always)]
    pub(crate) fn pxor(dst: &mut Self, src: &Self) {
        unsafe {
            dst.0 = _mm_xor_si128(dst.0, src.0);
        }
    }

    #[inline(always)]
    pub(crate) fn pslldq<const SHIFT: i32>(block: &mut Self) {
        unsafe { block.0 = _mm_slli_si128::<SHIFT>(block.0) }
    }

    #[inline(always)]
    pub(crate) fn pshufd<const CONTROL: i32>(block: &Self) -> Self {
        unsafe { Self(_mm_shuffle_epi32::<CONTROL>(block.0)) }
    }

    #[inline(always)]
    pub(crate) fn unpacklo_epi32(dst: &mut Self, src: &Self) {
        unsafe {
            dst.0 = _mm_unpacklo_epi32(dst.0, src.0);
        }
    }

    #[inline(always)]
    pub(crate) fn unpackhi_epi32(dst: &mut Self, src: &Self) {
        unsafe {
            dst.0 = _mm_unpackhi_epi32(dst.0, src.0);
        }
    }

    #[inline(always)]
    pub(crate) fn unpacklo_epi64(lhs: &Self, rhs: &Self) -> Self {
        unsafe { Self(_mm_unpacklo_epi64(lhs.0, rhs.0)) }
    }

    #[inline(always)]
    pub(crate) fn unpackhi_epi64(lhs: &Self, rhs: &Self) -> Self {
        unsafe { Self(_mm_unpackhi_epi64(lhs.0, rhs.0)) }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn aesenc_slice(block: &mut [u8; 16], key: &[u8; 16]) {
        let mut block_xmm = Simd128::read(block);
        let key_xmm = Simd128::read(key);
        Simd128::aesenc(&mut block_xmm, &key_xmm);
        block_xmm.write(block);
    }

    #[test]
    fn test_aesenc() {
        use super::super::constants;

        let mut dst = [0u8; 16];
        let key = [0u8; 16];
        let expect = [constants::AES_SBOX[0]; 16];
        aesenc_slice(&mut dst, &key);
        assert_eq!(dst, expect);
    }

    pub fn aesenclast_slice(block: &mut [u8; 16], rkey: &[u8; 16]) {
        let mut block_xmm = Simd128::read(block);
        let rkey_xmm = Simd128::read(rkey);
        Simd128::aesenclast(&mut block_xmm, &rkey_xmm);
        block_xmm.write(block);
    }

    #[test]
    fn test_aesenclast() {
        use super::super::constants;

        let mut dst = [0u8; 16];
        let rkey = [0u8; 16];
        let expect = [constants::AES_SBOX[0]; 16];
        aesenclast_slice(&mut dst, &rkey);
        assert_eq!(dst, expect);
    }

    fn pxor_slice(dst: &mut [u8; 16], src: &[u8; 16]) {
        let mut dst_xmm = Simd128::read(dst);
        let src_xmm = Simd128::read(src);
        Simd128::pxor(&mut dst_xmm, &src_xmm);
        dst_xmm.write(dst);
    }

    #[test]
    fn test_pxor() {
        let mut dst = [0xb2u8; 16];
        let src = [0xc5u8; 16];
        let expect = [(0xb2u8 ^ 0xc5u8); 16];
        pxor_slice(&mut dst, &src);
        assert_eq!(dst, expect);
    }

    fn unpacklo_epi32_slice(dst: &mut [u8; 16], src: &[u8; 16]) {
        let mut dst_xmm = Simd128::read(dst);
        let src_xmm = Simd128::read(src);
        Simd128::unpacklo_epi32(&mut dst_xmm, &src_xmm);
        dst_xmm.write(dst);
    }

    #[test]
    fn test_unpacklo_epi32() {
        let mut dst = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let src = [
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let expect = [0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23];
        unpacklo_epi32_slice(&mut dst, &src);
        assert_eq!(dst, expect);
    }

    fn unpackhi_epi32_slice(dst: &mut [u8; 16], src: &[u8; 16]) {
        let mut dst_xmm = Simd128::read(dst);
        let src_xmm = Simd128::read(src);
        Simd128::unpackhi_epi32(&mut dst_xmm, &src_xmm);
        dst_xmm.write(dst);
    }

    #[test]
    fn test_unpackhi_epi32() {
        let mut dst = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let src = [
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let expect = [8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31];
        unpackhi_epi32_slice(&mut dst, &src);
        assert_eq!(dst, expect);
    }

    fn unpacklo_epi64_slice(lhs: &[u8; 16], rhs: &[u8; 16]) -> [u8; 16] {
        let lhs_xmm = Simd128::read(lhs);
        let rhs_xmm = Simd128::read(rhs);
        let result = Simd128::unpacklo_epi64(&lhs_xmm, &rhs_xmm);
        let mut dst = [0; 16];
        result.write(&mut dst);
        dst
    }

    #[test]
    fn test_unpacklo_epi64() {
        let lhs = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let rhs = [
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let expect = [0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23];
        let unpacked = unpacklo_epi64_slice(&lhs, &rhs);
        assert_eq!(unpacked, expect);
    }

    fn unpackhi_epi64_slice(lhs: &[u8; 16], rhs: &[u8; 16]) -> [u8; 16] {
        let lhs_xmm = Simd128::read(lhs);
        let rhs_xmm = Simd128::read(rhs);
        let result = Simd128::unpackhi_epi64(&lhs_xmm, &rhs_xmm);
        let mut dst = [0; 16];
        result.write(&mut dst);
        dst
    }

    #[test]
    fn test_unpackhi_epi64() {
        let lhs = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let rhs = [
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let expect = [8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31];
        let unpacked = unpackhi_epi64_slice(&lhs, &rhs);
        assert_eq!(unpacked, expect);
    }
}
