use super::u64x2::u64x2;
use std::arch::asm;
use std::mem;

#[inline(always)]
pub(crate) fn aesenc(block: &mut u64x2, rkey: &u64x2) {
    unsafe {
        asm!(
            "aesenc {0}, {1}",
            inout(xmm_reg) *block,
            in(xmm_reg) *rkey,
            options(pure, nomem, nostack)
        );
    }
}

#[inline(always)]
pub(crate) fn aesenclast(block: &mut u64x2, rkey: &u64x2) {
    unsafe {
        asm!(
            "aesenclast {0}, {1}",
            inout(xmm_reg) *block,
            in(xmm_reg) *rkey,
            options(pure, nomem, nostack)
        );
    }
}

#[inline(always)]
pub(crate) fn aeskeygenassist_0x00(src: &u64x2) -> u64x2 {
    let mut dst = mem::MaybeUninit::<u64x2>::uninit();
    unsafe {
        asm!(
            "aeskeygenassist {0}, {1}, 0x00",
            inout(xmm_reg) *dst.as_mut_ptr(),
            in(xmm_reg) *src,
            options(pure, nomem, nostack)
        );
        dst.assume_init()
    }
}
#[inline(always)]
pub(crate) fn aeskeygenassist_0x01(src: &u64x2) -> u64x2 {
    let mut dst = mem::MaybeUninit::<u64x2>::uninit();
    unsafe {
        asm!(
            "aeskeygenassist {0}, {1}, 0x01",
            inout(xmm_reg) *dst.as_mut_ptr(),
            in(xmm_reg) *src,
            options(pure, nomem, nostack)
        );
        dst.assume_init()
    }
}
#[inline(always)]
pub(crate) fn aeskeygenassist_0x02(src: &u64x2) -> u64x2 {
    let mut dst = mem::MaybeUninit::<u64x2>::uninit();
    unsafe {
        asm!(
            "aeskeygenassist {0}, {1}, 0x02",
            inout(xmm_reg) *dst.as_mut_ptr(),
            in(xmm_reg) *src,
            options(pure, nomem, nostack)
        );
        dst.assume_init()
    }
}
#[inline(always)]
pub(crate) fn aeskeygenassist_0x04(src: &u64x2) -> u64x2 {
    let mut dst = mem::MaybeUninit::<u64x2>::uninit();
    unsafe {
        asm!(
            "aeskeygenassist {0}, {1}, 0x04",
            inout(xmm_reg) *dst.as_mut_ptr(),
            in(xmm_reg) *src,
            options(pure, nomem, nostack)
        );
        dst.assume_init()
    }
}
#[inline(always)]
pub(crate) fn aeskeygenassist_0x08(src: &u64x2) -> u64x2 {
    let mut dst = mem::MaybeUninit::<u64x2>::uninit();
    unsafe {
        asm!(
            "aeskeygenassist {0}, {1}, 0x08",
            inout(xmm_reg) *dst.as_mut_ptr(),
            in(xmm_reg) *src,
            options(pure, nomem, nostack)
        );
        dst.assume_init()
    }
}
#[inline(always)]
pub(crate) fn aeskeygenassist_0x10(src: &u64x2) -> u64x2 {
    let mut dst = mem::MaybeUninit::<u64x2>::uninit();
    unsafe {
        asm!(
            "aeskeygenassist {0}, {1}, 0x10",
            inout(xmm_reg) *dst.as_mut_ptr(),
            in(xmm_reg) *src,
            options(pure, nomem, nostack)
        );
        dst.assume_init()
    }
}
#[inline(always)]
pub(crate) fn aeskeygenassist_0x20(src: &u64x2) -> u64x2 {
    let mut dst = mem::MaybeUninit::<u64x2>::uninit();
    unsafe {
        asm!(
            "aeskeygenassist {0}, {1}, 0x20",
            inout(xmm_reg) *dst.as_mut_ptr(),
            in(xmm_reg) *src,
            options(pure, nomem, nostack)
        );
        dst.assume_init()
    }
}
#[inline(always)]
pub(crate) fn aeskeygenassist_0x40(src: &u64x2) -> u64x2 {
    let mut dst = mem::MaybeUninit::<u64x2>::uninit();
    unsafe {
        asm!(
            "aeskeygenassist {0}, {1}, 0x40",
            inout(xmm_reg) *dst.as_mut_ptr(),
            in(xmm_reg) *src,
            options(pure, nomem, nostack)
        );
        dst.assume_init()
    }
}

#[inline(always)]
pub(crate) fn pxor(dst: &mut u64x2, src: &u64x2) {
    unsafe {
        asm!(
            "pxor {0}, {1}",
            inout(xmm_reg) *dst,
            in(xmm_reg) *src,
            options(pure, nomem, nostack)
        );
    }
}

#[inline(always)]
pub(crate) fn pslldq_0x04(dst: &mut u64x2) {
    unsafe {
        asm!(
            "pslldq {0}, 0x04",
            inout(xmm_reg) * dst,
            options(pure, nomem, nostack)
        );
    }
}

#[inline(always)]
pub(crate) fn pshufd_0xff(src: &u64x2) -> u64x2 {
    let mut dst = mem::MaybeUninit::<u64x2>::uninit();
    unsafe {
        asm!(
            "pshufd {0}, {1}, 0xff",
            inout(xmm_reg) *dst.as_mut_ptr(),
            in(xmm_reg) *src,
            options(pure, nomem, nostack)
        );
        dst.assume_init()
    }
}
#[inline(always)]
pub(crate) fn pshufd_0xaa(src: &u64x2) -> u64x2 {
    let mut dst = mem::MaybeUninit::<u64x2>::uninit();
    unsafe {
        asm!(
            "pshufd {0}, {1}, 0xaa",
            inout(xmm_reg) *dst.as_mut_ptr(),
            in(xmm_reg) *src,
            options(pure, nomem, nostack)
        );
        dst.assume_init()
    }
}

#[inline(always)]
pub(crate) fn unpacklo_epi32(dst: &mut u64x2, src: &u64x2) {
    unsafe {
        asm!(
            "punpckldq {0}, {1}",
            inout(xmm_reg) *dst,
            in(xmm_reg) *src,
            options(pure, nomem, nostack)
        );
    }
}

#[inline(always)]
pub(crate) fn unpackhi_epi32(dst: &mut u64x2, src: &u64x2) {
    unsafe {
        asm!(
            "punpckhdq {0}, {1}",
            inout(xmm_reg) *dst,
            in(xmm_reg) *src,
            options(pure, nomem, nostack)
        );
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::primitives::constants;

    pub fn aesenc_slice(block: &mut [u8; 16], rkey: &[u8; 16]) {
        let mut block_xmm = u64x2::read(block);
        let rkey_xmm = u64x2::read(rkey);
        aesenc(&mut block_xmm, &rkey_xmm);
        block_xmm.write(block);
    }

    #[test]
    fn test_aesenc() {
        let mut dst = [0u8; 16];
        let rkey = [0u8; 16];
        let expect = [constants::AES_SBOX[0]; 16];
        aesenc_slice(&mut dst, &rkey);
        assert_eq!(dst, expect);
    }

    pub fn aesenclast_slice(block: &mut [u8; 16], rkey: &[u8; 16]) {
        let mut block_xmm = u64x2::read(block);
        let rkey_xmm = u64x2::read(rkey);
        aesenclast(&mut block_xmm, &rkey_xmm);
        block_xmm.write(block);
    }

    #[test]
    fn test_aesenclast() {
        let mut dst = [0u8; 16];
        let rkey = [0u8; 16];
        let expect = [constants::AES_SBOX[0]; 16];
        aesenclast_slice(&mut dst, &rkey);
        assert_eq!(dst, expect);
    }

    fn pxor_slice(dst: &mut [u8; 16], src: &[u8; 16]) {
        let mut dst_xmm = u64x2::read(dst);
        let src_xmm = u64x2::read(src);
        pxor(&mut dst_xmm, &src_xmm);
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
        let mut dst_xmm = u64x2::read(dst);
        let src_xmm = u64x2::read(src);
        unpacklo_epi32(&mut dst_xmm, &src_xmm);
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
        let mut dst_xmm = u64x2::read(dst);
        let src_xmm = u64x2::read(src);
        unpackhi_epi32(&mut dst_xmm, &src_xmm);
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
}
