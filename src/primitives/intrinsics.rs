use primitives::u64x2::u64x2;
use std::mem;

#[inline(always)]
pub(crate) fn aesenc(block: &mut u64x2, rkey: &u64x2) {
    unsafe {
        asm!("aesenc $0, $1"
            : "+x"(*block)
            : "x"(*rkey)
            :
            : "intel", "alignstack"
        );
    }
}

#[inline(always)]
pub(crate) fn aesenclast(block: &mut u64x2, rkey: &u64x2) {
    unsafe {
        asm!("aesenclast $0, $1"
            : "+x"(*block)
            : "x"(*rkey)
            :
            : "intel", "alignstack"
        );
    }
}

macro_rules! aeskeygenassist {
    ($src:ident, $i:expr) => {{
        let mut dst: u64x2;
        unsafe {
            dst = mem::uninitialized();
            asm!("aeskeygenassist $0, $1, $2"
                    : "+x"(dst)
                    : "x"(*$src), "i"($i)
                    :
                    : "intel", "alignstack"
                );
        }
        dst
    }}
}

#[inline(always)]
pub(crate) fn aeskeygenassist_0x00(src: &u64x2) -> u64x2 {
    aeskeygenassist!(src, 0x00)
}
#[inline(always)]
pub(crate) fn aeskeygenassist_0x01(src: &u64x2) -> u64x2 {
    aeskeygenassist!(src, 0x01)
}
#[inline(always)]
pub(crate) fn aeskeygenassist_0x02(src: &u64x2) -> u64x2 {
    aeskeygenassist!(src, 0x02)
}
#[inline(always)]
pub(crate) fn aeskeygenassist_0x04(src: &u64x2) -> u64x2 {
    aeskeygenassist!(src, 0x04)
}
#[inline(always)]
pub(crate) fn aeskeygenassist_0x08(src: &u64x2) -> u64x2 {
    aeskeygenassist!(src, 0x08)
}
#[inline(always)]
pub(crate) fn aeskeygenassist_0x10(src: &u64x2) -> u64x2 {
    aeskeygenassist!(src, 0x10)
}
#[inline(always)]
pub(crate) fn aeskeygenassist_0x20(src: &u64x2) -> u64x2 {
    aeskeygenassist!(src, 0x20)
}
#[inline(always)]
pub(crate) fn aeskeygenassist_0x40(src: &u64x2) -> u64x2 {
    aeskeygenassist!(src, 0x40)
}

#[inline(always)]
pub(crate) fn pxor(dst: &mut u64x2, src: &u64x2) {
    unsafe {
        asm!("pxor $0, $1"
            : "+x"(*dst)
            : "x"(*src)
            :
            : "intel", "alignstack"
        );
    }
}

macro_rules! pslldq {
    ($dst:ident, $i:expr) => {{
        unsafe {
            asm!("pslldq $0, $1"
                    : "+x"(*$dst)
                    : "i"($i)
                    :
                    : "intel", "alignstack"
                );
        }
    }}
}

#[inline(always)]
pub(crate) fn pslldq_0x04(dst: &mut u64x2) {
    pslldq!(dst, 0x04)
}

macro_rules! pshufd {
    ($src:ident, $i:expr) => {{
        let mut dst: u64x2;
        unsafe {
            dst = mem::uninitialized();
            asm!("pshufd $0, $1, $2"
                    : "+x"(dst)
                    : "x"(*$src), "i"($i)
                    :
                    : "intel", "alignstack"
                );
        }
        dst
    }}
}

#[inline(always)]
pub(crate) fn pshufd_0xff(src: &u64x2) -> u64x2 {
    pshufd!(src, 0xff)
}
#[inline(always)]
pub(crate) fn pshufd_0xaa(src: &u64x2) -> u64x2 {
    pshufd!(src, 0xaa)
}

#[inline(always)]
pub(crate) fn unpacklo_epi32(dst: &mut u64x2, src: &u64x2) {
    unsafe {
        asm!("punpckldq $0, $1"
            : "+x"(*dst)
            : "x"(*src)
            :
            : "intel", "alignstack"
        );
    }
}

#[inline(always)]
pub(crate) fn unpackhi_epi32(dst: &mut u64x2, src: &u64x2) {
    unsafe {
        asm!("punpckhdq $0, $1"
            : "+x"(*dst)
            : "x"(*src)
            :
            : "intel", "alignstack"
        );
    }
}


#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn aesenc_slice(block: &mut [u8; 16], rkey: &[u8; 16]) {
        let mut block_xmm = u64x2::read(block);
        let rkey_xmm = u64x2::read(rkey);
        aesenc(&mut block_xmm, &rkey_xmm);
        block_xmm.write(block);
    }

    #[test]
    fn test_aesenc() {
        use primitives::constants;

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
        use primitives::constants;

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
            16,
            17,
            18,
            19,
            20,
            21,
            22,
            23,
            24,
            25,
            26,
            27,
            28,
            29,
            30,
            31,
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
            16,
            17,
            18,
            19,
            20,
            21,
            22,
            23,
            24,
            25,
            26,
            27,
            28,
            29,
            30,
            31,
        ];
        let expect = [8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31];
        unpackhi_epi32_slice(&mut dst, &src);
        assert_eq!(dst, expect);
    }
}
