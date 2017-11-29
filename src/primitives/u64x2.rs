use std::ptr::copy_nonoverlapping;
use std::mem;

#[allow(non_camel_case_types)]
#[repr(simd)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct u64x2(pub u64, pub u64);

impl u64x2 {
    /// Reads u64x2 from array pointer (potentially unaligned)
    #[inline(always)]
    pub fn read(src: &[u8; 16]) -> Self {
        unsafe {
            let mut tmp: Self = mem::uninitialized();
            copy_nonoverlapping(src.as_ptr(), &mut tmp as *mut Self as *mut u8, 16);
            tmp
        }
    }

    /// Write u64x2 content into array pointer (potentially unaligned)
    #[inline(always)]
    pub fn write(self, dst: &mut [u8; 16]) {
        unsafe {
            copy_nonoverlapping(&self as *const Self as *const u8, dst.as_mut_ptr(), 16);
        }
    }
}
