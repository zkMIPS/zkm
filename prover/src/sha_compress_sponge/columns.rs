use crate::sha_compress::wrapping_add_2::WrappingAdd2Op;
use crate::util::{indices_arr, transmute_no_compile_time_size_checks};
use std::borrow::{Borrow, BorrowMut};
use std::mem::transmute;

pub(crate) struct ShaCompressSpongeColumnsView<T: Copy> {
    pub hx: [T; 32],
    // a, b, c,..., h after compress
    pub output_state: [T; 32],
    // hx[i] + a,..., hx[i+7] + h
    pub output_hx: [WrappingAdd2Op<T>; 8],
    pub hx_virt: [T; 8],
    pub w_start_virt: T,

    // The timestamp at which inputs should be read from memory.
    pub timestamp: T,
    pub context: T,
    pub segment: T,
    // The segment and context of w_start_virt
    pub w_start_segment: T,
    pub w_start_context: T,
    pub is_real_round: T,
}

pub const NUM_SHA_COMPRESS_SPONGE_COLUMNS: usize = size_of::<ShaCompressSpongeColumnsView<u8>>(); //1420

impl<T: Copy> From<[T; NUM_SHA_COMPRESS_SPONGE_COLUMNS]> for ShaCompressSpongeColumnsView<T> {
    fn from(value: [T; NUM_SHA_COMPRESS_SPONGE_COLUMNS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> From<ShaCompressSpongeColumnsView<T>> for [T; NUM_SHA_COMPRESS_SPONGE_COLUMNS] {
    fn from(value: ShaCompressSpongeColumnsView<T>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> Borrow<ShaCompressSpongeColumnsView<T>> for [T; NUM_SHA_COMPRESS_SPONGE_COLUMNS] {
    fn borrow(&self) -> &ShaCompressSpongeColumnsView<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<ShaCompressSpongeColumnsView<T>> for [T; NUM_SHA_COMPRESS_SPONGE_COLUMNS] {
    fn borrow_mut(&mut self) -> &mut ShaCompressSpongeColumnsView<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> Borrow<[T; NUM_SHA_COMPRESS_SPONGE_COLUMNS]> for ShaCompressSpongeColumnsView<T> {
    fn borrow(&self) -> &[T; NUM_SHA_COMPRESS_SPONGE_COLUMNS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<[T; NUM_SHA_COMPRESS_SPONGE_COLUMNS]> for ShaCompressSpongeColumnsView<T> {
    fn borrow_mut(&mut self) -> &mut [T; NUM_SHA_COMPRESS_SPONGE_COLUMNS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy + Default> Default for ShaCompressSpongeColumnsView<T> {
    fn default() -> Self {
        [T::default(); NUM_SHA_COMPRESS_SPONGE_COLUMNS].into()
    }
}

const fn make_col_map() -> ShaCompressSpongeColumnsView<usize> {
    let indices_arr = indices_arr::<NUM_SHA_COMPRESS_SPONGE_COLUMNS>();
    unsafe {
        transmute::<[usize; NUM_SHA_COMPRESS_SPONGE_COLUMNS], ShaCompressSpongeColumnsView<usize>>(
            indices_arr,
        )
    }
}

pub(crate) const SHA_COMPRESS_SPONGE_COL_MAP: ShaCompressSpongeColumnsView<usize> = make_col_map();
