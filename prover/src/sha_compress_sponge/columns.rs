use std::borrow::{Borrow, BorrowMut};
use std::intrinsics::transmute;
use crate::util::{indices_arr, transmute_no_compile_time_size_checks};

pub(crate) struct ShaCompressSpongeColumnsView<T: Copy> {
    /// The timestamp at which inputs should be read from memory.
    pub timestamp: T,

    /// hx_i
    pub hx: [T;8],

    /// w[i]
    pub w: [T; 64],

    /// a,b...,h values after compressed
    pub new_a: T,
    pub new_b: T,
    pub new_c: T,
    pub new_d: T,
    pub new_e: T,
    pub new_f: T,
    pub new_g: T,
    pub new_h: T,

    /// output
    pub final_hx: [T;8],

    /// The base address at which we will read the input block.
    pub context: T,
    pub segment: T,
    /// Hx addresses
    pub hx_virt: [T; 8],

    /// W_i addresses
    pub w_virt: [T;64],
}


pub const NUM_SHA_COMPRESS_SPONGE_COLUMNS: usize = size_of::<ShaCompressSpongeColumnsView<u8>>();

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
        transmute::<[usize; NUM_SHA_COMPRESS_SPONGE_COLUMNS], ShaCompressSpongeColumnsView<usize>>(indices_arr)
    }
}

pub(crate) const SHA_COMPRESS_SPONGE_COL_MAP: ShaCompressSpongeColumnsView<usize> = make_col_map();
