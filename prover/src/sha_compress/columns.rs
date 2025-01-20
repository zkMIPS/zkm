use std::borrow::{Borrow, BorrowMut};
use std::intrinsics::transmute;
use crate::util::{indices_arr, transmute_no_compile_time_size_checks};

pub(crate) struct ShaCompressColumnsView<T: Copy> {
    /// The timestamp at which inputs should be read from memory.
    pub timestamp: T,

    /// Round number
    pub i: T,

    /// 8 temp buffer values as input
    pub a: T,
    pub b: T,
    pub c: T,
    pub d: T,
    pub e: T,
    pub f: T,
    pub g: T,
    pub h: T,

    /// w[i]
    pub w: [T; 64],

    /// Selector
    pub round_i_filter: [T; 64],

    /// Intermediate values
    pub k_i: T,
    pub w_i: T,
    pub e_rr_6: T,
    pub e_rr_11: T,
    pub e_rr_25: T,
    pub s_1_inter: T,
    pub s_1: T,
    pub e_and_f: T,
    pub e_not: T,
    pub e_not_and_g: T,
    pub ch: T,
    pub temp1: T,
    pub a_rr_2: T,
    pub a_rr_13: T,
    pub a_rr_22: T,
    pub s_0_inter: T,
    pub s_0: T,
    pub a_and_b: T,
    pub a_and_c: T,
    pub b_and_c: T,
    pub maj_inter: T,
    pub maj: T,
    pub temp2: T,

    /// Out
    pub new_a: T,
    pub new_b: T,
    pub new_c: T,
    pub new_d: T,
    pub new_e: T,
    pub new_f: T,
    pub new_g: T,
    pub new_h: T,

    /// 1 if this is the final round of the compress phase, 0 otherwise
    pub is_final: T,

}

pub const NUM_SHA_COMPRESS_COLUMNS: usize = size_of::<ShaCompressColumnsView<u8>>();

impl<T: Copy> From<[T; NUM_SHA_COMPRESS_COLUMNS]> for ShaCompressColumnsView<T> {
    fn from(value: [T; NUM_SHA_COMPRESS_COLUMNS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> From<ShaCompressColumnsView<T>> for [T; NUM_SHA_COMPRESS_COLUMNS] {
    fn from(value: ShaCompressColumnsView<T>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> Borrow<ShaCompressColumnsView<T>> for [T; NUM_SHA_COMPRESS_COLUMNS] {
    fn borrow(&self) -> &ShaCompressColumnsView<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<ShaCompressColumnsView<T>> for [T; NUM_SHA_COMPRESS_COLUMNS] {
    fn borrow_mut(&mut self) -> &mut ShaCompressColumnsView<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> Borrow<[T; NUM_SHA_COMPRESS_COLUMNS]> for ShaCompressColumnsView<T> {
    fn borrow(&self) -> &[T; NUM_SHA_COMPRESS_COLUMNS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<[T; NUM_SHA_COMPRESS_COLUMNS]> for ShaCompressColumnsView<T> {
    fn borrow_mut(&mut self) -> &mut [T; NUM_SHA_COMPRESS_COLUMNS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy + Default> Default for ShaCompressColumnsView<T> {
    fn default() -> Self {
        [T::default(); NUM_SHA_COMPRESS_COLUMNS].into()
    }
}

const fn make_col_map() -> ShaCompressColumnsView<usize> {
    let indices_arr = indices_arr::<NUM_SHA_COMPRESS_COLUMNS>();
    unsafe {
        transmute::<[usize; NUM_SHA_COMPRESS_COLUMNS], ShaCompressColumnsView<usize>>(indices_arr)
    }
}

pub(crate) const SHA_COMPRESS_COL_MAP: ShaCompressColumnsView<usize> = make_col_map();
