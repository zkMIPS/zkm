use std::borrow::{Borrow, BorrowMut};
use std::intrinsics::transmute;
use crate::util::{indices_arr, transmute_no_compile_time_size_checks};

pub(crate) struct ShaExtendColumnsView<T: Copy> {

    /// The timestamp at which inputs should be read from memory.
    pub timestamp: T,

    /// round
    pub i: T,

    /// Input
    pub w_i_minus_15: T,
    pub w_i_minus_2: T,
    pub w_i_minus_16: T,
    pub w_i_minus_7: T,

    /// Intermediate values
    pub w_i_minus_15_rr_7: T,
    pub w_i_minus_15_rr_18: T,
    pub w_i_minus_15_rs_3: T,
    pub s_0_inter: T,
    pub s_0: T,
    pub w_i_minus_2_rr_17: T,
    pub w_i_minus_2_rr_19: T,
    pub w_i_minus_2_rs_10: T,
    pub s_i_inter: T,
    pub s_1: T,

    /// Output
    pub w_i: T,
}

pub const NUM_SHA_EXTEND_COLUMNS: usize = size_of::<ShaExtendColumnsView<u8>>();

impl<T: Copy> From<[T; NUM_SHA_EXTEND_COLUMNS]> for ShaExtendColumnsView<T> {
    fn from(value: [T; NUM_SHA_EXTEND_COLUMNS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> From<ShaExtendColumnsView<T>> for [T; NUM_SHA_EXTEND_COLUMNS] {
    fn from(value: ShaExtendColumnsView<T>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> Borrow<ShaExtendColumnsView<T>> for [T; NUM_SHA_EXTEND_COLUMNS] {
    fn borrow(&self) -> &ShaExtendColumnsView<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<ShaExtendColumnsView<T>> for [T; NUM_SHA_EXTEND_COLUMNS] {
    fn borrow_mut(&mut self) -> &mut ShaExtendColumnsView<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> Borrow<[T; NUM_SHA_EXTEND_COLUMNS]> for ShaExtendColumnsView<T> {
    fn borrow(&self) -> &[T; NUM_SHA_EXTEND_COLUMNS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<[T; NUM_SHA_EXTEND_COLUMNS]> for ShaExtendColumnsView<T> {
    fn borrow_mut(&mut self) -> &mut [T; NUM_SHA_EXTEND_COLUMNS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy + Default> Default for ShaExtendColumnsView<T> {
    fn default() -> Self {
        [T::default(); NUM_SHA_EXTEND_COLUMNS].into()
    }
}

const fn make_col_map() -> ShaExtendColumnsView<usize> {
    let indices_arr = indices_arr::<NUM_SHA_EXTEND_COLUMNS>();
    unsafe {
        transmute::<[usize; NUM_SHA_EXTEND_COLUMNS], ShaExtendColumnsView<usize>>(indices_arr)
    }
}

pub(crate) const SHA_EXTEND_COL_MAP: ShaExtendColumnsView<usize> = make_col_map();
