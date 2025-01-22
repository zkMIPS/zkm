use std::borrow::{Borrow, BorrowMut};
use std::intrinsics::transmute;
use crate::util::{indices_arr, transmute_no_compile_time_size_checks};

pub(crate) struct ShaExtendColumnsView<T: Copy> {

    /// Input in big-endian order
    pub w_i_minus_15: [T; 32],
    pub w_i_minus_2: [T; 32],
    pub w_i_minus_16: [T; 32],
    pub w_i_minus_7: [T; 32],

    /// Intermediate values
    pub w_i_minus_15_rr_7: [T; 32],
    pub w_i_minus_15_rr_18: [T; 32],
    pub w_i_minus_15_rs_3: [T; 32],
    pub s_0: [T; 32],
    pub w_i_minus_2_rr_17: [T; 32],
    pub w_i_minus_2_rr_19: [T; 32],
    pub w_i_minus_2_rs_10: [T; 32],
    pub s_1: [T; 32],
    pub w_i_inter_0: [T; 32], // s_1 + w_i_minus_7]
    pub carry_0: [T; 32],
    pub w_i_inter_1: [T; 32], // w_i_inter_0 + s_0
    pub carry_1: [T; 32],
    pub carry_2: [T; 32],
    /// Output
    pub w_i: [T; 32], // w_i_inter_1 + w_i_minus_16
    /// The timestamp at which inputs should be read from memory.
    pub timestamp: T,
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

pub fn get_input_range(i: usize) -> std::ops::Range<usize> {
    (0 + i * 32)..(32 + i * 32)
}

