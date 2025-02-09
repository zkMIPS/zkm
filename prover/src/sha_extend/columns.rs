use crate::sha_extend::rotate_right::RotateRightOp;
use crate::sha_extend::shift_right::ShiftRightOp;
use crate::sha_extend::wrapping_add_4::WrappingAdd4Op;
use crate::util::{indices_arr, transmute_no_compile_time_size_checks};
use std::borrow::{Borrow, BorrowMut};
use std::mem::transmute;

pub(crate) struct ShaExtendColumnsView<T: Copy> {
    /// Output
    pub w_i: WrappingAdd4Op<T>, // w_i_inter_1 + w_i_minus_16

    pub w_i_minus_15_rr_7: RotateRightOp<T>,
    pub w_i_minus_15_rr_18: RotateRightOp<T>,
    pub w_i_minus_15_rs_3: ShiftRightOp<T>,
    pub w_i_minus_2_rr_17: RotateRightOp<T>,
    pub w_i_minus_2_rr_19: RotateRightOp<T>,
    pub w_i_minus_2_rs_10: ShiftRightOp<T>,

    /// Input in le bytes order
    pub w_i_minus_15: [T; 4],
    pub w_i_minus_2: [T; 4],
    pub w_i_minus_16: [T; 4],
    pub w_i_minus_7: [T; 4],

    /// Intermediate values
    pub s_0_inter: [T; 4],
    pub s_0: [T; 4],
    pub s_1_inter: [T; 4],
    pub s_1: [T; 4],

    /// The timestamp at which inputs should be read from memory.
    pub timestamp: T,
    pub is_real_round: T,
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
