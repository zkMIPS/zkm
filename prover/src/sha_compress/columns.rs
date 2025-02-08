use crate::util::{indices_arr, transmute_no_compile_time_size_checks};
use std::borrow::{Borrow, BorrowMut};
use std::mem::transmute;
use crate::sha_compress::not_operation::NotOperation;
use crate::sha_compress::wrapping_add_2::WrappingAdd2Op;
use crate::sha_compress::wrapping_add_5::WrappingAdd5Op;
use crate::sha_extend::rotate_right::RotateRightOp;

pub(crate) struct ShaCompressColumnsView<T: Copy> {
    /// a,b,c,d,e,f,g,h in le bytes form
    pub state: [T; 32],
    pub tem1: WrappingAdd5Op<T>,

    pub e_not: NotOperation<T>,
    pub e_rr_6: RotateRightOp<T>,
    pub e_rr_11: RotateRightOp<T>,
    pub e_rr_25: RotateRightOp<T>,
    pub a_rr_2: RotateRightOp<T>,
    pub a_rr_13: RotateRightOp<T>,
    pub a_rr_22: RotateRightOp<T>,

    /// w[i] and key[i]
    pub w_i: [T; 4],
    pub k_i: [T; 4],

    /// Intermediate values

    pub s_1_inter: [T; 4],
    pub s_1: [T; 4],
    pub e_and_f: [T; 4],
    pub e_not_and_g: [T; 4],
    pub ch: [T; 4],

    pub s_0_inter: [T; 4],
    pub s_0: [T; 4],
    pub a_and_b: [T; 4],
    pub a_and_c: [T; 4],
    pub b_and_c: [T; 4],
    pub maj_inter: [T; 4],
    pub maj: [T; 4],

    pub temp2: WrappingAdd2Op<T>,
    pub d_add_temp1: WrappingAdd2Op<T>,
    pub temp1_add_temp2: WrappingAdd2Op<T>,

    // The timestamp at which inputs should be read from memory.
    pub timestamp: T,
    pub segment: T,
    pub context: T,
    pub w_i_virt: T,

    // round number
    pub round: [T; 65],
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
