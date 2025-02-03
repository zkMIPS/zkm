use crate::util::{indices_arr, transmute_no_compile_time_size_checks};
use std::borrow::{Borrow, BorrowMut};
use std::mem::transmute;
#[derive(Clone)]
pub(crate) struct ShaCompressColumnsView<T: Copy> {
    /// input state: a,b,c,d,e,f,g,h in binary form
    pub input_state: [T; 256],
    /// Out
    pub output_state: [T; 256],
    /// w[i] and key[i]
    pub w_i: [T; 32],
    pub k_i: [T; 32],

    /// Intermediate values
    pub e_rr_6: [T; 32],
    pub e_rr_11: [T; 32],
    pub e_rr_25: [T; 32],
    pub s_1: [T; 32],
    pub e_and_f: [T; 32],
    pub not_e_and_g: [T; 32],
    pub ch: [T; 32],
    // h.wrapping_add(s1)
    pub inter_1: [T; 32],
    pub carry_1: [T; 32],
    // inter_1.wrapping_add(ch)
    pub inter_2: [T; 32],
    pub carry_2: [T; 32],
    // inter_2.wrapping_add(SHA_COMPRESS_K[i])
    pub inter_3: [T; 32],
    pub carry_3: [T; 32],
    // inter_3.wrapping_add(w_i)
    pub temp1: [T; 32],
    pub carry_4: [T; 32],

    pub a_rr_2: [T; 32],
    pub a_rr_13: [T; 32],
    pub a_rr_22: [T; 32],
    pub s_0: [T; 32],
    pub a_and_b: [T; 32],
    pub a_and_c: [T; 32],
    pub b_and_c: [T; 32],
    pub maj: [T; 32],
    pub temp2: [T; 32],
    pub carry_5: [T; 32],
    pub carry_a: [T; 32],
    pub carry_e: [T; 32],

    /// The timestamp at which inputs should be read from memory.
    pub timestamp: T,
    pub is_normal_round: T,
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
