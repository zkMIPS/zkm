use crate::util::{indices_arr, transmute_no_compile_time_size_checks};
use std::borrow::{Borrow, BorrowMut};
use std::mem::transmute;

pub(crate) const NUM_EXTEND_INPUT: usize = 4;
pub(crate) const SHA_EXTEND_SPONGE_READ_BITS: usize = NUM_EXTEND_INPUT * 32;
pub(crate) struct ShaExtendSpongeColumnsView<T: Copy> {
    /// Input
    pub w_i_minus_15: [T; 32],
    pub w_i_minus_2: [T; 32],
    pub w_i_minus_16: [T; 32],
    pub w_i_minus_7: [T; 32],

    /// Output
    pub w_i: [T; 32],

    /// round
    pub round: [T; 48],

    /// Input address
    pub input_virt: [T; NUM_EXTEND_INPUT],

    /// Output address
    pub output_virt: T,

    pub context: T,
    pub segment: T,

    /// The timestamp at which inputs should be read from memory.
    pub timestamp: T,
}

pub const NUM_SHA_EXTEND_SPONGE_COLUMNS: usize = size_of::<ShaExtendSpongeColumnsView<u8>>(); //216

impl<T: Copy> From<[T; NUM_SHA_EXTEND_SPONGE_COLUMNS]> for ShaExtendSpongeColumnsView<T> {
    fn from(value: [T; NUM_SHA_EXTEND_SPONGE_COLUMNS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> From<ShaExtendSpongeColumnsView<T>> for [T; NUM_SHA_EXTEND_SPONGE_COLUMNS] {
    fn from(value: ShaExtendSpongeColumnsView<T>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> Borrow<ShaExtendSpongeColumnsView<T>> for [T; NUM_SHA_EXTEND_SPONGE_COLUMNS] {
    fn borrow(&self) -> &ShaExtendSpongeColumnsView<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<ShaExtendSpongeColumnsView<T>> for [T; NUM_SHA_EXTEND_SPONGE_COLUMNS] {
    fn borrow_mut(&mut self) -> &mut ShaExtendSpongeColumnsView<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> Borrow<[T; NUM_SHA_EXTEND_SPONGE_COLUMNS]> for ShaExtendSpongeColumnsView<T> {
    fn borrow(&self) -> &[T; NUM_SHA_EXTEND_SPONGE_COLUMNS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<[T; NUM_SHA_EXTEND_SPONGE_COLUMNS]> for ShaExtendSpongeColumnsView<T> {
    fn borrow_mut(&mut self) -> &mut [T; NUM_SHA_EXTEND_SPONGE_COLUMNS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy + Default> Default for ShaExtendSpongeColumnsView<T> {
    fn default() -> Self {
        [T::default(); NUM_SHA_EXTEND_SPONGE_COLUMNS].into()
    }
}

const fn make_col_map() -> ShaExtendSpongeColumnsView<usize> {
    let indices_arr = indices_arr::<NUM_SHA_EXTEND_SPONGE_COLUMNS>();
    unsafe {
        transmute::<[usize; NUM_SHA_EXTEND_SPONGE_COLUMNS], ShaExtendSpongeColumnsView<usize>>(
            indices_arr,
        )
    }
}

pub(crate) const SHA_EXTEND_SPONGE_COL_MAP: ShaExtendSpongeColumnsView<usize> = make_col_map();
