use crate::poseidon::constants::{SPONGE_CAPACITY, SPONGE_RATE, SPONGE_WIDTH};
use std::borrow::{Borrow, BorrowMut};
use std::mem::{size_of, transmute};

use crate::util::{indices_arr, transmute_no_compile_time_size_checks};

pub(crate) const POSEIDON_WIDTH_BYTES: usize = 48; // 12 * 4
pub(crate) const POSEIDON_WIDTH_U32S: usize = POSEIDON_WIDTH_BYTES / 4;
pub(crate) const POSEIDON_WIDTH_MINUS_DIGEST: usize = SPONGE_WIDTH - POSEIDON_DIGEST;
pub(crate) const POSEIDON_RATE_BYTES: usize = SPONGE_RATE * 4;
pub(crate) const POSEIDON_RATE_U32S: usize = POSEIDON_RATE_BYTES / 4;
pub(crate) const POSEIDON_CAPACITY_BYTES: usize = 64;
pub(crate) const POSEIDON_CAPACITY_U32S: usize = POSEIDON_CAPACITY_BYTES / 4;
pub(crate) const POSEIDON_DIGEST_BYTES: usize = 32;
pub(crate) const POSEIDON_DIGEST: usize = 4;

#[repr(C)]
#[derive(Eq, PartialEq, Debug)]
pub(crate) struct PoseidonSpongeColumnsView<T: Copy> {
    /// 1 if this row represents a full input block, i.e. one in which each byte is an input byte,
    /// not a padding byte; 0 otherwise.
    pub is_full_input_block: T,

    // The base address at which we will read the input block.
    pub context: T,
    pub segment: T,
    // address
    pub virt: [T; SPONGE_RATE],

    /// The timestamp at which inputs should be read from memory.
    pub timestamp: T,

    /// The length of the original input, in bytes.
    pub len: T,

    /// The number of input bytes that have already been absorbed prior to this block.
    pub already_absorbed_bytes: T,

    /// If this row represents a final block row, the `i`th entry should be 1 if the final chunk of
    /// input has length `i` (in other words if `len - already_absorbed == i`), otherwise 0.
    ///
    /// If this row represents a full input block, this should contain all 0s.
    pub is_final_input_len: [T; POSEIDON_RATE_BYTES],

    /// The initial rate part of the sponge, at the start of this step.
    pub original_rate: [T; SPONGE_RATE],

    /// The capacity part of the sponge, at the start of this step.
    pub original_capacity: [T; SPONGE_CAPACITY],

    /// The block being absorbed, which may contain input bytes and/or padding bytes.
    pub block_bytes: [T; POSEIDON_RATE_BYTES],

    /// The rate part of the sponge, that is the current block, before add round constant
    pub new_rate: [T; SPONGE_RATE],

    /// The entire state (rate + capacity) of the sponge, after the
    /// permutation is applied, minus the first limbs where the digest is extracted from.
    /// Those missing limbs can be recomputed from `updated_digest_state`.
    pub partial_updated_state: [T; POSEIDON_WIDTH_MINUS_DIGEST],

    /// The first part of the state of the sponge, after the permutation is applied.
    /// This also represents the output digest of the Poseidon sponge during the squeezing phase.
    pub updated_digest_state: [T; POSEIDON_DIGEST],
}

// `u8` is guaranteed to have a `size_of` of 1.
pub const NUM_POSEIDON_SPONGE_COLUMNS: usize = size_of::<PoseidonSpongeColumnsView<u8>>();

impl<T: Copy> From<[T; NUM_POSEIDON_SPONGE_COLUMNS]> for PoseidonSpongeColumnsView<T> {
    fn from(value: [T; NUM_POSEIDON_SPONGE_COLUMNS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> From<PoseidonSpongeColumnsView<T>> for [T; NUM_POSEIDON_SPONGE_COLUMNS] {
    fn from(value: PoseidonSpongeColumnsView<T>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> Borrow<PoseidonSpongeColumnsView<T>> for [T; NUM_POSEIDON_SPONGE_COLUMNS] {
    fn borrow(&self) -> &PoseidonSpongeColumnsView<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<PoseidonSpongeColumnsView<T>> for [T; NUM_POSEIDON_SPONGE_COLUMNS] {
    fn borrow_mut(&mut self) -> &mut PoseidonSpongeColumnsView<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> Borrow<[T; NUM_POSEIDON_SPONGE_COLUMNS]> for PoseidonSpongeColumnsView<T> {
    fn borrow(&self) -> &[T; NUM_POSEIDON_SPONGE_COLUMNS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<[T; NUM_POSEIDON_SPONGE_COLUMNS]> for PoseidonSpongeColumnsView<T> {
    fn borrow_mut(&mut self) -> &mut [T; NUM_POSEIDON_SPONGE_COLUMNS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy + Default> Default for PoseidonSpongeColumnsView<T> {
    fn default() -> Self {
        [T::default(); NUM_POSEIDON_SPONGE_COLUMNS].into()
    }
}

const fn make_col_map() -> PoseidonSpongeColumnsView<usize> {
    let indices_arr = indices_arr::<NUM_POSEIDON_SPONGE_COLUMNS>();
    unsafe {
        transmute::<[usize; NUM_POSEIDON_SPONGE_COLUMNS], PoseidonSpongeColumnsView<usize>>(
            indices_arr,
        )
    }
}

pub(crate) const POSEIDON_SPONGE_COL_MAP: PoseidonSpongeColumnsView<usize> = make_col_map();
