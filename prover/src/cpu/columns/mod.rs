use std::borrow::{Borrow, BorrowMut};
use std::fmt::Debug;
use std::mem::{size_of, transmute};
use std::ops::{Index, IndexMut};

use plonky2::field::types::Field;

use crate::cpu::columns::general::CpuGeneralColumnsView;
use crate::cpu::columns::ops::OpsColumnsView;
use crate::cpu::membus::NUM_GP_CHANNELS;
use crate::util::{indices_arr, transmute_no_compile_time_size_checks};

mod general;
pub(crate) mod ops;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuBranchView<T: Copy> {
    // A flag.
    pub should_jump: T,
    pub gt: T,
    pub lt: T,
    pub eq: T,
    pub is_gt: T,
    pub is_lt: T,
    pub is_eq: T,
    pub is_ge: T,
    pub is_le: T,
    pub is_ne: T,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryChannelView<T: Copy> {
    /// 1 if this row includes a memory operation in the `i`th channel of the memory bus, otherwise
    /// 0.
    pub used: T,
    pub is_read: T,
    pub addr_context: T,
    pub addr_segment: T,
    pub addr_virtual: T,
    pub value: T,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemIOView<T: Copy> {
    pub(crate) is_lh: T,
    pub(crate) is_lwl: T,
    pub(crate) is_lw: T,
    pub(crate) is_lbu: T,
    pub(crate) is_lhu: T,
    pub(crate) is_lwr: T,
    pub(crate) is_sb: T,
    pub(crate) is_sh: T,
    pub(crate) is_swl: T,
    pub(crate) is_sw: T,
    pub(crate) is_swr: T,
    pub(crate) is_ll: T,
    pub(crate) is_sc: T,
    pub(crate) is_sdc1: T,
    pub(crate) is_lb: T,
    pub(crate) aux_filter: T,
}

#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct CpuColumnsView<T: Copy> {
    /// Filter. 1 if the row is part of bootstrapping the kernel code, 0 otherwise.
    pub is_bootstrap_kernel: T,
    pub is_exit_kernel: T,

    /// If CPU cycle: Current context.
    // TODO: this is currently unconstrained
    pub context: T,

    /// If CPU cycle: Context for code memory channel.
    pub code_context: T,

    /// If CPU cycle: The program counter for the current instruction.
    pub program_counter: T,
    pub next_program_counter: T,

    /// If CPU cycle: We're in kernel (privileged) mode.
    pub is_kernel_mode: T,

    /// If CPU cycle: flags for ZKVM instructions (a few cannot be shared; see the comments in
    /// `OpsColumnsView`).
    pub op: OpsColumnsView<T>,

    pub branch: CpuBranchView<T>,

    /// If CPU cycle: the opcode, broken up into bits in little-endian order.
    pub opcode_bits: [T; 6], // insn[31:26]
    pub rs_bits: [T; 5],    // insn[25:21]
    pub rt_bits: [T; 5],    // insn[20:16]
    pub rd_bits: [T; 5],    // insn[15:11]
    pub shamt_bits: [T; 5], // insn[10:6] i.e. hint
    pub func_bits: [T; 6],  // insn[5:0]
    // imm | offset: [rd_bits, shamt_bits, func_bits]
    // code: [rs_bits, rt_bits, rd_bits, shamt_bits]
    // inst_index: [rs_bits, rt_bits, rd_bits, shamt_bits, func_bits]
    /// Filter. 1 iff a Poseidon sponge lookup is performed on this row.
    pub is_poseidon_sponge: T,

    pub(crate) general: CpuGeneralColumnsView<T>,

    pub(crate) memio: MemIOView<T>,

    pub(crate) clock: T,
    pub mem_channels: [MemoryChannelView<T>; NUM_GP_CHANNELS],
}

// `u8` is guaranteed to have a `size_of` of 1.
pub const NUM_CPU_COLUMNS: usize = size_of::<CpuColumnsView<u8>>();

impl<F: Field> Default for CpuColumnsView<F> {
    fn default() -> Self {
        Self::from([F::ZERO; NUM_CPU_COLUMNS])
    }
}

impl<T: Copy> From<[T; NUM_CPU_COLUMNS]> for CpuColumnsView<T> {
    fn from(value: [T; NUM_CPU_COLUMNS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> From<CpuColumnsView<T>> for [T; NUM_CPU_COLUMNS] {
    fn from(value: CpuColumnsView<T>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> Borrow<CpuColumnsView<T>> for [T; NUM_CPU_COLUMNS] {
    fn borrow(&self) -> &CpuColumnsView<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<CpuColumnsView<T>> for [T; NUM_CPU_COLUMNS] {
    fn borrow_mut(&mut self) -> &mut CpuColumnsView<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> Borrow<[T; NUM_CPU_COLUMNS]> for CpuColumnsView<T> {
    fn borrow(&self) -> &[T; NUM_CPU_COLUMNS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<[T; NUM_CPU_COLUMNS]> for CpuColumnsView<T> {
    fn borrow_mut(&mut self) -> &mut [T; NUM_CPU_COLUMNS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, I> Index<I> for CpuColumnsView<T>
where
    [T]: Index<I>,
{
    type Output = <[T] as Index<I>>::Output;

    fn index(&self, index: I) -> &Self::Output {
        let arr: &[T; NUM_CPU_COLUMNS] = self.borrow();
        <[T] as Index<I>>::index(arr, index)
    }
}

impl<T: Copy, I> IndexMut<I> for CpuColumnsView<T>
where
    [T]: IndexMut<I>,
{
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        let arr: &mut [T; NUM_CPU_COLUMNS] = self.borrow_mut();
        <[T] as IndexMut<I>>::index_mut(arr, index)
    }
}

const fn make_col_map() -> CpuColumnsView<usize> {
    let indices_arr = indices_arr::<NUM_CPU_COLUMNS>();
    unsafe { transmute::<[usize; NUM_CPU_COLUMNS], CpuColumnsView<usize>>(indices_arr) }
}

pub const COL_MAP: CpuColumnsView<usize> = make_col_map();
