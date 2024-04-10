#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MemIOView<T: Copy> {
    pub(crate) rs_le: [T; 32],
    pub(crate) rt_le: [T; 32],
    pub(crate) mem_le: [T; 32],
    pub(crate) aux_rs0_mul_rs1: T,
    pub(crate) aux_filter: T,
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
    pub(crate) is_lb: T,
}
