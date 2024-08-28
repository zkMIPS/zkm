use super::util::*;
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::kernel::assembler::Kernel;
use crate::generation::state::GenerationState;
use crate::memory::segments::Segment;
use crate::witness::errors::ProgramError;
use crate::witness::memory::MemoryAddress;
use crate::{arithmetic, logic};
use anyhow::{Context, Result};

use plonky2::field::types::Field;

use crate::poseidon_sponge::columns::POSEIDON_RATE_BYTES;
use itertools::Itertools;
use plonky2::hash::hash_types::RichField;
use std::fs;

pub const WORD_SIZE: usize = core::mem::size_of::<u32>();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BranchCond {
    EQ,
    NE,
    GE,
    LE,
    GT,
    LT,
}

impl BranchCond {
    pub(crate) fn result(&self, input0: i32, input1: i32) -> bool {
        match self {
            BranchCond::EQ => input0 == input1,
            BranchCond::NE => input0 != input1,
            BranchCond::GE => input0 >= input1,
            BranchCond::LE => input0 <= input1,
            BranchCond::GT => input0 > input1,
            BranchCond::LT => input0 < input1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MovCond {
    EQ,
    NE,
}

pub fn generate_pinv_diff<F: Field>(val0: u32, val1: u32, lv: &mut CpuColumnsView<F>) {
    let num_unequal_limbs = if val0 != val1 { 1 } else { 0 };
    let _equal = num_unequal_limbs == 0;

    // Form `diff_pinv`.
    // Let `diff = val0 - val1`. Consider `x[i] = diff[i]^-1` if `diff[i] != 0` and 0 otherwise.
    // Then `diff @ x = num_unequal_limbs`, where `@` denotes the dot product. We set
    // `diff_pinv = num_unequal_limbs^-1 * x` if `num_unequal_limbs != 0` and 0 otherwise. We have
    // `diff @ diff_pinv = 1 - equal` as desired.
    let logic = lv.general.logic_mut();
    let num_unequal_limbs_inv = F::from_canonical_usize(num_unequal_limbs)
        .try_inverse()
        .unwrap_or(F::ZERO);
    let val0_f = F::from_canonical_u32(val0);
    let val1_f = F::from_canonical_u32(val1);
    logic.diff_pinv = (val0_f - val1_f).try_inverse().unwrap_or(F::ZERO) * num_unequal_limbs_inv;
}

pub(crate) const SYSGETPID: usize = 4020;
pub(crate) const SYSGETGID: usize = 4047;
pub(crate) const SYSMMAP2: usize = 4210;
pub(crate) const SYSMMAP: usize = 4090;
pub(crate) const SYSBRK: usize = 4045;
pub(crate) const SYSCLONE: usize = 4120;
pub(crate) const SYSEXITGROUP: usize = 4246;
pub(crate) const SYSREAD: usize = 4003;
pub(crate) const SYSWRITE: usize = 4004;
pub(crate) const SYSFCNTL: usize = 4055;
pub(crate) const SYSSETTHREADAREA: usize = 4283;

pub(crate) const SYSHINTLEN: usize = 240;
pub(crate) const SYSHINTREAD: usize = 241;

pub(crate) const FD_STDIN: usize = 0;
pub(crate) const FD_STDOUT: usize = 1;
pub(crate) const FD_STDERR: usize = 2;
pub(crate) const FD_PUBLIC_VALUES: usize = 3;
pub(crate) const FD_HINT: usize = 4;

pub(crate) const MIPSEBADF: usize = 0x9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MemOp {
    LH,
    LWL,
    LW,
    LBU,
    LHU,
    LWR,
    SB,
    SH,
    SWL,
    SW,
    SWR,
    LL,
    SC,
    LB,
    SDC1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    Syscall,
    BinaryLogic(logic::Op, u8, u8, u8),
    BinaryLogicImm(logic::Op, u8, u8, u32),
    BinaryArithmetic(arithmetic::BinaryOperator, u8, u8, u8),
    BinaryArithmeticImm(arithmetic::BinaryOperator, u8, u8, u32),
    Count(bool, u8, u8),
    CondMov(MovCond, u8, u8, u8),
    KeccakGeneral,
    Jump(u8, u8),
    Jumpi(u8, u32),
    Branch(BranchCond, u8, u8, u32),
    JumpDirect(u8, u32),
    Pc,
    GetContext,
    SetContext,
    MloadGeneral(MemOp, u8, u8, u32),
    MstoreGeneral(MemOp, u8, u8, u32),
    Nop,
    Ext(u8, u8, u8, u8),
    Ins(u8, u8, u8, u8),
    Maddu(u8, u8),
    Ror(u8, u8, u8),
    Rdhwr(u8, u8),
    Signext(u8, u8, u8),
    SwapHalf(u8, u8),
    Teq(u8, u8),
}

pub(crate) fn generate_cond_mov_op<F: Field>(
    cond: MovCond,
    rs: u8,
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (in0, log_in0) = reg_read_with_log(rs, 0, state, &mut row)?;
    let (in1, log_in1) = reg_read_with_log(rt, 1, state, &mut row)?;
    let (in2, log_in2) = reg_read_with_log(rd, 2, state, &mut row)?;

    let mov = match cond {
        MovCond::EQ => in1 == 0,
        MovCond::NE => in1 != 0,
    };

    let out = if mov { in0 } else { in2 };

    generate_pinv_diff(in1 as u32, 0, &mut row);

    let log_out0 = reg_write_with_log(rd, 3, out, state, &mut row)?;
    let log_out1 = reg_write_with_log(0, 4, mov as usize, state, &mut row)?;

    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_in1);
    state.traces.push_memory(log_in2);
    state.traces.push_memory(log_out0);
    state.traces.push_memory(log_out1);
    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_count_op<F: Field>(
    is_clo: bool,
    rs: u8,
    rd: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (in0, log_in0) = reg_read_with_log(rs, 0, state, &mut row)?;
    let in0 = if is_clo { !(in0 as u32) } else { in0 as u32 };
    let out = in0.leading_zeros() as usize;

    let log_out0 = reg_write_with_log(rd, 1, out, state, &mut row)?;
    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_out0);

    let bits_le = (0..32)
        .map(|i| {
            let bit = (in0 >> i) & 0x01;
            F::from_canonical_u32(bit)
        })
        .collect_vec();
    row.general.io_mut().rs_le = bits_le.try_into().unwrap();

    let mut conds = vec![];
    let mut inv = vec![];
    for i in (0..31).rev() {
        let x = in0 >> i;
        conds.push(F::from_bool(x == 1));

        let b = F::from_canonical_u32(x) - F::ONE;
        inv.push(b.try_inverse().unwrap_or(F::ZERO));
    }
    conds.push(F::from_bool(in0 == 0));
    inv.push(F::from_canonical_u32(in0).try_inverse().unwrap_or(F::ZERO));
    // Used for aux data, nothing to do with `le`
    row.general.io_mut().rt_le = conds.try_into().unwrap();
    row.general.io_mut().mem_le = inv.try_into().unwrap();

    state.traces.push_cpu(row);

    Ok(())
}

pub(crate) fn generate_binary_logic_op<F: Field>(
    op: logic::Op,
    rs: u8,
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (in0, log_in0) = reg_read_with_log(rs, 0, state, &mut row)?;
    let (in1, log_in1) = reg_read_with_log(rt, 1, state, &mut row)?;
    let operation = logic::Operation::new(op, in0 as u32, in1 as u32);
    let out = operation.result;

    let log_out0 = reg_write_with_log(rd, 2, out as usize, state, &mut row)?;

    state.traces.push_logic(operation);
    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_in1);
    state.traces.push_memory(log_out0);
    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_binary_logic_imm_op<F: Field>(
    op: logic::Op,
    rs: u8,
    rd: u8,
    imm: u32,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (in0, log_in0) = reg_read_with_log(rs, 0, state, &mut row)?;
    let in1 = imm;
    let operation = logic::Operation::new(op, in0 as u32, in1);
    let out = operation.result;

    let log_out0 = reg_write_with_log(rd, 2, out as usize, state, &mut row)?;

    //state.traces.push_logic(operation);
    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_out0);
    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_binary_arithmetic_op<F: Field>(
    operator: arithmetic::BinaryOperator,
    rs: u8,
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    assert!(![
        arithmetic::BinaryOperator::DIV,
        arithmetic::BinaryOperator::DIVU,
        arithmetic::BinaryOperator::MULT,
        arithmetic::BinaryOperator::MULTU,
    ]
    .contains(&operator));
    let (in0, log_in0) = reg_read_with_log(rs, 0, state, &mut row)?;
    let (in1, log_in1) = reg_read_with_log(rt, 1, state, &mut row)?;
    let operation = arithmetic::Operation::binary(operator, in0 as u32, in1 as u32);
    let out = operation.result().0;

    let log_out0 = reg_write_with_log(rd, 2, out as usize, state, &mut row)?;

    state.traces.push_arithmetic(operation);
    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_in1);
    state.traces.push_memory(log_out0);
    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_binary_arithmetic_hilo_op<F: Field>(
    operator: arithmetic::BinaryOperator,
    rs: u8,
    rt: u8,
    _rd: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    assert!([
        arithmetic::BinaryOperator::DIV,
        arithmetic::BinaryOperator::DIVU,
        arithmetic::BinaryOperator::MULT,
        arithmetic::BinaryOperator::MULTU,
    ]
    .contains(&operator));

    let (in0, log_in0) = reg_read_with_log(rs, 0, state, &mut row)?;
    let (in1, log_in1) = reg_read_with_log(rt, 1, state, &mut row)?;
    let in0 = in0 as u32;
    let in1 = in1 as u32;
    /*
    let (hi, lo) = match operator {
        arithmetic::BinaryOperator::DIV => (
            ((in0 as i32) % (in1 as i32)) as u32,
            ((in0 as i32) / (in1 as i32)) as u32,
        ),
        arithmetic::BinaryOperator::DIVU => (in0 % in1, in0 / in1),
        arithmetic::BinaryOperator::MULT => {
            let out = (in0 as i64 * in1 as i64) as u64;
            u32_from_u64(out)
        }
        arithmetic::BinaryOperator::MULTU => {
            let out = in0 as u64 * in1 as u64;
            u32_from_u64(out)
        }
        _ => todo!(),
    };
    */
    let operation = arithmetic::Operation::binary(operator, in0, in1);
    let (lo, hi) = operation.result();

    let log_out0 = reg_write_with_log(32, 2, lo as usize, state, &mut row)?;
    let log_out1 = reg_write_with_log(33, 3, hi as usize, state, &mut row)?;

    state.traces.push_arithmetic(operation);
    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_in1);
    state.traces.push_memory(log_out0);
    state.traces.push_memory(log_out1);
    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_binary_arithmetic_imm_op<F: Field>(
    rs: u8,
    rt: u8,
    imm: u32,
    operator: arithmetic::BinaryOperator,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (in0, log_in0) = reg_read_with_log(rs, 0, state, &mut row)?;
    let in1 = sign_extend::<16>(imm);
    let log_in1 = reg_write_with_log(rt, 1, in1 as usize, state, &mut row)?;
    let operation = arithmetic::Operation::binary(operator, in0 as u32, in1);

    let out = operation.result().0;
    let log_out0 = reg_write_with_log(rt, 2, out as usize, state, &mut row)?;

    state.traces.push_arithmetic(operation);
    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_in1);
    state.traces.push_memory(log_out0);
    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_lui<F: Field>(
    _rs: u8,
    rt: u8,
    imm: u32,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let in0 = sign_extend::<16>(imm);
    let log_in0 = reg_write_with_log(_rs, 0, in0 as usize, state, &mut row)?;
    let in1 = 1u32 << 16;
    push_no_write(state, &mut row, in1, Some(1));
    let log_in1 = reg_write_with_log(rt, 1, in1 as usize, state, &mut row)?;

    let operation = arithmetic::Operation::binary(arithmetic::BinaryOperator::LUI, in0, in1);
    let out = operation.result().0;

    let log_out0 = reg_write_with_log(rt, 2, out as usize, state, &mut row)?;

    state.traces.push_arithmetic(operation);
    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_in1);
    state.traces.push_memory(log_out0);
    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_keccak_general<F: Field>(
    _state: &mut GenerationState<F>,
    _row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    //row.is_keccak_sponge = F::ONE;
    /*
    let [(context, _), (segment, log_in1), (base_virt, log_in2), (len, log_in3)] =
        stack_pop_with_log_and_fill::<4, _>(state, &mut row)?;
    */
    /*
    let lookup_addr ;
    let (context, _) = mem_read_gp_with_log_and_fill(0, lookup_addr, state, &mut row);
    let (segment, log_in1) = mem_read_gp_with_log_and_fill(1, lookup_addr, state, &mut row);
    let (base_virt, log_in2) = mem_read_gp_with_log_and_fill(2, lookup_addr, state, &mut row);
    let (len, log_in3) = mem_read_gp_with_log_and_fill(3, lookup_addr, state, &mut row);

    let base_address = MemoryAddress::new(context, Segment::Code, base_virt);
    let input = (0..len)
        .map(|i| {
            let address = MemoryAddress {
                virt: base_address.virt.saturating_add(i),
                ..base_address
            };
            let val = state.memory.get(address);
            val as u8
        })
        .collect_vec();
    log::trace!("Hashing {:?}", input);

    let hash = keccak(&input); // FIXME
    push_no_write(state, &mut row, hash[0], Some(NUM_GP_CHANNELS - 1));

    keccak_sponge_log(state, base_address, input);

    state.traces.push_memory(log_in1);
    state.traces.push_memory(log_in2);
    state.traces.push_memory(log_in3);
    state.traces.push_cpu(row);
    */
    Ok(())
}

pub(crate) fn generate_jump<F: Field>(
    link: u8,
    target: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (target_pc, target_op) = reg_read_with_log(target, 0, state, &mut row)?;
    let next_pc = state.registers.program_counter.wrapping_add(8);
    let link_op = reg_write_with_log(link, 1, next_pc, state, &mut row)?;
    state.traces.push_cpu(row);
    state.traces.push_memory(target_op);
    state.traces.push_memory(link_op);
    state.jump_to(target_pc);
    Ok(())
}

pub(crate) fn generate_branch<F: Field>(
    cond: BranchCond,
    src1: u8,
    src2: u8,
    target: u32,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (src1, src1_op) = reg_read_with_log(src1, 0, state, &mut row)?;
    let (src2, src2_op) = reg_read_with_log(src2, 1, state, &mut row)?;
    let should_jump = cond.result(src1 as i32, src2 as i32);

    match cond {
        BranchCond::EQ => row.branch.is_eq = F::ONE,
        BranchCond::NE => row.branch.is_ne = F::ONE,
        BranchCond::GE => row.branch.is_ge = F::ONE,
        BranchCond::LE => row.branch.is_le = F::ONE,
        BranchCond::GT => row.branch.is_gt = F::ONE,
        BranchCond::LT => row.branch.is_lt = F::ONE,
    };

    if src1 == src2 {
        row.branch.eq = F::ONE;
    }

    if src1 > src2 {
        row.branch.gt = F::ONE;
    }

    if src1 < src2 {
        row.branch.lt = F::ONE;
    }

    //log::info!("jump: {} c0: {}, c1: {}, aux1: {}, aux2: {}", should_jump, src1, src2, src1.wrapping_sub(src2), src2.wrapping_sub(src1));
    let aux1 = src1.wrapping_sub(src2);
    let aux2 = src2.wrapping_sub(src1);
    let aux3 = (src1 ^ src2) & 0x80000000 > 0;
    let target = sign_extend::<16>(target);
    let (mut target_pc, _) = target.overflowing_shl(2);
    let aux4 = target_pc;
    let log_out0 = reg_write_with_log(0, 2, aux1, state, &mut row)?;
    let log_out1 = reg_write_with_log(0, 3, aux2, state, &mut row)?;
    let log_out2 = reg_write_with_log(0, 4, aux3 as usize, state, &mut row)?;
    let log_out3 = reg_write_with_log(0, 5, aux4 as usize, state, &mut row)?;
    let pc = state.registers.program_counter as u32;
    if should_jump {
        target_pc = target_pc.wrapping_add(pc + 4);
        row.branch.should_jump = F::ONE;
        state.traces.push_cpu(row);
        state.jump_to(target_pc as usize);
    } else {
        let next_pc = pc.wrapping_add(8);
        row.branch.should_jump = F::ZERO;
        state.traces.push_cpu(row);
        state.jump_to(next_pc as usize);
    }
    state.traces.push_memory(src1_op);
    state.traces.push_memory(src2_op);
    state.traces.push_memory(log_out0);
    state.traces.push_memory(log_out1);
    state.traces.push_memory(log_out2);
    state.traces.push_memory(log_out3);
    Ok(())
}

pub(crate) fn generate_jumpi<F: Field>(
    link: u8,
    target: u32,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (mut target_pc, _) = (target as usize).overflowing_shl(2);
    let pc = state.registers.program_counter;
    let operation: logic::Operation =
        logic::Operation::new(logic::Op::And, pc as u32, 0xf0000000u32);
    let pc_result = operation.result as usize;
    let result_op = reg_write_with_log(0, 2, pc_result, state, &mut row)?;
    target_pc = target_pc.wrapping_add(pc_result);
    let next_pc = pc.wrapping_add(8);
    let link_op = reg_write_with_log(link, 1, next_pc, state, &mut row)?;
    // FIXME: skip for lookup check
    //state.traces.push_logic(operation);
    state.traces.push_cpu(row);
    state.jump_to(target_pc);
    state.traces.push_memory(link_op);
    state.traces.push_memory(result_op);
    Ok(())
}

pub(crate) fn generate_jumpdirect<F: Field>(
    link: u8,
    target: u32,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let target = sign_extend::<16>(target);
    let (target_pc, _) = target.overflowing_shl(2);
    let offset_op = reg_write_with_log(0, 2, target_pc as usize, state, &mut row)?;
    let pc = state.registers.program_counter as u32;
    let target_pc = target_pc.wrapping_add(pc + 4);
    let next_pc = pc.wrapping_add(8);
    let link_op = reg_write_with_log(link, 1, next_pc as usize, state, &mut row)?;
    // FIXME: skip for lookup check
    //state.traces.push_logic(operation);
    state.traces.push_cpu(row);
    state.jump_to(target_pc as usize);
    state.traces.push_memory(link_op);
    state.traces.push_memory(offset_op);
    Ok(())
}

pub(crate) fn generate_pc<F: Field>(
    state: &mut GenerationState<F>,
    row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_get_context<F: Field>(
    _state: &mut GenerationState<F>,
    _row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    /*
    push_with_write(state, &mut row, state.registers.context.into())?;
    state.traces.push_cpu(row);
    */
    Ok(())
}

pub(crate) fn generate_set_context<F: Field>(
    _state: &mut GenerationState<F>,
    _row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    /*
    let [(ctx, _)] = stack_pop_with_log_and_fill::<1, _>(state, &mut row)?;

    let sp_to_save = state.registers.stack_len.into();

    let old_ctx = state.registers.context;
    let new_ctx = ctx;

    let sp_field = ContextMetadata::StackSize as usize;
    let old_sp_addr = MemoryAddress::new(old_ctx, Segment::ContextMetadata, sp_field);
    let new_sp_addr = MemoryAddress::new(new_ctx, Segment::ContextMetadata, sp_field);

    let log_write_old_sp = mem_write_gp_log_and_fill(1, old_sp_addr, state, &mut row, sp_to_save);
    let (new_sp, log_read_new_sp) = if old_ctx == new_ctx {
        let op = MemoryOp::new(
            MemoryChannel::GeneralPurpose(2),
            state.traces.clock(),
            new_sp_addr,
            MemoryOpKind::Read,
            sp_to_save,
        );

        let channel = &mut row.mem_channels[2];
        assert_eq!(channel.used, F::ZERO);
        channel.used = F::ONE;
        channel.is_read = F::ONE;
        channel.addr_context = F::from_canonical_usize(new_ctx);
        channel.addr_segment = F::from_canonical_usize(Segment::ContextMetadata as usize);
        channel.addr_virtual = F::from_canonical_usize(new_sp_addr.virt);
        let val_limbs: [u64; 4] = sp_to_save.0;
        for (i, limb) in val_limbs.into_iter().enumerate() {
            channel.value[2 * i] = F::from_canonical_u32(limb as u32);
            channel.value[2 * i + 1] = F::from_canonical_u32((limb >> 32) as u32);
        }

        (sp_to_save, op)
    } else {
        mem_read_gp_with_log_and_fill(2, new_sp_addr, state, &mut row)
    };

    // If the new stack isn't empty, read stack_top from memory.
    let new_sp = new_sp.as_usize();
    if new_sp > 0 {
        // Set up columns to disable the channel if it *is* empty.
        let new_sp_field = F::from_canonical_usize(new_sp);
        if let Some(inv) = new_sp_field.try_inverse() {
            row.general.stack_mut().stack_inv = inv;
            row.general.stack_mut().stack_inv_aux = F::ONE;
        } else {
            row.general.stack_mut().stack_inv = F::ZERO;
            row.general.stack_mut().stack_inv_aux = F::ZERO;
        }

        let new_top_addr = MemoryAddress::new(new_ctx, Segment::Stack, new_sp - 1);
        let (new_top, log_read_new_top) =
            mem_read_gp_with_log_and_fill(3, new_top_addr, state, &mut row);
        state.registers.stack_top = new_top;
        state.traces.push_memory(log_read_new_top);
    } else {
        row.general.stack_mut().stack_inv = F::ZERO;
        row.general.stack_mut().stack_inv_aux = F::ZERO;
    }

    state.registers.context = new_ctx;
    state.registers.stack_len = new_sp;
    state.traces.push_memory(log_write_old_sp);
    state.traces.push_memory(log_read_new_sp);
    state.traces.push_cpu(row);
    */
    Ok(())
}

pub(crate) fn generate_shift_imm<F: Field>(
    op: arithmetic::BinaryOperator,
    sa: u8,
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    assert!([
        arithmetic::BinaryOperator::SLL,
        arithmetic::BinaryOperator::SRL,
        arithmetic::BinaryOperator::SRA
    ]
    .contains(&op));

    let (input0, log_in0) = reg_read_with_log(rt, 1, state, &mut row)?;
    state.traces.push_memory(log_in0);

    let shift = sa as u32;
    push_no_write(state, &mut row, shift, Some(0));

    let lookup_addr = MemoryAddress::new(0, Segment::ShiftTable, shift as usize);
    let (_, read) = mem_read_gp_with_log_and_fill(3, lookup_addr, state, &mut row);
    state.traces.push_memory(read);

    let operation = arithmetic::Operation::binary(op, input0 as u32, shift);
    let result = operation.result().0;

    state.traces.push_arithmetic(operation);
    let outlog = reg_write_with_log(rd, 2, result as usize, state, &mut row)?;

    state.traces.push_memory(outlog);
    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_sllv<F: Field>(
    rs: u8,
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (input0, log_in0) = reg_read_with_log(rs, 0, state, &mut row)?;
    let (input1, log_in1) = reg_read_with_log(rt, 1, state, &mut row)?;

    let lookup_addr = MemoryAddress::new(0, Segment::ShiftTable, input0);
    let (_, read) = mem_read_gp_with_log_and_fill(3, lookup_addr, state, &mut row);
    state.traces.push_memory(read);

    let operation = arithmetic::Operation::binary(
        arithmetic::BinaryOperator::SLLV,
        input1 as u32,
        input0 as u32,
    );
    let result = operation.result().0;

    state.traces.push_arithmetic(operation);
    let outlog = reg_write_with_log(rd, 2, result as usize, state, &mut row)?;
    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_in1);
    state.traces.push_memory(outlog);
    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_srlv<F: Field>(
    rs: u8,
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (input0, log_in0) = reg_read_with_log(rs, 0, state, &mut row)?;
    let (input1, log_in1) = reg_read_with_log(rt, 1, state, &mut row)?;

    let lookup_addr = MemoryAddress::new(0, Segment::ShiftTable, input0);
    let (_, read) = mem_read_gp_with_log_and_fill(3, lookup_addr, state, &mut row);
    state.traces.push_memory(read);

    let operation = arithmetic::Operation::binary(
        arithmetic::BinaryOperator::SRLV,
        input1 as u32,
        input0 as u32,
    );
    let result = operation.result().0;

    state.traces.push_arithmetic(operation);
    let outlog = reg_write_with_log(rd, 2, result as usize, state, &mut row)?;
    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_in1);
    state.traces.push_memory(outlog);
    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_srav<F: Field>(
    rs: u8,
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (input0, log_in0) = reg_read_with_log(rs, 0, state, &mut row)?;
    let (input1, log_in1) = reg_read_with_log(rt, 1, state, &mut row)?;
    // let input0 = in0 & 0x1F;

    let lookup_addr = MemoryAddress::new(0, Segment::ShiftTable, input0);
    let (_, read) = mem_read_gp_with_log_and_fill(3, lookup_addr, state, &mut row);
    state.traces.push_memory(read);

    let operation = arithmetic::Operation::binary(
        arithmetic::BinaryOperator::SRAV,
        input1 as u32,
        input0 as u32,
    );
    let result = operation.result().0;

    state.traces.push_arithmetic(operation);
    let outlog = reg_write_with_log(rd, 2, result as usize, state, &mut row)?;
    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_in1);
    state.traces.push_memory(outlog);
    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_ror<F: Field>(
    rd: u8,
    rt: u8,
    sa: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (input0, log_in0) = reg_read_with_log(rt, 0, state, &mut row)?;

    let sin = (input0 as u64) + ((input0 as u64) << 32);
    let result = (sin >> sa) as u32;

    let bits_le = (0..32)
        .map(|i| {
            let bit = (input0 >> i) & 0x01;
            F::from_canonical_u32(bit as u32)
        })
        .collect_vec();
    row.general.misc_mut().rs_bits = bits_le.try_into().unwrap();

    row.general.misc_mut().is_lsb = [F::ZERO; 32];
    row.general.misc_mut().is_lsb[sa as usize] = F::ONE;

    let outlog = reg_write_with_log(rd, 1, result as usize, state, &mut row)?;
    state.traces.push_memory(log_in0);
    state.traces.push_memory(outlog);
    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn load_preimage<F: RichField>(
    state: &mut GenerationState<F>,
    kernel: &Kernel,
) -> Result<()> {
    let mut hash_bytes = [0u8; 32];
    {
        let mut cpu_row = CpuColumnsView::default();
        cpu_row.clock = F::from_canonical_usize(state.traces.clock());
        for i in 0..8 {
            let address = MemoryAddress::new(0, Segment::Code, 0x30001000 + i * 4);
            let (mem, op) = mem_read_gp_with_log_and_fill(i, address, state, &mut cpu_row);
            hash_bytes[i * 4..i * 4 + 4].copy_from_slice(mem.to_be_bytes().as_ref());
            state.traces.push_memory(op);
        }
        state.traces.push_cpu(cpu_row);
    }

    let hex_string = hex::encode(hash_bytes);
    let mut preiamge_path = kernel.blockpath.clone();
    preiamge_path.push_str("0x");
    preiamge_path.push_str(hex_string.as_str());
    log::trace!("load file {}", preiamge_path);

    let content = fs::read(preiamge_path).expect("Read file failed");

    let mut cpu_row = CpuColumnsView::default();
    cpu_row.clock = F::from_canonical_usize(state.traces.clock());

    let mem_op = mem_write_gp_log_and_fill(
        0,
        MemoryAddress::new(0, Segment::Code, 0x31000000),
        state,
        &mut cpu_row,
        content.len() as u32,
    );
    log::trace!("{:X}: {:X}", 0x31000000, content.len() as u32);
    state.traces.push_memory(mem_op);

    let mut map_addr = 0x31000004;

    let mut j = 1;
    for i in (0..content.len()).step_by(WORD_SIZE) {
        if j == 8 {
            state.traces.push_cpu(cpu_row);
            cpu_row = CpuColumnsView::default();
            cpu_row.clock = F::from_canonical_usize(state.traces.clock());
            j = 0;
        }
        let mut word = 0;
        // Don't read past the end of the file.
        let len = core::cmp::min(content.len() - i, WORD_SIZE);
        for k in 0..len {
            let offset = i + k;
            let byte = content.get(offset).context("Invalid block offset")?;
            word |= (*byte as u32) << (k * 8);
        }
        let addr = MemoryAddress::new(0, Segment::Code, map_addr);
        // todo: check rate bytes
        if len < WORD_SIZE {
            let end = content.len() % POSEIDON_RATE_BYTES;
            word |= 0b1 << (len * 8);

            if end + 4 > POSEIDON_RATE_BYTES {
                word |= 0b10000000 << 24;
            }
        }

        log::trace!("{:X}: {:X}", map_addr, word);
        let mem_op = mem_write_gp_log_and_fill(j, addr, state, &mut cpu_row, word.to_be());
        state.traces.push_memory(mem_op);
        map_addr += 4;
        j += 1;
    }

    state.traces.push_cpu(cpu_row);

    Ok(())
}

pub(crate) fn load_input<F: RichField>(
    state: &mut GenerationState<F>,
    addr: usize,
    size: usize,
) -> Result<()> {
    let map_addr = addr;
    let vec = state.input_stream[state.input_stream_ptr].clone();
    state.input_stream_ptr += 1;
    assert_eq!(vec.len(), size, "hint input stream read length mismatch");
    assert_eq!(addr % 4, 0, "hint read address not aligned to 4 bytes");

    let mut cpu_row = CpuColumnsView::default();
    cpu_row.clock = F::from_canonical_usize(state.traces.clock());
    let mut j = 0;
    for i in (0..size).step_by(4) {
        // Get each byte in the chunk
        let b1 = vec[i];
        // In case the vec is not a multiple of 4, right-pad with 0s. This is fine because we
        // are assuming the word is uninitialized, so filling it with 0s makes sense.
        let b2 = vec.get(i + 1).copied().unwrap_or(0);
        let b3 = vec.get(i + 2).copied().unwrap_or(0);
        let b4 = vec.get(i + 3).copied().unwrap_or(0);
        let word = u32::from_be_bytes([b1, b2, b3, b4]);

        if j == 8 {
            state.traces.push_cpu(cpu_row);
            cpu_row = CpuColumnsView::default();
            cpu_row.clock = F::from_canonical_usize(state.traces.clock());
            j = 0;
        }
        let addr = MemoryAddress::new(0, Segment::Code, map_addr + i);
        let mem_op = mem_write_gp_log_and_fill(j, addr, state, &mut cpu_row, word);
        state.traces.push_memory(mem_op);
        j += 1;
    }

    state.traces.push_cpu(cpu_row);

    Ok(())
}

pub(crate) fn generate_syscall<F: RichField>(
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
    kernel: &Kernel,
) -> Result<(), ProgramError> {
    let (sys_num, log_in1) = reg_read_with_log(2, 0, state, &mut row)?;
    let (a0, log_in2) = reg_read_with_log(4, 1, state, &mut row)?;
    let (a1, log_in3) = reg_read_with_log(5, 2, state, &mut row)?;
    let (a2, log_in4) = reg_read_with_log(6, 3, state, &mut row)?;
    let mut v0 = 0usize;
    let mut v1 = 0usize;
    let mut is_load_preimage = false;
    let mut is_load_input = false;
    let result = match sys_num {
        SYSGETPID => {
            row.general.syscall_mut().sysnum[0] = F::ONE;
            is_load_preimage = true;
            Ok(())
        }
        SYSMMAP | SYSMMAP2 => {
            row.general.syscall_mut().sysnum[1] = F::ONE;
            let mut sz = a1;
            let mut sz_not_page_align = false;
            if sz & 0xFFF != 0 {
                row.general.syscall_mut().a1 = F::ONE;
                sz += 0x1000 - (sz & 0xFFF);
                row.general.syscall_mut().sysnum[9] = F::from_canonical_usize(sz);
                //use sysnum[9] to mark sz value
                sz_not_page_align = true;
            } else {
                row.general.syscall_mut().sysnum[10] = F::ONE;
                //use sysnum[10] to mark sz&0xfff == 0
                // row.general.syscall_mut().sysnum[10] = F::from_canonical_usize(sz.clone());//use sysnum[9] to mark sz
            }
            if a0 == 0 {
                row.general.syscall_mut().cond[0] = F::ONE;
                row.general.syscall_mut().a0[0] = F::ONE;
                if sz_not_page_align {
                    row.general.syscall_mut().cond[1] = F::ONE;
                } else {
                    row.general.syscall_mut().cond[2] = F::ONE;
                }
                let (heap, log_in5) = reg_read_with_log(34, 6, state, &mut row)?;
                v0 = heap;
                let heap = heap + sz;
                let outlog = reg_write_with_log(34, 7, heap, state, &mut row)?;
                state.traces.push_memory(log_in5);
                state.traces.push_memory(outlog);
            } else {
                row.general.syscall_mut().cond[3] = F::ONE;
                row.general.syscall_mut().a0[2] = F::ONE;
                v0 = a0;
            };
            Ok(())
        }
        SYSBRK => {
            row.general.syscall_mut().sysnum[2] = F::ONE;
            let (brk, log_in5) = reg_read_with_log(37, 6, state, &mut row)?;
            if a0 > brk {
                v0 = a0;
                row.general.syscall_mut().cond[10] = F::ONE;
            } else {
                v0 = brk;
                row.general.syscall_mut().cond[11] = F::ONE;
            }
            state.traces.push_memory(log_in5);
            Ok(())
        }
        SYSCLONE => {
            // clone (not supported)
            row.general.syscall_mut().sysnum[3] = F::ONE;
            v0 = 1;
            Ok(())
        }
        SYSEXITGROUP => {
            row.general.syscall_mut().sysnum[4] = F::ONE;
            state.registers.exited = true;
            state.registers.exit_code = a0 as u8;
            Ok(())
        }
        SYSREAD => {
            row.general.syscall_mut().sysnum[5] = F::ONE;
            match a0 {
                FD_STDIN => {
                    row.general.syscall_mut().a0[0] = F::ONE;
                    row.general.syscall_mut().cond[5] = F::ONE;
                } // fdStdin
                _ => {
                    row.general.syscall_mut().a0[2] = F::ONE;
                    row.general.syscall_mut().cond[4] = F::ONE;
                    v0 = 0xFFFFFFFF;
                    v1 = MIPSEBADF;
                }
            };
            Ok(())
        }
        SYSWRITE => {
            row.general.syscall_mut().sysnum[6] = F::ONE;
            match a0 {
                // fdStdout
                FD_STDOUT | FD_STDERR | FD_PUBLIC_VALUES | FD_HINT => {
                    row.general.syscall_mut().a0[1] = F::ONE;
                    row.general.syscall_mut().cond[7] = F::ONE;
                    v0 = a2;
                } // fdStdout
                _ => {
                    row.general.syscall_mut().a0[2] = F::ONE;
                    row.general.syscall_mut().cond[6] = F::ONE;
                    v0 = 0xFFFFFFFF;
                    v1 = MIPSEBADF;
                }
            };
            Ok(())
        }
        SYSFCNTL => {
            row.general.syscall_mut().sysnum[7] = F::ONE;
            match a0 {
                FD_STDIN => {
                    row.general.syscall_mut().a0[0] = F::ONE;
                    row.general.syscall_mut().cond[8] = F::ONE;
                    v0 = 0;
                } // fdStdin
                FD_STDOUT | FD_STDERR => {
                    row.general.syscall_mut().a0[1] = F::ONE;
                    row.general.syscall_mut().cond[9] = F::ONE;
                    v0 = 1;
                } // fdStdout / fdStderr
                _ => {
                    row.general.syscall_mut().a0[2] = F::ONE;
                    v0 = 0xFFFFFFFF;
                    v1 = MIPSEBADF;
                }
            };
            Ok(())
        }
        SYSSETTHREADAREA => {
            row.general.syscall_mut().sysnum[8] = F::ONE;
            let localop = reg_write_with_log(38, 6, a0, state, &mut row)?;
            state.traces.push_memory(localop);
            Ok(())
        }
        SYSHINTLEN => {
            if state.input_stream_ptr >= state.input_stream.len() {
                log::warn!("not enough vecs in hint input stream");
            }
            v0 = state.input_stream[state.input_stream_ptr].len();
            Ok(())
        }
        SYSHINTREAD => {
            if state.input_stream_ptr >= state.input_stream.len() {
                log::warn!("not enough vecs in hint input stream");
            }
            is_load_input = true;
            Ok(())
        }
        _ => {
            row.general.syscall_mut().sysnum[11] = F::ONE;
            Ok(())
        }
    };
    let outlog1 = reg_write_with_log(2, 4, v0, state, &mut row)?;
    let outlog2 = reg_write_with_log(7, 5, v1, state, &mut row)?;
    state.traces.push_memory(log_in1);
    state.traces.push_memory(log_in2);
    state.traces.push_memory(log_in3);
    state.traces.push_memory(log_in4);
    state.traces.push_memory(outlog1);
    state.traces.push_memory(outlog2);
    state.traces.push_cpu(row);
    if is_load_preimage {
        let _ = load_preimage(state, kernel);
    }

    if is_load_input {
        let _ = load_input(state, a0, a1);
    }
    result
}

pub(crate) fn generate_mload_general<F: Field>(
    op: MemOp,
    base: u8,
    rt_reg: u8,
    offset: u32,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (rs, log_in1) = reg_read_with_log(base, 0, state, &mut row)?;
    let (rt, log_in2) = reg_read_with_log(rt_reg, 1, state, &mut row)?;

    let virt_raw = (rs as u32).wrapping_add(sign_extend::<16>(offset));
    let virt = virt_raw & 0xFFFF_FFFC;
    let address = MemoryAddress::new(0, Segment::Code, virt as usize);
    let (mem, log_in3) = mem_read_gp_with_log_and_fill(2, address, state, &mut row);

    row.general
        .io_mut()
        .mem_le
        .iter_mut()
        .enumerate()
        .for_each(|(i, v)| {
            *v = F::from_canonical_u32((mem >> i) & 1);
        });

    let rs = virt_raw;
    let rt = rt as u32;

    let rs_from_bits = rs;
    row.general
        .io_mut()
        .rs_le
        .iter_mut()
        .enumerate()
        .for_each(|(i, v)| {
            *v = F::from_canonical_u32((rs >> i) & 1);
        });
    row.general
        .io_mut()
        .rt_le
        .iter_mut()
        .enumerate()
        .for_each(|(i, v)| {
            *v = F::from_canonical_u32((rt >> i) & 1);
        });
    row.memio.aux_filter = row.op.m_op_load * row.opcode_bits[5];

    let rs1 = (rs_from_bits >> 1) & 1;
    let rs0 = rs_from_bits & 1;
    let aux_rs_1_rs_0 = rs1 * rs0;

    let (aux_a, val) = match op {
        MemOp::LH => {
            row.memio.is_lh = F::ONE;
            let mem_fc = |i: u32| -> u32 { sign_extend::<16>((mem >> (16 - i * 8)) & 0xffff) };
            (0, mem_fc(rs & 2))
        }
        MemOp::LWL => {
            row.memio.is_lwl = F::ONE;
            let out = |i: u32| -> u32 {
                let val = mem << (i * 8);
                let mask: u32 = 0xffFFffFFu32 << (i * 8);
                (rt & (!mask)) | val
            };
            (aux_rs_1_rs_0, out(rs & 3))
        }
        MemOp::LW => {
            row.memio.is_lw = F::ONE;
            (0, mem)
        }
        MemOp::LBU => {
            row.memio.is_lbu = F::ONE;
            let out = |i: u32| -> u32 { (mem >> (24 - i * 8)) & 0xff };
            (aux_rs_1_rs_0, out(rs & 3))
        }
        MemOp::LHU => {
            row.memio.is_lhu = F::ONE;
            let mem_fc = |i: u32| -> u32 { (mem >> (16 - i * 8)) & 0xffff };
            (0, mem_fc(rs & 2))
        }
        MemOp::LWR => {
            row.memio.is_lwr = F::ONE;
            let out = |i: u32| -> u32 {
                let val = mem >> (24 - i * 8);
                let mask = 0xffFFffFFu32 >> (24 - i * 8);
                (rt & (!mask)) | val
            };
            (aux_rs_1_rs_0, out(rs & 3))
        }
        MemOp::LL => {
            row.memio.is_ll = F::ONE;
            (0, mem)
        }
        MemOp::LB => {
            row.memio.is_lb = F::ONE;
            let out = |i: u32| -> u32 { sign_extend::<8>((mem >> (24 - i * 8)) & 0xff) };
            (aux_rs_1_rs_0, out(rs & 3))
        }
        _ => todo!(),
    };

    row.general.io_mut().aux_rs0_mul_rs1 = F::from_canonical_u32(aux_a);

    let log_out0 = reg_write_with_log(rt_reg, 3, val as usize, state, &mut row)?;

    state.traces.push_memory(log_in1);
    state.traces.push_memory(log_in2);
    state.traces.push_memory(log_in3);
    state.traces.push_memory(log_out0);

    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_mstore_general<F: Field>(
    op: MemOp,
    base: u8,
    rt_reg: u8,
    offset: u32,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (rs, log_in1) = reg_read_with_log(base, 0, state, &mut row)?;
    let (rt, log_in2) = reg_read_with_log(rt_reg, 1, state, &mut row)?;

    let virt_raw = (rs as u32).wrapping_add(sign_extend::<16>(offset));
    let virt = virt_raw & 0xFFFF_FFFC;
    let address = MemoryAddress::new(0, Segment::Code, virt as usize);
    let (mem, log_in3) = mem_read_gp_with_log_and_fill(2, address, state, &mut row);

    row.general
        .io_mut()
        .mem_le
        .iter_mut()
        .enumerate()
        .for_each(|(i, v)| {
            *v = F::from_canonical_u32((mem >> i) & 1);
        });

    let rs = virt_raw;
    let rt = rt as u32;

    let rs_from_bits = rs;
    row.general
        .io_mut()
        .rs_le
        .iter_mut()
        .enumerate()
        .for_each(|(i, v)| {
            *v = F::from_canonical_u32((rs >> i) & 1);
        });
    row.general
        .io_mut()
        .rt_le
        .iter_mut()
        .enumerate()
        .for_each(|(i, v)| {
            *v = F::from_canonical_u32((rt >> i) & 1);
        });
    row.memio.aux_filter = row.op.m_op_store * row.opcode_bits[5];

    let rs1 = (rs_from_bits >> 1) & 1;
    let rs0 = rs_from_bits & 1;
    let aux_rs_1_rs_0 = rs1 * rs0;

    let (aux_a, val) = match op {
        MemOp::SB => {
            row.memio.is_sb = F::ONE;
            let out = |i: u32| -> u32 {
                let val = (rt & 0xff) << (24 - i * 8);
                let mask = 0xffFFffFFu32 ^ (0xff << (24 - i * 8));
                (mem & mask) | val
            };
            (aux_rs_1_rs_0, out(rs & 3))
        }
        MemOp::SH => {
            row.memio.is_sh = F::ONE;
            let mem_fc = |i: u32| -> u32 {
                let val = (rt & 0xffff) << (16 - i * 8);
                let mask = 0xffFFffFFu32 ^ (0xffff << (16 - i * 8));
                (mem & mask) | val
            };
            (0, mem_fc(rs & 2))
        }
        MemOp::SWL => {
            row.memio.is_swl = F::ONE;
            let out = |i: u32| -> u32 {
                let val = rt >> (i * 8);
                let mask = 0xffFFffFFu32 >> (i * 8);
                (mem & (!mask)) | val
            };
            (aux_rs_1_rs_0, out(rs & 3))
        }
        MemOp::SW => {
            row.memio.is_sw = F::ONE;
            (0, rt)
        }
        MemOp::SWR => {
            row.memio.is_swr = F::ONE;
            let out = |i: u32| -> u32 {
                let val = rt << (24 - (rs & i) * 8);
                let mask = 0xffFFffFFu32 << (24 - i * 8);
                (mem & (!mask)) | val
            };
            (aux_rs_1_rs_0, out(rs & 3))
        }
        MemOp::SC => {
            row.memio.is_sc = F::ONE;
            (0, rt)
        }
        MemOp::SDC1 => {
            row.memio.is_sdc1 = F::ONE;
            (0, 0)
        }
        _ => todo!(),
    };

    row.general.io_mut().aux_rs0_mul_rs1 = F::from_canonical_u32(aux_a);

    let log_out0 = mem_write_gp_log_and_fill(3, address, state, &mut row, val);

    log::trace!("write {:X} : {:X} ({})", address.virt, val, val);
    state.traces.push_memory(log_in1);
    state.traces.push_memory(log_in2);
    state.traces.push_memory(log_in3);
    state.traces.push_memory(log_out0);

    if op == MemOp::SC {
        let log_out1 = reg_write_with_log(rt_reg, 4, 1, state, &mut row)?;
        state.traces.push_memory(log_out1);
    }

    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_nop<F: Field>(
    state: &mut GenerationState<F>,
    row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    state.traces.push_cpu(row);

    Ok(())
}

pub(crate) fn generate_extract<F: Field>(
    rt: u8,
    rs: u8,
    msbd: u8,
    lsb: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    assert!(msbd + lsb < 32);
    let (in0, log_in0) = reg_read_with_log(rs, 0, state, &mut row)?;
    let mask_msb = (1 << (msbd + lsb + 1)) - 1;

    let bits_le = (0..32)
        .map(|i| {
            let bit = (in0 >> i) & 0x01;
            F::from_canonical_u32(bit as u32)
        })
        .collect_vec();
    row.general.misc_mut().rs_bits = bits_le.try_into().unwrap();

    row.general.misc_mut().is_msb = [F::ZERO; 32];
    row.general.misc_mut().is_msb[(msbd + lsb) as usize] = F::ONE;
    row.general.misc_mut().is_lsb = [F::ZERO; 32];
    row.general.misc_mut().is_lsb[lsb as usize] = F::ONE;
    row.general.misc_mut().auxs = F::from_canonical_u32(1 << lsb);

    let mask_lsb = (1 << lsb) - 1;
    let result = (in0 & mask_msb) >> lsb;
    row.general.misc_mut().auxm = F::from_canonical_u32((in0 & mask_msb) as u32);
    row.general.misc_mut().auxl = F::from_canonical_u32((in0 & mask_lsb) as u32);
    let log_out0 = reg_write_with_log(rt, 1, result, state, &mut row)?;

    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_out0);
    state.traces.push_cpu(row);

    Ok(())
}

pub(crate) fn generate_insert<F: Field>(
    rt: u8,
    rs: u8,
    msb: u8,
    lsb: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    assert!(msb < 32);
    assert!(lsb <= msb);
    let (in0, log_in0) = reg_read_with_log(rs, 0, state, &mut row)?;
    let (in1, log_in1) = reg_read_with_log(rt, 1, state, &mut row)?;
    let mask = (1 << (msb - lsb + 1)) - 1;
    let mask_field = mask << lsb;

    let rs_bits_le = (0..32)
        .map(|i| {
            let bit: usize = (in0 >> i) & 0x01;
            F::from_canonical_u32(bit as u32)
        })
        .collect_vec();
    row.general.misc_mut().rs_bits = rs_bits_le.try_into().unwrap();

    row.general.misc_mut().is_msb = [F::ZERO; 32];
    row.general.misc_mut().is_msb[(msb - lsb) as usize] = F::ONE;
    row.general.misc_mut().is_lsb = [F::ZERO; 32];
    row.general.misc_mut().is_lsb[lsb as usize] = F::ONE;
    row.general.misc_mut().auxs = F::from_canonical_u32(1 << lsb);

    row.general.misc_mut().auxm = F::from_canonical_u32((in1 & !mask_field) as u32);
    row.general.misc_mut().auxl = F::from_canonical_u32((in0 & mask) as u32);
    row.general.misc_mut().auxs = F::from_canonical_u32((1 << lsb) as u32);

    let result = (in1 & !mask_field) | ((in0 << lsb) & mask_field);
    let log_out0 = reg_write_with_log(rt, 2, result, state, &mut row)?;

    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_in1);
    state.traces.push_memory(log_out0);
    state.traces.push_cpu(row);

    Ok(())
}

pub(crate) fn generate_maddu<F: Field>(
    rt: u8,
    rs: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (in0, log_in0) = reg_read_with_log(rs, 0, state, &mut row)?;
    let (in1, log_in1) = reg_read_with_log(rt, 1, state, &mut row)?;
    let (in2, log_in2) = reg_read_with_log(33, 2, state, &mut row)?;
    let (in3, log_in3) = reg_read_with_log(32, 3, state, &mut row)?;
    let mul = in0 * in1;
    let addend = (in2 << 32) + in3;
    let (result, overflow) = (mul as u64).overflowing_add(addend as u64);
    let log_out0 = reg_write_with_log(33, 4, (result >> 32) as usize, state, &mut row)?;
    let log_out1 = reg_write_with_log(32, 5, (result as u32) as usize, state, &mut row)?;
    row.general.misc_mut().auxm = F::from_canonical_usize((overflow as usize) << 32);
    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_in1);
    state.traces.push_memory(log_in2);
    state.traces.push_memory(log_in3);
    state.traces.push_memory(log_out0);
    state.traces.push_memory(log_out1);
    state.traces.push_cpu(row);
    Ok(())
}
pub(crate) fn generate_rdhwr<F: Field>(
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    row.general.misc_mut().rd_index = F::from_canonical_u8(rd);
    let result = if rd == 0 {
        row.general.misc_mut().rd_index_eq_0 = F::ONE;
        1
    } else if rd == 29 {
        row.general.misc_mut().rd_index_eq_29 = F::ONE;
        let (in0, log_in0) = reg_read_with_log(38, 1, state, &mut row)?;
        state.traces.push_memory(log_in0);
        in0
    } else {
        0
    };

    let log_out0 = reg_write_with_log(rt, 0, result, state, &mut row)?;

    state.traces.push_memory(log_out0);
    state.traces.push_cpu(row);

    Ok(())
}

pub(crate) fn generate_signext<F: Field>(
    rd: u8,
    rt: u8,
    bits: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (in0, log_in0) = reg_read_with_log(rt, 0, state, &mut row)?;

    let bits_le = (0..32)
        .map(|i| {
            let bit = (in0 as u32 >> i) & 0x01;
            F::from_canonical_u32(bit)
        })
        .collect_vec();
    row.general.io_mut().rt_le = bits_le.try_into().unwrap();

    let bits = bits as usize;
    let is_signed = ((in0 >> (bits - 1)) & 0x1) != 0;
    let signed = ((1 << (32 - bits)) - 1) << bits;
    let mask = (1 << bits) - 1;
    let result = if is_signed {
        in0 & mask | signed
    } else {
        in0 & mask
    };

    let log_out0 = reg_write_with_log(rd, 1, result, state, &mut row)?;

    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_out0);
    state.traces.push_cpu(row);

    Ok(())
}

pub(crate) fn generate_swaphalf<F: Field>(
    rd: u8,
    rt: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (in0, log_in0) = reg_read_with_log(rt, 0, state, &mut row)?;

    let bits_le = (0..32)
        .map(|i| {
            let bit = (in0 as u32 >> i) & 0x01;
            F::from_canonical_u32(bit)
        })
        .collect_vec();
    row.general.io_mut().rt_le = bits_le.try_into().unwrap();

    let result = (((in0 >> 16) & 0xFF) << 24)
        | (((in0 >> 24) & 0xFF) << 16)
        | ((in0 & 0xFF) << 8)
        | ((in0 >> 8) & 0xFF);

    let log_out0 = reg_write_with_log(rd, 1, result, state, &mut row)?;

    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_out0);
    state.traces.push_cpu(row);

    Ok(())
}

pub(crate) fn generate_teq<F: Field>(
    rs: u8,
    rt: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (in0, log_in0) = reg_read_with_log(rs, 0, state, &mut row)?;
    let (in1, log_in1) = reg_read_with_log(rt, 1, state, &mut row)?;
    if in0 == in1 {
        Err(ProgramError::Trap)
    } else {
        generate_pinv_diff(in0 as u32, in1 as u32, &mut row);
        state.traces.push_memory(log_in0);
        state.traces.push_memory(log_in1);
        state.traces.push_cpu(row);

        Ok(())
    }
}
