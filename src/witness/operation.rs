use itertools::Itertools;
// use keccak_hash::keccak;
use plonky2::field::types::Field;

use super::util::*;
// use crate::arithmetic::BinaryOperator;
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::kernel::assembler::BYTES_PER_OFFSET;
// use crate::cpu::kernel::constants::context_metadata::ContextMetadata;
use crate::cpu::kernel::KERNEL;
// use crate::cpu::membus::NUM_GP_CHANNELS;
// use crate::cpu::simple_logic::eq_iszero::generate_pinv_diff;
use crate::generation::state::GenerationState;
use crate::memory::segments::Segment;
// use crate::witness::errors::MemoryError::{ContextTooLarge, SegmentTooLarge, VirtTooLarge};
use crate::witness::errors::ProgramError;
// use crate::witness::errors::ProgramError::MemoryError;
use crate::witness::memory::{MemoryAddress, MemoryOp};
// use crate::witness::operation::MemoryChannel::GeneralPurpose;
use crate::{arithmetic, logic};
use anyhow::{anyhow, bail, Context, Result};

use hex;
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

pub(crate) const SYSGETPID: usize = 4020;
pub(crate) const SYSGETGID: usize = 4047;
pub(crate) const SYSMMAP: usize = 4090;
pub(crate) const SYSBRK: usize = 4045;
pub(crate) const SYSCLONE: usize = 4120;
pub(crate) const SYSEXITGROUP: usize = 4246;
pub(crate) const SYSREAD: usize = 4003;
pub(crate) const SYSWRITE: usize = 4004;
pub(crate) const SYSFCNTL: usize = 4055;

pub(crate) const FD_STDIN: usize = 0;
pub(crate) const FD_STDOUT: usize = 1;
pub(crate) const FD_STDERR: usize = 2;

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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    Iszero,
    Not,
    Syscall,
    Eq,
    BinaryLogic(logic::Op, u8, u8, u8),
    BinaryLogicImm(logic::Op, u8, u8, u32),
    BinaryArithmetic(arithmetic::BinaryOperator, u8, u8, u8),
    BinaryArithmeticImm(arithmetic::BinaryOperator, u8, u8, u32),
    Count(bool, u8, u8),
    CondMov(BranchCond, u8, u8, u8),
    KeccakGeneral,
    ProverInput,
    Jump(u8, u8),
    Jumpi(u8, u32),
    Branch(BranchCond, u8, u8, u32),
    Pc,
    GetContext,
    SetContext,
    ExitKernel,
    MloadGeneral(MemOp, u8, u8, u32),
    MstoreGeneral(MemOp, u8, u8, u32),
}

pub(crate) fn generate_cond_mov_op<F: Field>(
    cond: BranchCond,
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
        BranchCond::EQ => in1 == 0,
        BranchCond::NE => in1 != 0,
        _ => true,
    };

    let out = if mov { in0 } else { in2 };

    let log_out0 = reg_write_with_log(rd, 3, out, state, &mut row)?;

    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_in1);
    state.traces.push_memory(log_in2);
    state.traces.push_memory(log_out0);
    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_count_op<F: Field>(
    ones: bool,
    rs: u8,
    rd: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (mut in0, log_in0) = reg_read_with_log(rs, 0, state, &mut row)?;

    let mut src = in0 as u32;
    if !ones {
        src = !src;
    }

    let mut out: usize = 0;
    while src & 0x80000000 != 0 {
        src <<= 1;
        out += 1;
    }

    let log_out0 = reg_write_with_log(rd, 1, out, state, &mut row)?;

    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_out0);
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

    state.traces.push_logic(operation);
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
    rd: u8,
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
    let operation = arithmetic::Operation::binary(operator, in0 as u32, in1 as u32);
    let (hi, lo) = operation.result();

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
    let operation = arithmetic::Operation::binary(operator, in0 as u32, in1);
    let out = operation.result().0;

    let log_out0 = reg_write_with_log(rt, 2, out as usize, state, &mut row)?;

    state.traces.push_arithmetic(operation);
    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_out0);
    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_keccak_general<F: Field>(
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    /*
    row.is_keccak_sponge = F::ONE;
    let [(context, _), (segment, log_in1), (base_virt, log_in2), (len, log_in3)] =
        stack_pop_with_log_and_fill::<4, _>(state, &mut row)?;

    let base_address = MemoryAddress::new(context, segment, base_virt);
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
    log::debug!("Hashing {:?}", input);

    let hash = keccak(&input);
    push_no_write(state, &mut row, hash.into_uint(), Some(NUM_GP_CHANNELS - 1));

    keccak_sponge_log(state, base_address, input);

    state.traces.push_memory(log_in1);
    state.traces.push_memory(log_in2);
    state.traces.push_memory(log_in3);
    state.traces.push_cpu(row);
    */
    Ok(())
}

pub(crate) fn generate_prover_input<F: Field>(
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    /*
    let pc = state.registers.program_counter;
    let input_fn = &KERNEL.prover_inputs[&pc];
    let input = state.prover_input(input_fn)?;
    push_with_write(state, &mut row, input)?;
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
    row.general.jumps_mut().should_jump = F::ONE;
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
    reg_write_with_log(0, 2, src1.wrapping_sub(src2), state, &mut row)?;
    reg_write_with_log(0, 3, src2.wrapping_sub(src1), state, &mut row)?;
    let pc = state.registers.program_counter as u32;
    if should_jump {
        let target = sign_extend::<16>(target);
        let (mut target_pc, _) = target.overflowing_shl(2);
        target_pc = target_pc.wrapping_add(pc + 4);
        row.general.jumps_mut().should_jump = F::ONE;
        state.traces.push_cpu(row);
        state.jump_to(target_pc as usize);
    } else {
        let next_pc = pc.wrapping_add(8);
        row.general.jumps_mut().should_jump = F::ZERO;
        state.traces.push_cpu(row);
        state.jump_to(next_pc as usize);
    }
    state.traces.push_cpu(row);
    state.traces.push_memory(src1_op);
    state.traces.push_memory(src2_op);
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
    target_pc = target_pc.wrapping_add(pc & 0xf0000000);
    row.general.jumps_mut().should_jump = F::ONE;
    let next_pc = pc.wrapping_add(8);
    let link_op = reg_write_with_log(link, 1, next_pc, state, &mut row)?;
    state.traces.push_cpu(row);
    state.jump_to(target_pc);
    state.traces.push_memory(link_op);
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
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    /*
    push_with_write(state, &mut row, state.registers.context.into())?;
    state.traces.push_cpu(row);
    */
    Ok(())
}

pub(crate) fn generate_set_context<F: Field>(
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
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

pub(crate) fn generate_not<F: Field>(
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    /*
    let [(x, _)] = stack_pop_with_log_and_fill::<1, _>(state, &mut row)?;
    let result = !x;
    push_no_write(state, &mut row, result, Some(NUM_GP_CHANNELS - 1));

    state.traces.push_cpu(row);
    */
    Ok(())
}

pub(crate) fn generate_iszero<F: Field>(
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    /*
    let [(x, _)] = stack_pop_with_log_and_fill::<1, _>(state, &mut row)?;
    let is_zero = x.is_zero();
    let result = {
        let t: u64 = is_zero.into();
        t.into()
    };

    generate_pinv_diff(x, 0, &mut row);

    push_no_write(state, &mut row, result, None);
    state.traces.push_cpu(row);
    */
    Ok(())
}

pub(crate) fn generate_shl<F: Field>(
    sa: u8,
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (input0, log_in0) = reg_read_with_log(rt, 0, state, &mut row)?;
    let input1 = sa as u32;
    let operation = arithmetic::Operation::binary(
        arithmetic::BinaryOperator::SLL,
        input0 as u32,
        input1 as u32,
    );
    let result = operation.result().0;

    state.traces.push_arithmetic(operation);
    let outlog = reg_write_with_log(rd, 1, result as usize, state, &mut row)?;

    state.traces.push_memory(log_in0);
    state.traces.push_memory(outlog);
    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_shr<F: Field>(
    sa: u8,
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (input0, log_in0) = reg_read_with_log(rt, 0, state, &mut row)?;
    let input1 = sa as u32;

    let operation = arithmetic::Operation::binary(
        arithmetic::BinaryOperator::SRL,
        input0 as u32,
        input1 as u32,
    );
    let result = operation.result().0;

    state.traces.push_arithmetic(operation);
    let outlog = reg_write_with_log(rd, 1, result as usize, state, &mut row)?;

    state.traces.push_memory(log_in0);
    state.traces.push_memory(outlog);
    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_sra<F: Field>(
    sa: u8,
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (in0, log_in0) = reg_read_with_log(rt, 0, state, &mut row)?;
    let in1 = sa as u32;

    let operation = arithmetic::Operation::binary(arithmetic::BinaryOperator::SRA, in0 as u32, in1);
    let result = operation.result().0;

    state.traces.push_arithmetic(operation);
    let outlog = reg_write_with_log(rd, 2, result as usize, state, &mut row)?;
    state.traces.push_memory(log_in0);
    state.traces.push_memory(outlog);
    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_shlv<F: Field>(
    rs: u8,
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (in0, log_in0) = reg_read_with_log(rs, 0, state, &mut row)?;
    let (input1, log_in1) = reg_read_with_log(rt, 1, state, &mut row)?;
    let input0 = in0 & 0x1F;
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

pub(crate) fn generate_shrv<F: Field>(
    rs: u8,
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (in0, log_in0) = reg_read_with_log(rs, 0, state, &mut row)?;
    let (input1, log_in1) = reg_read_with_log(rt, 1, state, &mut row)?;
    let input0 = in0 & 0x1F;
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

pub(crate) fn generate_shrav<F: Field>(
    rs: u8,
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (in0, log_in0) = reg_read_with_log(rs, 0, state, &mut row)?;
    let (input1, log_in1) = reg_read_with_log(rt, 1, state, &mut row)?;
    let input0 = in0 & 0x1F;

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

pub(crate) fn load_preimage<F: Field>(
    state: &mut GenerationState<F>,
    row: &mut CpuColumnsView<F>,
    preiamge: &str,
) -> Result<()> {
    let content = fs::read(preiamge).expect("Read file failed");

    state.memory.set(
        MemoryAddress::new(0, Segment::Code, 0x31000000),
        (content.len() as u32).to_be(),
    );
    let mut map_addr = 0x31000004;
    for i in (0..content.len()).step_by(WORD_SIZE) {
        let mut word = 0;
        // Don't read past the end of the file.
        let len = core::cmp::min(content.len() - i, WORD_SIZE);
        for j in 0..len {
            let offset = i + j;
            let byte = content.get(offset).context("Invalid block offset")?;
            word |= (*byte as u32) << (j * 8);
        }
        state
            .memory
            .set(MemoryAddress::new(0, Segment::Code, map_addr), word);
        map_addr += 4;
    }

    Ok(())
}

pub(crate) fn generate_syscall<F: Field>(
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (sys_num, log_in1) = reg_read_with_log(2, 0, state, &mut row)?;
    let (a0, log_in2) = reg_read_with_log(4, 1, state, &mut row)?;
    let (a1, log_in3) = reg_read_with_log(5, 2, state, &mut row)?;
    let (a2, log_in4) = reg_read_with_log(6, 3, state, &mut row)?;
    let mut v0 = 0usize;
    let mut v1 = 0usize;

    let result = match sys_num {
        SYSGETPID => {
            let mut hash_bytes = [0u8; 32];
            hash_bytes[0..4].copy_from_slice(
                state
                    .memory
                    .get(MemoryAddress::new(0, Segment::Code, 0x30001000))
                    .to_le_bytes()
                    .as_ref(),
            );
            hash_bytes[4..8].copy_from_slice(
                state
                    .memory
                    .get(MemoryAddress::new(0, Segment::Code, 0x30001004))
                    .to_le_bytes()
                    .as_ref(),
            );
            hash_bytes[8..12].copy_from_slice(
                state
                    .memory
                    .get(MemoryAddress::new(0, Segment::Code, 0x30001008))
                    .to_le_bytes()
                    .as_ref(),
            );
            hash_bytes[12..16].copy_from_slice(
                state
                    .memory
                    .get(MemoryAddress::new(0, Segment::Code, 0x3000100C))
                    .to_le_bytes()
                    .as_ref(),
            );
            hash_bytes[16..20].copy_from_slice(
                state
                    .memory
                    .get(MemoryAddress::new(0, Segment::Code, 0x30001010))
                    .to_le_bytes()
                    .as_ref(),
            );
            hash_bytes[20..24].copy_from_slice(
                state
                    .memory
                    .get(MemoryAddress::new(0, Segment::Code, 0x30001014))
                    .to_le_bytes()
                    .as_ref(),
            );
            hash_bytes[24..28].copy_from_slice(
                state
                    .memory
                    .get(MemoryAddress::new(0, Segment::Code, 0x30001018))
                    .to_le_bytes()
                    .as_ref(),
            );
            hash_bytes[28..32].copy_from_slice(
                state
                    .memory
                    .get(MemoryAddress::new(0, Segment::Code, 0x3000101C))
                    .to_le_bytes()
                    .as_ref(),
            );
            let hex_string = hex::encode(&hash_bytes);
            let mut preiamge_path = KERNEL.blockpath.clone();
            preiamge_path.push_str(hex_string.as_str());
            let _ = load_preimage(state, &mut row, preiamge_path.as_str());
            Ok(())
        }
        SYSMMAP => {
            let mut sz = a1;
            if sz & 0xFFF != 0 {
                sz += 0x1000 - sz & 0xFFF;
            };
            if a0 == 0 {
                let (heap, log_in5) = reg_read_with_log(34, 6, state, &mut row)?;
                v0 = heap;
                let heap = heap + sz;
                let outlog = reg_write_with_log(34, 7, heap, state, &mut row)?;
                state.traces.push_memory(log_in5);
                state.traces.push_memory(outlog);
            } else {
                v0 = a0;
            };
            Ok(())
        }
        SYSBRK => {
            v0 = 0x40000000;
            Ok(())
        }
        SYSCLONE => {
            // clone (not supported)
            v0 = 1;
            Ok(())
        }
        SYSEXITGROUP => {
            state.registers.exited = true;
            state.registers.exit_code = a0 as u8;
            Ok(())
        }
        SYSREAD => {
            match a0 {
                FD_STDIN => (), // fdStdin
                _ => {
                    v0 = 0xFFFFFFFF;
                    v1 = MIPSEBADF;
                }
            };
            Ok(())
        }
        SYSWRITE => {
            match a0 {
                FD_STDOUT | FD_STDERR => v0 = a2, // fdStdout
                _ => {
                    v0 = 0xFFFFFFFF;
                    v1 = MIPSEBADF;
                }
            };
            Ok(())
        }
        SYSFCNTL => {
            match a0 {
                FD_STDIN => {
                    v0 = 0;
                    ()
                } // fdStdin
                FD_STDOUT | FD_STDERR => {
                    v0 = 1;
                    ()
                } // fdStdout / fdStderr
                _ => {
                    v0 = 0xFFFFFFFF;
                    v1 = MIPSEBADF;
                }
            };
            Ok(())
        }
        _ => Ok(()),
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
    result
}

pub(crate) fn generate_eq<F: Field>(
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    /*
    let [(in0, _), (in1, log_in1)] = stack_pop_with_log_and_fill::<2, _>(state, &mut row)?;
    let eq = in0 == in1;
    // let result = U256::from(u64::from(eq));
    let result = u32::from(eq);

    generate_pinv_diff(in0, in1, &mut row);

    push_no_write(state, &mut row, result, None);
    state.traces.push_memory(log_in1);
    state.traces.push_cpu(row);
    */
    Ok(())
}

// FIXME: unused?
pub(crate) fn generate_exit_kernel<F: Field>(
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    /*
    let [(kexit_info, _)] = stack_pop_with_log_and_fill::<1, _>(state, &mut row)?;
    let kexit_info_u64 = kexit_info.0[0];
    let program_counter = kexit_info_u64 as u32 as usize;
    let is_kernel_mode_val = (kexit_info_u64 >> 32) as u32;
    assert!(is_kernel_mode_val == 0 || is_kernel_mode_val == 1);
    let is_kernel_mode = is_kernel_mode_val != 0;
    let gas_used_val = kexit_info.0[3];
    if TryInto::<u64>::try_into(gas_used_val).is_err() {
        return Err(ProgramError::GasLimitError);
    }

    state.registers.program_counter = program_counter;
    state.registers.is_kernel = is_kernel_mode;
    // state.registers.gas_used = gas_used_val;
    log::debug!(
        "Exiting to {}, is_kernel={}",
        program_counter,
        is_kernel_mode
    );

    state.traces.push_cpu(row);
    */

    Ok(())
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

    let rs = virt_raw as u32;
    let rt = rt as u32;

    let val = match op {
        MemOp::LH => sign_extend::<16>((mem >> (16 - (rs & 2) * 8)) & 0xffff),
        MemOp::LWL => {
            let val = mem << ((rs & 3) * 8);
            let mask = 0xffFFffFFu32 << ((rs & 3) * 8);
            (rt & (!mask)) | val
        }
        MemOp::LW => mem,
        MemOp::LBU => (mem >> (24 - (rs & 3) * 8)) & 0xff,
        MemOp::LHU => (mem >> (16 - (rs & 2) * 8)) & 0xffff,
        MemOp::LWR => {
            let val = mem >> (24 - (rs & 3) * 8);
            let mask = 0xffFFffFFu32 >> (24 - (rs & 3) * 8);
            (rt & (!mask)) | val
        }
        MemOp::LL => mem,
        MemOp::LB => sign_extend::<8>((mem >> (24 - (rs & 3) * 8)) & 0xff),
        _ => todo!(),
    };

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

    let rs = virt_raw as u32;
    let rt = rt as u32;

    let val = match op {
        MemOp::SB => {
            let val = (rt & 0xff) << (24 - (rs & 3) * 8);
            let mask = 0xffFFffFFu32 ^ (0xff << (24 - (rs & 3) * 8));
            (mem & mask) | val
        }
        MemOp::SH => {
            let val = (rt & 0xffff) << (16 - (rs & 2) * 8);
            let mask = 0xffFFffFFu32 ^ (0xffff << (16 - (rs & 2) * 8));
            (mem & mask) | val
        }
        MemOp::SWL => {
            let val = rt >> ((rs & 3) * 8);
            let mask = 0xffFFffFFu32 >> ((rs & 3) * 8);
            (mem & (!mask)) | val
        }
        MemOp::SW => rt,
        MemOp::SWR => {
            let val = rt << (24 - (rs & 3) * 8);
            let mask = 0xffFFffFFu32 << (24 - (rs & 3) * 8);
            (mem & (!mask)) | val
        }
        MemOp::SC => rt,
        _ => todo!(),
    };

    let log_out0 = mem_write_gp_log_and_fill(3, address, state, &mut row, val);

    log::debug!("write {:X} : {:X} ({})", address.virt, val, val);
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

pub(crate) fn generate_exception<F: Field>(
    exc_code: u8,
    state: &mut GenerationState<F>,
    mut row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    /*
    if TryInto::<u64>::try_into(state.registers.gas_used).is_err() {
        return Err(ProgramError::GasLimitError);
    }

    row.op.exception = F::ONE;

    let disallowed_len = F::from_canonical_usize(MAX_USER_STACK_SIZE + 1);
    let diff = row.stack_len - disallowed_len;
    if let Some(inv) = diff.try_inverse() {
        row.stack_len_bounds_aux = inv;
    } else {
        // This is a stack overflow that should have been caught earlier.
        return Err(ProgramError::InterpreterError);
    }

    if let Some(inv) = row.stack_len.try_inverse() {
        row.general.stack_mut().stack_inv = inv;
        row.general.stack_mut().stack_inv_aux = F::ONE;
    }

    if state.registers.is_stack_top_read {
        let channel = &mut row.mem_channels[0];
        channel.used = F::ONE;
        channel.is_read = F::ONE;
        channel.addr_context = F::from_canonical_usize(state.registers.context);
        channel.addr_segment = F::from_canonical_usize(Segment::Stack as usize);
        channel.addr_virtual = F::from_canonical_usize(state.registers.stack_len - 1);

        let address = MemoryAddress {
            context: state.registers.context,
            segment: Segment::Stack as usize,
            virt: state.registers.stack_len - 1,
        };

        let mem_op = MemoryOp::new(
            GeneralPurpose(0),
            state.traces.clock(),
            address,
            MemoryOpKind::Read,
            state.registers.stack_top,
        );
        state.traces.push_memory(mem_op);
        state.registers.is_stack_top_read = false;
    }
    */

    row.general.exception_mut().exc_code_bits = [
        F::from_bool(exc_code & 1 != 0),
        F::from_bool(exc_code & 2 != 0),
        F::from_bool(exc_code & 4 != 0),
    ];

    let handler_jumptable_addr = KERNEL.global_labels["exception_jumptable"];
    let handler_addr_addr =
        handler_jumptable_addr + (exc_code as usize) * (BYTES_PER_OFFSET as usize);
    assert_eq!(BYTES_PER_OFFSET, 3, "Code below assumes 3 bytes per offset");
    let (handler_addr0, log_in0) = mem_read_gp_with_log_and_fill(
        1,
        MemoryAddress::new(0, Segment::Code, handler_addr_addr),
        state,
        &mut row,
    );
    let (handler_addr1, log_in1) = mem_read_gp_with_log_and_fill(
        2,
        MemoryAddress::new(0, Segment::Code, handler_addr_addr + 1),
        state,
        &mut row,
    );
    let (handler_addr2, log_in2) = mem_read_gp_with_log_and_fill(
        3,
        MemoryAddress::new(0, Segment::Code, handler_addr_addr + 2),
        state,
        &mut row,
    );

    let handler_addr = (handler_addr0 << 16) + (handler_addr1 << 8) + handler_addr2;
    let new_program_counter = handler_addr;

    let exc_info = state.registers.program_counter as u32;
    // U256::from(state.registers.program_counter) + (U256::from(state.registers.gas_used) << 192);

    // Set registers before pushing to the stack; in particular, we need to set kernel mode so we
    // can't incorrectly trigger a stack overflow. However, note that we have to do it _after_ we
    // make `exc_info`, which should contain the old values.
    state.registers.program_counter = new_program_counter as usize;
    state.registers.is_kernel = true;

    push_with_write(state, &mut row, exc_info)?;

    log::debug!(
        "Exception to {}",
        KERNEL.offset_name(new_program_counter as usize)
    );

    state.traces.push_memory(log_in0);
    state.traces.push_memory(log_in1);
    state.traces.push_memory(log_in2);
    state.traces.push_cpu(row);

    Ok(())
}
