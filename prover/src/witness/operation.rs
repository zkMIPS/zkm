use super::util::*;
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::kernel::assembler::Kernel;
use crate::generation::state::GenerationState;
use crate::memory::segments::Segment;
use crate::witness::errors::ProgramError;
use crate::witness::memory::MemoryAddress;
use crate::{arithmetic, logic};

use anyhow::Result;

use plonky2::field::types::Field;

use super::util::keccak_sponge_log;
use crate::keccak_sponge::columns::{KECCAK_RATE_BYTES, KECCAK_RATE_U32S};
// use itertools::Itertools;
use keccak_hash::keccak;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::GenericConfig;

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

pub(crate) const SYSSHAEXTEND: usize = 0x00300105;
pub(crate) const SYSSHACOMPRESS: usize = 0x00010106;
pub(crate) const SYSKECCAK: usize = 0x010109;
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
pub(crate) const SYSVERIFY: usize = 242;

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
    Teq(u8, u8),
}

pub(crate) fn generate_binary_logic_op<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    op: logic::Op,
    rs: u8,
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F, C, D>,
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

pub(crate) fn generate_binary_logic_imm_op<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    op: logic::Op,
    rs: u8,
    rd: u8,
    imm: u32,
    state: &mut GenerationState<F, C, D>,
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

pub(crate) fn generate_binary_arithmetic_op<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    operator: arithmetic::BinaryOperator,
    rs: u8,
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F, C, D>,
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

pub(crate) fn generate_binary_arithmetic_hilo_op<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    operator: arithmetic::BinaryOperator,
    rs: u8,
    rt: u8,
    _rd: u8,
    state: &mut GenerationState<F, C, D>,
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

pub(crate) fn generate_binary_arithmetic_imm_op<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    rs: u8,
    rt: u8,
    imm: u32,
    operator: arithmetic::BinaryOperator,
    state: &mut GenerationState<F, C, D>,
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

pub(crate) fn generate_lui<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    _rs: u8,
    rt: u8,
    imm: u32,
    state: &mut GenerationState<F, C, D>,
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

pub(crate) fn generate_keccak_general<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    _state: &mut GenerationState<F, C, D>,
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
        .collect();
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

pub(crate) fn generate_jump<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    link: u8,
    target: u8,
    state: &mut GenerationState<F, C, D>,
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

pub(crate) fn generate_branch<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    cond: BranchCond,
    src1: u8,
    src2: u8,
    target: u32,
    state: &mut GenerationState<F, C, D>,
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

pub(crate) fn generate_jumpi<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    link: u8,
    target: u32,
    state: &mut GenerationState<F, C, D>,
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

pub(crate) fn generate_jumpdirect<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    link: u8,
    target: u32,
    state: &mut GenerationState<F, C, D>,
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

pub(crate) fn generate_pc<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    state: &mut GenerationState<F, C, D>,
    row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    state.traces.push_cpu(row);
    Ok(())
}

pub(crate) fn generate_get_context<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    _state: &mut GenerationState<F, C, D>,
    _row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    /*
    push_with_write(state, &mut row, state.registers.context.into())?;
    state.traces.push_cpu(row);
    */
    Ok(())
}

pub(crate) fn generate_set_context<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    _state: &mut GenerationState<F, C, D>,
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

pub(crate) fn generate_shift_imm<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    op: arithmetic::BinaryOperator,
    sa: u8,
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F, C, D>,
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

pub(crate) fn generate_sllv<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    rs: u8,
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F, C, D>,
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

pub(crate) fn generate_srlv<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    rs: u8,
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F, C, D>,
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

pub(crate) fn generate_srav<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    rs: u8,
    rt: u8,
    rd: u8,
    state: &mut GenerationState<F, C, D>,
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

pub(crate) fn verify<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    state: &mut GenerationState<F, C, D>,
    addr: usize,
    size: usize,
) -> Result<()> {
    assert!(size == 32);
    let mut claim_digest = [0u8; 32];
    {
        let mut cpu_row = CpuColumnsView::default();
        cpu_row.clock = F::from_canonical_usize(state.traces.clock());
        for i in 0..8 {
            let address = MemoryAddress::new(0, Segment::Code, addr + i * 4);
            let (mem, op) = mem_read_gp_with_log_and_fill(i, address, state, &mut cpu_row);
            claim_digest[i * 4..i * 4 + 4].copy_from_slice(mem.to_be_bytes().as_ref());
            state.traces.push_memory(op);
        }
        state.traces.push_cpu(cpu_row);
    }

    log::debug!("SYS_VERIFY: ({:?})", claim_digest);

    let assumption = state.find_assumption(&claim_digest);

    // Mark the assumption as accessed, pushing it to the head of the list, and return the success code.
    match assumption {
        Some(assumpt) => {
            state.assumptions_used.borrow_mut().insert(0, assumpt);
        }
        None => panic!("Assumption Not Found"),
    }
    Ok(())
}

pub(crate) fn load_input<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    state: &mut GenerationState<F, C, D>,
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

pub(crate) fn commit<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    state: &mut GenerationState<F, C, D>,
    addr: usize,
    size: usize,
) -> Result<()> {
    let map_addr = addr;

    let mut cpu_row = CpuColumnsView::default();
    cpu_row.clock = F::from_canonical_usize(state.traces.clock());
    let mut j = 0;
    for i in (0..size).step_by(4) {
        if j == 8 {
            state.traces.push_cpu(cpu_row);
            cpu_row = CpuColumnsView::default();
            cpu_row.clock = F::from_canonical_usize(state.traces.clock());
            j = 0;
        }

        // Get each byte in the chunk
        let addr = MemoryAddress::new(0, Segment::Code, map_addr + i);
        let (data, mem_op) = mem_read_gp_with_log_and_fill(j, addr, state, &mut cpu_row);
        state.traces.push_memory(mem_op);
        let len = if i + 3 >= size { size - i } else { 4 };
        state
            .public_values_stream
            .extend_from_slice(&data.to_be_bytes()[..len]);
        j += 1;
    }
    state.traces.push_cpu(cpu_row);
    Ok(())
}

pub(crate) fn generate_keccak<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    state: &mut GenerationState<F, C, D>,
    addr: usize,
    len: usize,
    ptr: usize,
) -> Result<()> {
    let mut map_addr = addr;
    let mut cpu_row = CpuColumnsView::default();
    cpu_row.clock = F::from_canonical_usize(state.traces.clock());
    let mut j = 0;
    let mut keccak_data_addr = Vec::new();
    let mut keccak_value_byte_be = vec![0u8; len];

    for i in (0..len).step_by(WORD_SIZE) {
        if j == 8 {
            state.traces.push_cpu(cpu_row);
            cpu_row = CpuColumnsView::default();
            cpu_row.clock = F::from_canonical_usize(state.traces.clock());
            j = 0;
        }
        let addr = MemoryAddress::new(0, Segment::Code, map_addr);
        let (word, mem_op) = mem_read_gp_with_log_and_fill(j, addr, state, &mut cpu_row);
        let bytes = word.to_be_bytes();
        let final_len = if i + 4 > len { len - i } else { 4 };
        keccak_value_byte_be[i..i + final_len].copy_from_slice(&bytes[0..final_len]);
        keccak_data_addr.push(addr);
        state.traces.push_memory(mem_op);
        map_addr += 4;
        j += 1;
    }

    state.traces.push_cpu(cpu_row);
    state.memory.apply_ops(&state.traces.memory_ops);

    let mut cpu_row = CpuColumnsView::default();
    cpu_row.clock = F::from_canonical_usize(state.traces.clock());
    cpu_row.is_keccak_sponge = F::ONE;

    // The Keccak sponge CTL uses memory value columns for its inputs and outputs.
    cpu_row.mem_channels[0].value = F::ZERO; // context
    cpu_row.mem_channels[1].value = F::from_canonical_usize(Segment::Code as usize);
    let final_idx = len / KECCAK_RATE_BYTES * KECCAK_RATE_U32S;
    let virt = if final_idx >= keccak_data_addr.len() {
        0
    } else {
        keccak_data_addr[final_idx].virt
    };
    cpu_row.mem_channels[2].value = F::from_canonical_usize(virt);
    cpu_row.mem_channels[3].value = F::from_canonical_usize(len);

    let hash_data_bytes = keccak(&keccak_value_byte_be).0;
    let hash_data_be = core::array::from_fn(|i| {
        u32::from_le_bytes(core::array::from_fn(|j| hash_data_bytes[i * 4 + j]))
    });

    let hash_data = hash_data_be.map(u32::from_be);

    cpu_row.general.khash_mut().value = hash_data.map(F::from_canonical_u32);
    cpu_row.general.khash_mut().value.reverse();

    keccak_sponge_log(state, keccak_data_addr, keccak_value_byte_be);
    state.traces.push_cpu(cpu_row);

    cpu_row = CpuColumnsView::default();
    cpu_row.clock = F::from_canonical_usize(state.traces.clock());
    map_addr = ptr;
    assert!(hash_data_be.len() == 8);
    for i in 0..hash_data_be.len() {
        let addr = MemoryAddress::new(0, Segment::Code, map_addr);
        let mem_op =
            mem_write_gp_log_and_fill(i, addr, state, &mut cpu_row, hash_data_be[i].to_be());
        state.traces.push_memory(mem_op);
        map_addr += 4;
    }
    state.traces.push_cpu(cpu_row);
    Ok(())
}

pub(crate) fn generate_sha_extend<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    state: &mut GenerationState<F, C, D>,
    w_ptr: usize,
    a1: usize,
) -> Result<()> {
    assert!(a1 == 0, "arg2 must be 0");

    for i in 16..64 {
        let mut cpu_row = CpuColumnsView::default();
        cpu_row.clock = F::from_canonical_usize(state.traces.clock());
        let mut input_addresses = vec![];
        // let mut input_value_bit_be = vec![];
        let mut input_le_bytes = vec![];
        let addr = MemoryAddress::new(0, Segment::Code, w_ptr + (i - 15) * 4);
        let (w_i_minus_15, mem_op) = mem_read_gp_with_log_and_fill(0, addr, state, &mut cpu_row);
        state.traces.push_memory(mem_op);
        input_addresses.push(addr);
        input_le_bytes.push(w_i_minus_15.to_le_bytes());

        let s0_inter = w_i_minus_15.rotate_right(7) ^ w_i_minus_15.rotate_right(18);
        xor_logic_log(
            state,
            w_i_minus_15.rotate_right(7),
            w_i_minus_15.rotate_right(18),
        );
        let s0 = s0_inter ^ (w_i_minus_15 >> 3);
        xor_logic_log(state, s0_inter, w_i_minus_15 >> 3);

        // Read w[i-2].
        let addr = MemoryAddress::new(0, Segment::Code, w_ptr + (i - 2) * 4);
        let (w_i_minus_2, mem_op) = mem_read_gp_with_log_and_fill(1, addr, state, &mut cpu_row);
        state.traces.push_memory(mem_op);
        input_addresses.push(addr);
        input_le_bytes.push(w_i_minus_2.to_le_bytes());

        // Compute `s1`.
        let s1_inter = w_i_minus_2.rotate_right(17) ^ w_i_minus_2.rotate_right(19);
        xor_logic_log(
            state,
            w_i_minus_2.rotate_right(17),
            w_i_minus_2.rotate_right(19),
        );
        let s1 = s1_inter ^ (w_i_minus_2 >> 10);
        xor_logic_log(state, s1_inter, w_i_minus_2 >> 10);

        // Read w[i-16].
        let addr = MemoryAddress::new(0, Segment::Code, w_ptr + (i - 16) * 4);
        let (w_i_minus_16, mem_op) = mem_read_gp_with_log_and_fill(2, addr, state, &mut cpu_row);
        state.traces.push_memory(mem_op);
        input_addresses.push(addr);
        // input_value_bit_be.push(from_u32_to_be_bits(w_i_minus_16));
        input_le_bytes.push(w_i_minus_16.to_le_bytes());

        // Read w[i-7].
        let addr = MemoryAddress::new(0, Segment::Code, w_ptr + (i - 7) * 4);
        let (w_i_minus_7, mem_op) = mem_read_gp_with_log_and_fill(3, addr, state, &mut cpu_row);
        state.traces.push_memory(mem_op);
        input_addresses.push(addr);
        input_le_bytes.push(w_i_minus_7.to_le_bytes());

        // Compute `w_i`.
        let w_i = s1
            .wrapping_add(w_i_minus_16)
            .wrapping_add(s0)
            .wrapping_add(w_i_minus_7);

        // Write w[i].
        log::debug!(
            "{:X}, {:X}, {:X} {:X} {:X} {:X}",
            s1,
            s0,
            w_i_minus_16,
            w_i_minus_7,
            w_i_minus_15,
            w_i_minus_2
        );
        let addr = MemoryAddress::new(0, Segment::Code, w_ptr + i * 4);
        log::debug!("extend write {:X} {:X}", w_ptr + i * 4, w_i);
        let mem_op = mem_write_gp_log_and_fill(4, addr, state, &mut cpu_row, w_i);

        state.traces.push_memory(mem_op);
        state.traces.push_cpu(cpu_row);
        state.memory.apply_ops(&state.traces.memory_ops);

        cpu_row = CpuColumnsView::default();
        cpu_row.clock = F::from_canonical_usize(state.traces.clock());
        cpu_row.is_sha_extend_sponge = F::ONE;

        // The SHA extend sponge CTL uses memory value columns for its inputs and outputs.
        cpu_row.mem_channels[0].value = F::ZERO; // context
        cpu_row.mem_channels[1].value = F::from_canonical_usize(Segment::Code as usize);
        cpu_row.mem_channels[2].value = F::from_canonical_usize(addr.virt);
        cpu_row.general.element_mut().value = F::from_canonical_u32(w_i);
        sha_extend_sponge_log(state, input_addresses, input_le_bytes, addr, i - 16);
        state.traces.push_cpu(cpu_row);
    }

    Ok(())
}

pub const SHA_COMPRESS_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub(crate) fn generate_sha_compress<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    state: &mut GenerationState<F, C, D>,
    w_ptr: usize,
    h_ptr: usize,
) -> Result<()> {
    let mut hx = [0u32; 8];
    let mut cpu_row = CpuColumnsView::default();
    cpu_row.clock = F::from_canonical_usize(state.traces.clock());

    let mut hx_addresses = vec![];
    let mut hx_values = vec![];
    let mut w_i_values = vec![];
    let mut w_i_addresses = vec![];
    let mut state_values = vec![];

    for i in 0..8 {
        let addr = MemoryAddress::new(0, Segment::Code, h_ptr + i * 4);
        let (value, mem_op) = mem_read_gp_with_log_and_fill(i, addr, state, &mut cpu_row);
        state.traces.push_memory(mem_op);
        hx[i] = value;
        hx_addresses.push(addr);
        hx_values.push(value.to_le_bytes());
    }
    state.traces.push_cpu(cpu_row);
    // Execute the "compress" phase.
    let mut a = hx[0];
    let mut b = hx[1];
    let mut c = hx[2];
    let mut d = hx[3];
    let mut e = hx[4];
    let mut f = hx[5];
    let mut g = hx[6];
    let mut h = hx[7];
    let mut j = 0;
    cpu_row = CpuColumnsView::default();
    cpu_row.clock = F::from_canonical_usize(state.traces.clock());
    for i in 0..64 {
        let input_state = [a, b, c, d, e, f, g, h]
            .iter()
            .map(|x| x.to_le_bytes())
            .collect();
        state_values.push(input_state);

        let s_1_inter = e.rotate_right(6) ^ e.rotate_right(11);
        let s1 = s_1_inter ^ e.rotate_right(25);

        let e_not = !e;
        let e_and_f = e & f;
        let not_e_and_g = e_not & g;
        let ch = e_and_f ^ not_e_and_g;

        if j == 8 {
            state.traces.push_cpu(cpu_row);
            cpu_row = CpuColumnsView::default();
            cpu_row.clock = F::from_canonical_usize(state.traces.clock());
            j = 0;
        }

        let addr = MemoryAddress::new(0, Segment::Code, w_ptr + i * 4);
        let (w_i, mem_op) = mem_read_gp_with_log_and_fill(j, addr, state, &mut cpu_row);
        state.traces.push_memory(mem_op);
        j += 1;
        w_i_values.push(w_i.to_le_bytes());
        w_i_addresses.push(addr);

        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA_COMPRESS_K[i])
            .wrapping_add(w_i);

        let s0_inter = a.rotate_right(2) ^ a.rotate_right(13);
        let s0 = s0_inter ^ a.rotate_right(22);

        let a_and_b = a & b;
        let a_and_c = a & c;
        let b_and_c = b & c;
        let maj_inter = a_and_b ^ a_and_c;
        let maj = maj_inter ^ b_and_c;

        let temp2 = s0.wrapping_add(maj);

        xor_logic_log(state, e.rotate_right(6), e.rotate_right(11));
        xor_logic_log(state, s_1_inter, e.rotate_right(25));
        and_logic_log(state, e, f);
        and_logic_log(state, e_not, g);
        xor_logic_log(state, e_and_f, not_e_and_g);
        xor_logic_log(state, a.rotate_right(2), a.rotate_right(13));
        xor_logic_log(state, s0_inter, a.rotate_right(22));
        and_logic_log(state, a, b);
        and_logic_log(state, a, c);
        and_logic_log(state, b, c);
        xor_logic_log(state, a_and_b, a_and_c);
        xor_logic_log(state, maj_inter, b_and_c);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }
    let input_state = [a, b, c, d, e, f, g, h]
        .iter()
        .map(|x| x.to_le_bytes())
        .collect();
    state_values.push(input_state);

    state.traces.push_cpu(cpu_row);
    // Execute the "finalize" phase.

    let mut cpu_row = CpuColumnsView::default();
    cpu_row.clock = F::from_canonical_usize(state.traces.clock());
    cpu_row.is_sha_compress_sponge = F::ONE;

    cpu_row.mem_channels[0].value = F::ZERO; // context
    cpu_row.mem_channels[1].value = F::from_canonical_usize(Segment::Code as usize);
    cpu_row.mem_channels[2].value = F::from_canonical_usize(hx_addresses[0].virt); // start address of hx

    let u32_result: Vec<u32> = [a, b, c, d, e, f, g, h]
        .iter()
        .enumerate()
        .map(|(i, x)| hx[i].wrapping_add(*x))
        .collect();

    cpu_row.general.shash_mut().value = u32_result
        .into_iter()
        .map(F::from_canonical_u32)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    // cpu_row.general.shash_mut().value.reverse();
    sha_compress_sponge_log(
        state,
        hx_values,
        hx_addresses,
        w_i_values,
        w_i_addresses,
        state_values,
    );
    state.traces.push_cpu(cpu_row);

    let v = [a, b, c, d, e, f, g, h];
    let mut cpu_row = CpuColumnsView::default();
    cpu_row.clock = F::from_canonical_usize(state.traces.clock());
    for i in 0..8 {
        let addr = MemoryAddress::new(0, Segment::Code, h_ptr + i * 4);
        let mem_op =
            mem_write_gp_log_and_fill(i, addr, state, &mut cpu_row, hx[i].wrapping_add(v[i]));
        state.traces.push_memory(mem_op);
        log::debug!("write {:X} {:X}", h_ptr + i * 4, hx[i].wrapping_add(v[i]));
    }
    state.traces.push_cpu(cpu_row);
    Ok(())
}

pub(crate) fn generate_syscall<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    state: &mut GenerationState<F, C, D>,
    mut row: CpuColumnsView<F>,
    _kernel: &Kernel,
) -> Result<(), ProgramError> {
    let (sys_num, log_in1) = reg_read_with_log(2, 0, state, &mut row)?;
    let (a0, log_in2) = reg_read_with_log(4, 1, state, &mut row)?;
    let (a1, log_in3) = reg_read_with_log(5, 2, state, &mut row)?;
    let (a2, log_in4) = reg_read_with_log(6, 3, state, &mut row)?;
    let mut v0 = 0usize;
    let mut v1 = 0usize;
    let mut is_load_input = false;
    let mut is_verify = false;
    let mut is_keccak = false;
    let mut is_commit = false;
    let mut is_sha_extend = false;
    let mut is_sha_compress = false;
    let result = match sys_num {
        SYSEXITGROUP => {
            state.registers.exited = true;
            state.registers.exit_code = a0 as u8;
            Ok(())
        }
        SYSWRITE => {
            match a0 {
                // fdStdout
                FD_STDOUT | FD_STDERR | FD_HINT => {
                    row.general.syscall_mut().cond[0] = F::ONE;
                    v0 = a2;
                } // fdStdout
                FD_PUBLIC_VALUES => {
                    row.general.syscall_mut().cond[0] = F::ONE;
                    is_commit = true;
                    v0 = a2;
                }
                _ => {
                    row.general.syscall_mut().cond[1] = F::ONE;
                    v0 = 0xFFFFFFFF;
                    v1 = MIPSEBADF;
                }
            };
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
        SYSVERIFY => {
            is_verify = true;
            Ok(())
        }
        SYSKECCAK => {
            is_keccak = true;
            Ok(())
        }
        SYSSHACOMPRESS => {
            is_sha_compress = true;
            Ok(())
        }
        SYSSHAEXTEND => {
            is_sha_extend = true;
            Ok(())
        }
        _ => {
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

    if is_load_input {
        let _ = load_input(state, a0, a1);
    }

    if is_verify {
        let _ = verify(state, a1, a2);
    }
    if is_commit {
        let _ = commit(state, a1, a2);
    }
    if is_keccak {
        let _ = generate_keccak(state, a0, a1, a2);
    }
    if is_sha_compress {
        let _ = generate_sha_compress(state, a0, a1);
    }
    if is_sha_extend {
        let _ = generate_sha_extend(state, a0, a1);
    }
    result
}

pub(crate) fn generate_mload_general<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    op: MemOp,
    base: u8,
    rt_reg: u8,
    offset: u32,
    state: &mut GenerationState<F, C, D>,
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

pub(crate) fn generate_mstore_general<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    op: MemOp,
    base: u8,
    rt_reg: u8,
    offset: u32,
    state: &mut GenerationState<F, C, D>,
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

pub(crate) fn generate_nop<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    state: &mut GenerationState<F, C, D>,
    row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    state.traces.push_cpu(row);

    Ok(())
}

pub(crate) fn generate_teq<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    rs: u8,
    rt: u8,
    state: &mut GenerationState<F, C, D>,
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
