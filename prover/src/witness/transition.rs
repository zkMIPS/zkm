use anyhow::bail;
use log::log_enabled;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;

use crate::cpu::columns::CpuColumnsView;

use crate::cpu::kernel::assembler::Kernel;
use crate::generation::state::GenerationState;
use crate::memory::segments::Segment;
use crate::witness::errors::ProgramError;
use crate::witness::memory::MemoryAddress;

use crate::witness::operation::*;
use crate::witness::state::RegistersState;
use crate::witness::util::mem_read_code_with_log_and_fill;
use crate::{arithmetic, logic};

fn read_code_memory<F: Field>(state: &mut GenerationState<F>, row: &mut CpuColumnsView<F>) -> u32 {
    let code_context = state.registers.code_context();
    row.code_context = F::from_canonical_usize(code_context);

    let address = MemoryAddress::new(code_context, Segment::Code, state.registers.program_counter);
    let (opcode, mem_log) = mem_read_code_with_log_and_fill(address, state, row);
    log::trace!(
        "read_code_memory: PC {:X} ({}) op: {:?}, {:?}",
        state.registers.program_counter,
        state.registers.program_counter,
        opcode,
        mem_log
    );

    state.traces.push_memory(mem_log);
    opcode
}

fn decode(registers: RegistersState, insn: u32) -> Result<Operation, ProgramError> {
    let opcode = ((insn >> 26) & 0x3F).to_le_bytes()[0];
    let func = (insn & 0x3F).to_le_bytes()[0];
    let rt = ((insn >> 16) & 0x1F).to_le_bytes()[0];
    let rs = ((insn >> 21) & 0x1F).to_le_bytes()[0];
    let rd = ((insn >> 11) & 0x1F).to_le_bytes()[0];
    let sa = ((insn >> 6) & 0x1F).to_le_bytes()[0];
    let offset = insn & 0xffff; // as known as imm
    let target = insn & 0x3ffffff;
    log::trace!(
        "op {}, func {}, rt {}, rs {}, rd {}",
        opcode,
        func,
        rt,
        rs,
        rd
    );
    log::trace!(
        "decode: insn {:X}, opcode {:X}, func {:X}",
        insn,
        opcode,
        func
    );

    match (opcode, func, registers.is_kernel) {
        (0b000000, 0b001010, _) => Ok(Operation::CondMov(MovCond::EQ, rs, rt, rd)), // MOVZ: rd = rs if rt == 0
        (0b000000, 0b001011, _) => Ok(Operation::CondMov(MovCond::NE, rs, rt, rd)), // MOVN: rd = rs if rt != 0
        (0b000000, 0b100000, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::ADD,
            rs,
            rt,
            rd,
        )), // ADD: rd = rs+rt
        (0b000000, 0b100001, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::ADDU,
            rs,
            rt,
            rd,
        )), // ADDU: rd = rs+rt
        (0b000000, 0b100010, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::SUB,
            rs,
            rt,
            rd,
        )), // SUB: rd = rs-rt
        (0b000000, 0b100011, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::SUBU,
            rs,
            rt,
            rd,
        )), // SUBU: rd = rs-rt
        (0b000000, 0b000000, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::SLL,
            sa,
            rt,
            rd,
        )), // SLL: rd = rt << sa
        (0b000000, 0b000010, _) => {
            if rs == 1 {
                Ok(Operation::Ror(rd, rt, sa))
            } else {
                Ok(Operation::BinaryArithmetic(
                    arithmetic::BinaryOperator::SRL,
                    sa,
                    rt,
                    rd,
                ))
            }
        } // SRL: rd = rt >> sa
        (0b000000, 0b000011, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::SRA,
            sa,
            rt,
            rd,
        )), // SRA: rd = rt >> sa
        (0b000000, 0b000100, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::SLLV,
            rs,
            rt,
            rd,
        )), // SLLV: rd = rt << rs[4:0]
        (0b000000, 0b000110, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::SRLV,
            rs,
            rt,
            rd,
        )), // SRLV: rd = rt >> rs[4:0]
        (0b000000, 0b000111, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::SRAV,
            rs,
            rt,
            rd,
        )), // SRAV: rd = rt >> rs[4:0]
        (0b011100, 0b000010, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::MUL,
            rs,
            rt,
            rd,
        )), // MUL: rd = rt * rs
        (0b000000, 0b011000, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::MULT,
            rs,
            rt,
            rd,
        )), // MULT: (hi, lo) = rt * rs
        (0b000000, 0b011001, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::MULTU,
            rs,
            rt,
            rd,
        )), // MULTU: (hi, lo) = rt * rs
        (0b000000, 0b011010, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::DIV,
            rs,
            rt,
            rd,
        )), // DIV: (hi, lo) = rt / rs
        (0b000000, 0b011011, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::DIVU,
            rs,
            rt,
            rd,
        )), // DIVU: (hi, lo) = rt / rs
        (0b000000, 0b010000, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::MFHI,
            33,
            0,
            rd,
        )), // MFHI: rd = hi
        (0b000000, 0b010001, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::MTHI,
            rs,
            0,
            33,
        )), // MTHI: hi = rs
        (0b000000, 0b010010, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::MFLO,
            32,
            0,
            rd,
        )), // MFLO: rd = lo
        (0b000000, 0b010011, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::MTLO,
            rs,
            0,
            32,
        )), // MTLO: lo = rs
        (0b000000, 0b001111, _) => Ok(Operation::Nop),                              // SYNC
        (0b011100, 0b100000, _) => Ok(Operation::Count(false, rs, rd)), // CLZ: rd = count_leading_zeros(rs)
        (0b011100, 0b100001, _) => Ok(Operation::Count(true, rs, rd)), // CLO: rd = count_leading_ones(rs)
        (0x00, 0x08, _) => Ok(Operation::Jump(0u8, rs)),               // JR
        (0x00, 0x09, _) => Ok(Operation::Jump(rd, rs)),                // JALR
        (0x01, _, _) => {
            if rt == 1 {
                Ok(Operation::Branch(BranchCond::GE, rs, 0u8, offset)) // BGEZ
            } else if rt == 0 {
                Ok(Operation::Branch(BranchCond::LT, rs, 0u8, offset)) // BLTZ
            } else if rt == 0x11 && rs == 0 {
                Ok(Operation::JumpDirect(31, offset)) // BAL
            } else {
                Err(ProgramError::InvalidOpcode)
            }
        }
        (0x02, _, _) => Ok(Operation::Jumpi(0u8, target)), // J
        (0x03, _, _) => Ok(Operation::Jumpi(31u8, target)), // JAL
        (0x04, _, _) => Ok(Operation::Branch(BranchCond::EQ, rs, rt, offset)), // BEQ
        (0x05, _, _) => Ok(Operation::Branch(BranchCond::NE, rs, rt, offset)), // BNE
        (0x06, _, _) => Ok(Operation::Branch(BranchCond::LE, rs, 0u8, offset)), // BLEZ
        (0x07, _, _) => Ok(Operation::Branch(BranchCond::GT, rs, 0u8, offset)), // BGTZ

        (0b100000, _, _) => Ok(Operation::MloadGeneral(MemOp::LB, rs, rt, offset)),
        (0b100001, _, _) => Ok(Operation::MloadGeneral(MemOp::LH, rs, rt, offset)),
        (0b100010, _, _) => Ok(Operation::MloadGeneral(MemOp::LWL, rs, rt, offset)),
        (0b100011, _, _) => Ok(Operation::MloadGeneral(MemOp::LW, rs, rt, offset)),
        (0b100100, _, _) => Ok(Operation::MloadGeneral(MemOp::LBU, rs, rt, offset)),
        (0b100101, _, _) => Ok(Operation::MloadGeneral(MemOp::LHU, rs, rt, offset)),
        (0b100110, _, _) => Ok(Operation::MloadGeneral(MemOp::LWR, rs, rt, offset)),
        (0b110000, _, _) => Ok(Operation::MloadGeneral(MemOp::LL, rs, rt, offset)),
        (0b101000, _, _) => Ok(Operation::MstoreGeneral(MemOp::SB, rs, rt, offset)),
        (0b101001, _, _) => Ok(Operation::MstoreGeneral(MemOp::SH, rs, rt, offset)),
        (0b101010, _, _) => Ok(Operation::MstoreGeneral(MemOp::SWL, rs, rt, offset)),
        (0b101011, _, _) => Ok(Operation::MstoreGeneral(MemOp::SW, rs, rt, offset)),
        (0b101110, _, _) => Ok(Operation::MstoreGeneral(MemOp::SWR, rs, rt, offset)),
        (0b111000, _, _) => Ok(Operation::MstoreGeneral(MemOp::SC, rs, rt, offset)),
        (0b111101, _, _) => Ok(Operation::MstoreGeneral(MemOp::SDC1, rs, rt, offset)),
        (0b001000, _, _) => Ok(Operation::BinaryArithmeticImm(
            arithmetic::BinaryOperator::ADDI,
            rs,
            rt,
            offset,
        )), // ADDI: rt = rs + sext(imm)

        (0b001001, _, _) => Ok(Operation::BinaryArithmeticImm(
            arithmetic::BinaryOperator::ADDIU,
            rs,
            rt,
            offset,
        )), // ADDIU: rt = rs + sext(imm)

        (0b001010, _, _) => Ok(Operation::BinaryArithmeticImm(
            arithmetic::BinaryOperator::SLTI,
            rs,
            rt,
            offset,
        )), // SLTI: rt = rs < sext(imm)

        (0b001011, _, _) => Ok(Operation::BinaryArithmeticImm(
            arithmetic::BinaryOperator::SLTIU,
            rs,
            rt,
            offset,
        )), // SLTIU: rt = rs < sext(imm)

        (0b000000, 0b101010, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::SLT,
            rs,
            rt,
            rd,
        )), // SLT: rd = rs < rt

        (0b000000, 0b101011, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::SLTU,
            rs,
            rt,
            rd,
        )), // SLTU: rd = rs < rt

        (0b001111, _, _) => Ok(Operation::BinaryArithmeticImm(
            arithmetic::BinaryOperator::LUI,
            rs,
            rt,
            offset,
        )), // LUI: rt = imm << 16
        (0b000000, 0b100100, _) => Ok(Operation::BinaryLogic(logic::Op::And, rs, rt, rd)), // AND: rd = rs & rt
        (0b000000, 0b100101, _) => Ok(Operation::BinaryLogic(logic::Op::Or, rs, rt, rd)), // OR: rd = rs | rt
        (0b000000, 0b100110, _) => Ok(Operation::BinaryLogic(logic::Op::Xor, rs, rt, rd)), // XOR: rd = rs ^ rt
        (0b000000, 0b100111, _) => Ok(Operation::BinaryLogic(logic::Op::Nor, rs, rt, rd)), // NOR: rd = ! rs | rt

        (0b001100, _, _) => Ok(Operation::BinaryLogicImm(logic::Op::And, rs, rt, offset)), // ANDI: rt = rs + zext(imm)
        (0b001101, _, _) => Ok(Operation::BinaryLogicImm(logic::Op::Or, rs, rt, offset)), // ORI: rt = rs + zext(imm)
        (0b001110, _, _) => Ok(Operation::BinaryLogicImm(logic::Op::Xor, rs, rt, offset)), // XORI: rt = rs + zext(imm)
        (0b000000, 0b001100, _) => Ok(Operation::Syscall), // Syscall
        (0b110011, _, _) => Ok(Operation::Nop),            // Pref
        (0b011100, 0b000001, _) => Ok(Operation::Maddu(rt, rs)), // rdhwr
        (0b011111, 0b000000, _) => Ok(Operation::Ext(rt, rs, rd, sa)), // ext
        (0b011111, 0b000100, _) => Ok(Operation::Ins(rt, rs, rd, sa)), // ins
        (0b011111, 0b111011, _) => Ok(Operation::Rdhwr(rt, rd)), // rdhwr
        (0b011111, 0b100000, _) => {
            if sa == 0b011000 {
                Ok(Operation::Signext(rd, rt, 16)) // seh
            } else if sa == 0b010000 {
                Ok(Operation::Signext(rd, rt, 8)) // seb
            } else if sa == 0b000010 {
                Ok(Operation::SwapHalf(rd, rt)) // wsbh
            } else {
                log::warn!(
                    "decode: invalid opcode {:#08b} {:#08b} {:#08b}",
                    opcode,
                    func,
                    sa
                );
                Err(ProgramError::InvalidOpcode)
            }
        }
        (0b000000, 0b110100, _) => Ok(Operation::Teq(rs, rt)), // teq
        _ => {
            log::warn!("decode: invalid opcode {:#08b} {:#08b}", opcode, func);
            Err(ProgramError::InvalidOpcode)
        }
    }
}

fn fill_op_flag<F: Field>(op: Operation, row: &mut CpuColumnsView<F>) {
    let flags = &mut row.op;
    *match op {
        Operation::Syscall => &mut flags.syscall,
        Operation::CondMov(MovCond::EQ, _, _, _) => &mut flags.movz_op,
        Operation::CondMov(MovCond::NE, _, _, _) => &mut flags.movn_op,
        Operation::Count(false, _, _) => &mut flags.clz_op,
        Operation::Count(true, _, _) => &mut flags.clo_op,
        Operation::BinaryLogic(_, _, _, _) => &mut flags.logic_op,
        Operation::BinaryLogicImm(_, _, _, _) => &mut flags.logic_imm_op,
        Operation::BinaryArithmetic(arithmetic::BinaryOperator::SLL, ..)
        | Operation::BinaryArithmetic(arithmetic::BinaryOperator::SRL, ..)
        | Operation::BinaryArithmetic(arithmetic::BinaryOperator::SRA, ..) => &mut flags.shift_imm,
        Operation::BinaryArithmetic(arithmetic::BinaryOperator::SLLV, ..)
        | Operation::BinaryArithmetic(arithmetic::BinaryOperator::SRLV, ..)
        | Operation::BinaryArithmetic(arithmetic::BinaryOperator::SRAV, ..) => &mut flags.shift,
        Operation::BinaryArithmetic(..) => &mut flags.binary_op,
        Operation::BinaryArithmeticImm(..) => &mut flags.binary_imm_op,
        Operation::KeccakGeneral => &mut flags.keccak_general,
        Operation::Jump(_, _) => &mut flags.jumps,
        Operation::Jumpi(_, _) => &mut flags.jumpi,
        Operation::JumpDirect(_, _) => &mut flags.jumpdirect,
        Operation::Branch(_, _, _, _) => &mut flags.branch,
        Operation::Pc => &mut flags.pc,
        Operation::GetContext => &mut flags.get_context,
        Operation::SetContext => &mut flags.set_context,
        Operation::MloadGeneral(..) => &mut flags.m_op_load,
        Operation::MstoreGeneral(..) => &mut flags.m_op_store,
        Operation::Nop => &mut flags.nop,
        Operation::Ext(_, _, _, _) => &mut flags.ext,
        Operation::Ins(_, _, _, _) => &mut flags.ins,
        Operation::Maddu(_, _) => &mut flags.maddu,
        Operation::Ror(_, _, _) => &mut flags.ror,
        Operation::Rdhwr(_, _) => &mut flags.rdhwr,
        Operation::Signext(_, _, 8u8) => &mut flags.signext8,
        Operation::Signext(_, _, _) => &mut flags.signext16,
        Operation::SwapHalf(_, _) => &mut flags.swaphalf,
        Operation::Teq(_, _) => &mut flags.teq,
    } = F::ONE;
}

fn perform_op<F: RichField>(
    state: &mut GenerationState<F>,
    op: Operation,
    row: CpuColumnsView<F>,
    kernel: &Kernel,
) -> Result<(), ProgramError> {
    log::trace!("perform_op {:?}", op);
    match op {
        Operation::Syscall => generate_syscall(state, row, kernel)?,
        Operation::CondMov(cond, rs, rt, rd) => generate_cond_mov_op(cond, rs, rt, rd, state, row)?,
        Operation::Count(is_clo, rs, rd) => generate_count_op(is_clo, rs, rd, state, row)?,
        Operation::BinaryLogic(binary_logic_op, rs, rt, rd) => {
            generate_binary_logic_op(binary_logic_op, rs, rt, rd, state, row)?
        }
        Operation::BinaryArithmetic(arithmetic::BinaryOperator::MULT, rs, rt, rd) => {
            generate_binary_arithmetic_hilo_op(
                arithmetic::BinaryOperator::MULT,
                rs,
                rt,
                rd,
                state,
                row,
            )?
        }
        Operation::BinaryArithmetic(arithmetic::BinaryOperator::MULTU, rs, rt, rd) => {
            generate_binary_arithmetic_hilo_op(
                arithmetic::BinaryOperator::MULTU,
                rs,
                rt,
                rd,
                state,
                row,
            )?
        }
        Operation::BinaryArithmetic(arithmetic::BinaryOperator::DIV, rs, rt, rd) => {
            generate_binary_arithmetic_hilo_op(
                arithmetic::BinaryOperator::DIV,
                rs,
                rt,
                rd,
                state,
                row,
            )?
        }
        Operation::BinaryArithmetic(arithmetic::BinaryOperator::DIVU, rs, rt, rd) => {
            generate_binary_arithmetic_hilo_op(
                arithmetic::BinaryOperator::DIVU,
                rs,
                rt,
                rd,
                state,
                row,
            )?
        }
        Operation::BinaryLogicImm(binary_logic_op, rs, rd, imm) => {
            generate_binary_logic_imm_op(binary_logic_op, rs, rd, imm, state, row)?
        }

        Operation::BinaryArithmetic(arithmetic::BinaryOperator::SLL, sa, rt, rd) => {
            generate_shift_imm(arithmetic::BinaryOperator::SLL, sa, rt, rd, state, row)?
        }
        Operation::BinaryArithmetic(arithmetic::BinaryOperator::SRL, sa, rt, rd) => {
            generate_shift_imm(arithmetic::BinaryOperator::SRL, sa, rt, rd, state, row)?
        }
        Operation::BinaryArithmetic(arithmetic::BinaryOperator::SRA, sa, rt, rd) => {
            generate_shift_imm(arithmetic::BinaryOperator::SRA, sa, rt, rd, state, row)?
        }

        Operation::BinaryArithmetic(arithmetic::BinaryOperator::SLLV, rs, rt, rd) => {
            generate_sllv(rs, rt, rd, state, row)?
        }
        Operation::BinaryArithmetic(arithmetic::BinaryOperator::SRLV, rs, rt, rd) => {
            generate_srlv(rs, rt, rd, state, row)?
        }
        Operation::BinaryArithmetic(arithmetic::BinaryOperator::SRAV, rs, rt, rd) => {
            generate_srav(rs, rt, rd, state, row)?
        }
        Operation::BinaryArithmetic(op, rs, rt, rd) => {
            generate_binary_arithmetic_op(op, rs, rt, rd, state, row)?
        }
        Operation::BinaryArithmeticImm(arithmetic::BinaryOperator::LUI, rs, rt, imm) => {
            generate_lui(rs, rt, imm, state, row)?
        }
        Operation::BinaryArithmeticImm(op, rs, rt, imm) => {
            generate_binary_arithmetic_imm_op(rs, rt, imm, op, state, row)?
        }
        Operation::KeccakGeneral => generate_keccak_general(state, row)?,
        Operation::Jump(link, target) => generate_jump(link, target, state, row)?,
        Operation::Jumpi(link, target) => generate_jumpi(link, target, state, row)?,
        Operation::JumpDirect(link, target) => generate_jumpdirect(link, target, state, row)?,
        Operation::Branch(cond, input1, input2, target) => {
            generate_branch(cond, input1, input2, target, state, row)?
        }
        Operation::Pc => generate_pc(state, row)?,
        Operation::MloadGeneral(op, base, rt, offset) => {
            generate_mload_general(op, base, rt, offset, state, row)?
        }
        Operation::MstoreGeneral(op, base, rt, offset) => {
            generate_mstore_general(op, base, rt, offset, state, row)?
        }
        Operation::GetContext => generate_get_context(state, row)?,
        Operation::SetContext => generate_set_context(state, row)?,
        Operation::Nop => generate_nop(state, row)?,
        Operation::Ext(rt, rs, msbd, lsb) => generate_extract(rt, rs, msbd, lsb, state, row)?,
        Operation::Ins(rt, rs, msb, lsb) => generate_insert(rt, rs, msb, lsb, state, row)?,
        Operation::Maddu(rt, rs) => generate_maddu(rt, rs, state, row)?,
        Operation::Ror(rd, rt, sa) => generate_ror(rd, rt, sa, state, row)?,
        Operation::Rdhwr(rt, rd) => generate_rdhwr(rt, rd, state, row)?,
        Operation::Signext(rd, rt, bits) => generate_signext(rd, rt, bits, state, row)?,
        Operation::SwapHalf(rd, rt) => generate_swaphalf(rd, rt, state, row)?,
        Operation::Teq(rs, rt) => generate_teq(rs, rt, state, row)?,
    };

    match op {
        Operation::Jump(_, _)
        | Operation::Jumpi(_, _)
        | Operation::JumpDirect(_, _)
        | Operation::Branch(_, _, _, _) => {
            // Do nothing
        }
        _ => {
            state.registers.program_counter = state.registers.next_pc;
            state.registers.next_pc += 4;
        }
    };

    match op {
        Operation::Jump(_, _)
        | Operation::Jumpi(_, _)
        | Operation::JumpDirect(_, _)
        | Operation::Branch(_, _, _, _) => {
            log::trace!(
                "states: pc {} registers: {:?}",
                state.registers.program_counter,
                state.registers.gprs
            );
        }
        Operation::Syscall => {
            log::trace!(
                "states: pc {} registers: {:?}",
                state.registers.program_counter + 4,
                state.registers.gprs
            );
        }
        _ => (),
    };

    Ok(())
}

/// Row that has the correct values for system registers and the code channel, but is otherwise
/// blank. It fulfills the constraints that are common to successful operations and the exception
/// operation. It also returns the opcode.
fn base_row<F: Field>(state: &mut GenerationState<F>) -> (CpuColumnsView<F>, u32) {
    let mut row: CpuColumnsView<F> = CpuColumnsView::default();
    row.clock = F::from_canonical_usize(state.traces.clock());
    row.context = F::from_canonical_usize(state.registers.context);
    row.program_counter = F::from_canonical_usize(state.registers.program_counter);
    row.next_program_counter = F::from_canonical_usize(state.registers.next_pc);
    row.is_kernel_mode = F::from_bool(state.registers.is_kernel);

    let opcode = read_code_memory(state, &mut row);
    (row, opcode)
}

fn try_perform_instruction<F: RichField>(
    state: &mut GenerationState<F>,
    kernel: &Kernel,
) -> Result<(), ProgramError> {
    let (mut row, opcode) = base_row(state);
    let op = decode(state.registers, opcode)?;

    if state.registers.is_kernel {
        log_kernel_instruction(state, op, kernel);
    } else {
        log::trace!("user instruction: {:?}", op);
    }

    fill_op_flag(op, &mut row);

    /*
    if state.registers.is_kernel {
        row.stack_len_bounds_aux = F::ZERO;
    } else {
        let disallowed_len = F::from_canonical_usize(MAX_USER_STACK_SIZE + 1);
        let diff = row.stack_len - disallowed_len;
        if let Some(inv) = diff.try_inverse() {
            row.stack_len_bounds_aux = inv;
        } else {
            // This is a stack overflow that should have been caught earlier.
            return Err(ProgramError::InterpreterError);
        }
    }
    */

    perform_op(state, op, row, kernel)
}

fn log_kernel_instruction<F: Field>(state: &GenerationState<F>, op: Operation, kernel: &Kernel) {
    // The logic below is a bit costly, so skip it if debug logs aren't enabled.
    if !log_enabled!(log::Level::Debug) {
        return;
    }

    let pc = state.registers.program_counter;
    let is_interesting_offset = kernel
        .offset_label(pc)
        .filter(|label| !label.starts_with("halt"))
        .is_some();
    let level = if is_interesting_offset {
        log::Level::Debug
    } else {
        log::Level::Trace
    };
    log::log!(
        level,
        "Cycle {}, ctx={}, pc={}, instruction={:?}, stack={:?}",
        state.traces.clock(),
        state.registers.context,
        kernel.offset_name(pc),
        op,
        //state.stack(),
        0,
    );

    //assert!(pc < KERNEL.program.image.len(), "Kernel PC is out of range: {}", pc);
}

fn handle_error<F: Field>(state: &mut GenerationState<F>, err: ProgramError) -> anyhow::Result<()> {
    let exc_code: u8 = match err {
        ProgramError::OutOfGas => 0,
        ProgramError::InvalidOpcode => 1,
        ProgramError::StackUnderflow => 2,
        ProgramError::InvalidJumpDestination => 3,
        ProgramError::InvalidJumpiDestination => 4,
        ProgramError::StackOverflow => 5,
        _ => bail!("TODO: figure out what to do with this..."),
    };
    log::debug!("handle_error: {:?}", exc_code);

    let checkpoint = state.checkpoint();

    state
        .memory
        .apply_ops(state.traces.mem_ops_since(checkpoint.traces));
    Ok(())
}

pub(crate) fn transition<F: RichField>(
    state: &mut GenerationState<F>,
    kernel: &Kernel,
) -> anyhow::Result<()> {
    let checkpoint = state.checkpoint();
    let result = try_perform_instruction(state, kernel);

    match result {
        Ok(()) => {
            state
                .memory
                .apply_ops(state.traces.mem_ops_since(checkpoint.traces));
            Ok(())
        }
        Err(e) => {
            if state.registers.is_kernel {
                let offset_name = kernel.offset_name(state.registers.program_counter);
                bail!(
                    "{:?} in kernel at pc={}, stack={:?}, memory={:?}",
                    e,
                    offset_name,
                    //state.stack(),
                    0,
                    state.memory.contexts[0].segments[Segment::KernelGeneral as usize].content,
                );
            }
            state.rollback(checkpoint);
            handle_error(state, e)
        }
    }
}
