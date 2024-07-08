use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;

use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::columns::{CpuColumnsView, COL_MAP};

/// List of opcode blocks
///  Each block corresponds to exactly one flag, and each flag corresponds to exactly one block.
///  Each block of opcodes:
/// - is contiguous,
/// - has a length that is a power of 2, and
/// - its start index is a multiple of its length (it is aligned).
///  These properties permit us to check if an opcode belongs to a block of length 2^n by checking
/// its top 8-n bits.
///  Additionally, each block can be made available only to the user, only to the kernel, or to
/// both. This is mainly useful for making some instructions kernel-only, while still decoding to
/// invalid for the user. We do this by making one kernel-only block and another user-only block.
/// The exception is the PANIC instruction which is user-only without a corresponding kernel block.
/// This makes the proof unverifiable when PANIC is executed in kernel mode, which is the intended
/// behavior.
/// Note: invalid opcodes are not represented here. _Any_ opcode is permitted to decode to
/// `is_invalid`. The kernel then verifies that the opcode was _actually_ invalid.
/// FIXME: stephen
const OPCODES: [(u32, usize, bool, usize); 8] = [
    // (start index of block, number of top bits to check (log2), kernel-only, flag column)
    // ADD, MUL, SUB, DIV, MOD, LT, GT and BYTE flags are handled partly manually here, and partly through the Arithmetic table CTL.
    // ADDMOD, MULMOD and SUBMOD flags are handled partly manually here, and partly through the Arithmetic table CTL.
    (0x7, 1, false, COL_MAP.op.eq_iszero),
    // AND, OR and XOR flags are handled partly manually here, and partly through the Logic table CTL.
    // SHL and SHR flags are handled partly manually here, and partly through the Logic table CTL.
    (0x0B, 0, true, COL_MAP.op.keccak_general),
    (0x0D, 1, false, COL_MAP.op.jumps), // 0x56-0x57
    (0x0E, 0, false, COL_MAP.op.branch),
    (0x0F, 0, false, COL_MAP.op.pc),
    (0x12, 0, true, COL_MAP.op.get_context),
    (0x13, 0, true, COL_MAP.op.set_context),
    (0x16, 0, true, COL_MAP.op.exit_kernel),
    // MLOAD_GENERAL and MSTORE_GENERAL flags are handled manually here.
];

/// List of combined opcodes requiring a special handling.
/// Each index in the list corresponds to an arbitrary combination
/// of opcodes defined in evm/src/cpu/columns/ops.rs.
const COMBINED_OPCODES: [usize; 7] = [
    COL_MAP.op.logic_op,
    COL_MAP.op.binary_op,
    COL_MAP.op.binary_imm_op,
    COL_MAP.op.shift,
    COL_MAP.op.shift_imm,
    COL_MAP.op.m_op_load,
    COL_MAP.op.m_op_store,
];

/// Break up an opcode (which is 32 bits long) into its 32 bits.
fn bits_from_opcode(opcode: u32) -> [bool; 32] {
    let mut insn = [false; 32];
    for i in 0..32 {
        insn[i] = opcode & (1 << i) != 0;
    }
    insn
}

pub fn eval_packed_generic<P: PackedField>(
    lv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    // Ensure that the kernel flag is valid (either 0 or 1).
    let kernel_mode = lv.is_kernel_mode;
    yield_constr.constraint(kernel_mode * (kernel_mode - P::ONES));

    // Ensure that the opcode bits are valid: each has to be either 0 or 1.
    for bit in lv.opcode_bits {
        yield_constr.constraint(bit * (bit - P::ONES));
    }

    // Check that the instruction flags are valid.
    // First, check that they are all either 0 or 1.
    for (_, _, _, flag_col) in OPCODES {
        let flag = lv[flag_col];
        yield_constr.constraint(flag * (flag - P::ONES));
    }
    // Also check that the combined instruction flags are valid.
    for flag_idx in COMBINED_OPCODES {
        yield_constr.constraint(lv[flag_idx] * (lv[flag_idx] - P::ONES));
    }

    // Now check that they sum to 0 or 1, including the combined flags.
    let flag_sum: P = OPCODES
        .into_iter()
        .map(|(_, _, _, flag_col)| lv[flag_col])
        .chain(COMBINED_OPCODES.map(|op| lv[op]))
        .sum::<P>();
    yield_constr.constraint(flag_sum * (flag_sum - P::ONES));

    // Finally, classify all opcodes, together with the kernel flag, into blocks
    // TODO
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    // Note: The constraints below do not need to be restricted to CPU cycles.

    // Ensure that the kernel flag is valid (either 0 or 1).
    let kernel_mode = lv.is_kernel_mode;
    {
        let constr = builder.mul_sub_extension(kernel_mode, kernel_mode, kernel_mode);
        yield_constr.constraint(builder, constr);
    }

    // Ensure that the opcode bits are valid: each has to be either 0 or 1.
    for bit in lv.opcode_bits {
        let constr = builder.mul_sub_extension(bit, bit, bit);
        yield_constr.constraint(builder, constr);
    }

    // Check that the instruction flags are valid.
    // First, check that they are all either 0 or 1.
    for (_, _, _, flag_col) in OPCODES {
        let flag = lv[flag_col];
        let constr = builder.mul_sub_extension(flag, flag, flag);
        yield_constr.constraint(builder, constr);
    }
    // Also check that the combined instruction flags are valid.
    for flag_idx in COMBINED_OPCODES {
        let constr = builder.mul_sub_extension(lv[flag_idx], lv[flag_idx], lv[flag_idx]);
        yield_constr.constraint(builder, constr);
    }

    // Now check that they sum to 0 or 1, including the combined flags.
    {
        let mut flag_sum =
            builder.add_many_extension(COMBINED_OPCODES.into_iter().map(|idx| lv[idx]));
        for (_, _, _, flag_col) in OPCODES {
            let flag = lv[flag_col];
            flag_sum = builder.add_extension(flag_sum, flag);
        }
        let constr = builder.mul_sub_extension(flag_sum, flag_sum, flag_sum);
        yield_constr.constraint(builder, constr);
    }

    // Finally, classify all opcodes, together with the kernel flag, into blocks
}
