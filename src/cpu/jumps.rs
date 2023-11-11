use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::columns::CpuColumnsView;

//use plonky2_evm::util::limb_from_bits_le;

use crate::util::{limb_from_bits_le, limb_from_bits_le_recursive};

/// 2^-32 mod (2^64 - 2^32 + 1)
const GOLDILOCKS_INVERSE_2EXP32: u64 = 18446744065119617026;

pub fn eval_packed_exit_kernel<P: PackedField>(
    lv: &CpuColumnsView<P>,
    nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let input = lv.mem_channels[0].value;
    let filter = lv.op.exit_kernel;
    // If we are executing `EXIT_KERNEL` then we simply restore the program counter, kernel mode
    // flag, and gas counter. The middle 4 (32-bit) limbs are ignored (this is not part of the spec,
    // but we trust the kernel to set them to zero).
    yield_constr.constraint_transition(filter * (input[0] - nv.program_counter));
    yield_constr.constraint_transition(filter * (input[1] - nv.is_kernel_mode));
    //yield_constr.constraint_transition(filter * (input[6] - nv.gas));
    // High limb of gas must be 0 for convenient detection of overflow.
    //yield_constr.constraint(filter * input[7]);
}

pub fn eval_ext_circuit_exit_kernel<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    nv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let input = lv.mem_channels[0].value;
    let filter = lv.op.exit_kernel;

    // If we are executing `EXIT_KERNEL` then we simply restore the program counter and kernel mode
    // flag. The top 6 (32-bit) limbs are ignored (this is not part of the spec, but we trust the
    // kernel to set them to zero).

    let pc_constr = builder.sub_extension(input[0], nv.program_counter);
    let pc_constr = builder.mul_extension(filter, pc_constr);
    yield_constr.constraint_transition(builder, pc_constr);

    let kernel_constr = builder.sub_extension(input[1], nv.is_kernel_mode);
    let kernel_constr = builder.mul_extension(filter, kernel_constr);
    yield_constr.constraint_transition(builder, kernel_constr);

    /*
    {
        let diff = builder.sub_extension(input[6], nv.gas);
        let constr = builder.mul_extension(filter, diff);
        yield_constr.constraint_transition(builder, constr);
    }
    {
        // High limb of gas must be 0 for convenient detection of overflow.
        let constr = builder.mul_extension(filter, input[7]);
        yield_constr.constraint(builder, constr);
    }
    */
}

pub fn eval_packed_jump_jumpi<P: PackedField>(
    lv: &CpuColumnsView<P>,
    nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let jumps_lv = lv.general.jumps();

    let filter = lv.op.jumps; // `JUMP` or `JUMPI`
    let is_jump = filter * (P::ONES - lv.opcode_bits[1]);
    let is_jumpi = filter * lv.opcode_bits[1];

    let is_link = is_jump * lv.func_bits[0];
    let is_linki = is_jumpi * lv.opcode_bits[0];

    // Check `should_jump`:
    // constraint: filter * (should_jump - 1) == 0
    yield_constr.constraint(filter * (P::ONES - jumps_lv.should_jump));

    // Check `jump target value`:
    // constraint: is_jump * (next_program_coutner - reg[rs]) == 0
    {
        let reg_dst = lv.mem_channels[0].value[0];
        let jump_dest = reg_dst;
        yield_constr.constraint(is_jump * (nv.program_counter - jump_dest));
    }

    // Check `jump target register`:
    // constraint: is_jump *(jump_reg - rs) == 0
    {
        let jump_reg = lv.mem_channels[0].addr_virtual;
        let mut jump_reg_index = [P::ONES; 5];
        jump_reg_index.copy_from_slice(&lv.rs_bits);
        let jump_dst = limb_from_bits_le(jump_reg_index.into_iter());
        yield_constr.constraint(is_jump * (jump_dst - jump_reg));
    }

    // Check `jumpi target value`:
    // constraint:
    // * jump_dest =  offset << 2 + pc_remain
    // * is_jumpi * (next_program_coutner - jump_dest) == 0
    // * where pc_remain is  pc[28..32] << 28
    {
        let mut jump_imm = [P::ONES; 26];
        jump_imm[0..6].copy_from_slice(&lv.func_bits);
        jump_imm[6..11].copy_from_slice(&lv.shamt_bits);
        jump_imm[11..16].copy_from_slice(&lv.rd_bits);
        jump_imm[16..21].copy_from_slice(&lv.rt_bits);
        jump_imm[21..26].copy_from_slice(&lv.rs_bits);

        let imm_dst = limb_from_bits_le(jump_imm.into_iter());
        let pc_remain = lv.mem_channels[7].value[0];
        let jump_dest = pc_remain + imm_dst * P::Scalar::from_canonical_u8(4);
        yield_constr.constraint(is_jumpi * (nv.program_counter - jump_dest));
    }

    // Check `link/linki target value`:
    // constraint:
    // * next_addr = program_counter + 8
    // * link = is_link + is_linki
    // * link * (ret_addr - next_addr) == 0
    {
        let link_dest = lv.mem_channels[1].value[0];
        yield_constr.constraint(
            (is_link + is_linki)
                * (lv.program_counter + P::Scalar::from_canonical_u64(8) - link_dest),
        );
    }

    // Check `link target regiseter`:
    // constraint: is_link * (ret_reg - rd) == 0
    let link_reg = lv.mem_channels[1].addr_virtual;
    {
        let link_dst = limb_from_bits_le(lv.rd_bits.into_iter());
        yield_constr.constraint(is_link * (link_reg - link_dst));
    }

    // Check `linki target regiseter`:
    // constraint: is_linki * (ret_reg - 31) == 0
    {
        yield_constr.constraint(is_linki * (link_reg - P::Scalar::from_canonical_u64(31)));
    }
}

pub fn eval_ext_circuit_jump_jumpi<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    nv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let jumps_lv = lv.general.jumps();
    let filter = lv.op.jumps; // `JUMP` or `JUMPI`
    let one_extension = builder.one_extension();
    let b27 = lv.opcode_bits[1];
    let is_jump = builder.sub_extension(one_extension, b27);
    let is_jump = builder.mul_extension(filter, is_jump);
    let is_jumpi = builder.mul_extension(filter, b27);

    let is_link = builder.mul_extension(is_jump, lv.func_bits[0]);
    let is_linki = builder.mul_extension(is_jumpi, lv.opcode_bits[0]);

    // Check `should_jump`:
    // constraint: filter * (should_jump - 1) == 0
    {
        let constr = builder.sub_extension(one_extension, jumps_lv.should_jump);
        let constr = builder.mul_extension(filter, constr);
        yield_constr.constraint(builder, constr);
    }

    // Check `jump target value`:
    // constraint: is_jump * (next_program_coutner - reg[rs]) == 0
    {
        let reg_dst = lv.mem_channels[0].value[0];
        let constr = builder.sub_extension(nv.program_counter, reg_dst);
        let constr = builder.mul_extension(is_jump, constr);
        yield_constr.constraint(builder, constr);
    }

    // Check `jump target register`:
    // constraint: is_jump *(jump_reg - rs) == 0
    {
        let jump_reg = lv.mem_channels[0].addr_virtual;
        let mut jump_reg_index = [one_extension; 5];
        jump_reg_index.copy_from_slice(&lv.rs_bits);
        let jump_dst = limb_from_bits_le_recursive(builder, jump_reg_index.into_iter());
        let constr = builder.sub_extension(jump_dst, jump_reg);
        let constr = builder.mul_extension(constr, is_jump);
        yield_constr.constraint(builder, constr);
    }

    // Check `jumpi target value`:
    // constraint:
    // * jump_dest =  offset << 2 + pc_remain
    // * is_jumpi * (next_program_coutner - jump_dest) == 0
    // * where pc_remain is  pc[28..32] << 28
    {
        let mut jump_imm = [one_extension; 26];
        jump_imm[0..6].copy_from_slice(&lv.func_bits);
        jump_imm[6..11].copy_from_slice(&lv.shamt_bits);
        jump_imm[11..16].copy_from_slice(&lv.rd_bits);
        jump_imm[16..21].copy_from_slice(&lv.rt_bits);
        jump_imm[21..26].copy_from_slice(&lv.rs_bits);

        let jump_dest = limb_from_bits_le_recursive(builder, jump_imm.into_iter());
        let jump_dest = builder.mul_const_extension(F::from_canonical_u64(4), jump_dest); //TO FIX

        let constr = builder.add_extension(lv.mem_channels[7].value[0], jump_dest);
        let constr = builder.sub_extension(nv.program_counter, constr);
        let constr = builder.mul_extension(is_jumpi, constr);
        yield_constr.constraint(builder, constr);
    }

    // Check `link/linki target value`:
    // constraint:
    // * next_addr = program_counter + 8
    // * link = is_link + is_linki
    // * link * (ret_addr - next_addr) == 0
    {
        let link_dst = lv.mem_channels[1].value[0];
        let link_dest = builder.add_const_extension(lv.program_counter, F::from_canonical_u64(8));
        let constr = builder.sub_extension(link_dest, link_dst);
        let is_link = builder.add_extension(is_link, is_linki);
        let constr = builder.mul_extension(is_link, constr);
        yield_constr.constraint(builder, constr);
    }

    // Check `link target register`:
    // constraint: is_link * (ret_reg - rd) == 0
    let link_reg = lv.mem_channels[1].addr_virtual;
    {
        let link_dst = limb_from_bits_le_recursive(builder, lv.rd_bits.into_iter());
        let constr = builder.sub_extension(link_reg, link_dst);
        let constr = builder.mul_extension(constr, is_link);
        yield_constr.constraint(builder, constr);
    }

    // Check `linki target register`
    // constraint: is_linki * (ret_reg - 31) == 0
    {
        let reg_31 = builder.constant_extension(F::Extension::from_canonical_u64(31));
        let constr = builder.sub_extension(link_reg, reg_31);
        let constr = builder.mul_extension(constr, is_linki);
        yield_constr.constraint(builder, constr);
    }
}

pub fn eval_packed_branch<P: PackedField>(
    lv: &CpuColumnsView<P>,
    nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let jumps_lv = lv.general.jumps();

    let filter = lv.op.branch; // `BRANCH`
    let norm_filter = lv.opcode_bits[2];
    let special_filter = P::ONES - lv.opcode_bits[2];
    let is_eq = lv.opcode_bits[2] * (P::ONES - lv.opcode_bits[1]) * (P::ONES - lv.opcode_bits[0]);
    let is_ne = lv.opcode_bits[2] * (P::ONES - lv.opcode_bits[1]) * lv.opcode_bits[0];
    let is_le = lv.opcode_bits[2] * lv.opcode_bits[1] * (P::ONES - lv.opcode_bits[0]);
    let is_gt = lv.opcode_bits[2] * lv.opcode_bits[1] * lv.opcode_bits[0];
    let is_ge = (P::ONES - lv.opcode_bits[2]) * lv.rt_bits[0];
    let is_lt = (P::ONES - lv.opcode_bits[2]) * (P::ONES - lv.rt_bits[0]);
    let overflow = P::Scalar::from_canonical_u64(1 << 32);
    let overflow_inv = P::Scalar::from_canonical_u64(GOLDILOCKS_INVERSE_2EXP32);

    // Check `should_jump`:
    // constraint: filter * (1 - should_jump) * should_jump == 0
    yield_constr.constraint(filter * jumps_lv.should_jump * (P::ONES - jumps_lv.should_jump));

    // Check `branch target value`:
    // constraints:
    // * jump_dest =  sign_extended(offset << 2) + pc
    // * next_addr = pc + 8
    // * next_pc = jump_dest * should_jump + next_addr * (1 - should_jump)
    // * filter * (next_program_coutner - next_pc) == 0
    {
        let mut branch_offset = [P::ZEROS; 32];

        branch_offset[2..8].copy_from_slice(&lv.func_bits); // 6 bits
        branch_offset[8..13].copy_from_slice(&lv.shamt_bits); // 5 bits
        branch_offset[13..18].copy_from_slice(&lv.rd_bits); // 5 bits
        branch_offset[18..32].copy_from_slice(&[lv.rd_bits[4]; 14]); // lv.insn_bits[15]

        let offset_dst = limb_from_bits_le(branch_offset.into_iter());
        let branch_dst = lv.program_counter + offset_dst;
        let next_inst = lv.program_counter + P::Scalar::from_canonical_u64(8);
        let branch_dst =
            jumps_lv.should_jump * branch_dst + next_inst * (P::ONES - jumps_lv.should_jump);
        yield_constr.constraint(filter * (nv.program_counter - branch_dst));
    }

    // Check Aux Reg
    // constraint:
    // * sum = aux1 + aux2
    // * filter * (1 - sum * overflow_inv) == 0
    {
        let aux1 = lv.mem_channels[2].addr_virtual;
        let aux2 = lv.mem_channels[3].addr_virtual;
        yield_constr.constraint(filter * (P::ONES - (aux1 + aux2) * overflow_inv));
    }

    // Check rs Reg
    // constraint: filter * (src1_reg - rs) == 0
    {
        let rs_reg = lv.mem_channels[0].addr_virtual;
        let rs_src = limb_from_bits_le(lv.rs_bits.into_iter());
        yield_constr.constraint(filter * (rs_reg - rs_src));
    }

    // Check rt Reg
    // constraint: filter * (src2_reg - rt) == 0
    {
        let rt_reg = lv.mem_channels[1].addr_virtual;
        let rt_src = limb_from_bits_le(lv.rt_bits.into_iter());
        yield_constr.constraint(filter * norm_filter * (rt_reg - rt_src));
        yield_constr.constraint(filter * special_filter * rt_reg);
    }

    // Check Condition
    {
        let src1 = lv.mem_channels[0].value[0];
        let src2 = lv.mem_channels[1].value[0];
        let aux1 = lv.mem_channels[2].value[0];
        let aux2 = lv.mem_channels[3].value[0];

        // constraints:
        // * z = src2 + aux - src1
        // * filter * z * (overflow - z) == 0
        // * is_lt = z * overflow_inv
        // * filter * lt * (1 - is_lt) == 0
        // where aux = src1 - src2 in u32, overflow - 2^32, overflow_inv = 2^-32
        let constr_a = src2 + aux1 - src1;
        yield_constr.constraint(filter * constr_a * (overflow - constr_a));
        let lt = constr_a * overflow_inv;
        yield_constr.constraint(filter * lt * (P::ONES - lt));

        // constraints:
        // * z = src1 + aux - src2
        // * filter * z * (overflow - z) == 0
        // * is_gt = z * overflow_inv
        // * filter * gt * (1 - is_gt) == 0
        // where aux = src2 - src1 in u32, overflow - 2^32, overflow_inv = 2^-32
        let constr_b = src1 + aux2 - src2;
        yield_constr.constraint(filter * constr_b * (overflow - constr_b));
        let gt = constr_b * overflow_inv;
        yield_constr.constraint(filter * gt * (P::ONES - gt));

        // constraints:
        // * is_ne = is_lt + is_gt
        // * filter * ne * (1 - is_ne) == 0
        let ne = lt + gt;
        yield_constr.constraint(filter * ne * (P::ONES - ne));

        // constraints:
        // * is_eq = 1 - is_ne
        // * is_ge = 1 - is_lt
        // * is_le = 1 - is_gt
        // * is_jump = eq * is_eq + ne * is_ne + le * is_le + ge * is_ge + lt * is_lt + gt * is_gt
        // * filter * (should_jump - is_jump) == 0
        let constr_eq = (P::ONES - ne) * is_eq;
        let constr_ne = ne * is_ne;
        let constr_le = (P::ONES - gt) * is_le;
        let constr_ge = (P::ONES - lt) * is_ge;
        let constr_gt = gt * is_gt;
        let constr_lt = lt * is_lt;
        let constr = constr_eq + constr_ne + constr_le + constr_ge + constr_lt + constr_gt;
        yield_constr.constraint(filter * (jumps_lv.should_jump - constr));
    }
}

pub fn eval_ext_circuit_branch<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    nv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let jumps_lv = lv.general.jumps();
    let filter = lv.op.branch; // `BRANCH`
    let one_extension = builder.one_extension();
    let zero_extension = builder.zero_extension();
    let norm_filter = lv.opcode_bits[2];
    let spec_filter = builder.sub_extension(one_extension, lv.opcode_bits[2]);
    let bit27_not = builder.sub_extension(one_extension, lv.opcode_bits[1]);
    let bit26_not = builder.sub_extension(one_extension, lv.opcode_bits[0]);
    let bit16_not = builder.sub_extension(one_extension, lv.rt_bits[0]);
    let is_eq = builder.mul_extension(norm_filter, bit27_not);
    let is_ne = builder.mul_extension(is_eq, lv.opcode_bits[0]);
    let is_eq = builder.mul_extension(is_eq, bit26_not);
    let is_le = builder.mul_extension(norm_filter, lv.opcode_bits[1]);
    let is_gt = builder.mul_extension(is_le, lv.opcode_bits[0]);
    let is_le = builder.mul_extension(is_le, bit26_not);
    let is_ge = builder.mul_extension(spec_filter, lv.rt_bits[0]);
    let is_lt = builder.mul_extension(spec_filter, bit16_not);
    let overflow = builder.constant_extension(F::Extension::from_canonical_u64(1 << 32));
    let overflow_inv =
        builder.constant_extension(F::Extension::from_canonical_u64(GOLDILOCKS_INVERSE_2EXP32));

    // Check `should_jump`:
    {
        let constr = builder.sub_extension(one_extension, jumps_lv.should_jump);
        let constr = builder.mul_extension(filter, constr);
        let constr = builder.mul_extension(jumps_lv.should_jump, constr);
        yield_constr.constraint(builder, constr);
    }

    // Check `branch target value`:
    // constraints:
    // * jump_dest =  sign_extended(offset << 2) + pc
    // * next_addr = pc + 8
    // * next_pc = jump_dest * should_jump + next_addr * (1 - should_jump)
    // * filter * (next_program_coutner - next_pc) == 0
    {
        let mut branch_offset = [zero_extension; 32];

        branch_offset[2..8].copy_from_slice(&lv.func_bits); // 6 bits
        branch_offset[8..13].copy_from_slice(&lv.shamt_bits); // 5 bits
        branch_offset[13..18].copy_from_slice(&lv.rd_bits); // 5 bits
        branch_offset[18..32].copy_from_slice(&[lv.rd_bits[4]; 14]); // lv.insn_bits[15]
        let offset_dst = limb_from_bits_le_recursive(builder, branch_offset.into_iter());

        let branch_dst = builder.add_extension(lv.program_counter, offset_dst);
        let next_insn = builder.add_const_extension(lv.program_counter, F::from_canonical_u64(8));
        let constr_a = builder.mul_extension(branch_dst, jumps_lv.should_jump);

        let constr_b = builder.sub_extension(one_extension, jumps_lv.should_jump);
        let constr_b = builder.mul_extension(constr_b, next_insn);
        let constr = builder.add_extension(constr_a, constr_b);
        let constr = builder.sub_extension(nv.program_counter, constr);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check Aux Reg
    // constraint:
    // * sum = aux1 + aux2
    // * filter * (1 - sum * overflow_inv) == 0
    {
        let aux1 = lv.mem_channels[2].addr_virtual;
        let aux2 = lv.mem_channels[3].addr_virtual;
        let constr = builder.add_extension(aux1, aux2);
        let constr = builder.mul_extension(constr, overflow_inv);
        let constr = builder.sub_extension(one_extension, constr);
        let constr = builder.mul_extension(constr, filter);

        yield_constr.constraint(builder, constr);
    }

    // Check rs Reg
    {
        let rs_reg = lv.mem_channels[0].addr_virtual;
        let mut rs_reg_index = [one_extension; 5];
        rs_reg_index.copy_from_slice(&lv.rs_bits);
        let rs_src = limb_from_bits_le_recursive(builder, rs_reg_index.into_iter());
        let constr = builder.sub_extension(rs_reg, rs_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check rt Reg
    {
        let rt_reg = lv.mem_channels[1].addr_virtual;
        let rt_src = limb_from_bits_le_recursive(builder, lv.rt_bits.into_iter());
        let constr = builder.sub_extension(rt_reg, rt_src);
        let constr = builder.mul_extension(constr, norm_filter);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);

        let constr = builder.mul_extension(rt_reg, spec_filter);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check Condition
    {
        let src1 = lv.mem_channels[0].value[0];
        let src2 = lv.mem_channels[1].value[0];
        let aux1 = lv.mem_channels[2].value[0];
        let aux2 = lv.mem_channels[3].value[0];

        // constraints:
        // * z = src2 + aux - src1
        // * filter * z * (overflow - z) == 0
        // * is_lt = z * overflow_inv
        // * filter * lt * (1 - is_lt) == 0
        // where aux = src1 - src2 in u32, overflow - 2^32, overflow_inv = 2^-32
        let diff_a = builder.add_extension(src2, aux1);
        let diff_a = builder.sub_extension(diff_a, src1);
        let constr_a = builder.sub_extension(overflow, diff_a);
        let constr_a = builder.mul_extension(constr_a, diff_a);
        let constr_a = builder.mul_extension(constr_a, filter);
        yield_constr.constraint(builder, constr_a);
        let lt = builder.mul_extension(overflow_inv, diff_a);
        let constr = builder.sub_extension(one_extension, lt);
        let constr = builder.mul_extension(constr, lt);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);

        // constraints:
        // * z = src1 + aux - src2
        // * filter * z * (overflow - z) == 0
        // * is_gt = z * overflow_inv
        // * filter * gt * (1 - is_gt) == 0
        // where aux = src2 - src1 in u32, overflow - 2^32, overflow_inv = 2^-32
        let diff_b = builder.add_extension(src1, aux2);
        let diff_b = builder.sub_extension(diff_b, src2);
        let constr_b = builder.sub_extension(overflow, diff_b);
        let constr_b = builder.mul_extension(constr_b, diff_b);
        let constr_b = builder.mul_extension(constr_b, filter);
        yield_constr.constraint(builder, constr_b);
        let gt = builder.mul_extension(overflow_inv, diff_b);
        let constr = builder.sub_extension(one_extension, gt);
        let constr = builder.mul_extension(constr, gt);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);

        // constraints:
        // * is_ne = is_lt + is_gt
        // * filter * ne * (1 - is_ne) == 0
        let ne = builder.add_extension(lt, gt);
        let constr = builder.sub_extension(one_extension, ne);
        let constr = builder.mul_extension(constr, ne);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);

        // constraints:
        // * is_eq = 1 - is_ne
        // * is_ge = 1 - is_lt
        // * is_le = 1 - is_gt
        // * is_jump = eq * is_eq + ne * is_ne + le * is_le + ge * is_ge + lt * is_lt + gt * is_gt
        // * filter * (should_jump - is_jump) == 0
        let constr_eq = builder.sub_extension(one_extension, ne);
        let constr_eq = builder.mul_extension(constr_eq, is_eq);
        let constr_ne = builder.mul_extension(ne, is_ne);
        let constr_le = builder.sub_extension(one_extension, gt);
        let constr_le = builder.mul_extension(constr_le, is_le);
        let constr_ge = builder.sub_extension(one_extension, lt);
        let constr_ge = builder.mul_extension(constr_ge, is_ge);
        let constr_gt = builder.mul_extension(gt, is_gt);
        let constr_lt = builder.mul_extension(lt, is_lt);

        let constr = builder.add_extension(constr_eq, constr_ne);
        let constr = builder.add_extension(constr, constr_le);
        let constr = builder.add_extension(constr, constr_ge);
        let constr = builder.add_extension(constr, constr_lt);
        let constr = builder.add_extension(constr, constr_gt);
        let constr = builder.sub_extension(jumps_lv.should_jump, constr);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }
}

pub fn eval_packed_condmov<P: PackedField>(
    lv: &CpuColumnsView<P>,
    nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let rs = lv.mem_channels[0].value[0]; // rs
    let rt = lv.mem_channels[1].value[0]; // rt
    let rd = lv.mem_channels[2].value[0]; // rd
    let out = lv.mem_channels[3].value[0]; // out
    let filter = lv.op.condmov_op;
    let is_movn = lv.func_bits[0];
    let is_movz = P::ONES - lv.func_bits[0];

    // constraints:
    // * is_ne = p_inv0 * rt
    // * filter * (is_ne * (1 - is_ne)) == 0
    // * is_mov = is_ne * is_movn + (1 - is_ne) * is_movz
    // * filter * is_mov * (1 - is_mov) == 0
    // * res = is_mov * rs + (1 - is_mov) * rd
    // * filter * (out - res) == 0
    {
        let p_inv0 = lv.general.logic().diff_pinv[0]; // rt^-1
        let is_ne = p_inv0 * rt;
        let is_eq = P::ONES - is_ne;
        yield_constr.constraint(filter * is_eq * is_ne);

        let is_mov = is_ne * is_movn + is_eq * is_movz;
        yield_constr.constraint(filter * is_mov * (P::ONES - is_mov));

        yield_constr.constraint(filter * (out - (is_mov * rs + (P::ONES - is_mov) * rd)));
    }
}

pub fn eval_ext_circuit_condmov<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    nv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let rs = lv.mem_channels[0].value[0]; // rs
    let rt = lv.mem_channels[1].value[0]; // rt
    let rd = lv.mem_channels[2].value[0]; // rd
    let out = lv.mem_channels[3].value[0]; // out
    let filter = lv.op.condmov_op;
    let is_movn = lv.func_bits[0];
    let one_extension = builder.one_extension();
    let is_movz = builder.sub_extension(one_extension, lv.func_bits[0]);

    // constraints:
    // * is_ne = p_inv0 * rt
    // * filter * (is_ne * (1 - is_ne)) == 0
    // * is_mov = is_ne * is_movn + (1 - is_ne) * is_movz
    // * filter * is_mov * (1 - is_mov) == 0
    // * res = is_mov * rs + (1 - is_mov) * rd
    // * filter * (out - res) == 0
    {
        let p_inv0 = lv.general.logic().diff_pinv[0]; // rt^-1
        let is_ne = builder.mul_extension(p_inv0, rt);
        let is_eq = builder.sub_extension(one_extension, is_ne);
        let constr = builder.mul_extension(is_eq, is_ne);
        let constr = builder.mul_extension(filter, constr);
        yield_constr.constraint(builder, constr);

        let is_movn_mov = builder.mul_extension(is_ne, is_movn);
        let is_movz_mov = builder.mul_extension(is_eq, is_movz);
        let is_mov = builder.add_extension(is_movn_mov, is_movz_mov);
        let no_mov = builder.sub_extension(one_extension, is_mov);
        let constr = builder.mul_extension(is_mov, no_mov);
        let constr = builder.mul_extension(filter, constr);
        yield_constr.constraint(builder, constr);

        let constr_a = builder.mul_extension(is_mov, rs);
        let constr_b = builder.mul_extension(no_mov, rd);
        let constr = builder.add_extension(constr_a, constr_b);
        let constr = builder.sub_extension(out, constr);
        let constr = builder.mul_extension(filter, constr);
        yield_constr.constraint(builder, constr);
    }
}

pub fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    eval_packed_exit_kernel(lv, nv, yield_constr);
    eval_packed_jump_jumpi(lv, nv, yield_constr);
    eval_packed_branch(lv, nv, yield_constr);
    eval_packed_condmov(lv, nv, yield_constr);
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    nv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    eval_ext_circuit_exit_kernel(builder, lv, nv, yield_constr);
    eval_ext_circuit_jump_jumpi(builder, lv, nv, yield_constr);
    eval_ext_circuit_branch(builder, lv, nv, yield_constr);
    eval_ext_circuit_condmov(builder, lv, nv, yield_constr);
}
