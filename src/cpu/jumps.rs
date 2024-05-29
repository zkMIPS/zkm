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

pub fn eval_packed_jump_jumpi<P: PackedField>(
    lv: &CpuColumnsView<P>,
    nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let is_jump = lv.op.jumps;
    let is_jumpi = lv.op.jumpi;
    let is_jumpdirect = lv.op.jumpdirect;

    let is_link = is_jump * lv.func_bits[0];
    let is_linki = is_jumpi * lv.opcode_bits[0];

    // Check `jump target value`:
    // constraint: is_jump * (next_program_counter - reg[rs]) == 0
    {
        let reg_dst = lv.mem_channels[0].value;
        yield_constr.constraint(is_jump * (nv.next_program_counter - reg_dst));
    }

    // Check `jump target register`:
    // constraint: is_jump *(jump_reg - rs) == 0
    {
        let jump_reg = lv.mem_channels[0].addr_virtual;
        let jump_dst = limb_from_bits_le(lv.rs_bits);
        yield_constr.constraint(is_jump * (jump_dst - jump_reg));
    }

    // Check `jumpi target value`:
    // constraint:
    // * jump_dest =  offset << 2 + pc_remain
    // * is_jumpi * (next_program_coutner - jump_dest) == 0
    // * where pc_remain is  pc[28..32] << 28
    {
        let mut jump_imm = [P::ZEROS; 28];
        jump_imm[2..8].copy_from_slice(&lv.func_bits);
        jump_imm[8..13].copy_from_slice(&lv.shamt_bits);
        jump_imm[13..18].copy_from_slice(&lv.rd_bits);
        jump_imm[18..23].copy_from_slice(&lv.rt_bits);
        jump_imm[23..28].copy_from_slice(&lv.rs_bits);

        let imm_dst = limb_from_bits_le(jump_imm);
        let pc_remain = lv.mem_channels[2].value;
        let jump_dest = pc_remain + imm_dst;
        yield_constr.constraint(is_jumpi * (nv.next_program_counter - jump_dest));
    }

    // Check `jumpdirect target value`:
    // constraint:
    // * jump_dest =  offset << 2 + pc
    // * is_jumpdirect * (next_program_coutner - jump_dest) == 0
    {
        let aux = lv.mem_channels[2].value;
        let overflow = P::Scalar::from_canonical_u64(1 << 32);
        let mut jump_offset = [P::ZEROS; 32];

        jump_offset[2..8].copy_from_slice(&lv.func_bits); // 6 bits
        jump_offset[8..13].copy_from_slice(&lv.shamt_bits); // 5 bits
        jump_offset[13..18].copy_from_slice(&lv.rd_bits); // 5 bits
        jump_offset[18..32].copy_from_slice(&[lv.rd_bits[4]; 14]); // lv.insn_bits[15]

        let offset_dst = limb_from_bits_le(jump_offset);

        yield_constr.constraint(is_jumpdirect * (aux - offset_dst));

        let jump_dst = lv.program_counter + P::Scalar::from_canonical_u8(4) + aux;

        yield_constr.constraint(
            is_jumpdirect
                * (nv.next_program_counter - jump_dst)
                * (nv.next_program_counter + overflow - jump_dst),
        );
    }

    // Check `link/linki target value`:
    // constraint:
    // * next_addr = program_counter + 8
    // * link = is_link + is_linki + is_jumpdirect
    // * link * (ret_addr - next_addr) == 0
    {
        let link_dest = lv.mem_channels[1].value;
        yield_constr.constraint(
            (is_link + is_linki + is_jumpdirect)
                * (lv.program_counter + P::Scalar::from_canonical_u64(8) - link_dest),
        );
    }

    // Check `link target regiseter`:
    // constraint: is_link * (ret_reg - rd) == 0
    let link_reg = lv.mem_channels[1].addr_virtual;
    {
        let link_dst = limb_from_bits_le(lv.rd_bits);
        yield_constr.constraint(is_link * (link_reg - link_dst));
    }

    // Check `linki/jumpdirect target regiseter`:
    // constraint: (is_linki + is_jumpdirect) * (ret_reg - 31) == 0
    {
        yield_constr.constraint(
            (is_linki + is_jumpdirect) * (link_reg - P::Scalar::from_canonical_u64(31)),
        );
    }
}

pub fn eval_ext_circuit_jump_jumpi<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    nv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let is_jump = lv.op.jumps;
    let is_jumpi = lv.op.jumpi;
    let is_jumpdirect = lv.op.jumpdirect;

    let zero_extension = builder.zero_extension();

    let is_link = builder.mul_extension(is_jump, lv.func_bits[0]);
    let is_linki = builder.mul_extension(is_jumpi, lv.opcode_bits[0]);

    // Check `jump target value`:
    // constraint: is_jump * (next_program_coutner - reg[rs]) == 0
    {
        let reg_dst = lv.mem_channels[0].value;
        let constr = builder.sub_extension(nv.next_program_counter, reg_dst);
        let constr = builder.mul_extension(is_jump, constr);
        yield_constr.constraint(builder, constr);
    }

    // Check `jump target register`:
    // constraint: is_jump *(jump_reg - rs) == 0
    {
        let jump_reg = lv.mem_channels[0].addr_virtual;
        let jump_dst = limb_from_bits_le_recursive(builder, lv.rs_bits);
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
        let mut jump_imm = [zero_extension; 28];

        jump_imm[2..8].copy_from_slice(&lv.func_bits);
        jump_imm[8..13].copy_from_slice(&lv.shamt_bits);
        jump_imm[13..18].copy_from_slice(&lv.rd_bits);
        jump_imm[18..23].copy_from_slice(&lv.rt_bits);
        jump_imm[23..28].copy_from_slice(&lv.rs_bits);

        let jump_dest = limb_from_bits_le_recursive(builder, jump_imm);

        let constr = builder.add_extension(lv.mem_channels[2].value, jump_dest);
        let constr = builder.sub_extension(nv.next_program_counter, constr);
        let constr = builder.mul_extension(is_jumpi, constr);
        yield_constr.constraint(builder, constr);
    }

    // Check `jumpdirect target value`:
    // constraints:
    // * aux = sign_extended(offset << 2)
    // * jump_dest =  sign_extended(offset << 2) + pc + 4
    // * is_jumpdirect *(next_program_coutner - jump_dest) * (next_program_coutner + 1 << 32 - jump_dest) == 0
    {
        let aux = lv.mem_channels[2].value;
        let overflow = builder.constant_extension(F::Extension::from_canonical_u64(1 << 32));
        let mut jump_offset = [zero_extension; 32];

        jump_offset[2..8].copy_from_slice(&lv.func_bits); // 6 bits
        jump_offset[8..13].copy_from_slice(&lv.shamt_bits); // 5 bits
        jump_offset[13..18].copy_from_slice(&lv.rd_bits); // 5 bits
        jump_offset[18..32].copy_from_slice(&[lv.rd_bits[4]; 14]); // lv.insn_bits[15]
        let offset_dst = limb_from_bits_le_recursive(builder, jump_offset);

        let constr = builder.sub_extension(aux, offset_dst);
        let constr = builder.mul_extension(is_jumpdirect, constr);
        yield_constr.constraint(builder, constr);

        let base_pc = builder.add_const_extension(lv.program_counter, F::from_canonical_u64(4));
        let jump_dst = builder.add_extension(base_pc, aux);

        let overflow_target = builder.add_extension(nv.next_program_counter, overflow);
        let constr_a = builder.sub_extension(overflow_target, jump_dst);
        let constr_b = builder.sub_extension(nv.next_program_counter, jump_dst);
        let constr = builder.mul_extension(is_jumpdirect, constr_a);
        let constr = builder.mul_extension(constr, constr_b);
        yield_constr.constraint(builder, constr);
    }

    // Check `link/linki target value`:
    // constraint:
    // * next_addr = program_counter + 8
    // * link = is_link + is_linki
    // * link * (ret_addr - next_addr) == 0
    {
        let link_dst = lv.mem_channels[1].value;
        let link_dest = builder.add_const_extension(lv.program_counter, F::from_canonical_u64(8));
        let constr = builder.sub_extension(link_dest, link_dst);
        let is_link = builder.add_extension(is_link, is_linki);
        let is_link = builder.add_extension(is_link, is_jumpdirect);
        let constr = builder.mul_extension(is_link, constr);
        yield_constr.constraint(builder, constr);
    }

    // Check `link target register`:
    // constraint: is_link * (ret_reg - rd) == 0
    let link_reg = lv.mem_channels[1].addr_virtual;
    {
        let link_dst = limb_from_bits_le_recursive(builder, lv.rd_bits);
        let constr = builder.sub_extension(link_reg, link_dst);
        let constr = builder.mul_extension(constr, is_link);
        yield_constr.constraint(builder, constr);
    }

    // Check `linki target register`
    // constraint: (is_linki + is_jumpdirect) * (ret_reg - 31) == 0
    {
        let reg_31 = builder.constant_extension(F::Extension::from_canonical_u64(31));
        let constr = builder.sub_extension(link_reg, reg_31);
        let link31 = builder.add_extension(is_jumpdirect, is_linki);
        let constr = builder.mul_extension(constr, link31);
        yield_constr.constraint(builder, constr);
    }
}

pub fn eval_packed_branch<P: PackedField>(
    lv: &CpuColumnsView<P>,
    nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let branch_lv = lv.branch;

    let filter = lv.op.branch; // `BRANCH`
    let is_eq = branch_lv.is_eq;
    let is_ne = branch_lv.is_ne;
    let is_le = branch_lv.is_le;
    let is_gt = branch_lv.is_gt;
    let is_ge = branch_lv.is_ge;
    let is_lt = branch_lv.is_lt;
    let norm_filter = is_eq + is_ne + is_le + is_gt;
    let special_filter = is_ge + is_lt;
    let src1 = lv.mem_channels[0].value;
    let src2 = lv.mem_channels[1].value;
    let aux1 = lv.mem_channels[2].value; // src1 - src2
    let aux2 = lv.mem_channels[3].value; // src2 - src1
    let aux3 = lv.mem_channels[4].value; // (src1 ^ src2) & 0x80000000 > 0
    let aux4 = lv.mem_channels[5].value; // branch offset

    let overflow = P::Scalar::from_canonical_u64(1 << 32);
    let overflow_inv = P::Scalar::from_canonical_u64(GOLDILOCKS_INVERSE_2EXP32);

    // Check `should_jump`:
    // constraint:
    //      (1 - should_jump) * should_jump == 0
    //      should_jump * (1 - filter) == 0

    yield_constr.constraint(branch_lv.should_jump * (P::ONES - branch_lv.should_jump));
    yield_constr.constraint(branch_lv.should_jump * (P::ONES - filter));

    // Check branch flags:
    //      filter * (1 - (is_eq + is_ne + is_le + is_gt + is_ge + is_lt)) == 0
    //      filter * (1 - (lt + gt + eq)) == 0
    yield_constr.constraint(filter * (P::ONES - (norm_filter + special_filter)));
    yield_constr.constraint(filter * (P::ONES - (branch_lv.lt + branch_lv.gt + branch_lv.eq)));

    // Check `branch target value`:
    // constraints:
    // * aux4 = sign_extended(offset << 2)
    // * jump_dest =  sign_extended(offset << 2) + pc + 4
    // * should_jump *(next_program_coutner - jump_dest) * (next_program_coutner + 1 << 32 - jump_dest) == 0
    // * next_addr = pc + 8
    // * filter * (1 - should_jump) * (next_program_coutner - next_pc) == 0
    {
        let mut branch_offset = [P::ZEROS; 32];

        branch_offset[2..8].copy_from_slice(&lv.func_bits); // 6 bits
        branch_offset[8..13].copy_from_slice(&lv.shamt_bits); // 5 bits
        branch_offset[13..18].copy_from_slice(&lv.rd_bits); // 5 bits
        branch_offset[18..32].copy_from_slice(&[lv.rd_bits[4]; 14]); // lv.insn_bits[15]

        let offset_dst = limb_from_bits_le(branch_offset);

        yield_constr.constraint(filter * (aux4 - offset_dst));

        let branch_dst = lv.program_counter + P::Scalar::from_canonical_u8(4) + aux4;

        yield_constr.constraint(
            branch_lv.should_jump
                * (nv.next_program_counter - branch_dst)
                * (nv.next_program_counter + overflow - branch_dst),
        );

        let next_inst = lv.program_counter + P::Scalar::from_canonical_u64(8);
        yield_constr.constraint(
            filter * (P::ONES - branch_lv.should_jump) * (nv.next_program_counter - next_inst),
        );
    }

    // Check Aux Reg
    // constraint:
    // * sum = aux1 + aux2
    // * filter * aux1 * (sum - overflow) == 0
    // * filter * aux3 * (1 - aux3) == 0
    {
        yield_constr.constraint(filter * (aux1 + src2 - src1) * (aux1 + src2 - src1 - overflow));
        yield_constr.constraint(filter * (aux2 + src1 - src2) * (aux2 + src1 - src2 - overflow));
        yield_constr.constraint(filter * aux1 * ((aux1 + aux2) - overflow));

        yield_constr.constraint(filter * aux3 * (P::ONES - aux3));
    }

    // Check rs Reg
    // constraint: filter * (src1_reg - rs) == 0
    {
        let rs_reg = lv.mem_channels[0].addr_virtual;
        let rs_src = limb_from_bits_le(lv.rs_bits);
        yield_constr.constraint(filter * (rs_reg - rs_src));
    }

    // Check rt Reg
    // constraint: filter * (src2_reg - rt) == 0
    {
        let rt_reg = lv.mem_channels[1].addr_virtual;
        let rt_src = limb_from_bits_le(lv.rt_bits);
        yield_constr.constraint(norm_filter * (rt_reg - rt_src));
        yield_constr.constraint(special_filter * rt_reg * (P::ONES - rt_reg));
    }

    // Check Condition
    {
        // constraints:
        // * z = src2 + aux - src1
        // * filter * z * (overflow - z) == 0
        // * is_lt = z * overflow_inv
        // * branch_lv.lt * (1 - is_lt) == 0
        // where aux = src1 - src2 in u32, overflow - 2^32, overflow_inv = 2^-32
        let constr_a = src2 + aux1 - src1;
        yield_constr.constraint(filter * constr_a * (overflow - constr_a));

        let lt = constr_a * overflow_inv;
        yield_constr.constraint(branch_lv.lt * (P::ONES - lt));

        // constraints:
        // * z = src1 + aux - src2
        // * filter * z * (overflow - z) == 0
        // * is_gt = z * overflow_inv
        // * branch_lv.gt * (1 - is_gt) == 0
        // where aux = src2 - src1 in u32, overflow - 2^32, overflow_inv = 2^-32
        let constr_b = src1 + aux2 - src2;
        yield_constr.constraint(filter * constr_b * (overflow - constr_b));

        let gt = constr_b * overflow_inv;
        yield_constr.constraint(branch_lv.gt * (P::ONES - gt));

        // constraints:
        // * is_ne = is_lt + is_gt
        // * branch_lv.eq * ne == 0
        let ne = lt + gt;
        yield_constr.constraint(branch_lv.eq * ne);

        // invert lt/gt if aux3 = 1 (src1 and src2 have different sign bits)
        let lt = branch_lv.lt * (P::ONES - aux3) + (P::ONES - branch_lv.lt) * aux3;
        let gt = branch_lv.gt * (P::ONES - aux3) + (P::ONES - branch_lv.gt) * aux3;

        // constraints:
        // * is_eq * (1 - filter) = 0
        // * is_eq * (should_jump  - (1 - ne)) == 0
        yield_constr.constraint(is_eq * (P::ONES - filter));
        yield_constr.constraint(is_eq * (branch_lv.should_jump - (P::ONES - ne)));

        yield_constr.constraint(is_ne * (P::ONES - filter));
        yield_constr.constraint(is_ne * (branch_lv.should_jump - ne));

        yield_constr.constraint(is_le * (P::ONES - filter));
        yield_constr.constraint(is_le * (branch_lv.should_jump - (P::ONES - gt)));

        yield_constr.constraint(is_ge * (P::ONES - filter));
        yield_constr.constraint(is_ge * (branch_lv.should_jump - (P::ONES - lt)));

        yield_constr.constraint(is_gt * (P::ONES - filter));
        yield_constr.constraint(is_gt * (branch_lv.should_jump - gt));

        yield_constr.constraint(is_lt * (P::ONES - filter));
        yield_constr.constraint(is_lt * (branch_lv.should_jump - lt));
    }
}

pub fn eval_ext_circuit_branch<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    nv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let branch_lv = lv.branch;
    let filter = lv.op.branch; // `BRANCH`
    let one_extension = builder.one_extension();
    let zero_extension = builder.zero_extension();
    let is_eq = branch_lv.is_eq;
    let is_ne = branch_lv.is_ne;
    let is_le = branch_lv.is_le;
    let is_gt = branch_lv.is_gt;
    let is_ge = branch_lv.is_ge;
    let is_lt = branch_lv.is_lt;

    let src1 = lv.mem_channels[0].value;
    let src2 = lv.mem_channels[1].value;
    let aux1 = lv.mem_channels[2].value; // src1 - src2
    let aux2 = lv.mem_channels[3].value; // src2 - src1
    let aux3 = lv.mem_channels[4].value; // (src1 ^ src2) & 0x80000000 > 0
    let aux4 = lv.mem_channels[5].value; // branch offset

    let norm_filter = builder.add_extension(is_eq, is_ne);
    let norm_filter = builder.add_extension(norm_filter, is_le);
    let norm_filter = builder.add_extension(norm_filter, is_gt);
    let special_filter = builder.add_extension(is_ge, is_lt);
    let overflow = builder.constant_extension(F::Extension::from_canonical_u64(1 << 32));
    let overflow_inv =
        builder.constant_extension(F::Extension::from_canonical_u64(GOLDILOCKS_INVERSE_2EXP32));

    // Check `should_jump`:
    {
        let constr = builder.sub_extension(one_extension, branch_lv.should_jump);
        let constr = builder.mul_extension(branch_lv.should_jump, constr);
        yield_constr.constraint(builder, constr);

        let constr = builder.sub_extension(one_extension, filter);
        let constr = builder.mul_extension(branch_lv.should_jump, constr);
        yield_constr.constraint(builder, constr);
    }

    // Check branch flags:
    {
        let constr = builder.add_extension(norm_filter, special_filter);
        let constr = builder.sub_extension(one_extension, constr);
        let constr = builder.mul_extension(filter, constr);
        yield_constr.constraint(builder, constr);

        let constr = builder.add_extension(branch_lv.lt, branch_lv.gt);
        let constr = builder.add_extension(constr, branch_lv.eq);
        let constr = builder.sub_extension(one_extension, constr);
        let constr = builder.mul_extension(filter, constr);
        yield_constr.constraint(builder, constr);
    }

    // Check `branch target value`:
    // constraints:
    // * aux4 = sign_extended(offset << 2)
    // * jump_dest =  sign_extended(offset << 2) + pc + 4
    // * filter * should_jump *(next_program_coutner - jump_dest) * (next_program_coutner + 1 << 32 - jump_dest) == 0
    // * next_addr = pc + 8
    // * filter * (1 - should_jump) * (next_program_coutner - next_pc) == 0
    {
        let mut branch_offset = [zero_extension; 32];

        branch_offset[2..8].copy_from_slice(&lv.func_bits); // 6 bits
        branch_offset[8..13].copy_from_slice(&lv.shamt_bits); // 5 bits
        branch_offset[13..18].copy_from_slice(&lv.rd_bits); // 5 bits
        branch_offset[18..32].copy_from_slice(&[lv.rd_bits[4]; 14]); // lv.insn_bits[15]
        let offset_dst = limb_from_bits_le_recursive(builder, branch_offset);

        let constr = builder.sub_extension(aux4, offset_dst);
        let constr = builder.mul_extension(filter, constr);
        yield_constr.constraint(builder, constr);

        let base_pc = builder.add_const_extension(lv.program_counter, F::from_canonical_u64(4));
        let branch_dst = builder.add_extension(base_pc, aux4);

        let overflow_target = builder.add_extension(nv.next_program_counter, overflow);
        let constr_a = builder.sub_extension(overflow_target, branch_dst);
        let constr_b = builder.sub_extension(nv.next_program_counter, branch_dst);
        let constr = builder.mul_extension(branch_lv.should_jump, constr_a);
        let constr = builder.mul_extension(constr, constr_b);
        yield_constr.constraint(builder, constr);

        let next_insn = builder.add_const_extension(lv.program_counter, F::from_canonical_u64(8));
        let constr_a = builder.sub_extension(one_extension, branch_lv.should_jump);
        let constr_b = builder.sub_extension(nv.next_program_counter, next_insn);
        let constr = builder.mul_extension(constr_a, constr_b);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check Aux Reg
    // constraint:
    // * sum = aux1 + aux2
    // * filter * aux1 * (sum - overflow) == 0
    // * filter * aux3 * (1 - aux3) == 0
    {
        let constr_a = builder.add_extension(aux1, src2);
        let constr_a = builder.sub_extension(constr_a, src1);
        let constr_b = builder.sub_extension(constr_a, overflow);
        let constr = builder.mul_extension(constr_a, constr_b);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);

        let constr_a = builder.add_extension(aux2, src1);
        let constr_a = builder.sub_extension(constr_a, src2);
        let constr_b = builder.sub_extension(constr_a, overflow);
        let constr = builder.mul_extension(constr_a, constr_b);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);

        let constr = builder.add_extension(aux1, aux2);
        let constr = builder.sub_extension(constr, overflow);
        let constr = builder.mul_extension(aux1, constr);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);

        let constr = builder.sub_extension(one_extension, aux3);
        let constr = builder.mul_extension(filter, constr);
        let constr = builder.mul_extension(aux3, constr);
        yield_constr.constraint(builder, constr);
    }

    // Check rs Reg
    {
        let rs_reg = lv.mem_channels[0].addr_virtual;
        let mut rs_reg_index = [one_extension; 5];
        rs_reg_index.copy_from_slice(&lv.rs_bits);
        let rs_src = limb_from_bits_le_recursive(builder, rs_reg_index);
        let constr = builder.sub_extension(rs_reg, rs_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check rt Reg
    {
        let rt_reg = lv.mem_channels[1].addr_virtual;
        let rt_src = limb_from_bits_le_recursive(builder, lv.rt_bits);
        let constr = builder.sub_extension(rt_reg, rt_src);
        let constr = builder.mul_extension(constr, norm_filter);
        yield_constr.constraint(builder, constr);

        let constr = builder.sub_extension(one_extension, rt_reg);
        let constr = builder.mul_extension(constr, rt_reg);
        let constr = builder.mul_extension(constr, special_filter);
        yield_constr.constraint(builder, constr);
    }

    // Check Condition
    {
        let src1 = lv.mem_channels[0].value;
        let src2 = lv.mem_channels[1].value;
        let aux1 = lv.mem_channels[2].value;
        let aux2 = lv.mem_channels[3].value;
        let aux3 = lv.mem_channels[4].value;

        // constraints:
        // * z = src2 + aux - src1
        // * filter * z * (overflow - z) == 0
        // * is_lt = z * overflow_inv
        // * branch_lv.lt * (1 - is_lt) == 0
        // where aux = src1 - src2 in u32, overflow - 2^32, overflow_inv = 2^-32
        let diff_a = builder.add_extension(src2, aux1);
        let diff_a = builder.sub_extension(diff_a, src1);
        let constr_a = builder.sub_extension(overflow, diff_a);
        let constr_a = builder.mul_extension(constr_a, diff_a);
        let constr_a = builder.mul_extension(constr_a, filter);
        yield_constr.constraint(builder, constr_a);

        let lt = builder.mul_extension(diff_a, overflow_inv);
        let constr = builder.sub_extension(one_extension, lt);
        let constr = builder.mul_extension(constr, branch_lv.lt);
        yield_constr.constraint(builder, constr);

        // constraints:
        // * z = src1 + aux - src2
        // * filter * z * (overflow - z) == 0
        // * is_gt = z * overflow_inv
        // * branch_lv.gt * (1 - is_gt) == 0
        // where aux = src2 - src1 in u32, overflow - 2^32, overflow_inv = 2^-32
        let diff_b = builder.add_extension(src1, aux2);
        let diff_b = builder.sub_extension(diff_b, src2);
        let constr_b = builder.sub_extension(overflow, diff_b);
        let constr_b = builder.mul_extension(constr_b, diff_b);
        let constr_b = builder.mul_extension(constr_b, filter);
        yield_constr.constraint(builder, constr_b);

        let gt = builder.mul_extension(diff_b, overflow_inv);
        let constr = builder.sub_extension(one_extension, gt);
        let constr = builder.mul_extension(constr, branch_lv.gt);
        yield_constr.constraint(builder, constr);

        // constraints:
        // * is_ne = is_lt + is_gt
        // * branch_lv.eq * ne == 0
        let ne = builder.add_extension(lt, gt);
        let constr = builder.mul_extension(branch_lv.eq, ne);
        yield_constr.constraint(builder, constr);

        // invert lt/gt if aux3 = 1 (src1 and src2 have different sign bits)
        let inv_aux3 = builder.sub_extension(one_extension, aux3);
        let inv_lt = builder.sub_extension(one_extension, branch_lv.lt);
        let inv_gt = builder.sub_extension(one_extension, branch_lv.gt);
        let lt_norm = builder.mul_extension(branch_lv.lt, inv_aux3);
        let lt_inv = builder.mul_extension(inv_lt, aux3);
        let lt = builder.add_extension(lt_norm, lt_inv);
        let gt_norm = builder.mul_extension(branch_lv.gt, inv_aux3);
        let gt_inv = builder.mul_extension(inv_gt, aux3);
        let gt = builder.add_extension(gt_norm, gt_inv);

        // constraints:
        // * is_eq * (1 - filter) = 0
        // * is_eq * (should_jump  - (1 - ne)) == 0
        let constr_eq = builder.sub_extension(one_extension, filter);
        let constr_eq = builder.mul_extension(constr_eq, is_eq);
        yield_constr.constraint(builder, constr_eq);

        let eq = builder.sub_extension(one_extension, ne);
        let constr_eq = builder.sub_extension(branch_lv.should_jump, eq);
        let constr_eq = builder.mul_extension(constr_eq, is_eq);
        yield_constr.constraint(builder, constr_eq);

        let constr_ne = builder.sub_extension(one_extension, filter);
        let constr_ne = builder.mul_extension(constr_ne, is_ne);
        yield_constr.constraint(builder, constr_ne);

        let constr_ne = builder.sub_extension(branch_lv.should_jump, ne);
        let constr_ne = builder.mul_extension(constr_ne, is_ne);
        yield_constr.constraint(builder, constr_ne);

        let constr_le = builder.sub_extension(one_extension, filter);
        let constr_le = builder.mul_extension(constr_le, is_le);
        yield_constr.constraint(builder, constr_le);

        let le = builder.sub_extension(one_extension, gt);
        let constr_le = builder.sub_extension(branch_lv.should_jump, le);
        let constr_le = builder.mul_extension(constr_le, is_le);
        yield_constr.constraint(builder, constr_le);

        let constr_ge = builder.sub_extension(one_extension, filter);
        let constr_ge = builder.mul_extension(constr_ge, is_ge);
        yield_constr.constraint(builder, constr_ge);

        let ge = builder.sub_extension(one_extension, lt);
        let constr_ge = builder.sub_extension(branch_lv.should_jump, ge);
        let constr_ge = builder.mul_extension(constr_ge, is_ge);
        yield_constr.constraint(builder, constr_ge);

        let constr_gt = builder.sub_extension(one_extension, filter);
        let constr_gt = builder.mul_extension(constr_gt, is_gt);
        yield_constr.constraint(builder, constr_gt);

        let constr_gt = builder.sub_extension(branch_lv.should_jump, gt);
        let constr_gt = builder.mul_extension(constr_gt, is_gt);
        yield_constr.constraint(builder, constr_gt);

        let constr_lt = builder.sub_extension(one_extension, filter);
        let constr_lt = builder.mul_extension(constr_lt, is_lt);
        yield_constr.constraint(builder, constr_lt);

        let constr_lt = builder.sub_extension(branch_lv.should_jump, lt);
        let constr_lt = builder.mul_extension(constr_lt, is_lt);
        yield_constr.constraint(builder, constr_lt);
    }
}

pub fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    //eval_packed_exit_kernel(lv, nv, yield_constr);
    eval_packed_jump_jumpi(lv, nv, yield_constr);
    eval_packed_branch(lv, nv, yield_constr);
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    nv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    //eval_ext_circuit_exit_kernel(builder, lv, nv, yield_constr);
    eval_ext_circuit_jump_jumpi(builder, lv, nv, yield_constr);
    eval_ext_circuit_branch(builder, lv, nv, yield_constr);
}
