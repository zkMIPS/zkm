use elf::abi::R_ARM_JUMP24;
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2_evm::util::limb_from_bits_le_recursive;
//use plonky2_evm::util::limb_from_bits_le;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::membus::NUM_GP_CHANNELS;
use crate::memory::segments::Segment;
use crate::util::limb_from_bits_le;

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
    // yield_constr.constraint_transition(filter * (input[6] - nv.gas));
    // High limb of gas must be 0 for convenient detection of overflow.
    yield_constr.constraint(filter * input[7]);
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
    */
    {
        // High limb of gas must be 0 for convenient detection of overflow.
        let constr = builder.mul_extension(filter, input[7]);
        yield_constr.constraint(builder, constr);
    }
}

pub fn eval_packed_jump_jumpi<P: PackedField>(
    lv: &CpuColumnsView<P>,
    nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let jumps_lv = lv.general.jumps();

    let filter = lv.op.jumps; // `JUMP` or `JUMPI`
    let is_jump = filter * (P::ONES - lv.insn_bits[27]);
    let is_jumpi = filter * lv.insn_bits[27];

    let is_link = is_jump * lv.insn_bits[0];
    let is_linki = is_jumpi * lv.insn_bits[26];

    // Check `should_jump`:
    yield_constr.constraint(filter * (jumps_lv.should_jump - P::ONES));

    // Check `jump target value`:
    {
        let reg_dst = lv.mem_channels[0].value[0];
        let jump_dest = reg_dst;
        yield_constr.constraint_transition(is_jump * (nv.program_counter - jump_dest));
    }

    // Check `jump target register`:
    {
        let jump_reg = lv.mem_channels[0].addr_virtual;
        let mut jump_reg_index = [P::ONES; 5];
        jump_reg_index.copy_from_slice(lv.insn_bits[21..26].as_ref());
        let jump_dst = limb_from_bits_le(jump_reg_index.into_iter());
        yield_constr.constraint_transition(is_jump * (jump_dst - jump_reg));
    }

    // Check `jumpi target value`:
    {
        let mut jump_imm = [P::ONES; 26];
        jump_imm.copy_from_slice(lv.insn_bits[0..26].as_ref());
        let imm_dst = limb_from_bits_le(jump_imm.into_iter());
        let remain = lv.program_counter / P::Scalar::from_canonical_u64(1 << 28);
        let remain = remain * P::Scalar::from_canonical_u64(1 << 28);
        let jump_dest = remain + imm_dst * P::Scalar::from_canonical_u8(4);
        yield_constr.constraint_transition(is_jumpi * (nv.program_counter - jump_dest));
    }

    // Check `link/linki target value`:
    {
        let link_val = lv.mem_channels[1].value[0];
        let link_dest = link_val;
        yield_constr.constraint_transition(
            (is_link + is_linki)
                * (lv.program_counter + P::Scalar::from_canonical_u64(8) - link_dest),
        );
    }

    // Check `link target regiseter`:
    let link_reg = lv.mem_channels[1].addr_virtual;
    {
        let mut link_reg_index = [P::ONES; 5];
        link_reg_index.copy_from_slice(lv.insn_bits[11..16].as_ref());
        let link_dst = limb_from_bits_le(link_reg_index.into_iter());
        yield_constr.constraint_transition(is_link * (link_dst - link_reg));
    }

    // Check `linki target regiseter`:
    {
        yield_constr
            .constraint_transition(is_linki * (P::Scalar::from_canonical_u64(31) - link_reg));
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
    let is_jump = builder.sub_extension(one_extension, lv.insn_bits[27]);
    let is_jump = builder.mul_extension(filter, is_jump);
    let is_jumpi = builder.mul_extension(filter, lv.insn_bits[27]);

    let is_link = builder.mul_extension(is_jump, lv.insn_bits[0]);
    let is_linki = builder.mul_extension(is_jumpi, lv.insn_bits[26]);

    // Check `should_jump`:
    {
        let constr = builder.sub_extension(one_extension, jumps_lv.should_jump);
        let constr = builder.mul_extension(filter, constr);
        yield_constr.constraint(builder, constr);
    }

    // Check `jump target value`:
    {
        let reg_dst = lv.mem_channels[0].value[0];
        let jump_dest = builder.mul_extension(reg_dst, is_jump);
        let constr = builder.sub_extension(nv.program_counter, jump_dest);
        let constr = builder.mul_extension(is_jump, constr);
        yield_constr.constraint_transition(builder, constr);
    }

    // Check `jump target register`:
    {
        let jump_reg = lv.mem_channels[0].addr_virtual;
        let mut jump_reg_index = [one_extension; 5];
        jump_reg_index.copy_from_slice(lv.insn_bits[21..26].as_ref());
        let jump_dst = limb_from_bits_le_recursive(builder, jump_reg_index.into_iter());
        let constr = builder.sub_extension(jump_reg, jump_dst);
        let constr = builder.mul_extension(constr, is_jump);
        yield_constr.constraint_transition(builder, constr);
    }

    // Check `jumpi target value`:
    {
        let mut jump_imm = [one_extension; 26];
        jump_imm.copy_from_slice(lv.insn_bits[0..26].as_ref());
        let jump_dest = limb_from_bits_le_recursive(builder, jump_imm.into_iter());
        let jump_dest = builder.mul_const_extension(F::from_canonical_u64(4), jump_dest); //TO FIX

        let remain = builder.mul_const_extension(F::from_canonical_u64(1 << 28), one_extension);
        let constr = builder.div_extension(lv.program_counter, remain);
        let constr = builder.mul_extension(constr, remain);
        let constr = builder.add_extension(constr, jump_dest);
        let constr = builder.sub_extension(nv.program_counter, constr);
        let constr = builder.mul_extension(is_jumpi, constr);
        yield_constr.constraint_transition(builder, constr);
    }

    // Check `link/linki target value`:
    {
        let link_dst = lv.mem_channels[1].value[0];
        let link_dest = builder.add_const_extension(lv.program_counter, F::from_canonical_u64(8));
        let constr = builder.sub_extension(link_dst, link_dest);
        let is_link = builder.add_extension(is_link, is_linki);
        let constr = builder.mul_extension(is_link, constr);
        yield_constr.constraint_transition(builder, constr);
    }

    // Check `link target register`:
    let link_reg = lv.mem_channels[1].addr_virtual;
    {
        let mut link_reg_index = [one_extension; 5];
        link_reg_index.copy_from_slice(lv.insn_bits[11..16].as_ref());
        let link_dst = limb_from_bits_le_recursive(builder, link_reg_index.into_iter());
        let constr = builder.sub_extension(link_reg, link_dst);
        let constr = builder.mul_extension(constr, is_link);
        yield_constr.constraint_transition(builder, constr);
    }

    // Check `linki target register`
    {
        let constr_a = builder.mul_const_extension(F::from_canonical_u64(31), is_linki);
        let constr_b = builder.mul_extension(link_reg, is_linki);
        let constr = builder.sub_extension(constr_a, constr_b);
        yield_constr.constraint_transition(builder, constr);
    }
}

pub fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    eval_packed_exit_kernel(lv, nv, yield_constr);
    eval_packed_jump_jumpi(lv, nv, yield_constr);
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    nv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    eval_ext_circuit_exit_kernel(builder, lv, nv, yield_constr);
    eval_ext_circuit_jump_jumpi(builder, lv, nv, yield_constr);
}
