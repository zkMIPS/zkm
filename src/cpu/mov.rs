use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::columns::CpuColumnsView;
use crate::util::{limb_from_bits_le, limb_from_bits_le_recursive};

pub fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let filter = lv.op.condmov_op; // `MOVZ` or `MOVN`

    let is_zero_mov_filter = filter * lv.insn_bits[16];
    let is_non_zero_mov_filter = filter * (P::ONES - lv.insn_bits[16]);

    // Check `mov target register`:
    {
        let mov_dst_reg = lv.mem_channels[2].value[0];
        let mut mov_dst_reg_index = [P::ONES; 5];
        mov_dst_reg_index.copy_from_slice(lv.insn_bits[11..16].as_ref());
        let mov_dst_val = limb_from_bits_le(mov_dst_reg_index.into_iter());
        yield_constr.constraint(mov_dst_val - mov_dst_reg);

        let mov_src_reg = lv.mem_channels[0].value[0];
        let mut mov_src_reg_index = [P::ONES; 5];
        mov_src_reg_index.copy_from_slice(lv.insn_bits[21..26].as_ref());
        let mov_src_val = limb_from_bits_le(mov_src_reg_index.into_iter());
        yield_constr.constraint(mov_src_val - mov_src_reg);

        yield_constr.constraint(is_zero_mov_filter * (mov_dst_reg - mov_src_reg));
        yield_constr.constraint(is_non_zero_mov_filter * (mov_dst_reg - mov_src_reg));
    }
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let filter = lv.op.condmov_op; // `MOVZ` or `MOVN`
    let one_extension = builder.one_extension();
    let is_zero_mov_filter = builder.mul_extension(one_extension, lv.insn_bits[16]);
    let is_zero_mov_filter = builder.mul_extension(filter, is_zero_mov_filter);

    let is_non_zero_mov_filter = builder.sub_extension(one_extension, lv.insn_bits[16]);
    let is_non_zero_mov_filter = builder.mul_extension(filter, is_non_zero_mov_filter);

    // Check `mov target register`:
    {
        let mov_dst_reg = lv.mem_channels[2].value[0];
        let mut mov_dst_reg_index = [one_extension; 5];
        mov_dst_reg_index.copy_from_slice(lv.insn_bits[11..16].as_ref());
        let mov_dst_val = limb_from_bits_le_recursive(builder, mov_dst_reg_index.into_iter());
        let constr = builder.sub_extension(mov_dst_val,mov_dst_reg);
        yield_constr.constraint(builder, constr);

        let mov_src_reg = lv.mem_channels[0].value[0];
        let mut mov_src_reg_index = [one_extension; 5];
        mov_src_reg_index.copy_from_slice(lv.insn_bits[21..26].as_ref());
        let mov_src_val = limb_from_bits_le_recursive(builder,mov_src_reg_index.into_iter());
        let constr = builder.sub_extension(mov_src_val, mov_src_reg);
        yield_constr.constraint(builder, constr);

        let constr = builder.sub_extension(mov_dst_reg, mov_src_reg);
        let constr = builder.mul_extension(is_zero_mov_filter, constr);
        yield_constr.constraint(builder, constr);

        let constr = builder.sub_extension(mov_dst_reg, mov_src_reg);
        let constr = builder.mul_extension(is_non_zero_mov_filter, constr);
        yield_constr.constraint(builder, constr);
    }
}