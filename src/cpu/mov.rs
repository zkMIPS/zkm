use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::columns::CpuColumnsView;
use crate::util::{limb_from_bits_le, limb_from_bits_le_recursive};
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;

pub fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let filter = lv.op.condmov_op; // `MOVZ` or `MOVN`

    let is_zero_mov_filter = filter * lv.insn_bits[16];
    let is_non_zero_mov_filter = filter * (P::ONES - lv.insn_bits[16]);
    // rt*(rd-rs)+(1-rt)*(rd-rs)=0
    // Check `mov target register`:
    {
        let mov_dst_val = lv.mem_channels[2].value[0];
        let mov_src_val = lv.mem_channels[0].value[0];

        yield_constr.constraint(
            is_zero_mov_filter * (mov_dst_val - mov_src_val)
                + is_non_zero_mov_filter * (mov_dst_val - mov_src_val),
        );
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
        let mov_dst_val = lv.mem_channels[2].value[0];
        let mov_src_val = lv.mem_channels[0].value[0];
        let diff_val = builder.sub_extension(mov_dst_val, mov_src_val);

        let left = builder.mul_extension(is_zero_mov_filter, diff_val);
        let right = builder.mul_extension(is_non_zero_mov_filter, diff_val);

        let constr = builder.add_extension(left, right);
        yield_constr.constraint(builder, constr);
    }
}
