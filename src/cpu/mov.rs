use plonky2::field::packed::PackedField;
use crate::constraint_consumer::ConstraintConsumer;
use crate::cpu::columns::CpuColumnsView;
use crate::util::limb_from_bits_le;

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
        let mov_src_val = limb_from_bits_le(mov_src_reg_index.into_iter());
        yield_constr.constraint(mov_src_val - mov_src_reg);

        yield_constr.constraint(is_zero_mov_filter * (mov_dst_reg - mov_src_reg));
        yield_constr.constraint(is_non_zero_mov_filter * (mov_dst_reg - mov_src_reg));
    }
}