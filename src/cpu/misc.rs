use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::columns::CpuColumnsView;
use crate::util::{limb_from_bits_le, limb_from_bits_le_recursive};
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;

pub fn eval_packed_rdhwr<P: PackedField>(
    lv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let filter = lv.op.rdhwr;

    // Check rt Reg
    {
        let rt_reg = lv.mem_channels[0].addr_virtual;
        let rt_src = limb_from_bits_le(lv.rt_bits);
        yield_constr.constraint(filter * (rt_reg - rt_src));
    }

    // Check rd index
    {
        let rd_index = lv.general.misc().rd_index;
        let rd_dst = limb_from_bits_le(lv.rd_bits);
        yield_constr.constraint(filter * (rd_index - rd_dst));
    }

    // Check rt value
    {
        let rt_val = lv.mem_channels[0].value;
        let local_user = lv.mem_channels[1].value;
        let rd_index = lv.general.misc().rd_index;
        let rd_eq_0 = lv.general.misc().rd_index_eq_0;
        let rd_eq_29 = lv.general.misc().rd_index_eq_29;
        yield_constr.constraint(filter * rd_eq_0 * rd_index);
        yield_constr.constraint(filter * rd_eq_0 * (rt_val - P::ONES));
        yield_constr
            .constraint(filter * rd_eq_29 * (rd_index - P::Scalar::from_canonical_usize(29)));
        yield_constr.constraint(filter * rd_eq_29 * (rt_val - local_user));
        yield_constr.constraint(filter * (P::ONES - rd_eq_29 - rd_eq_0) * rt_val);
    }
}

pub fn eval_ext_circuit_rdhwr<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let filter = lv.op.rdhwr;

    // Check rt Reg
    {
        let rt_reg = lv.mem_channels[0].addr_virtual;
        let rt_src = limb_from_bits_le_recursive(builder, lv.rt_bits);
        let constr = builder.sub_extension(rt_reg, rt_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check rd index
    {
        let rd_index = lv.general.misc().rd_index;
        let rd_src = limb_from_bits_le_recursive(builder, lv.rd_bits);
        let constr = builder.sub_extension(rd_index, rd_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check rt value
    {
        let rt_val = lv.mem_channels[0].value;
        let local_user = lv.mem_channels[1].value;
        let rd_index = lv.general.misc().rd_index;
        let rd_eq_0 = lv.general.misc().rd_index_eq_0;
        let rd_eq_29 = lv.general.misc().rd_index_eq_29;
        let one_extension = builder.one_extension();

        let constr = builder.mul_extension(rd_eq_0, rd_index);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);

        let constr = builder.sub_extension(rt_val, one_extension);
        let constr = builder.mul_extension(constr, rd_eq_0);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);

        let constant29 = builder.constant_extension(F::Extension::from_canonical_usize(29));
        let constr = builder.sub_extension(rd_index, constant29);
        let constr = builder.mul_extension(rd_eq_29, constr);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);

        let constr = builder.sub_extension(rt_val, local_user);
        let constr = builder.mul_extension(constr, rd_eq_29);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);

        let constr = builder.sub_extension(one_extension, rd_eq_0);
        let constr = builder.sub_extension(constr, rd_eq_29);
        let constr = builder.mul_extension(constr, rt_val);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }
}

pub fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    eval_packed_rdhwr(lv, yield_constr);
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    eval_ext_circuit_rdhwr(builder, lv, yield_constr);
}
