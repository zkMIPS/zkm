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

pub fn eval_packed_condmov<P: PackedField>(
    lv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let rs = lv.mem_channels[0].value; // rs
    let rt = lv.mem_channels[1].value; // rt
    let rd = lv.mem_channels[2].value; // rd
    let out = lv.mem_channels[3].value; // out
    let mov = lv.mem_channels[4].value; // mov rs to rd
    let is_movn = lv.op.movn_op;
    let is_movz = lv.op.movz_op;
    let filter = is_movn + is_movz;
    //let is_movn = lv.func_bits[0];
    //let is_movz = P::ONES - lv.func_bits[0];

    // constraints:
    // * is_ne = p_inv0 * rt
    // * is_eq = 1 - is_ne
    // * is_movn * (mov - is_ne) == 0
    // * is_movz * (mov - is_eq) == 0
    // * filter * mov * (1 - mov) == 0
    // * res = mov * rs + (1 - mov) * rd
    // * filter * (out - res) == 0
    {
        let p_inv0 = lv.general.logic().diff_pinv; // rt^-1
        let is_ne = p_inv0 * rt;
        let is_eq = P::ONES - is_ne;

        let no_mov = P::ONES - mov;

        yield_constr.constraint(is_movn * (mov - is_ne));
        yield_constr.constraint(is_movz * (mov - is_eq));

        yield_constr.constraint(filter * mov * no_mov);

        yield_constr.constraint(filter * (out - (mov * rs + no_mov * rd)));
    }
}

pub fn eval_ext_circuit_condmov<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let rs = lv.mem_channels[0].value; // rs
    let rt = lv.mem_channels[1].value; // rt
    let rd = lv.mem_channels[2].value; // rd
    let out = lv.mem_channels[3].value; // out
    let mov = lv.mem_channels[4].value; // mov rs to rd
    let is_movn = lv.op.movn_op;
    let is_movz = lv.op.movz_op;
    let filter = builder.add_extension(is_movn, is_movz);
    let one_extension = builder.one_extension();

    // constraints:
    // * is_ne = p_inv0 * rt
    // * is_eq = 1 - is_ne
    // * is_movn * (mov - is_ne) == 0
    // * is_movz * (mov - is_eq) == 0
    // * filter * mov * (1 - mov) == 0
    // * res = mov * rs + (1 - mov) * rd
    // * filter * (out - res) == 0
    {
        let p_inv0 = lv.general.logic().diff_pinv; // rt^-1
        let is_ne = builder.mul_extension(p_inv0, rt);
        let is_eq = builder.sub_extension(one_extension, is_ne);

        let constr = builder.sub_extension(mov, is_ne);
        let constr = builder.mul_extension(is_movn, constr);
        yield_constr.constraint(builder, constr);

        let constr = builder.sub_extension(mov, is_eq);
        let constr = builder.mul_extension(is_movz, constr);
        yield_constr.constraint(builder, constr);

        let no_mov = builder.sub_extension(one_extension, mov);
        let constr = builder.mul_extension(mov, no_mov);
        let constr = builder.mul_extension(filter, constr);
        yield_constr.constraint(builder, constr);

        let constr_a = builder.mul_extension(mov, rs);
        let constr_b = builder.mul_extension(no_mov, rd);
        let constr = builder.add_extension(constr_a, constr_b);
        let constr = builder.sub_extension(out, constr);
        let constr = builder.mul_extension(filter, constr);
        yield_constr.constraint(builder, constr);
    }
}

pub fn eval_packed_teq<P: PackedField>(
    lv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let filter = lv.op.teq;

    // Check rt Reg
    {
        let rt_reg = lv.mem_channels[1].addr_virtual;
        let rt_src = limb_from_bits_le(lv.rt_bits);
        yield_constr.constraint(filter * (rt_reg - rt_src));
    }

    // Check rs Reg
    {
        let rs_reg = lv.mem_channels[0].addr_virtual;
        let rs_dst = limb_from_bits_le(lv.rs_bits);
        yield_constr.constraint(filter * (rs_reg - rs_dst));
    }

    // Check rs_val != rt_val, Otherwise trap will be triggered
    {
        let rs_val = lv.mem_channels[0].value;
        let rt_val = lv.mem_channels[1].value;
        let p_inv0 = lv.general.logic().diff_pinv;
        let is_ne = (rs_val - rt_val) * p_inv0;
        yield_constr.constraint(filter * (P::ONES - is_ne));
    }
}

pub fn eval_ext_circuit_teq<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let filter = lv.op.teq;

    // Check rt Reg
    {
        let rt_reg = lv.mem_channels[1].addr_virtual;
        let rt_src = limb_from_bits_le_recursive(builder, lv.rt_bits);
        let constr = builder.sub_extension(rt_reg, rt_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check rs Reg
    {
        let rs_reg = lv.mem_channels[0].addr_virtual;
        let rs_src = limb_from_bits_le_recursive(builder, lv.rs_bits);
        let constr = builder.sub_extension(rs_reg, rs_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check rs_val != rt_val, Otherwise trap will be triggered
    {
        let rs_val = lv.mem_channels[0].value;
        let rt_val = lv.mem_channels[1].value;
        let p_inv0 = lv.general.logic().diff_pinv;
        let one_extension = builder.one_extension();
        let diff = builder.sub_extension(rs_val, rt_val);
        let is_ne = builder.mul_extension(diff, p_inv0);
        let constr = builder.sub_extension(one_extension, is_ne);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }
}

pub fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    eval_packed_rdhwr(lv, yield_constr);
    eval_packed_condmov(lv, yield_constr);
    eval_packed_teq(lv, yield_constr);
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    eval_ext_circuit_rdhwr(builder, lv, yield_constr);
    eval_ext_circuit_condmov(builder, lv, yield_constr);
    eval_ext_circuit_teq(builder, lv, yield_constr);
}
