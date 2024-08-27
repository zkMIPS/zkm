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

pub fn eval_packed_extract<P: PackedField>(
    lv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let filter = lv.op.ext;

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

    // Check ext result
    {
        let msbd = limb_from_bits_le(lv.rd_bits);
        let rs_bits = lv.general.misc().rs_bits;
        let lsb = limb_from_bits_le(lv.shamt_bits);
        let msb = lsb + msbd;
        let auxm = lv.general.misc().auxm;
        let auxl = lv.general.misc().auxl;
        let auxs = lv.general.misc().auxs;
        let rd_result = lv.mem_channels[1].value;

        yield_constr.constraint(filter * (rd_result * auxs + auxl - auxm));

        for i in 0..32 {
            let mpartial = limb_from_bits_le(rs_bits[0..i + 1].to_vec());
            let mut lpartial = P::ZEROS;
            if i != 0 {
                lpartial = limb_from_bits_le(rs_bits[0..i].to_vec());
            }
            let is_msb = lv.general.misc().is_msb[i];
            let is_lsb = lv.general.misc().is_lsb[i];
            let cur_index = P::Scalar::from_canonical_usize(i);
            let cur_mul = P::Scalar::from_canonical_usize(1 << i);
            yield_constr.constraint(filter * is_msb * (msb - cur_index));
            yield_constr.constraint(filter * is_msb * (auxm - mpartial));
            yield_constr.constraint(filter * is_lsb * (lsb - cur_index));
            yield_constr.constraint(filter * is_lsb * (auxl - lpartial));
            yield_constr.constraint(filter * is_lsb * (auxs - cur_mul));
        }
    }
}

pub fn eval_ext_circuit_extract<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let filter = lv.op.ext;

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

    // Check ext result
    {
        let msbd = limb_from_bits_le_recursive(builder, lv.rd_bits);
        let rs_bits = lv.general.misc().rs_bits;
        let lsb = limb_from_bits_le_recursive(builder, lv.shamt_bits);
        let msb = builder.add_extension(lsb, msbd);
        let auxm = lv.general.misc().auxm;
        let auxl = lv.general.misc().auxl;
        let auxs = lv.general.misc().auxs;
        let rd_result = lv.mem_channels[1].value;

        let constr = builder.mul_extension(rd_result, auxs);
        let constr = builder.add_extension(constr, auxl);
        let constr = builder.sub_extension(constr, auxm);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);

        for i in 0..32 {
            let mpartial = limb_from_bits_le_recursive(builder, rs_bits[0..i + 1].to_vec());
            let mut lpartial = builder.zero_extension();
            if i != 0 {
                lpartial = limb_from_bits_le_recursive(builder, rs_bits[0..i].to_vec());
            }
            let is_msb = lv.general.misc().is_msb[i];
            let is_lsb = lv.general.misc().is_lsb[i];
            let cur_index = builder.constant_extension(F::Extension::from_canonical_usize(i));
            let cur_mul = builder.constant_extension(F::Extension::from_canonical_usize(1 << i));

            let constr_msb = builder.mul_extension(filter, is_msb);
            let constr_lsb = builder.mul_extension(filter, is_lsb);

            let constr = builder.sub_extension(msb, cur_index);
            let constr = builder.mul_extension(constr_msb, constr);
            yield_constr.constraint(builder, constr);

            let constr = builder.sub_extension(auxm, mpartial);
            let constr = builder.mul_extension(constr, constr_msb);
            yield_constr.constraint(builder, constr);

            let constr = builder.sub_extension(lsb, cur_index);
            let constr = builder.mul_extension(constr, constr_lsb);
            yield_constr.constraint(builder, constr);

            let constr = builder.sub_extension(auxl, lpartial);
            let constr = builder.mul_extension(constr, constr_lsb);
            yield_constr.constraint(builder, constr);

            let constr = builder.sub_extension(auxs, cur_mul);
            let constr = builder.mul_extension(constr, constr_lsb);
            yield_constr.constraint(builder, constr);
        }
    }
}

pub fn eval_packed_insert<P: PackedField>(
    lv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let filter = lv.op.ins;

    // Check rt Reg
    // addr(channels[1]) == rt
    // addr(channels[2]) == rt
    {
        let rt_reg_read = lv.mem_channels[1].addr_virtual;
        let rt_reg_write = lv.mem_channels[2].addr_virtual;
        let rt_src = limb_from_bits_le(lv.rt_bits);
        yield_constr.constraint(filter * (rt_reg_read - rt_src));

        yield_constr.constraint(filter * (rt_reg_write - rt_src));
    }

    // Check rs Reg
    // addr(channels[0]) == rs
    {
        let rs_reg = lv.mem_channels[0].addr_virtual;
        let rs_dst = limb_from_bits_le(lv.rs_bits);
        yield_constr.constraint(filter * (rs_reg - rs_dst));
    }

    // Check ins result
    // is_lsb[i] = 1 if i = lsb
    // is_lsb[i] = 0 if i != lsb
    // is_lsb[i] * (lsb - i) == 0
    // auxs = 1 << lsd
    // is_lsb[i] * (auxs - (i << 1)) == 0
    // size = msb -lsb
    // is_msb[i] = 1 if i = size
    // is_msb[i] = 0 if i != size
    // is_msb[i] * (size - i) == 0
    // auxm = rt & !(mask << lsb)
    // auxl = rs[0 : size+1]
    // is_msb[i] * (auxl - rs[0:i+1]) == 0
    // result == auxm + auxl * auxs
    {
        let msb = limb_from_bits_le(lv.rd_bits);
        let rs_bits = lv.general.misc().rs_bits;
        let lsb = limb_from_bits_le(lv.shamt_bits);

        let auxm = lv.general.misc().auxm;
        let auxl = lv.general.misc().auxl;
        let auxs = lv.general.misc().auxs;
        let rd_result = lv.mem_channels[2].value;

        yield_constr.constraint(filter * (rd_result - auxm - auxl * auxs));

        for i in 0..32 {
            let is_msb = lv.general.misc().is_msb[i];
            let is_lsb = lv.general.misc().is_lsb[i];
            let cur_index = P::Scalar::from_canonical_usize(i);
            let cur_mul = P::Scalar::from_canonical_usize(1 << i);

            yield_constr.constraint(filter * is_lsb * (lsb - cur_index));
            yield_constr.constraint(filter * is_lsb * (auxs - cur_mul));

            yield_constr.constraint(filter * is_msb * (msb - lsb - cur_index));

            let mut insert_bits = [P::ZEROS; 32];
            insert_bits[0..i + 1].copy_from_slice(&rs_bits[0..i + 1]);
            let insert_val = limb_from_bits_le(insert_bits.to_vec());
            yield_constr.constraint(filter * is_msb * (auxl - insert_val));
        }
    }
}

pub fn eval_ext_circuit_insert<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let filter = lv.op.ins;

    // Check rt Reg
    // addr(channels[1]) == rt
    // addr(channels[2]) == rt
    {
        let rt_reg_read = lv.mem_channels[1].addr_virtual;
        let rt_reg_write = lv.mem_channels[2].addr_virtual;
        let rt_src = limb_from_bits_le_recursive(builder, lv.rt_bits);

        let constr = builder.sub_extension(rt_reg_read, rt_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);

        let constr = builder.sub_extension(rt_reg_write, rt_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check rs Reg
    // addr(channels[0]) == rs
    {
        let rs_reg = lv.mem_channels[0].addr_virtual;
        let rs_src = limb_from_bits_le_recursive(builder, lv.rs_bits);
        let constr = builder.sub_extension(rs_reg, rs_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check ins result
    // is_lsb[i] = 1 if i = lsb
    // is_lsb[i] = 0 if i != lsb
    // is_lsb[i] * (lsb - i) == 0
    // auxs = 1 << lsd
    // is_lsb[i] * (auxs - (i << 1)) == 0
    // size = msb -lsb
    // is_msb[i] = 1 if i = size
    // is_msb[i] = 0 if i != size
    // is_msb[i] * (size - i) == 0
    // auxm = rt & !(mask << lsb)
    // auxl = rs[0 : size+1]
    // is_msb[i] * (auxl - rs[0:i+1]) == 0
    // result == auxm + auxl * auxs
    {
        let msb = limb_from_bits_le_recursive(builder, lv.rd_bits);
        let rs_bits = lv.general.misc().rs_bits;
        let lsb = limb_from_bits_le_recursive(builder, lv.shamt_bits);
        let auxm = lv.general.misc().auxm;
        let auxl = lv.general.misc().auxl;
        let auxs = lv.general.misc().auxs;
        let rd_result = lv.mem_channels[2].value;

        let constr = builder.mul_extension(auxl, auxs);
        let constr = builder.sub_extension(rd_result, constr);
        let constr = builder.sub_extension(constr, auxm);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);

        for i in 0..32 {
            let is_msb = lv.general.misc().is_msb[i];
            let is_lsb = lv.general.misc().is_lsb[i];
            let cur_index = builder.constant_extension(F::Extension::from_canonical_usize(i));
            let cur_mul = builder.constant_extension(F::Extension::from_canonical_usize(1 << i));

            let constr_msb = builder.mul_extension(filter, is_msb);
            let constr_lsb = builder.mul_extension(filter, is_lsb);

            let constr = builder.sub_extension(lsb, cur_index);
            let constr = builder.mul_extension(constr, constr_lsb);
            yield_constr.constraint(builder, constr);

            let constr = builder.sub_extension(auxs, cur_mul);
            let constr = builder.mul_extension(constr, constr_lsb);
            yield_constr.constraint(builder, constr);

            let constr = builder.sub_extension(msb, lsb);
            let constr = builder.sub_extension(constr, cur_index);
            let constr = builder.mul_extension(constr, constr_msb);
            yield_constr.constraint(builder, constr);

            let mut insert_bits = [builder.zero_extension(); 32];
            insert_bits[0..i + 1].copy_from_slice(&rs_bits[0..i + 1]);
            let insert_val = limb_from_bits_le_recursive(builder, insert_bits);
            let constr = builder.sub_extension(auxl, insert_val);
            let constr = builder.mul_extension(constr, constr_msb);
            yield_constr.constraint(builder, constr);
        }
    }
}

pub fn eval_packed_ror<P: PackedField>(
    lv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let filter = lv.op.ror;

    // Check rd Reg
    {
        let rd_reg = lv.mem_channels[1].addr_virtual;
        let rd_src = limb_from_bits_le(lv.rd_bits);
        yield_constr.constraint(filter * (rd_reg - rd_src));
    }

    // Check rt Reg
    {
        let rt_reg = lv.mem_channels[0].addr_virtual;
        let rt_dst = limb_from_bits_le(lv.rt_bits);
        yield_constr.constraint(filter * (rt_reg - rt_dst));
    }

    // Check ror result
    {
        let rt_bits = lv.general.misc().rs_bits;
        let sa = limb_from_bits_le(lv.shamt_bits);

        let rd_result = lv.mem_channels[1].value;

        let mut rd_bits = [P::ZEROS; 32];
        for i in 0..32 {
            rd_bits[0..32 - i].copy_from_slice(&rt_bits[i..32]);
            rd_bits[32 - i..32].copy_from_slice(&rt_bits[0..i]);

            let rd_val = limb_from_bits_le(rd_bits.to_vec());

            let is_sa = lv.general.misc().is_lsb[i];
            let cur_index = P::Scalar::from_canonical_usize(i);
            yield_constr.constraint(filter * is_sa * (sa - cur_index));
            yield_constr.constraint(filter * is_sa * (rd_result - rd_val));
        }
    }
}

pub fn eval_ext_circuit_ror<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let filter = lv.op.ror;

    // Check rd Reg
    {
        let rd_reg = lv.mem_channels[1].addr_virtual;
        let rd_src = limb_from_bits_le_recursive(builder, lv.rd_bits);
        let constr = builder.sub_extension(rd_reg, rd_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check rt Reg
    {
        let rt_reg = lv.mem_channels[0].addr_virtual;
        let rt_src = limb_from_bits_le_recursive(builder, lv.rt_bits);
        let constr = builder.sub_extension(rt_reg, rt_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check ror result
    {
        let rt_bits = lv.general.misc().rs_bits;
        let sa = limb_from_bits_le_recursive(builder, lv.shamt_bits);
        let rd_result = lv.mem_channels[1].value;

        let mut rd_bits = [builder.zero_extension(); 32];
        for i in 0..32 {
            rd_bits[0..32 - i].copy_from_slice(&rt_bits[i..32]);
            rd_bits[32 - i..32].copy_from_slice(&rt_bits[0..i]);

            let rd_val = limb_from_bits_le_recursive(builder, rd_bits);

            let is_sa = lv.general.misc().is_lsb[i];
            let cur_index = builder.constant_extension(F::Extension::from_canonical_usize(i));

            let constr_sa = builder.mul_extension(filter, is_sa);

            let constr = builder.sub_extension(sa, cur_index);
            let constr = builder.mul_extension(constr, constr_sa);
            yield_constr.constraint(builder, constr);

            let constr = builder.sub_extension(rd_result, rd_val);
            let constr = builder.mul_extension(constr, constr_sa);
            yield_constr.constraint(builder, constr);
        }
    }
}

pub fn eval_packed_maddu<P: PackedField>(
    lv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let filter = lv.op.maddu;

    // Check rs Reg
    // addr(channels[0]) == rs
    {
        let rs_reg = lv.mem_channels[0].addr_virtual;
        let rs_src = limb_from_bits_le(lv.rs_bits);
        yield_constr.constraint(filter * (rs_reg - rs_src));
    }

    // Check rt Reg
    // addr(channels[1]) == rt
    {
        let rt_reg = lv.mem_channels[1].addr_virtual;
        let rt_dst = limb_from_bits_le(lv.rt_bits);
        yield_constr.constraint(filter * (rt_reg - rt_dst));
    }

    // Check hi Reg
    // addr(channels[2]) == 33
    // addr(channels[4]) == 33
    {
        let hi_reg_read = lv.mem_channels[2].addr_virtual;
        let hi_reg_write = lv.mem_channels[4].addr_virtual;
        let hi_src = P::Scalar::from_canonical_usize(33);
        yield_constr.constraint(filter * (hi_reg_read - hi_src));
        yield_constr.constraint(filter * (hi_reg_write - hi_src));
    }

    // Check lo Reg
    // addr(channels[3]) == 32
    // addr(channels[5]) == 32
    {
        let lo_reg_read = lv.mem_channels[3].addr_virtual;
        let lo_reg_write = lv.mem_channels[5].addr_virtual;
        let lo_src = P::Scalar::from_canonical_usize(32);
        yield_constr.constraint(filter * (lo_reg_read - lo_src));
        yield_constr.constraint(filter * (lo_reg_write - lo_src));
    }

    // Check maddu result
    // carry = overflow << 32
    // scale = 1 << 32
    // carry * (carry - scale) == 0
    // result +  (overflow << 32) == (hi,lo) + rs * rt
    {
        let rs = lv.mem_channels[0].value;
        let rt = lv.mem_channels[1].value;
        let hi = lv.mem_channels[2].value;
        let lo = lv.mem_channels[3].value;
        let hi_result: P = lv.mem_channels[4].value;
        let lo_result = lv.mem_channels[5].value;
        let carry = lv.general.misc().auxm;
        let scale = P::Scalar::from_canonical_usize(1 << 32);
        let result = hi_result * scale + lo_result;
        let mul = rs * rt;
        let addend = hi * scale + lo;
        let overflow = carry * scale;

        yield_constr.constraint(filter * carry * (carry - scale));
        yield_constr.constraint(filter * (mul + addend - overflow - result));
    }
}

pub fn eval_ext_circuit_maddu<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let filter = lv.op.maddu;

    // Check rs Reg
    // addr(channels[0]) == rs
    {
        let rs_reg = lv.mem_channels[0].addr_virtual;
        let rs_src = limb_from_bits_le_recursive(builder, lv.rs_bits);
        let constr = builder.sub_extension(rs_reg, rs_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check rt Reg
    // addr(channels[1]) == rt
    {
        let rt_reg = lv.mem_channels[1].addr_virtual;
        let rt_src = limb_from_bits_le_recursive(builder, lv.rt_bits);
        let constr = builder.sub_extension(rt_reg, rt_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check hi Reg
    // addr(channels[2]) == 33
    // addr(channels[4]) == 33
    {
        let hi_reg_read = lv.mem_channels[2].addr_virtual;
        let hi_reg_write = lv.mem_channels[4].addr_virtual;
        let hi_src = builder.constant_extension(F::Extension::from_canonical_usize(33));
        let constr = builder.sub_extension(hi_reg_read, hi_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);

        let constr = builder.sub_extension(hi_reg_write, hi_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check lo Reg
    // addr(channels[3]) == 32
    // addr(channels[5]) == 32
    {
        let lo_reg_read = lv.mem_channels[3].addr_virtual;
        let lo_reg_write = lv.mem_channels[5].addr_virtual;
        let lo_src = builder.constant_extension(F::Extension::from_canonical_usize(32));
        let constr = builder.sub_extension(lo_reg_read, lo_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);

        let constr = builder.sub_extension(lo_reg_write, lo_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check maddu result
    // carry = overflow << 32
    // scale = 1 << 32
    // carry * (carry - scale) == 0
    // result +  (overflow << 32) == (hi,lo) + rs * rt
    {
        let rs = lv.mem_channels[0].value;
        let rt = lv.mem_channels[1].value;
        let hi = lv.mem_channels[2].value;
        let lo = lv.mem_channels[3].value;
        let hi_result = lv.mem_channels[4].value;
        let lo_result = lv.mem_channels[5].value;
        let carry = lv.general.misc().auxm;
        let scale = builder.constant_extension(F::Extension::from_canonical_usize(1 << 32));
        let result = builder.mul_extension(hi_result, scale);
        let result = builder.add_extension(result, lo_result);
        let mul = builder.mul_extension(rs, rt);
        let addend = builder.mul_extension(hi, scale);
        let addend = builder.add_extension(addend, lo);

        let overflow = builder.mul_extension(carry, scale);

        let constr = builder.sub_extension(carry, scale);
        let constr = builder.mul_extension(constr, carry);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);

        let constr = builder.add_extension(mul, addend);
        let constr = builder.sub_extension(constr, overflow);
        let constr = builder.sub_extension(constr, result);
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
    eval_packed_extract(lv, yield_constr);
    eval_packed_ror(lv, yield_constr);
    eval_packed_insert(lv, yield_constr);
    eval_packed_maddu(lv, yield_constr);
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    eval_ext_circuit_rdhwr(builder, lv, yield_constr);
    eval_ext_circuit_condmov(builder, lv, yield_constr);
    eval_ext_circuit_teq(builder, lv, yield_constr);
    eval_ext_circuit_extract(builder, lv, yield_constr);
    eval_ext_circuit_ror(builder, lv, yield_constr);
    eval_ext_circuit_insert(builder, lv, yield_constr);
    eval_ext_circuit_maddu(builder, lv, yield_constr);
}
