use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::columns::CpuColumnsView;
use crate::util::{limb_from_bits_le, limb_from_bits_le_recursive};
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;

pub fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let filter_clz = lv.op.clz_op;
    let filter_clo = lv.op.clo_op;
    let filter = filter_clo + filter_clz;

    // check op code
    let opcode = limb_from_bits_le(lv.opcode_bits);
    yield_constr.constraint(filter * (opcode - P::Scalar::from_canonical_u8(0b011100)));
    //check func bits
    let func = limb_from_bits_le(lv.func_bits);
    yield_constr.constraint(filter_clz * (func - P::Scalar::from_canonical_u8(0b100000)));
    yield_constr.constraint(filter_clo * (func - P::Scalar::from_canonical_u8(0b100001)));

    // Check rs Reg
    {
        let rs_reg = lv.mem_channels[0].addr_virtual;
        let rs_src = limb_from_bits_le(lv.rs_bits);
        yield_constr.constraint(filter * (rs_reg - rs_src));
    }

    // Check rd Reg
    {
        let rd_reg = lv.mem_channels[1].addr_virtual;
        let rd_dst = limb_from_bits_le(lv.rd_bits);
        yield_constr.constraint(filter * (rd_reg - rd_dst));
    }

    let rs = lv.mem_channels[0].value;
    let bits_le = lv.general.io().rs_le;
    for bit in bits_le {
        yield_constr.constraint(filter * bit * (P::ONES - bit));
    }
    let sum = limb_from_bits_le(bits_le);

    yield_constr.constraint(filter_clz * (rs - sum));
    yield_constr.constraint(filter_clo * (P::Scalar::from_canonical_u32(0xffffffff) - rs - sum));

    let rd = lv.mem_channels[1].value;
    let mut is_eqs = lv.general.io().rt_le.iter();
    let mut invs = lv.general.io().mem_le.iter();

    yield_constr.constraint(filter * bits_le[31] * rd);
    for i in (0..31).rev() {
        let partial = limb_from_bits_le(bits_le[i..].to_vec());
        let is_eq = is_eqs.next().unwrap();
        let inv = invs.next().unwrap();

        let diff = partial - P::ONES;
        yield_constr.constraint(filter * diff * *is_eq);
        yield_constr.constraint(filter * (diff * *inv + *is_eq - P::ONES));
        yield_constr.constraint(filter * *is_eq * (rd - P::Scalar::from_canonical_usize(31 - i)));

        if i == 0 {
            let is_eq = is_eqs.next().unwrap();
            let inv = invs.next().unwrap();

            yield_constr.constraint(filter * partial * *is_eq);
            yield_constr.constraint(filter * (partial * *inv + *is_eq - P::ONES));
            yield_constr.constraint(filter * *is_eq * (rd - P::Scalar::from_canonical_usize(32)));
        }
    }
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let filter_clz = lv.op.clz_op;
    let filter_clo = lv.op.clo_op;
    let filter = builder.add_extension(filter_clo, filter_clz);

    // check op code
    let opcode = limb_from_bits_le_recursive(builder, lv.opcode_bits);
    let opcode_ = builder.constant_extension(F::Extension::from_canonical_u8(0b011100));
    let t0 = builder.sub_extension(opcode, opcode_);
    let t = builder.mul_extension(filter, t0);
    yield_constr.constraint(builder, t);
    //check func bits
    let func = limb_from_bits_le_recursive(builder, lv.func_bits);
    let func_clz = builder.constant_extension(F::Extension::from_canonical_u8(0b100000));
    let t0 = builder.sub_extension(func, func_clz);
    let t = builder.mul_extension(filter_clz, t0);
    yield_constr.constraint(builder, t);

    let func_clo = builder.constant_extension(F::Extension::from_canonical_u8(0b100001));
    let t0 = builder.sub_extension(func, func_clo);
    let t = builder.mul_extension(filter_clo, t0);
    yield_constr.constraint(builder, t);

    // Check rs Reg
    {
        let rs_reg = lv.mem_channels[0].addr_virtual;
        let rs_src = limb_from_bits_le_recursive(builder, lv.rs_bits);
        let constr = builder.sub_extension(rs_reg, rs_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check rd Reg
    {
        let rd_reg = lv.mem_channels[1].addr_virtual;
        let rd_src = limb_from_bits_le_recursive(builder, lv.rd_bits);
        let constr = builder.sub_extension(rd_reg, rd_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    let one = builder.one_extension();
    let rs = lv.mem_channels[0].value;
    let bits_le = lv.general.io().rs_le;
    for bit in bits_le {
        let bit_neg = builder.sub_extension(one, bit);
        let t = builder.mul_many_extension([filter, bit, bit_neg]);
        yield_constr.constraint(builder, t);
    }
    let sum = limb_from_bits_le_recursive(builder, bits_le);

    let t1 = builder.sub_extension(rs, sum);
    let t = builder.mul_extension(filter_clz, t1);
    yield_constr.constraint(builder, t);

    let cst = builder.constant_extension(F::Extension::from_canonical_u32(0xffffffff));
    let t2 = builder.sub_extension(cst, rs);
    let t3 = builder.sub_extension(t2, sum);
    let t = builder.mul_extension(filter_clo, t3);
    yield_constr.constraint(builder, t);

    let rd = lv.mem_channels[1].value;
    let mut is_eqs = lv.general.io().rt_le.iter();
    let mut invs = lv.general.io().mem_le.iter();

    let t = builder.mul_many_extension([filter, bits_le[31], rd]);
    yield_constr.constraint(builder, t);

    for i in (0..31).rev() {
        let partial = limb_from_bits_le_recursive(builder, bits_le[i..].to_vec());
        let is_eq = is_eqs.next().unwrap();
        let inv = invs.next().unwrap();

        let diff = builder.sub_extension(partial, one);
        let t = builder.mul_many_extension([filter, diff, *is_eq]);
        yield_constr.constraint(builder, t);

        let t1 = builder.mul_extension(diff, *inv);
        let t2 = builder.add_extension(t1, *is_eq);
        let t3 = builder.sub_extension(t2, one);
        let t = builder.mul_extension(filter, t3);
        yield_constr.constraint(builder, t);

        let cst = builder.constant_extension(F::Extension::from_canonical_usize(31 - i));
        let t1 = builder.sub_extension(rd, cst);
        let t = builder.mul_many_extension([filter, *is_eq, t1]);
        yield_constr.constraint(builder, t);

        if i == 0 {
            let is_eq = is_eqs.next().unwrap();
            let inv = invs.next().unwrap();

            let t = builder.mul_many_extension([filter, partial, *is_eq]);
            yield_constr.constraint(builder, t);

            let t1 = builder.mul_extension(partial, *inv);
            let t2 = builder.add_extension(t1, *is_eq);
            let t3 = builder.sub_extension(t2, one);
            let t = builder.mul_extension(filter, t3);
            yield_constr.constraint(builder, t);

            let cst = builder.constant_extension(F::Extension::from_canonical_usize(32));
            let t1 = builder.sub_extension(rd, cst);
            let t = builder.mul_many_extension([filter, *is_eq, t1]);
            yield_constr.constraint(builder, t);
        }
    }
}
