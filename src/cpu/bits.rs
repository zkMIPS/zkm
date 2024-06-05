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
    let filter_seh = lv.op.signext16;
    let filter_seb = lv.op.signext8;
    let filter_wsbh = lv.op.swaphalf;
    let filter = filter_seh + filter_seb + filter_wsbh;

    // Check rt Reg
    {
        let rt_reg = lv.mem_channels[0].addr_virtual;
        let rt_src = limb_from_bits_le(lv.rt_bits);
        yield_constr.constraint(filter * (rt_reg - rt_src));
    }

    // Check rd Reg
    {
        let rd_reg = lv.mem_channels[1].addr_virtual;
        let rd_dst = limb_from_bits_le(lv.rd_bits);
        yield_constr.constraint(filter * (rd_reg - rd_dst));
    }

    let rt = lv.mem_channels[0].value;
    let bits_le = lv.general.io().rt_le;
    for bit in bits_le {
        yield_constr.constraint(filter * bit * (P::ONES - bit));
    }
    let sum = limb_from_bits_le(bits_le);

    yield_constr.constraint(filter * (rt - sum));

    // check seb result
    let rd = lv.mem_channels[1].value;
    let mut seb_result = [bits_le[7]; 32];
    seb_result[..7].copy_from_slice(&bits_le[..7]);
    let sum = limb_from_bits_le(seb_result);
    yield_constr.constraint(filter_seb * (rd - sum));

    // check seh result
    let mut seh_result = [bits_le[15]; 32];
    seh_result[..15].copy_from_slice(&bits_le[..15]);
    let sum = limb_from_bits_le(seh_result);
    yield_constr.constraint(filter_seh * (rd - sum));

    // check wsbh result
    let mut wsbh_result = [bits_le[0]; 32];
    wsbh_result[..8].copy_from_slice(&bits_le[8..16]);
    wsbh_result[8..16].copy_from_slice(&bits_le[..8]);
    wsbh_result[16..24].copy_from_slice(&bits_le[24..32]);
    wsbh_result[24..32].copy_from_slice(&bits_le[16..24]);

    let sum = limb_from_bits_le(wsbh_result);
    yield_constr.constraint(filter_wsbh * (rd - sum));
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let filter_seh = lv.op.signext16;
    let filter_seb = lv.op.signext8;
    let filter_wsbh = lv.op.swaphalf;
    let filter = builder.add_extension(filter_seh, filter_seb);
    let filter = builder.add_extension(filter_wsbh, filter);

    // Check rt Reg
    {
        let rt_reg = lv.mem_channels[0].addr_virtual;
        let rt_src = limb_from_bits_le_recursive(builder, lv.rt_bits);
        let constr = builder.sub_extension(rt_reg, rt_src);
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
    let rt = lv.mem_channels[0].value;
    let bits_le = lv.general.io().rt_le;
    for bit in bits_le {
        let bit_neg = builder.sub_extension(one, bit);
        let t = builder.mul_many_extension([filter, bit, bit_neg]);
        yield_constr.constraint(builder, t);
    }
    let sum = limb_from_bits_le_recursive(builder, bits_le);

    let t1 = builder.sub_extension(rt, sum);
    let t = builder.mul_extension(filter, t1);
    yield_constr.constraint(builder, t);

    // check seb result
    let rd = lv.mem_channels[1].value;
    let mut seb_result = [bits_le[7]; 32];
    seb_result[..7].copy_from_slice(&bits_le[..7]);
    let sum = limb_from_bits_le_recursive(builder, seb_result);

    let t1 = builder.sub_extension(rd, sum);
    let t = builder.mul_extension(filter_seb, t1);
    yield_constr.constraint(builder, t);

    // check seh result
    let mut seh_result = [bits_le[15]; 32];
    seh_result[..15].copy_from_slice(&bits_le[..15]);
    let sum = limb_from_bits_le_recursive(builder, seh_result);

    let t1 = builder.sub_extension(rd, sum);
    let t = builder.mul_extension(filter_seh, t1);
    yield_constr.constraint(builder, t);

    // check wsbh result
    let mut wsbh_result = [bits_le[0]; 32];
    wsbh_result[..8].copy_from_slice(&bits_le[8..16]);
    wsbh_result[8..16].copy_from_slice(&bits_le[..8]);
    wsbh_result[16..24].copy_from_slice(&bits_le[24..32]);
    wsbh_result[24..32].copy_from_slice(&bits_le[16..24]);

    let sum = limb_from_bits_le_recursive(builder, wsbh_result);

    let t1 = builder.sub_extension(rd, sum);
    let t = builder.mul_extension(filter_wsbh, t1);
    yield_constr.constraint(builder, t);
}
