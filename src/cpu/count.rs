use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::columns::{CpuColumnsView, MemValue};
use crate::memory;
use crate::util::{limb_from_bits_le, limb_from_bits_le_recursive};
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;

pub fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let filter = lv.op.count_op; // `CLZ` or `CLO`

    let rs_val = lv.mem_channels[0].value;
    let rd_val = lv.mem_channels[1].value;

    // CLZ and CLO are differentiated by their first func_bits.
    let clz_filter = filter * (P::ONES - lv.func_bits[0]);
    let clo_filter = filter * lv.func_bits[0];

    // Check rs Reg
    // constraint: filter * (rs_reg - rs) == 0
    {
        let rs_reg = lv.mem_channels[0].addr_virtual;
        let rs_src = limb_from_bits_le(lv.rs_bits.into_iter());
        yield_constr.constraint(filter * (rs_reg - rs_src));
    }

    // Check rd Reg
    // constraint: filter * (rd_reg - rd) == 0
    {
        let rd_reg = lv.mem_channels[1].addr_virtual;
        let rd_dst = limb_from_bits_le(lv.rd_bits.into_iter());
        yield_constr.constraint(filter * (rd_reg - rd_dst));
    }

    // Check CLZ
    {
        /**
        1.if rs is all zero,
        2.if rs is not zero,leading count for upper bit is zero and (leading count + 1) is one.
         */
        for limb in rs_val.iter() {
            // FIXME
            yield_constr.constraint(clz_filter * (*limb));
        }
        // yield_constr.constraint(clz_filter * limb0);

        // if leading_zero_count == 32 {
        //     for limb in rs_val.iter() {
        //         yield_constr.constraint(clz_filter * (*limb)); // rs is all zero
        //     }
        // } else {
        //     let first_non_leading_one_id = 32 - leading_zero_count - 1;
        //     for (i,limb) in rs_val.iter().enumerate() {
        //         if i == first_non_leading_one_id {
        //             yield_constr.constraint(clz_filter * (P::ONES - limb)); // check first non leading one
        //         } else if i > first_non_leading_one_id {
        //             yield_constr.constraint(clz_filter * limb); // check upper bit is zero
        //         }
        //     }
        // }
    }

    // Check CLO
    {
        /**
        1.if rs is all one,rd==32
        2.if rs is not all one,leading count for upper bit is one and (leading count + 1) is zero.
         */
        for limb in rs_val.iter() {
            // FIXME
            yield_constr.constraint(clo_filter * (P::ONES - *limb));
        }
    }
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let one = builder.one_extension();
    // CLZ and CLO are differentiated by their first func_bits.
    let filter = lv.op.count_op; // `CLZ` or `CLO`
    let clz_filter = builder.sub_extension(one, lv.func_bits[0]);
    let clz_filter = builder.mul_extension(filter, clz_filter);
    let clo_filter = builder.mul_extension(filter, lv.func_bits[0]);

    let rs_val = lv.mem_channels[0].value;
    let rd_val = lv.mem_channels[1].value;

    // Check rs Reg
    {
        let rs_reg = lv.mem_channels[0].addr_virtual;
        let mut rs_reg_index = [one; 5];
        rs_reg_index.copy_from_slice(&lv.rs_bits);
        let rs_src = limb_from_bits_le_recursive(builder, rs_reg_index.into_iter());
        let constr = builder.sub_extension(rs_reg, rs_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check rd Reg
    // constraint: filter * (rd_reg - rd) == 0
    {
        let rd_reg = lv.mem_channels[1].addr_virtual;
        let mut rd_reg_index = [one; 5];
        rd_reg_index.copy_from_slice(&lv.rd_bits);
        let rd_src = limb_from_bits_le_recursive(builder, rd_reg_index.into_iter());
        let constr = builder.sub_extension(rd_reg, rd_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check CLZ
    {
        for limb in rs_val {
            let constr = builder.mul_extension(clz_filter, limb);
            yield_constr.constraint(builder, constr);
        }
    }

    // Check CLO
    {
        for limb in rs_val {
            let constr = builder.sub_extension(one, limb);
            let constr = builder.mul_extension(clo_filter, constr);
            yield_constr.constraint(builder, constr);
        }
    }
}
