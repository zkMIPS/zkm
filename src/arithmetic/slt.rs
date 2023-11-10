use crate::arithmetic::columns::*;
use crate::arithmetic::columns::{
    INPUT_REGISTER_0, INPUT_REGISTER_1, IS_SLT, IS_SLTU, LIMB_BITS, NUM_ARITH_COLUMNS,
    OUTPUT_REGISTER,
};
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::columns::CpuColumnsView;
use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

/// 2^-16 mod (2^64 - 2^32 + 1)
const GOLDILOCKS_INVERSE_65536: u64 = 18446462594437939201;

pub fn eval_packed_generic<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let is_slt = lv[IS_SLT];
    let is_sltu = lv[IS_SLTU];

    let rs = &lv[INPUT_REGISTER_0];
    let rt = &lv[INPUT_REGISTER_1];
    let rd = &lv[OUTPUT_REGISTER];

    let overflow = P::Scalar::from_canonical_u64(1u64 << LIMB_BITS);
    let overflow_inv = P::Scalar::from_canonical_u64(GOLDILOCKS_INVERSE_65536);
    debug_assert!(
        overflow * overflow_inv == P::Scalar::ONE,
        "only works with LIMB_BITS=16 and F=Goldilocks"
    );

    let mut cy = P::ZEROS;
    for (&xi, &yi) in rs.iter().zip_eq(rt) {
        // Verify that (xi - yi) is either 0 or 2^LIMB_BITS
        let t = cy + xi - yi;
        yield_constr.constraint(is_slt * t * (overflow - t));
        // cy <-- 0 or 1
        // NB: this is multiplication by a constant, so doesn't
        // increase the degree of the constraint.
        cy = t * overflow_inv;
    }

    yield_constr.constraint(is_slt * rd[0] * (rd[0] - P::ONES));
    yield_constr.constraint(is_slt * (cy - rd[0]));
    for i in 1..N_LIMBS {
        yield_constr.constraint(is_slt * rd[i]);
    }
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let is_slt = lv[IS_SLT];
    let is_sltu = lv[IS_SLTU];

    let rs = &lv[INPUT_REGISTER_0];
    let rt = &lv[INPUT_REGISTER_1];
    let rd = &lv[OUTPUT_REGISTER];

    // 2^LIMB_BITS in the base field
    let overflow_base = F::from_canonical_u64(1 << LIMB_BITS);
    // 2^LIMB_BITS in the extension field as an ExtensionTarget
    let overflow = builder.constant_extension(F::Extension::from(overflow_base));
    // 2^-LIMB_BITS in the base field.
    let overflow_inv = F::from_canonical_u64(GOLDILOCKS_INVERSE_65536);

    let mut cy = builder.zero_extension();
    for (&xi, &yi) in rs.iter().zip_eq(rt) {
        // t0 = cy + xi
        let t0 = builder.add_many_extension([cy, xi]);
        // t = t0 - yi
        let t = builder.sub_extension(t0, yi);
        // t1 = overflow - t
        let t1 = builder.sub_extension(overflow, t);
        // t2 = t * t1
        let t2 = builder.mul_extension(t, t1);

        let filtered_limb_constraint = builder.mul_extension(is_slt, t2);
        yield_constr.constraint(builder, filtered_limb_constraint);

        cy = builder.mul_const_extension(overflow_inv, t);
    }

    let good_cy = builder.sub_extension(cy, rd[0]);
    let cy_filter = builder.mul_extension(is_slt, good_cy);

    // Check given carry is one bit
    let bit_constr = builder.mul_sub_extension(rd[0], rd[0], rd[0]);
    let bit_filter = builder.mul_extension(is_slt, bit_constr);

    yield_constr.constraint(builder, bit_filter);
    yield_constr.constraint(builder, cy_filter);
    for i in 1..N_LIMBS {
        let t = builder.mul_extension(is_slt, rd[i]);
        yield_constr.constraint(builder, t);
    }
}
