use crate::arithmetic::columns::*;
use crate::arithmetic::utils::u32_to_array;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

/// Generate row for SLT operations.
pub(crate) fn generate<F: PrimeField64>(
    lv: &mut [F],
    filter: usize,
    left_in: u32,
    right_in: u32,
    rd: u32,
) {
    u32_to_array(&mut lv[INPUT_REGISTER_0], left_in);
    u32_to_array(&mut lv[INPUT_REGISTER_1], right_in);
    u32_to_array(&mut lv[INPUT_REGISTER_2], 0);

    match filter {
        IS_SLT | IS_SLTI => {
            let (diff, cy) = left_in.overflowing_sub(right_in);
            let mut cy_val = cy as u32;
            if (left_in & 0x80000000u32) != (right_in & 0x80000000u32) {
                cy_val = 1u32 << 16 | (!cy as u32);
            }

            u32_to_array(&mut lv[AUX_INPUT_REGISTER_0], diff);
            u32_to_array(&mut lv[AUX_INPUT_REGISTER_1], cy_val);
            u32_to_array(&mut lv[OUTPUT_REGISTER], rd);
        }
        IS_SLTU | IS_SLTIU => {
            let (diff, cy) = left_in.overflowing_sub(right_in);
            u32_to_array(&mut lv[AUX_INPUT_REGISTER_0], diff);
            u32_to_array(&mut lv[AUX_INPUT_REGISTER_1], cy as u32);
            u32_to_array(&mut lv[OUTPUT_REGISTER], rd);
        }
        _ => panic!("unexpected operation filter"),
    };
}

/// 2^-16 mod (2^64 - 2^32 + 1)
const GOLDILOCKS_INVERSE_65536: u64 = 18446462594437939201;

pub fn eval_packed_generic<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let is_lt = lv[IS_SLT] + lv[IS_SLTU];
    let is_lti = lv[IS_SLTI] + lv[IS_SLTIU];
    let is_lt = is_lt + is_lti;
    let is_sign = lv[IS_SLT] + lv[IS_SLTI];

    let in0 = &lv[INPUT_REGISTER_0];
    let in1 = &lv[INPUT_REGISTER_1];
    let out = &lv[OUTPUT_REGISTER];
    let aux = &lv[AUX_INPUT_REGISTER_0];
    let rd = &lv[AUX_INPUT_REGISTER_1];

    eval_packed_generic_slt(yield_constr, is_lt, is_sign, in1, aux, in0, rd, out);
}

pub(crate) fn eval_packed_generic_slt<P: PackedField>(
    yield_constr: &mut ConstraintConsumer<P>,
    filter: P,
    sign: P,
    x: &[P],        // right
    y: &[P],        // diff (left-right)
    z: &[P],        // left
    given_cy: &[P], // out
    rd: &[P],       // rd
) {
    debug_assert!(
        x.len() == N_LIMBS && y.len() == N_LIMBS && z.len() == N_LIMBS && given_cy.len() == N_LIMBS
    );

    let overflow = P::Scalar::from_canonical_u64(1u64 << LIMB_BITS);
    let overflow_inv = P::Scalar::from_canonical_u64(GOLDILOCKS_INVERSE_65536);
    debug_assert!(
        overflow * overflow_inv == P::Scalar::ONE,
        "only works with LIMB_BITS=16 and F=Goldilocks"
    );

    let mut cy = P::ZEROS;
    for ((&xi, &yi), &zi) in x.iter().zip_eq(y).zip_eq(z) {
        // Verify that (xi + yi) - zi is either 0 or 2^LIMB_BITS  (right[i]+aux[i]-left[i])
        let t = cy + xi + yi - zi;
        yield_constr.constraint(filter * t * (overflow - t));

        // cy <-- 0 or 1   le:cy=0 gt:cy=1
        // NB: this is multiplication by a constant, so doesn't
        // increase the degree of the constraint.
        cy = t * overflow_inv; // (right[i]+aux[i]-left[i])/overflow
    }

    {
        yield_constr.constraint(filter * given_cy[0] * (given_cy[0] - P::ONES));
        yield_constr.constraint(filter * (cy - given_cy[0]) * (P::ONES - sign));
        yield_constr.constraint(filter * given_cy[1] * (P::ONES - cy - given_cy[0]));
        yield_constr.constraint_transition(filter * (rd[0] - given_cy[0]));
        for i in 1..N_LIMBS {
            yield_constr.constraint(filter * given_cy[i] * (P::ONES - sign));
            yield_constr.constraint_transition(filter * rd[i]);
        }
    }
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let is_lt = builder.add_extension(lv[IS_SLT], lv[IS_SLTU]);
    let is_lti = builder.add_extension(lv[IS_SLTI], lv[IS_SLTIU]);
    let is_lt = builder.add_extension(is_lt, is_lti);
    let is_sign = builder.add_extension(lv[IS_SLT], lv[IS_SLTI]);

    let in0 = &lv[INPUT_REGISTER_0];
    let in1 = &lv[INPUT_REGISTER_1];
    let out = &lv[OUTPUT_REGISTER];
    let aux = &lv[AUX_INPUT_REGISTER_0];
    let rd = &lv[AUX_INPUT_REGISTER_1];

    eval_ext_circuit_slt(
        builder,
        yield_constr,
        is_lt,
        is_sign,
        in1,
        aux,
        in0,
        rd,
        out,
    );
}

#[allow(clippy::needless_collect)]
pub(crate) fn eval_ext_circuit_slt<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    filter: ExtensionTarget<D>,
    sign: ExtensionTarget<D>,
    x: &[ExtensionTarget<D>],
    y: &[ExtensionTarget<D>],
    z: &[ExtensionTarget<D>],
    given_cy: &[ExtensionTarget<D>],
    rd: &[ExtensionTarget<D>],
) {
    debug_assert!(
        x.len() == N_LIMBS && y.len() == N_LIMBS && z.len() == N_LIMBS && given_cy.len() == N_LIMBS
    );

    // 2^LIMB_BITS in the base field
    let overflow_base = F::from_canonical_u64(1 << LIMB_BITS);
    // 2^LIMB_BITS in the extension field as an ExtensionTarget
    let overflow = builder.constant_extension(F::Extension::from(overflow_base));
    // 2^-LIMB_BITS in the base field.
    let overflow_inv = F::from_canonical_u64(GOLDILOCKS_INVERSE_65536);

    let mut cy = builder.zero_extension();
    let one = builder.one_extension();
    let not_sign = builder.sub_extension(one, sign);

    for ((&xi, &yi), &zi) in x.iter().zip_eq(y).zip_eq(z) {
        // t0 = cy + xi + yi
        let t0 = builder.add_many_extension([cy, xi, yi]);
        // t  = t0 - zi
        let t = builder.sub_extension(t0, zi);
        // t1 = overflow - t
        let t1 = builder.sub_extension(overflow, t);
        // t2 = t * t1
        let t2 = builder.mul_extension(t, t1);

        let filtered_limb_constraint = builder.mul_extension(filter, t2);
        yield_constr.constraint(builder, filtered_limb_constraint);

        cy = builder.mul_const_extension(overflow_inv, t);
    }

    let good_cy1 = builder.sub_extension(cy, given_cy[0]);
    let cy_filter1 = builder.mul_extension(good_cy1, not_sign);
    let cy_filter1 = builder.mul_extension(filter, cy_filter1);

    let good_cy2 = builder.sub_extension(one, cy);
    let good_cy2 = builder.sub_extension(good_cy2, given_cy[0]);
    let cy_filter2 = builder.mul_extension(given_cy[1], good_cy2);
    let cy_filter2 = builder.mul_extension(filter, cy_filter2);

    // Check given carry is one bit
    let bit_constr = builder.mul_sub_extension(given_cy[0], given_cy[0], given_cy[0]);
    let bit_filter = builder.mul_extension(filter, bit_constr);

    {
        yield_constr.constraint(builder, bit_filter);
        yield_constr.constraint(builder, cy_filter1);
        yield_constr.constraint(builder, cy_filter2);
        let rd_filter = builder.sub_extension(rd[0], given_cy[0]);
        let rd_filter = builder.mul_extension(filter, rd_filter);
        yield_constr.constraint_transition(builder, rd_filter);
        for i in 1..N_LIMBS {
            let t = builder.mul_extension(filter, given_cy[i]);
            let t = builder.mul_extension(t, not_sign);
            yield_constr.constraint(builder, t);
            let r = builder.mul_extension(filter, rd[i]);
            yield_constr.constraint_transition(builder, r);
        }
    }
}
