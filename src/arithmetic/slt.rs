use crate::arithmetic::columns::*;
use crate::arithmetic::columns::{
    INPUT_REGISTER_0, INPUT_REGISTER_1, IS_SLT, LIMB_BITS, NUM_ARITH_COLUMNS,
    OUTPUT_REGISTER,
};
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
            u32_to_array(&mut lv[AUX_INPUT_REGISTER_0], cy as u32);
            u32_to_array(&mut lv[AUX_INPUT_REGISTER_1], rd);
            u32_to_array(&mut lv[OUTPUT_REGISTER], diff);
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
    let is_slt = lv[IS_SLT];
    let is_slti = lv[IS_SLTI];

    let in0 = &lv[INPUT_REGISTER_0];
    let in1 = &lv[INPUT_REGISTER_1];
    let out = &lv[OUTPUT_REGISTER];
    let aux = &lv[AUX_INPUT_REGISTER_0];
    let rd = &lv[AUX_INPUT_REGISTER_1];

    eval_packed_generic_slt(yield_constr, is_slt, in1, aux, in0, out, rd, false);
    eval_packed_generic_slt(yield_constr, is_slti, in1, aux, in0, out, rd, false);
}

pub(crate) fn eval_packed_generic_slt<P: PackedField>(
    yield_constr: &mut ConstraintConsumer<P>,
    filter: P,
    x: &[P],        // right
    y: &[P],        // aux
    z: &[P],        // left
    given_cy: &[P], // diff (left-right)
    rd: &[P],       // rd
    is_two_row_op: bool,
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
        if is_two_row_op {
            yield_constr.constraint_transition(filter * t * (overflow - t));
        } else {
            yield_constr.constraint(filter * t * (overflow - t));
        }
        // cy <-- 0 or 1   le:cy=0 gt:cy=1
        // NB: this is multiplication by a constant, so doesn't
        // increase the degree of the constraint.
        cy = t * overflow_inv; // (right[i]+aux[i]-left[i])/overflow
    }

    if is_two_row_op {
        // NB: Mild hack: We don't check that given_cy[0] is 0 or 1
        // when is_two_row_op is true because that's only the case
        // when this function is called from
        // modular::modular_constr_poly(), in which case (1) this
        // condition has already been checked and (2) it exceeds the
        // degree budget because given_cy[0] is already degree 2.
        yield_constr.constraint_transition(filter * (cy - given_cy[0]));
        yield_constr.constraint_transition(filter * (rd[0] - P::ONES));
        for i in 1..N_LIMBS {
            yield_constr.constraint_transition(filter * given_cy[i]);
            yield_constr.constraint_transition(filter * rd[i]);
        }
    } else {
        yield_constr.constraint(filter * given_cy[0] * (given_cy[0] - P::ONES));
        yield_constr.constraint(filter * (cy - given_cy[0]));
        yield_constr.constraint_transition(filter * (rd[0] - P::ONES));
        for i in 1..N_LIMBS {
            yield_constr.constraint(filter * given_cy[i]);
            yield_constr.constraint_transition(filter * rd[i]);
        }
    }
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let is_slt = lv[IS_SLT];
    let is_slti = lv[IS_SLTI];

    let in0 = &lv[INPUT_REGISTER_0];
    let in1 = &lv[INPUT_REGISTER_1];
    let out = &lv[OUTPUT_REGISTER];
    let aux = &lv[AUX_INPUT_REGISTER_0];
    let rd = &lv[AUX_INPUT_REGISTER_1];

    eval_ext_circuit_slt(builder, yield_constr, is_slt, in1, aux, in0, out, rd, false);

    eval_ext_circuit_slt(
        builder,
        yield_constr,
        is_slti,
        in1,
        aux,
        in0,
        out,
        rd,
        false,
    );
}

#[allow(clippy::needless_collect)]
pub(crate) fn eval_ext_circuit_slt<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    filter: ExtensionTarget<D>,
    x: &[ExtensionTarget<D>],
    y: &[ExtensionTarget<D>],
    z: &[ExtensionTarget<D>],
    given_cy: &[ExtensionTarget<D>],
    rd: &[ExtensionTarget<D>],
    is_two_row_op: bool,
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
        if is_two_row_op {
            yield_constr.constraint_transition(builder, filtered_limb_constraint);
        } else {
            yield_constr.constraint(builder, filtered_limb_constraint);
        }

        cy = builder.mul_const_extension(overflow_inv, t);
    }

    let good_cy = builder.sub_extension(cy, given_cy[0]);
    let cy_filter = builder.mul_extension(filter, good_cy);

    // Check given carry is one bit
    let bit_constr = builder.mul_sub_extension(given_cy[0], given_cy[0], given_cy[0]);
    let bit_filter = builder.mul_extension(filter, bit_constr);

    if is_two_row_op {
        yield_constr.constraint_transition(builder, cy_filter);
        let one = builder.one_extension();
        let rd_filter = builder.sub_extension(rd[0], one);
        let rd_filter = builder.mul_extension(filter, rd_filter);
        yield_constr.constraint_transition(builder, rd_filter);
        for i in 1..N_LIMBS {
            let t = builder.mul_extension(filter, given_cy[i]);
            yield_constr.constraint_transition(builder, t);
            let r = builder.mul_extension(filter, rd[i]);
            yield_constr.constraint_transition(builder, r);
        }
    } else {
        yield_constr.constraint(builder, bit_filter);
        yield_constr.constraint(builder, cy_filter);
        let one = builder.one_extension();
        let rd_filter = builder.sub_extension(rd[0], one);
        let rd_filter = builder.mul_extension(filter, rd_filter);
        yield_constr.constraint_transition(builder, rd_filter);
        for i in 1..N_LIMBS {
            let t = builder.mul_extension(filter, given_cy[i]);
            yield_constr.constraint(builder, t);
            let r = builder.mul_extension(filter, rd[i]);
            yield_constr.constraint_transition(builder, r);
        }
    }
}
