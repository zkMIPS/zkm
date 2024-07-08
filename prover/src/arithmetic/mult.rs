//! Support for the MIPS MULT/MULTU instruction.
//!
//! This crate verifies an MIPS MULT/MULTU instruction, which takes two
//! 32-bit inputs A and B, and produces two 32-bit output H and L satisfying
//!
//!    (H,L)=A*B
//!
//! i.e. H is the higher half of the usual long multiplication
//! A*B and L is the lower half. Inputs A and B, and output H and L, are given as arrays of 16-bit
//! limbs. For example, if the limbs of A are a[0],a[1], then
//!
//!    A = \sum_{i=0}^1 a[i] β^i,
//!
//! where β = 2^16 = 2^LIMB_BITS. To verify that A, B and H, L satisfy
//! the equation we proceed as follows. Define
//!
//!    a(x) = \sum_{i=0}^1 a[i] x^i
//!
//! (so A = a(β)) and similarly for b(x), h(x) and l(x). Then A*B = (H,L)
//! if and only if  the polynomial
//!
//!    a(x) * b(x) - [h,l](x)
//!
//! is zero when evaluated at x = β, i.e. it is divisible by (x - β);
//! equivalently, there exists a polynomial s (representing the
//! carries from the long multiplication) such that
//!
//!    a(x) * b(x) - [h,l](x)  - (x - β) * s(x) == 0
//!
//! In the code below, this "constraint polynomial" is constructed in
//! the variable `constr_poly`. It must be identically zero for the
//! multiplication operation to be verified, or, equivalently, each of
//! its coefficients must be zero. The variable names of the
//! constituent polynomials are (writing N for N_LIMBS=2):
//!
//!   a(x) = \sum_{i=0}^{N-1} input0[i] * x^i
//!   b(x) = \sum_{i=0}^{N-1} input1[i] * x^i
//!   h(x) = \sum_{i=0}^{N-1} output0[i] * x^i
//!   l(x) = \sum_{i=0}^{N-1} output1[i] * x^i
//!   s(x) = \sum_i^{2N-2} aux[i] * x^i

use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::arithmetic::columns::*;
use crate::arithmetic::utils::*;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

/// Given the two limbs of `input0` and `input1`, computes `input0 * input1`.
pub(crate) fn generate<F: PrimeField64>(lv: &mut [F], filter: usize, input0: u32, input1: u32) {
    u32_to_array(&mut lv[INPUT_REGISTER_0], input0);
    u32_to_array(&mut lv[INPUT_REGISTER_1], input1);

    let left_in = read_value_i64_limbs(lv, INPUT_REGISTER_0);
    let right_in = read_value_i64_limbs(lv, INPUT_REGISTER_1);

    if filter == IS_MULT {
        generate_mult(lv, input0, input1);
    } else if filter == IS_MULTU {
        generate_multu(lv, left_in, right_in);
    } else {
        panic!()
    }
}
pub(crate) fn generate_mult<F: PrimeField64>(lv: &mut [F], input0: u32, input1: u32) {
    log::debug!("generate_mult");
    let is_input0_neg = (input0 as i32) < 0;
    let is_input1_neg = (input1 as i32) < 0;

    lv[AUX_EXTRA.start] = F::from_bool(is_input0_neg);
    lv[AUX_EXTRA.start + 1] = F::from_bool(is_input1_neg);
    lv[INPUT_REGISTER_2.start] = F::from_canonical_u32((input0 >> LIMB_BITS) ^ 0x8000);
    lv[INPUT_REGISTER_2.start + 1] = F::from_canonical_u32((input1 >> LIMB_BITS) ^ 0x8000);

    let sign_extend = |is_neg, range| {
        let input = read_value_i64_limbs::<N_LIMBS, _>(lv, range);
        let pad = [if is_neg { u16::MAX as i64 } else { 0 }; N_LIMBS];

        let mut result = [0; 2 * N_LIMBS];
        result[..N_LIMBS].clone_from_slice(&input);
        result[N_LIMBS..].clone_from_slice(&pad);

        result
    };

    let left_in = sign_extend(is_input0_neg, INPUT_REGISTER_0);
    let right_in = sign_extend(is_input1_neg, INPUT_REGISTER_1);

    generate_mult_helper(lv, left_in, right_in);
}

pub(crate) fn generate_multu<F: PrimeField64>(
    lv: &mut [F],
    input0: [i64; N_LIMBS],
    input1: [i64; N_LIMBS],
) {
    let mut left_in = [0; 2 * N_LIMBS];
    left_in[..N_LIMBS].clone_from_slice(&input0);
    let mut right_in = [0; 2 * N_LIMBS];
    right_in[..N_LIMBS].clone_from_slice(&input1);

    generate_mult_helper(lv, left_in, right_in);
}

pub(crate) fn generate_mult_helper<F: PrimeField64>(
    lv: &mut [F],
    left_in: [i64; 2 * N_LIMBS],
    right_in: [i64; 2 * N_LIMBS],
) {
    const MASK: i64 = (1i64 << LIMB_BITS) - 1i64;

    // Input and output have 16-bit limbs
    let mut output_limbs = [0i64; 2 * N_LIMBS];

    // Column-wise pen-and-paper long multiplication on 16-bit limbs.
    // First calculate the coefficients of a(x)*b(x) (in unreduced_prod),
    // then do carry propagation to obtain C = c(β) = a(β)*b(β).
    let mut cy = 0i64;
    let mut unreduced_prod = pol_mul_lo(left_in, right_in);
    for col in 0..2 * N_LIMBS {
        let t = unreduced_prod[col] + cy;
        cy = t >> LIMB_BITS;

        output_limbs[col] = t & MASK;
    }

    lv[OUTPUT_REGISTER_LO].copy_from_slice(
        &output_limbs[..N_LIMBS]
            .iter()
            .map(|c| F::from_canonical_i64(*c))
            .collect::<Vec<_>>(),
    );
    lv[OUTPUT_REGISTER_HI].copy_from_slice(
        &output_limbs[N_LIMBS..]
            .iter()
            .map(|c| F::from_canonical_i64(*c))
            .collect::<Vec<_>>(),
    );
    pol_sub_assign(&mut unreduced_prod, &output_limbs);

    let mut aux_limbs = pol_remove_root_2exp::<LIMB_BITS, _, { 2 * N_LIMBS }>(unreduced_prod);
    aux_limbs[2 * N_LIMBS - 1] = -cy;

    for c in aux_limbs.iter_mut() {
        *c += AUX_COEFF_ABS_MAX;
    }

    debug_assert!(aux_limbs.iter().all(|&c| c.abs() <= 2 * AUX_COEFF_ABS_MAX));

    lv[MULT_AUX_LO].copy_from_slice(&aux_limbs.map(|c| F::from_canonical_u16(c as u16)));
    lv[MULT_AUX_HI].copy_from_slice(&aux_limbs.map(|c| F::from_canonical_u16((c >> 16) as u16)));
}

pub fn eval_packed_generic<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let input0_limbs = read_value::<N_LIMBS, _>(lv, INPUT_REGISTER_0);
    let input1_limbs = read_value::<N_LIMBS, _>(lv, INPUT_REGISTER_1);

    let output_limbs_lo = read_value::<N_LIMBS, _>(lv, OUTPUT_REGISTER_LO);
    let output_limbs_hi = read_value::<N_LIMBS, _>(lv, OUTPUT_REGISTER_HI);
    let mut output_limbs = [P::ZEROS; 2 * N_LIMBS];
    output_limbs[..N_LIMBS].copy_from_slice(&output_limbs_lo);
    output_limbs[N_LIMBS..].copy_from_slice(&output_limbs_hi);

    eval_packed_generic_mult(
        lv,
        lv[IS_MULT],
        input0_limbs,
        input1_limbs,
        output_limbs,
        yield_constr,
    );
    eval_packed_generic_multu(
        lv,
        lv[IS_MULTU],
        input0_limbs,
        input1_limbs,
        output_limbs,
        yield_constr,
    );
}

pub(crate) fn eval_packed_generic_mult<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    filter: P,
    left_in_limbs: [P; N_LIMBS],
    right_in_limbs: [P; N_LIMBS],
    output_limbs: [P; 2 * N_LIMBS],
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let base = P::Scalar::from_canonical_u64(1 << LIMB_BITS);

    let sign_extend = |is_neg_idx: usize,
                       sum_idx: usize,
                       input: &[P; N_LIMBS],
                       yield_constr: &mut ConstraintConsumer<P>| {
        let is_neg = lv[is_neg_idx];
        yield_constr.constraint(filter * is_neg * (P::ONES - is_neg));

        let add = P::Scalar::from_canonical_u64(1 << (LIMB_BITS - 1));
        let sum = lv[sum_idx];
        let input_hi = input[N_LIMBS - 1];
        yield_constr.constraint(filter * (input_hi + add - sum - is_neg * base));

        // Let's begin to extend
        let mut result = [P::ZEROS; 2 * N_LIMBS];
        let pad = [is_neg * P::Scalar::from_canonical_u16(u16::MAX); N_LIMBS];
        result[..N_LIMBS].clone_from_slice(input);
        result[N_LIMBS..].clone_from_slice(&pad);

        result
    };
    let left_in_limbs = sign_extend(
        AUX_EXTRA.start,
        INPUT_REGISTER_2.start,
        &left_in_limbs,
        yield_constr,
    );

    let right_in_limbs = sign_extend(
        AUX_EXTRA.start + 1,
        INPUT_REGISTER_2.start + 1,
        &right_in_limbs,
        yield_constr,
    );

    eval_packed_generic_mult_helper(
        lv,
        filter,
        left_in_limbs,
        right_in_limbs,
        output_limbs,
        yield_constr,
    );
}

pub(crate) fn eval_packed_generic_multu<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    filter: P,
    left_in_limbs: [P; N_LIMBS],
    right_in_limbs: [P; N_LIMBS],
    output_limbs: [P; 2 * N_LIMBS],
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let left_in_limbs = {
        let mut limbs = [P::ZEROS; 2 * N_LIMBS];
        limbs[..N_LIMBS].clone_from_slice(&left_in_limbs);

        limbs
    };

    let right_in_limbs = {
        let mut limbs = [P::ZEROS; 2 * N_LIMBS];
        limbs[..N_LIMBS].clone_from_slice(&right_in_limbs);

        limbs
    };

    eval_packed_generic_mult_helper(
        lv,
        filter,
        left_in_limbs,
        right_in_limbs,
        output_limbs,
        yield_constr,
    );
}

pub(crate) fn eval_packed_generic_mult_helper<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    filter: P,
    left_in_limbs: [P; 2 * N_LIMBS],
    right_in_limbs: [P; 2 * N_LIMBS],
    output_limbs: [P; 2 * N_LIMBS],
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let base = P::Scalar::from_canonical_u64(1 << LIMB_BITS);

    let aux_limbs = {
        // MUL_AUX_INPUT was offset by 2^20 in generation, so we undo
        // that here
        let offset = P::Scalar::from_canonical_u64(AUX_COEFF_ABS_MAX as u64);
        let mut aux_limbs = read_value::<{ 2 * N_LIMBS }, _>(lv, MULT_AUX_LO);
        let aux_limbs_hi = &lv[MULT_AUX_HI];
        for (lo, &hi) in aux_limbs.iter_mut().zip(aux_limbs_hi) {
            *lo += hi * base - offset;
        }
        aux_limbs
    };

    // Constraint poly holds the coefficients of the polynomial that
    // must be identically zero for this multiplication to be
    // verified.
    //
    // These two lines set constr_poly to the polynomial a(x)b(x) - [h,l](x),
    // where a, b, h and l are the polynomials
    //
    //   a(x) = \sum_i input0_limbs[i] * x^i
    //   b(x) = \sum_i input1_limbs[i] * x^i
    //   [h,l](x) = \sum_i output_limbs[i] * x^i
    //
    // This polynomial should equal (x - β)*s(x) where s is
    //
    //   s(x) = \sum_i aux_limbs[i] * x^i
    //
    let mut constr_poly = pol_mul_lo(left_in_limbs, right_in_limbs);
    pol_sub_assign(&mut constr_poly, &output_limbs);

    // This subtracts (x - β) * s(x) from constr_poly.
    pol_sub_assign(&mut constr_poly, &pol_adjoin_root(aux_limbs, base));

    // At this point constr_poly holds the coefficients of the
    // polynomial a(x)b(x) - [h,l](x) - (x - β)*s(x). The
    // multiplication is valid if and only if all of those
    // coefficients are zero.
    for &c in &constr_poly {
        yield_constr.constraint(filter * c);
    }
}

pub(crate) fn eval_ext_mult_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    filter: ExtensionTarget<D>,
    left_in_limbs: [ExtensionTarget<D>; N_LIMBS],
    right_in_limbs: [ExtensionTarget<D>; N_LIMBS],
    output_limbs: [ExtensionTarget<D>; 2 * N_LIMBS],
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let base = builder.constant_extension(F::Extension::from_canonical_u64(1 << LIMB_BITS));
    let one = builder.one_extension();

    let sign_extend = |builder: &mut CircuitBuilder<F, D>,
                       is_neg_idx: usize,
                       sum_idx: usize,
                       input: &[ExtensionTarget<D>; N_LIMBS],
                       yield_constr: &mut RecursiveConstraintConsumer<F, D>| {
        let is_neg = lv[is_neg_idx];
        let t0 = builder.sub_extension(one, is_neg);
        let t = builder.mul_many_extension([filter, is_neg, t0]);
        yield_constr.constraint(builder, t);

        let add =
            builder.constant_extension(F::Extension::from_canonical_u64(1 << (LIMB_BITS - 1)));
        let sum = lv[sum_idx];
        let input_hi = input[N_LIMBS - 1];
        let t0 = builder.add_extension(input_hi, add);
        let t1 = builder.sub_extension(t0, sum);
        let t2 = builder.mul_extension(is_neg, base);
        let t3 = builder.sub_extension(t1, t2);
        let t = builder.mul_extension(filter, t3);

        yield_constr.constraint(builder, t);

        // Let's begin to extend
        let mut result = [ExtensionTarget::default(); 2 * N_LIMBS];
        let u16_max = builder.constant_extension(F::Extension::from_canonical_u16(u16::MAX));
        let pad = builder.mul_extension(is_neg, u16_max);

        result[..N_LIMBS].clone_from_slice(input);
        result[N_LIMBS..].clone_from_slice(&[pad; N_LIMBS]);

        result
    };
    let left_in_limbs = sign_extend(
        builder,
        AUX_EXTRA.start,
        INPUT_REGISTER_2.start,
        &left_in_limbs,
        yield_constr,
    );
    let right_in_limbs = sign_extend(
        builder,
        AUX_EXTRA.start + 1,
        INPUT_REGISTER_2.start + 1,
        &right_in_limbs,
        yield_constr,
    );

    eval_ext_mult_helper_circuit(
        builder,
        lv,
        filter,
        left_in_limbs,
        right_in_limbs,
        output_limbs,
        yield_constr,
    );
}

pub(crate) fn eval_ext_multu_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    filter: ExtensionTarget<D>,
    left_in_limbs: [ExtensionTarget<D>; N_LIMBS],
    right_in_limbs: [ExtensionTarget<D>; N_LIMBS],
    output_limbs: [ExtensionTarget<D>; 2 * N_LIMBS],
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let left_in_limbs = {
        let mut limbs = [builder.zero_extension(); 2 * N_LIMBS];
        limbs[..N_LIMBS].clone_from_slice(&left_in_limbs);

        limbs
    };

    let right_in_limbs = {
        let mut limbs = [builder.zero_extension(); 2 * N_LIMBS];
        limbs[..N_LIMBS].clone_from_slice(&right_in_limbs);

        limbs
    };

    eval_ext_mult_helper_circuit(
        builder,
        lv,
        filter,
        left_in_limbs,
        right_in_limbs,
        output_limbs,
        yield_constr,
    );
}
pub(crate) fn eval_ext_mult_helper_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    filter: ExtensionTarget<D>,
    left_in_limbs: [ExtensionTarget<D>; 2 * N_LIMBS],
    right_in_limbs: [ExtensionTarget<D>; 2 * N_LIMBS],
    output_limbs: [ExtensionTarget<D>; 2 * N_LIMBS],
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let base = builder.constant_extension(F::Extension::from_canonical_u64(1 << LIMB_BITS));
    let aux_limbs = {
        let offset =
            builder.constant_extension(F::Extension::from_canonical_u64(AUX_COEFF_ABS_MAX as u64));
        let mut aux_limbs = read_value::<{ 2 * N_LIMBS }, _>(lv, MULT_AUX_LO);
        let aux_limbs_hi = &lv[MULT_AUX_HI];
        for (lo, &hi) in aux_limbs.iter_mut().zip(aux_limbs_hi) {
            //*lo = lo + hi * base - offset;
            let t = builder.mul_sub_extension(hi, base, offset);
            *lo = builder.add_extension(*lo, t);
        }

        aux_limbs
    };

    let mut constr_poly = pol_mul_lo_ext_circuit(builder, left_in_limbs, right_in_limbs);
    pol_sub_assign_ext_circuit(builder, &mut constr_poly, &output_limbs);

    let rhs = pol_adjoin_root_ext_circuit(builder, aux_limbs, base);
    pol_sub_assign_ext_circuit(builder, &mut constr_poly, &rhs);

    for &c in &constr_poly {
        let filter = builder.mul_extension(filter, c);
        yield_constr.constraint(builder, filter);
    }
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let input0_limbs = read_value::<N_LIMBS, _>(lv, INPUT_REGISTER_0);
    let input1_limbs = read_value::<N_LIMBS, _>(lv, INPUT_REGISTER_1);

    let output_limbs_lo = read_value::<N_LIMBS, _>(lv, OUTPUT_REGISTER_LO);
    let output_limbs_hi = read_value::<N_LIMBS, _>(lv, OUTPUT_REGISTER_HI);
    let mut output_limbs = [ExtensionTarget::default(); 2 * N_LIMBS];
    output_limbs[..N_LIMBS].copy_from_slice(&output_limbs_lo);
    output_limbs[N_LIMBS..].copy_from_slice(&output_limbs_hi);

    eval_ext_mult_circuit(
        builder,
        lv,
        lv[IS_MULT],
        input0_limbs,
        input1_limbs,
        output_limbs,
        yield_constr,
    );

    eval_ext_multu_circuit(
        builder,
        lv,
        lv[IS_MULTU],
        input0_limbs,
        input1_limbs,
        output_limbs,
        yield_constr,
    );
}

#[cfg(test)]
mod tests {
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Sample;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;

    const N_RND_TESTS: usize = 100000;
    const OPS: [usize; 2] = [IS_MULT, IS_MULTU];
    #[test]
    fn generate_eval_consistency_not_mult() {
        type F = GoldilocksField;

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);
        let mut lv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));

        // if `IS_MULT and IS_MULTU == 0`, then the constraints should be met even
        // if all values are garbage.
        lv[IS_MULT] = F::ZERO;
        lv[IS_MULTU] = F::ZERO;

        let mut constraint_consumer = ConstraintConsumer::new(
            vec![GoldilocksField(2), GoldilocksField(3), GoldilocksField(5)],
            GoldilocksField::ONE,
            GoldilocksField::ONE,
            GoldilocksField::ONE,
        );
        eval_packed_generic(&lv, &mut constraint_consumer);
        for &acc in &constraint_consumer.constraint_accs {
            assert_eq!(acc, GoldilocksField::ZERO);
        }
    }

    #[test]
    fn generate_eval_consistency_mult() {
        type F = GoldilocksField;

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);
        let mut lv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));

        for op_filter in OPS {
            for op in OPS {
                lv[op] = F::ZEROS;
            }
            lv[op_filter] = F::ONES;
            for i in 0..N_RND_TESTS {
                // set inputs to random values
                for (ai, bi) in INPUT_REGISTER_0.zip(INPUT_REGISTER_1) {
                    lv[ai] = F::from_canonical_u16(rng.gen());
                    lv[bi] = F::from_canonical_u16(rng.gen());
                }

                let mut left_in = rng.gen::<u32>();
                if i > N_RND_TESTS / 2 {
                    left_in |= 0x80000000;
                }
                let right_in = rng.gen::<u32>();
                generate(&mut lv, op_filter, left_in, right_in);

                let mut constraint_consumer = ConstraintConsumer::new(
                    vec![GoldilocksField(2), GoldilocksField(3), GoldilocksField(5)],
                    GoldilocksField::ONE,
                    GoldilocksField::ONE,
                    GoldilocksField::ONE,
                );
                eval_packed_generic(&lv, &mut constraint_consumer);
                for &acc in &constraint_consumer.constraint_accs {
                    assert_eq!(acc, GoldilocksField::ZERO);
                }
            }
        }
    }
}
