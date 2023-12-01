//! Support for the MIPS MULTU instruction.
//!
//! This crate verifies an MIPS MULTU instruction, which takes two
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
//!    a(x) * b(x) - h(x) * x^2 - l(x)
//!
//! is zero when evaluated at x = β, i.e. it is divisible by (x - β);
//! equivalently, there exists a polynomial s (representing the
//! carries from the long multiplication) such that
//!
//!    a(x) * b(x) - h(x) * x^2 - l(x)  - (x - β) * s(x) == 0
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
//!
//! Because A, B and C are 32-bit numbers, the degrees of a, b, h and l
//! are (at most) 1. Thus deg(s) <= 2; On the other hand, the coefficients
//! of s(x) can be as large as 17 bits.
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::arithmetic::columns::*;
use crate::arithmetic::utils::*;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

/// Given the two limbs of `left_in` and `right_in`, computes `left_in * right_in`.
pub(crate) fn generate_multu<F: PrimeField64>(
    lv: &mut [F],
    input0: [i64; N_LIMBS],
    input1: [i64; N_LIMBS],
) {
    let mut left_in = [0; 2 * N_LIMBS];
    left_in[..N_LIMBS].clone_from_slice(&input0);
    let mut right_in = [0; 2 * N_LIMBS];
    right_in[..N_LIMBS].clone_from_slice(&input1);
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

pub fn generate<F: PrimeField64>(lv: &mut [F], left_in: u32, right_in: u32) {
    // TODO: It would probably be clearer/cleaner to read the U32
    // into an [i64;N] and then copy that to the lv table.
    u32_to_array(&mut lv[INPUT_REGISTER_0], left_in);
    u32_to_array(&mut lv[INPUT_REGISTER_1], right_in);

    let input0 = read_value_i64_limbs(lv, INPUT_REGISTER_0);
    let input1 = read_value_i64_limbs(lv, INPUT_REGISTER_1);

    generate_multu(lv, input0, input1);
}

pub(crate) fn eval_packed_generic_multu<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    filter: P,
    left_in_limbs: [P; N_LIMBS],
    right_in_limbs: [P; N_LIMBS],
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let output_limbs_lo = read_value::<N_LIMBS, _>(lv, OUTPUT_REGISTER_LO);
    let output_limbs_hi = read_value::<N_LIMBS, _>(lv, OUTPUT_REGISTER_HI);
    let mut output_limbs = [P::ZEROS; 2 * N_LIMBS];
    output_limbs[..N_LIMBS].copy_from_slice(&output_limbs_lo);
    output_limbs[N_LIMBS..].copy_from_slice(&output_limbs_hi);

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
    // These two lines set constr_poly to the polynomial a(x)b(x) - h(x) * x^2 - l(x),
    // where a, b, h and l are the polynomials
    //
    //   a(x) = \sum_i input0_limbs[i] * x^i
    //   b(x) = \sum_i input1_limbs[i] * x^i
    //   l(x) = \sum_i output0_limbs[i] * x^i
    //   h(x) = \sum_i output1_limbs[i] * x^i
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
    // polynomial a(x)b(x) - h(x) * x^2 - l(x) - (x - β)*s(x). The
    // multiplication is valid if and only if all of those
    // coefficients are zero.
    for &c in &constr_poly {
        yield_constr.constraint(filter * c);
    }
}

pub fn eval_packed_generic<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let input0_limbs = read_value::<N_LIMBS, _>(lv, INPUT_REGISTER_0);
    let input1_limbs = read_value::<N_LIMBS, _>(lv, INPUT_REGISTER_1);

    eval_packed_generic_multu(lv, lv[IS_MULTU], input0_limbs, input1_limbs, yield_constr);
}

pub(crate) fn eval_ext_multu_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    filter: ExtensionTarget<D>,
    left_in_limbs: [ExtensionTarget<D>; N_LIMBS],
    right_in_limbs: [ExtensionTarget<D>; N_LIMBS],
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let output_limbs_lo = read_value::<N_LIMBS, _>(lv, OUTPUT_REGISTER_LO);
    let output_limbs_hi = read_value::<N_LIMBS, _>(lv, OUTPUT_REGISTER_HI);
    let mut output_limbs = [ExtensionTarget::default(); 2 * N_LIMBS];
    output_limbs[..N_LIMBS].copy_from_slice(&output_limbs_lo);
    output_limbs[N_LIMBS..].copy_from_slice(&output_limbs_hi);

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

    eval_ext_multu_circuit(
        builder,
        lv,
        lv[IS_MULTU],
        input0_limbs,
        input1_limbs,
        yield_constr,
    );
}

#[cfg(test)]
mod tests {
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::{Field, Sample};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::arithmetic::columns::NUM_ARITH_COLUMNS;
    use crate::constraint_consumer::ConstraintConsumer;

    const N_RND_TESTS: usize = 100000;
    #[test]
    fn generate_eval_consistency_not_multu() {
        type F = GoldilocksField;

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);
        let mut lv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));

        // if `IS_MULTU == 0`, then the constraints should be met even
        // if all values are garbage.
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
    fn generate_eval_consistency_multu() {
        type F = GoldilocksField;

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);
        let mut lv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));

        // set `IS_MULTU == 1` and ensure all constraints are satisfied.
        lv[IS_MULTU] = F::ONE;

        for _i in 0..N_RND_TESTS {
            // set inputs to random values
            for (ai, bi) in INPUT_REGISTER_0.zip(INPUT_REGISTER_1) {
                lv[ai] = F::from_canonical_u16(rng.gen());
                lv[bi] = F::from_canonical_u16(rng.gen());
            }

            let left_in = rng.gen::<u32>();
            let right_in = rng.gen::<u32>();
            generate(&mut lv, left_in, right_in);

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
