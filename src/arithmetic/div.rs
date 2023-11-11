//! Support for MIPS instructions DIV and DIVU.
use std::ops::Range;

use crate::arithmetic::addcy::{eval_ext_circuit_addcy, eval_packed_generic_addcy};
use num::{One, Zero};
use num_bigint::{BigInt, Sign};
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::arithmetic::columns::*;
use crate::arithmetic::utils::*;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

/// Generate the output and auxiliary values for given `operation`.
///
/// NB: `operation` can set the higher order elements in its result to
/// zero if they are not used.
pub(crate) fn generate_modular_op<F: PrimeField64>(
    lv: &[F],
    nv: &mut [F],
    filter: usize,
    pol_input: [i64; 2 * N_LIMBS - 1],
    modulus_range: Range<usize>,
) -> ([F; N_LIMBS], [F; 2 * N_LIMBS]) {
    assert_eq!(modulus_range.len(), N_LIMBS);
    let mut modulus_limbs = read_value_i64_limbs(lv, modulus_range);

    // BigInts are just used to avoid having to implement modular
    // reduction.
    let mut modulus = columns_to_bigint(&modulus_limbs);

    // constr_poly is initialised to the input calculation as
    // polynomials, and is used as such for the BigInt reduction;
    // later, other values are added/subtracted, which is where its
    // meaning as the "constraint polynomial" comes in.
    let mut constr_poly = [0i64; 2 * N_LIMBS];
    constr_poly[..2 * N_LIMBS - 1].copy_from_slice(&pol_input);

    // two_exp_32 == 2^32
    let two_exp_32 = {
        let mut t = BigInt::zero();
        t.set_bit(32, true);
        t
    };

    let mut mod_is_zero = F::ZERO;
    if modulus.is_zero() {
        if filter == IS_DIV || filter == IS_DIVU {
            // set modulus = 2^32; the condition above means we know
            // it's zero at this point, so we can just set bit 32.
            modulus.set_bit(32, true);
            // modulus_limbs don't play a role below
        } else {
            // set modulus = 1
            modulus = BigInt::one();
            modulus_limbs[0] = 1i64;
        }
        mod_is_zero = F::ONE;
    }

    let input = columns_to_bigint(&constr_poly);

    // modulus != 0 here, because, if the given modulus was zero, then
    // it was set to 1 or 2^32 above
    let mut output = &input % &modulus;
    // output will be -ve (but > -modulus) if input was -ve, so we can
    // add modulus to obtain a "canonical" +ve output.
    if output.sign() == Sign::Minus {
        output += &modulus;
    }
    let output_limbs = bigint_to_columns::<N_LIMBS>(&output);
    // exact division; can be -ve for SUB* operations.
    let quot = (&input - &output) / &modulus;
    if quot.sign() == Sign::Minus {
        // TODO: check if any op use?
        unimplemented!();
    }
    let quot_limbs = bigint_to_columns::<{ 2 * N_LIMBS }>(&quot);

    // output < modulus here; the proof requires (output - modulus) % 2^32:
    let out_aux_red = bigint_to_columns::<N_LIMBS>(&(two_exp_32 - modulus + output));

    // constr_poly is the array of coefficients of the polynomial
    //
    //   operation(a(x), b(x)) - c(x) - s(x)*m(x).
    //
    pol_sub_assign(&mut constr_poly, &output_limbs);
    let prod = pol_mul_wide2(quot_limbs, modulus_limbs);
    pol_sub_assign(&mut constr_poly, &prod[0..2 * N_LIMBS]);

    // Higher order terms of the product must be zero for valid quot and modulus:
    debug_assert!(&prod[2 * N_LIMBS..].iter().all(|&x| x == 0i64));

    // constr_poly must be zero when evaluated at x = β :=
    // 2^LIMB_BITS, hence it's divisible by (x - β). `aux_limbs` is
    // the result of removing that root.
    let mut aux_limbs = pol_remove_root_2exp::<LIMB_BITS, _, { 2 * N_LIMBS }>(constr_poly);

    for c in aux_limbs.iter_mut() {
        // we store the unsigned offset value c + 2^20.
        *c += AUX_COEFF_ABS_MAX;
    }
    debug_assert!(aux_limbs.iter().all(|&c| c.abs() <= 2 * AUX_COEFF_ABS_MAX));

    for (i, &c) in MODULAR_AUX_INPUT_LO.zip(&aux_limbs[..2 * N_LIMBS - 1]) {
        nv[i] = F::from_canonical_u16(c as u16);
    }
    for (i, &c) in MODULAR_AUX_INPUT_HI.zip(&aux_limbs[..2 * N_LIMBS - 1]) {
        nv[i] = F::from_canonical_u16((c >> 16) as u16);
    }

    // quo_input can be negative for SUB* operations, so we offset it
    // to ensure i

    nv[MODULAR_MOD_IS_ZERO] = mod_is_zero;
    nv[MODULAR_OUT_AUX_RED].copy_from_slice(&out_aux_red.map(F::from_canonical_i64));
    nv[MODULAR_DIV_DENOM_IS_ZERO] = mod_is_zero * (lv[IS_DIV] + lv[IS_DIVU]);

    (
        output_limbs.map(F::from_canonical_i64),
        quot_limbs.map(F::from_noncanonical_i64),
    )
}

/// Generates the output and auxiliary values for modular operations,
/// assuming the input, modular and output limbs are already set.
pub(crate) fn generate_div<F: PrimeField64>(
    lv: &mut [F],
    nv: &mut [F],
    filter: usize,
    input_limbs_range: Range<usize>,
    modulus_range: Range<usize>,
) {
    let input_limbs = read_value_i64_limbs::<N_LIMBS, _>(lv, input_limbs_range);
    let pol_input = pol_extend(input_limbs);
    let (out, quo_input) = generate_modular_op(lv, nv, filter, pol_input, modulus_range);

    debug_assert!(
        &quo_input[N_LIMBS..].iter().all(|&x| x == F::ZERO),
        "expected top half of quo_input to be zero"
    );

    // Initialise whole (double) register to zero; the low half will
    // be overwritten via lv[AUX_INPUT_REGISTER] below.
    for i in MODULAR_QUO_INPUT {
        lv[i] = F::ZERO;
    }

    // TODO: Add more ops(shift?) that use div
    match filter {
        IS_DIV | IS_DIVU => {
            debug_assert!(
                lv[OUTPUT_REGISTER]
                    .iter()
                    .zip(&quo_input[..N_LIMBS])
                    .all(|(x, y)| x == y),
                "computed output doesn't match expected"
            );
            lv[AUX_INPUT_REGISTER_0].copy_from_slice(&out);
        }
        _ => panic!("expected filter to be IS_DIV, or IS_DIVU but it was {filter}"),
    };
}

/// Generate the output and auxiliary values for modular operations.
pub(crate) fn generate<F: PrimeField64>(
    lv: &mut [F],
    nv: &mut [F],
    filter: usize,
    input0: u32,
    input1: u32,
    result: u32,
) {
    debug_assert!(lv.len() == NUM_ARITH_COLUMNS);

    u32_to_array(&mut lv[INPUT_REGISTER_0], input0);
    u32_to_array(&mut lv[INPUT_REGISTER_1], input1);
    u32_to_array(&mut lv[OUTPUT_REGISTER], result);

    generate_div(lv, nv, filter, INPUT_REGISTER_0, INPUT_REGISTER_1);
}

/// Convert the base-2^16 representation of a number into a BigInt.
///
/// Given `N` signed (16 + ε)-bit values in `limbs`, return the BigInt
///
///   \sum_{i=0}^{N-1} limbs[i] * β^i.
///
/// This is basically "evaluate the given polynomial at β". Although
/// the input type is i64, the values must always be in (-2^16 - ε,
/// 2^16 + ε) because of the caller's range check on the inputs (the ε
/// allows us to convert calculated output, which can be bigger than
/// 2^16).
fn columns_to_bigint<const N: usize>(limbs: &[i64; N]) -> BigInt {
    const BASE: i64 = 1i64 << LIMB_BITS;

    let mut pos_limbs_u32 = Vec::with_capacity(N / 2 + 1);
    let mut neg_limbs_u32 = Vec::with_capacity(N / 2 + 1);
    let mut cy = 0i64; // cy is necessary to handle ε > 0
    for i in 0..(N / 2) {
        let t = cy + limbs[2 * i] + BASE * limbs[2 * i + 1];
        pos_limbs_u32.push(if t > 0 { t as u32 } else { 0u32 });
        neg_limbs_u32.push(if t < 0 { -t as u32 } else { 0u32 });
        cy = t / (1i64 << 32);
    }
    if N & 1 != 0 {
        // If N is odd we need to add the last limb on its own
        let t = cy + limbs[N - 1];
        pos_limbs_u32.push(if t > 0 { t as u32 } else { 0u32 });
        neg_limbs_u32.push(if t < 0 { -t as u32 } else { 0u32 });
        cy = t / (1i64 << 32);
    }
    pos_limbs_u32.push(if cy > 0 { cy as u32 } else { 0u32 });
    neg_limbs_u32.push(if cy < 0 { -cy as u32 } else { 0u32 });

    let pos = BigInt::from_slice(Sign::Plus, &pos_limbs_u32);
    let neg = BigInt::from_slice(Sign::Plus, &neg_limbs_u32);
    pos - neg
}

/// Convert a BigInt into a base-2^16 representation.
///
/// Given a BigInt `num`, return an array of `N` signed 16-bit
/// values, say `limbs`, such that
///
///   num = \sum_{i=0}^{N-1} limbs[i] * β^i.
///
/// Note that `N` must be at least ceil(log2(num)/16) in order to be
/// big enough to hold `num`.
fn bigint_to_columns<const N: usize>(num: &BigInt) -> [i64; N] {
    assert!(num.bits() <= 16 * N as u64);
    let mut output = [0i64; N];
    for (i, limb) in num.iter_u32_digits().enumerate() {
        output[2 * i] = limb as u16 as i64;
        output[2 * i + 1] = (limb >> LIMB_BITS) as i64;
    }
    if num.sign() == Sign::Minus {
        for c in output.iter_mut() {
            *c = -*c;
        }
    }
    output
}

pub(crate) fn check_reduced<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    nv: &[P; NUM_ARITH_COLUMNS],
    yield_constr: &mut ConstraintConsumer<P>,
    filter: P,
    output: [P; N_LIMBS],
    modulus: [P; N_LIMBS],
    mod_is_zero: P,
) {
    // Verify that the output is reduced, i.e. output < modulus.
    let out_aux_red = &nv[MODULAR_OUT_AUX_RED];
    // This sets is_less_than to 1 unless we get mod_is_zero when
    // doing a DIV, DIV or maybe `shift` ; in that case, we need is_less_than=0,
    // since eval_packed_generic_addcy checks
    //
    //   modulus + out_aux_red == output + is_less_than*2^64
    //
    // and we are given output = out_aux_red when modulus is zero.
    let mut is_less_than = [P::ZEROS; N_LIMBS];
    is_less_than[0] = P::ONES - mod_is_zero * (lv[IS_DIV] + lv[IS_DIVU]);
    // NB: output and modulus in lv while out_aux_red and
    // is_less_than (via mod_is_zero) depend on nv, hence the
    // 'is_two_row_op' argument is set to 'true'.
    eval_packed_generic_addcy(
        yield_constr,
        filter,
        &modulus,
        out_aux_red,
        &output,
        &is_less_than,
        true,
    );
}

/// Build the part of the constraint polynomial that applies to the
/// DIV, DIVU operations and perform the common verifications.
///
/// Specifically, with the notation above, build the polynomial
///
///   c(x) + q(x) * m(x) + (x - β) * s(x)
///
/// and check consistency when m = 0, and that c is reduced. Note that
/// q(x) CANNOT be negative here.
pub(crate) fn modular_constr_poly<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    nv: &[P; NUM_ARITH_COLUMNS],
    yield_constr: &mut ConstraintConsumer<P>,
    filter: P,
    mut output: [P; N_LIMBS],
    mut modulus: [P; N_LIMBS],
    quot: [P; 2 * N_LIMBS],
) -> [P; 2 * N_LIMBS] {
    let mod_is_zero = nv[MODULAR_MOD_IS_ZERO];

    // Check that mod_is_zero is zero or one
    yield_constr.constraint_transition(filter * (mod_is_zero * mod_is_zero - mod_is_zero));

    // Check that mod_is_zero is zero if modulus is not zero (they
    // could both be zero)
    let limb_sum = modulus.into_iter().sum::<P>();
    yield_constr.constraint_transition(filter * limb_sum * mod_is_zero);

    // See the file documentation for why this suffices to handle
    // modulus = 0.
    modulus[0] += mod_is_zero;

    // Is 1 iff the operation is DIV or DIVU and the denominator is zero.
    // TODO: shift ops
    let div_denom_is_zero = nv[MODULAR_DIV_DENOM_IS_ZERO];
    yield_constr.constraint_transition(
        filter * (mod_is_zero * (lv[IS_DIV] + lv[IS_DIVU]) - div_denom_is_zero),
    );

    // Needed to compensate for adding mod_is_zero to modulus above,
    // since the call eval_packed_generic_addcy() below subtracts modulus
    // to verify in the case of a DIV or SHR.
    output[0] += div_denom_is_zero;

    check_reduced(lv, nv, yield_constr, filter, output, modulus, mod_is_zero);

    // restore output[0]
    output[0] -= div_denom_is_zero;

    // prod = q(x) * m(x)
    let prod = pol_mul_wide2(quot, modulus);
    // higher order terms must be zero
    for &x in prod[2 * N_LIMBS..].iter() {
        yield_constr.constraint_transition(filter * x);
    }

    // constr_poly = c(x) + q(x) * m(x)
    let mut constr_poly: [_; 2 * N_LIMBS] = prod[0..2 * N_LIMBS].try_into().unwrap();
    pol_add_assign(&mut constr_poly, &output);

    let base = P::Scalar::from_canonical_u64(1 << LIMB_BITS);
    // TODO: change AUX_COEFF_ABS_MAX?
    let offset = P::Scalar::from_canonical_u64(AUX_COEFF_ABS_MAX as u64);

    // constr_poly = c(x) + q(x) * m(x) + (x - β) * s(x)c
    let mut aux = [P::ZEROS; 2 * N_LIMBS];
    for (c, i) in aux.iter_mut().zip(MODULAR_AUX_INPUT_LO) {
        // MODULAR_AUX_INPUT elements were offset by 2^20 in
        // generation, so we undo that here.
        *c = nv[i] - offset;
    }
    // add high 16-bits of aux input
    for (c, j) in aux.iter_mut().zip(MODULAR_AUX_INPUT_HI) {
        *c += base * nv[j];
    }

    pol_add_assign(&mut constr_poly, &pol_adjoin_root(aux, base));

    constr_poly
}

/// Verify that num = quo * den + rem and 0 <= rem < den.
pub(crate) fn eval_packed_divmod_helper<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    nv: &[P; NUM_ARITH_COLUMNS],
    yield_constr: &mut ConstraintConsumer<P>,
    filter: P,
    num_range: Range<usize>,
    den_range: Range<usize>,
    quo_range: Range<usize>,
    rem_range: Range<usize>,
) {
    debug_assert!(quo_range.len() == N_LIMBS);
    debug_assert!(rem_range.len() == N_LIMBS);

    yield_constr.constraint_last_row(filter);

    let num = &lv[num_range];
    let den = read_value(lv, den_range);
    let quo = {
        let mut quo = [P::ZEROS; 2 * N_LIMBS];
        quo[..N_LIMBS].copy_from_slice(&lv[quo_range]);
        quo
    };
    let rem = read_value(lv, rem_range);

    let mut constr_poly = modular_constr_poly(lv, nv, yield_constr, filter, rem, den, quo);

    let input = num;
    pol_sub_assign(&mut constr_poly, input);

    for &c in constr_poly.iter() {
        yield_constr.constraint_transition(filter * c);
    }
}

pub(crate) fn eval_packed<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    nv: &[P; NUM_ARITH_COLUMNS],
    yield_constr: &mut ConstraintConsumer<P>,
) {
    eval_packed_divmod_helper(
        lv,
        nv,
        yield_constr,
        lv[IS_DIV] + lv[IS_DIVU],
        INPUT_REGISTER_0,
        INPUT_REGISTER_1,
        OUTPUT_REGISTER,
        AUX_INPUT_REGISTER_0,
    );
}

pub(crate) fn modular_constr_poly_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    nv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    builder: &mut CircuitBuilder<F, D>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    filter: ExtensionTarget<D>,
    mut output: [ExtensionTarget<D>; N_LIMBS],
    mut modulus: [ExtensionTarget<D>; N_LIMBS],
    quot: [ExtensionTarget<D>; 2 * N_LIMBS],
) -> [ExtensionTarget<D>; 2 * N_LIMBS] {
    let mod_is_zero = nv[MODULAR_MOD_IS_ZERO];

    // Check that mod_is_zero is zero or one
    let t = builder.mul_sub_extension(mod_is_zero, mod_is_zero, mod_is_zero);
    let t = builder.mul_extension(filter, t);
    yield_constr.constraint_transition(builder, t);

    // Check that mod_is_zero is zero if modulus is not zero (they
    // could both be zero)
    let limb_sum = builder.add_many_extension(modulus);
    let t = builder.mul_extension(limb_sum, mod_is_zero);
    let t = builder.mul_extension(filter, t);
    yield_constr.constraint_transition(builder, t);

    modulus[0] = builder.add_extension(modulus[0], mod_is_zero);

    // Is 1 iff the operation is DIV, DIVU and the denominator is zero.
    let div_denom_is_zero = nv[MODULAR_DIV_DENOM_IS_ZERO];
    let div_shr_filter = builder.add_extension(lv[IS_DIV], lv[IS_DIVU]);
    let t = builder.mul_sub_extension(mod_is_zero, div_shr_filter, div_denom_is_zero);
    let t = builder.mul_extension(filter, t);
    yield_constr.constraint_transition(builder, t);

    // Needed to compensate for adding mod_is_zero to modulus above,
    // since the call eval_packed_generic_addcy() below subtracts modulus
    // to verify in the case of a DIV or DIVU.
    output[0] = builder.add_extension(output[0], div_denom_is_zero);

    // Verify that the output is reduced, i.e. output < modulus.
    let out_aux_red = &nv[MODULAR_OUT_AUX_RED];
    let one = builder.one_extension();
    let zero = builder.zero_extension();
    let mut is_less_than = [zero; N_LIMBS];
    is_less_than[0] =
        builder.arithmetic_extension(F::NEG_ONE, F::ONE, mod_is_zero, div_shr_filter, one);

    eval_ext_circuit_addcy(
        builder,
        yield_constr,
        filter,
        &modulus,
        out_aux_red,
        &output,
        &is_less_than,
        true,
    );
    // restore output[0]
    output[0] = builder.sub_extension(output[0], div_denom_is_zero);

    // prod = q(x) * m(x)
    let prod = pol_mul_wide2_ext_circuit(builder, quot, modulus);
    // higher order terms must be zero
    for &x in prod[2 * N_LIMBS..].iter() {
        let t = builder.mul_extension(filter, x);
        yield_constr.constraint_transition(builder, t);
    }

    // constr_poly = c(x) + q(x) * m(x)
    let mut constr_poly: [_; 2 * N_LIMBS] = prod[0..2 * N_LIMBS].try_into().unwrap();
    pol_add_assign_ext_circuit(builder, &mut constr_poly, &output);

    let offset =
        builder.constant_extension(F::Extension::from_canonical_u64(AUX_COEFF_ABS_MAX as u64));
    let zero = builder.zero_extension();

    // constr_poly = c(x) + q(x) * m(x)
    let mut aux = [zero; 2 * N_LIMBS];
    for (c, i) in aux.iter_mut().zip(MODULAR_AUX_INPUT_LO) {
        *c = builder.sub_extension(nv[i], offset);
    }
    // add high 16-bits of aux input
    let base = F::from_canonical_u64(1u64 << LIMB_BITS);
    for (c, j) in aux.iter_mut().zip(MODULAR_AUX_INPUT_HI) {
        *c = builder.mul_const_add_extension(base, nv[j], *c);
    }

    let base = builder.constant_extension(base.into());
    let t = pol_adjoin_root_ext_circuit(builder, aux, base);
    pol_add_assign_ext_circuit(builder, &mut constr_poly, &t);

    constr_poly
}

pub(crate) fn eval_ext_circuit_divmod_helper<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    nv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    filter: ExtensionTarget<D>,
    num_range: Range<usize>,
    den_range: Range<usize>,
    quo_range: Range<usize>,
    rem_range: Range<usize>,
) {
    yield_constr.constraint_last_row(builder, filter);

    let num = &lv[num_range];
    let den = read_value(lv, den_range);
    let quo = {
        let zero = builder.zero_extension();
        let mut quo = [zero; 2 * N_LIMBS];
        quo[..N_LIMBS].copy_from_slice(&lv[quo_range]);
        quo
    };
    let rem = read_value(lv, rem_range);

    let mut constr_poly =
        modular_constr_poly_ext_circuit(lv, nv, builder, yield_constr, filter, rem, den, quo);

    let input = num;
    pol_sub_assign_ext_circuit(builder, &mut constr_poly, input);

    for &c in constr_poly.iter() {
        let t = builder.mul_extension(filter, c);
        yield_constr.constraint_transition(builder, t);
    }
}

pub(crate) fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    nv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let filter = builder.add_extension(lv[IS_DIV], lv[IS_DIVU]);
    eval_ext_circuit_divmod_helper(
        builder,
        lv,
        nv,
        yield_constr,
        filter,
        INPUT_REGISTER_0,
        INPUT_REGISTER_1,
        OUTPUT_REGISTER,
        AUX_INPUT_REGISTER_0,
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

    const N_RND_TESTS: usize = 1000;
    const MODULAR_OPS: [usize; 2] = [IS_DIV, IS_DIVU];

    #[test]
    fn generate_eval_consistency_not_modular() {
        type F = GoldilocksField;

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);
        let mut lv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));
        let nv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));

        // if `IS_MOD == 0`, then the constraints should be met even
        // if all values are garbage (and similarly for the other operations).
        for op in MODULAR_OPS {
            lv[op] = F::ZERO;
        }

        let mut constraint_consumer = ConstraintConsumer::new(
            vec![GoldilocksField(2), GoldilocksField(3), GoldilocksField(5)],
            GoldilocksField::ONE,
            GoldilocksField::ONE,
            GoldilocksField::ONE,
        );
        eval_packed(&lv, &nv, &mut constraint_consumer);
        for &acc in &constraint_consumer.constraint_accs {
            assert_eq!(acc, GoldilocksField::ZERO);
        }
    }

    #[test]
    fn generate_eval_consistency() {
        type F = GoldilocksField;

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);

        for op_filter in MODULAR_OPS {
            for i in 0..N_RND_TESTS {
                // set inputs to random values
                let mut lv = [F::default(); NUM_ARITH_COLUMNS]
                    .map(|_| F::from_canonical_u16(rng.gen::<u16>()));
                let mut nv = [F::default(); NUM_ARITH_COLUMNS]
                    .map(|_| F::from_canonical_u16(rng.gen::<u16>()));

                // Reset operation columns, then select one
                for op in MODULAR_OPS {
                    lv[op] = F::ZERO;
                }
                lv[op_filter] = F::ONE;

                let input0 = rng.gen();
                let mut input1: u32 = rng.gen();
                if i > N_RND_TESTS / 2 {
                    input1 &= 0xffff;
                }

                let result = if input1 == 0 {
                    0
                } else if op_filter == IS_DIV || op_filter == IS_DIVU {
                    input0 / input1
                } else {
                    panic!()
                };
                generate(&mut lv, &mut nv, op_filter, input0, input1, result);

                let mut constraint_consumer = ConstraintConsumer::new(
                    vec![GoldilocksField(2), GoldilocksField(3), GoldilocksField(5)],
                    GoldilocksField::ONE,
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                );
                eval_packed(&lv, &nv, &mut constraint_consumer);
                for &acc in &constraint_consumer.constraint_accs {
                    assert_eq!(acc, GoldilocksField::ZERO);
                }
            }
        }
    }

    #[test]
    fn zero_modulus() {
        type F = GoldilocksField;

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);

        for op_filter in MODULAR_OPS {
            for _i in 0..N_RND_TESTS {
                // set inputs to random values and the modulus to zero;
                // the output is defined to be zero when modulus is zero.
                let mut lv = [F::default(); NUM_ARITH_COLUMNS]
                    .map(|_| F::from_canonical_u16(rng.gen::<u16>()));
                let mut nv = [F::default(); NUM_ARITH_COLUMNS]
                    .map(|_| F::from_canonical_u16(rng.gen::<u16>()));

                // Reset operation columns, then select one
                for op in MODULAR_OPS {
                    lv[op] = F::ZERO;
                }
                lv[op_filter] = F::ONE;

                let input0 = rng.gen();
                let input1 = 0;

                generate(&mut lv, &mut nv, op_filter, input0, input1, 0);

                // check that the correct output was generated
                assert!(lv[OUTPUT_REGISTER].iter().all(|&c| c == F::ZERO));

                let mut constraint_consumer = ConstraintConsumer::new(
                    vec![GoldilocksField(2), GoldilocksField(3), GoldilocksField(5)],
                    GoldilocksField::ONE,
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                );
                eval_packed(&lv, &nv, &mut constraint_consumer);
                assert!(constraint_consumer
                    .constraint_accs
                    .iter()
                    .all(|&acc| acc == F::ZERO));

                // Corrupt one output limb by setting it to a non-zero value
                let random_oi = OUTPUT_REGISTER.start + rng.gen::<usize>() % N_LIMBS;
                lv[random_oi] = F::from_canonical_u16(rng.gen_range(1..u16::MAX));

                eval_packed(&lv, &nv, &mut constraint_consumer);

                // Check that at least one of the constraints was non-zero
                assert!(constraint_consumer
                    .constraint_accs
                    .iter()
                    .any(|&acc| acc != F::ZERO));
            }
        }
    }
}
