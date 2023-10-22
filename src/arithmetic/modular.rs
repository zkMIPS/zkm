use std::ops::Range;

use num::bigint::Sign;
use num::{BigInt, One, Zero};
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use static_assertions::const_assert;

use super::columns;
use crate::arithmetic::addcy::{eval_ext_circuit_addcy, eval_packed_generic_addcy};
use crate::arithmetic::columns::*;
use crate::arithmetic::utils::*;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

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
    assert!(modulus_range.len() == N_LIMBS);
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
        if filter == columns::IS_DIV || filter == columns::IS_SHR {
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
        debug_assert!(filter == IS_SUBMOD);
    }
    let mut quot_limbs = bigint_to_columns::<{ 2 * N_LIMBS }>(&quot);

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
    // to ensure it's positive.
    if [columns::IS_SUBMOD].contains(&filter) {
        let (lo, hi) = quot_limbs.split_at_mut(N_LIMBS);

        // Verify that the elements are in the expected range.
        debug_assert!(lo.iter().all(|&c| c <= u16::max_value() as i64));

        // Top half of quot_limbs should be zero.
        debug_assert!(hi.iter().all(|&d| d.is_zero()));

        if quot.sign() == Sign::Minus {
            // quot is negative, so each c should be negative, i.e. in
            // the range [-(2^16 - 1), 0]; so we add 2^16 - 1 to c so
            // it's in the range [0, 2^16 - 1] which will correctly
            // range-check.
            for c in lo {
                *c += u16::max_value() as i64;
            }
            // Store the sign of the quotient after the quotient.
            hi[0] = 1;
        } else {
            hi[0] = 0;
        };
    }

    nv[MODULAR_MOD_IS_ZERO] = mod_is_zero;
    nv[MODULAR_OUT_AUX_RED].copy_from_slice(&out_aux_red.map(F::from_canonical_i64));
    nv[MODULAR_DIV_DENOM_IS_ZERO] = mod_is_zero * (lv[IS_DIV] + lv[IS_SHR]);

    (
        output_limbs.map(F::from_canonical_i64),
        quot_limbs.map(F::from_noncanonical_i64),
    )
}

/// Build the part of the constraint polynomial that applies to the
/// DIV, MOD, ADDMOD, MULMOD operations (and the FP254 variants), and
/// perform the common verifications.
///
/// Specifically, with the notation above, build the polynomial
///
///   c(x) + q(x) * m(x) + (x - β) * s(x)
///
/// and check consistency when m = 0, and that c is reduced. Note that
/// q(x) CANNOT be negative here, but, in contrast to
/// addsubmod_constr_poly above, it is twice as long.
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

    // Is 1 iff the operation is DIV or SHR and the denominator is zero.
    let div_denom_is_zero = nv[MODULAR_DIV_DENOM_IS_ZERO];
    yield_constr.constraint_transition(
        filter * (mod_is_zero * (lv[IS_DIV] + lv[IS_SHR]) - div_denom_is_zero),
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
    let offset = P::Scalar::from_canonical_u64(AUX_COEFF_ABS_MAX as u64);

    // constr_poly = c(x) + q(x) * m(x) + (x - β) * s(x)
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
    // doing a DIV or SHR; in that case, we need is_less_than=0, since
    // eval_packed_generic_addcy checks
    //
    //   modulus + out_aux_red == output + is_less_than*2^32
    //
    // and we are given output = out_aux_red when modulus is zero.
    let mut is_less_than = [P::ZEROS; N_LIMBS];
    is_less_than[0] = P::ONES - mod_is_zero * (lv[IS_DIV] + lv[IS_SHR]);
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

    let t = builder.mul_sub_extension(mod_is_zero, mod_is_zero, mod_is_zero);
    let t = builder.mul_extension(filter, t);
    yield_constr.constraint_transition(builder, t);

    let limb_sum = builder.add_many_extension(modulus);
    let t = builder.mul_extension(limb_sum, mod_is_zero);
    let t = builder.mul_extension(filter, t);
    yield_constr.constraint_transition(builder, t);

    modulus[0] = builder.add_extension(modulus[0], mod_is_zero);

    let div_denom_is_zero = nv[MODULAR_DIV_DENOM_IS_ZERO];
    let div_shr_filter = builder.add_extension(lv[IS_DIV], lv[IS_SHR]);
    let t = builder.mul_sub_extension(mod_is_zero, div_shr_filter, div_denom_is_zero);
    let t = builder.mul_extension(filter, t);
    yield_constr.constraint_transition(builder, t);
    output[0] = builder.add_extension(output[0], div_denom_is_zero);

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
    output[0] = builder.sub_extension(output[0], div_denom_is_zero);

    let prod = pol_mul_wide2_ext_circuit(builder, quot, modulus);
    for &x in prod[2 * N_LIMBS..].iter() {
        let t = builder.mul_extension(filter, x);
        yield_constr.constraint_transition(builder, t);
    }

    let mut constr_poly: [_; 2 * N_LIMBS] = prod[0..2 * N_LIMBS].try_into().unwrap();
    pol_add_assign_ext_circuit(builder, &mut constr_poly, &output);

    let offset =
        builder.constant_extension(F::Extension::from_canonical_u64(AUX_COEFF_ABS_MAX as u64));
    let zero = builder.zero_extension();
    let mut aux = [zero; 2 * N_LIMBS];
    for (c, i) in aux.iter_mut().zip(MODULAR_AUX_INPUT_LO) {
        *c = builder.sub_extension(nv[i], offset);
    }
    let base = F::from_canonical_u64(1u64 << LIMB_BITS);
    for (c, j) in aux.iter_mut().zip(MODULAR_AUX_INPUT_HI) {
        *c = builder.mul_const_add_extension(base, nv[j], *c);
    }

    let base = builder.constant_extension(base.into());
    let t = pol_adjoin_root_ext_circuit(builder, aux, base);
    pol_add_assign_ext_circuit(builder, &mut constr_poly, &t);

    constr_poly
}

/// Generate the output and auxiliary values for modular operations.
///
/// `filter` must be one of `columns::IS_{ADD,MUL,SUB}{MOD,FP254}`.
pub(crate) fn generate<F: PrimeField64>(
    lv: &mut [F],
    nv: &mut [F],
    filter: usize,
    input0: u32,
    input1: u32,
    modulus: u32,
) {
    debug_assert!(lv.len() == NUM_ARITH_COLUMNS && nv.len() == NUM_ARITH_COLUMNS);

    u32_to_array(&mut lv[MODULAR_INPUT_0], input0);
    u32_to_array(&mut lv[MODULAR_INPUT_1], input1);
    u32_to_array(&mut lv[MODULAR_MODULUS], modulus);

    // Inputs are all in [0, 2^16), so the "as i64" conversion is safe.
    let input0_limbs = read_value_i64_limbs(lv, MODULAR_INPUT_0);
    let input1_limbs = read_value_i64_limbs(lv, MODULAR_INPUT_1);

    let pol_input = match filter {
        columns::IS_ADDMOD => pol_add(input0_limbs, input1_limbs),
        columns::IS_SUBMOD => pol_sub(input0_limbs, input1_limbs),
        columns::IS_MULMOD => pol_mul_wide(input0_limbs, input1_limbs),
        _ => panic!("generate modular operation called with unknown opcode"),
    };
    let (out, quo_input) = generate_modular_op(lv, nv, filter, pol_input, MODULAR_MODULUS);
    lv[MODULAR_OUTPUT].copy_from_slice(&out);
    lv[MODULAR_QUO_INPUT].copy_from_slice(&quo_input);
}
