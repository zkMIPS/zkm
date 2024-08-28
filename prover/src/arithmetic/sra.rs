//! Support for the MIPS SRA(V) instructions.
//!
//! This crate verifies an MIPS shift instruction, which takes two
//! 32-bit inputs S and A, and produces a 32-bit output C satisfying
//!
//!    C = A >> S (mod 2^32)

use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::field::interpolation::interpolant;
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialCoeffs;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::arithmetic::columns::*;
use crate::arithmetic::div::{
    eval_ext_circuit_divmod_helper, eval_packed_div_helper, generate_divu_helper,
};
use crate::arithmetic::utils::{read_value, u32_to_array};
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

/// Generates a shift operation (SRA(V).
///
/// The inputs are stored in the form `(shift, input, 1 >> shift)`.
/// NB: if `shift >= 32`, then the third register holds 0.
/// We leverage the functions in div.rs to carry out
/// the computation.
pub fn generate<F: PrimeField64>(
    lv: &mut [F],
    nv: &mut [F],
    filter: usize,
    shift: u32,
    input: u32,
    result: u32,
) {
    // We use the multiplication logic to generate SLL(V)
    // TODO: It would probably be clearer/cleaner to read the U32
    // into an [i64;N] and then copy that to the lv table.
    // The first input is the shift we need to apply.
    u32_to_array(&mut lv[INPUT_REGISTER_0], shift);
    // The second register holds the input which needs shifting.
    u32_to_array(&mut lv[INPUT_REGISTER_1], input);
    u32_to_array(&mut lv[OUTPUT_REGISTER], result);
    // Compute 1 << shift and store it in the third input register.
    let shifted_displacement = 1u32 << (shift & 0x1F);

    u32_to_array(&mut lv[INPUT_REGISTER_2], shifted_displacement);

    // input >> shift
    u32_to_array(&mut lv[AUX_INPUT_REGISTER_2], input >> shift);

    // Set lv[AUX_INPUT_REGISTER_2.end] = (input_high_16 + 2^15) % 2^16
    lv[AUX_INPUT_REGISTER_2.end] = F::from_canonical_u32((input >> 16) ^ 0x8000);
    // Set lv[AUX_INPUT_REGISTER_2.end+1] = 1 if neg otherwise 0.
    lv[AUX_INPUT_REGISTER_2.end + 1] = F::from_canonical_u32(input >> 31);

    // set aux data in lv[SRA_EXTRA] and nv[SRA_EXTRA]
    // We do not check if shift < 32.
    let aux_data = eval_aux_sign_extend(F::from_canonical_u32(shift));
    lv[AUX_EXTRA].copy_from_slice(&aux_data[..8]);
    nv[AUX_EXTRA].copy_from_slice(&aux_data[8..]);

    // This equals to nv[SRA_EXTRA.end-1]
    u32_to_array(
        &mut nv[AUX_INPUT_REGISTER_2],
        ((1 << shift) - 1) << ((32 - shift) % 32),
    );

    // shift * shift
    nv[AUX_INPUT_REGISTER_2.end] = F::from_canonical_u32(shift * shift);

    match filter {
        IS_SRA | IS_SRAV => {
            generate_divu_helper(
                lv,
                nv,
                filter,
                INPUT_REGISTER_1,
                INPUT_REGISTER_2,
                AUX_INPUT_REGISTER_2,
                None,
            );
        }
        _ => panic!("expected filter to be IS_SRA(V), but it was {filter}"),
    }
}

/// Evaluates the constraints for an SRA(V) opcode.
/// We use div and add to impl the opcode.
pub fn eval_packed_generic<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    nv: &[P; NUM_ARITH_COLUMNS],
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let filter = lv[IS_SRA] + lv[IS_SRAV];
    let shift = &lv[INPUT_REGISTER_0];
    // The high limbs should be 0.
    for i in shift.iter().skip(1) {
        yield_constr.constraint_transition(filter * *i);
    }
    // check is_neg is bool
    let is_neg = lv[AUX_INPUT_REGISTER_2.end + 1];
    yield_constr.constraint_transition(filter * is_neg * (P::ONES - is_neg));

    // check input is negative or not. We just check the most significant bit in significant limb
    let over_flow = P::Scalar::from_canonical_u64(1 << LIMB_BITS);
    let add = P::Scalar::from_canonical_u64(1 << (LIMB_BITS - 1));
    let sum = lv[AUX_INPUT_REGISTER_2.end];
    let input_hi = lv[INPUT_REGISTER_1.end - 1];
    yield_constr.constraint_transition(filter * (input_hi + add - sum - is_neg * over_flow));

    // shift_sq == shift * shift
    let shift_sq = nv[AUX_INPUT_REGISTER_2.end];
    yield_constr.constraint_transition(filter * (shift_sq - shift[0] * shift[0]));
    // Compute the added number if negative
    let intermediate1 = lv[AUX_EXTRA].to_vec();
    let intermediate2 = nv[AUX_EXTRA].to_vec();
    let mut coeffs = sign_extend_poly::<P::Scalar>().coeffs;
    coeffs.reverse();

    let mut acc = P::ZEROS;
    for (w, j) in intermediate1
        .into_iter()
        .chain(intermediate2.into_iter())
        .zip(coeffs.chunks(2))
    {
        yield_constr.constraint_transition(filter * (acc * shift_sq + j[0] * shift[0] + j[1] - w));
        acc = w;
    }

    // acc ==   nv[AUX_INPUT_REGISTER_2]
    let acc_lo = nv[AUX_INPUT_REGISTER_2.start];
    let acc_hi = nv[AUX_INPUT_REGISTER_2.start + 1];
    yield_constr.constraint_transition(filter * (acc_hi * over_flow + acc_lo - acc));

    // check input >> shift == lv[AUX_INPUT_REGISTER_2]
    eval_packed_div_helper(
        lv,
        nv,
        yield_constr,
        filter,
        INPUT_REGISTER_1,
        INPUT_REGISTER_2,
        AUX_INPUT_REGISTER_2,
        AUX_INPUT_REGISTER_0,
    );

    // next will check lv[AUX_INPUT_REGISTER_2] + is_neg * nv[AUX_INPUT_REGISTER_2] == lv[OUTPUT_REGISTER]
    // There is not overflow for each added limb
    let logic_shifted_input = &lv[AUX_INPUT_REGISTER_2];
    let output = &lv[OUTPUT_REGISTER];
    for (x, (y, z)) in logic_shifted_input
        .iter()
        .zip(([acc_lo, acc_hi].iter()).zip(output.iter()))
    {
        yield_constr.constraint_transition(filter * (*x + *y * is_neg - *z));
    }
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    nv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let filter = builder.add_extension(lv[IS_SRA], lv[IS_SRAV]);
    let shift: [ExtensionTarget<D>; N_LIMBS] = read_value(lv, INPUT_REGISTER_0);
    // The high limbs should be 0.
    for i in shift.iter().skip(1) {
        let t = builder.mul_extension(filter, *i);
        yield_constr.constraint_transition(builder, t);
    }
    // check is_neg is bool
    let is_neg = lv[AUX_INPUT_REGISTER_2.end + 1];
    {
        let one = builder.one_extension();
        let t = builder.sub_extension(one, is_neg);
        let multi_t = builder.mul_many_extension([filter, is_neg, t]);
        yield_constr.constraint_transition(builder, multi_t);
    }

    // check input is negative or not. We just check the most significant bit in significant limb
    let over_flow = builder.constant_extension(F::Extension::from_canonical_u64(1 << LIMB_BITS));
    {
        let add =
            builder.constant_extension(F::Extension::from_canonical_u64(1 << (LIMB_BITS - 1)));
        let sum = lv[AUX_INPUT_REGISTER_2.end];
        let input_hi = lv[INPUT_REGISTER_1.end - 1];
        let t0 = builder.add_extension(input_hi, add);
        let t1 = builder.sub_extension(t0, sum);
        let t2 = builder.mul_extension(over_flow, is_neg);
        let t3 = builder.sub_extension(t1, t2);
        let t = builder.mul_extension(filter, t3);
        yield_constr.constraint_transition(builder, t); //filter * (input_hi + add - sum - is_neg * over_flow
    }

    // shift_sq == shift * shift
    let shift_sq = nv[AUX_INPUT_REGISTER_2.end];
    let sq = builder.square_extension(shift[0]);
    let t0 = builder.sub_extension(shift_sq, sq);
    let t = builder.mul_extension(filter, t0);
    yield_constr.constraint_transition(builder, t);

    // Compute the added number if negative
    let mut acc = builder.zero_extension();
    {
        let intermediate1 = lv[AUX_EXTRA].to_vec();
        let intermediate2 = nv[AUX_EXTRA].to_vec();
        let coeffs = sign_extend_poly::<F>()
            .coeffs
            .into_iter()
            .map(|c| F::Extension::from(c))
            .map(|c| builder.constant_extension(c))
            .rev()
            .collect_vec();

        for (w, j) in intermediate1
            .into_iter()
            .chain(intermediate2.into_iter())
            .zip(coeffs.chunks(2))
        {
            let t0 = builder.wide_arithmetic_extension(acc, shift_sq, j[0], shift[0], j[1]);
            let t = builder.sub_extension(t0, w);
            let constr = builder.mul_extension(filter, t);
            yield_constr.constraint_transition(builder, constr);
            acc = w;
        }
    }

    // acc ==   nv[AUX_INPUT_REGISTER_2]
    let acc_lo = nv[AUX_INPUT_REGISTER_2.start];
    let acc_hi = nv[AUX_INPUT_REGISTER_2.start + 1];
    {
        let t0 = builder.sub_extension(acc_lo, acc);
        let t1 = builder.mul_add_extension(over_flow, acc_hi, t0);
        let t = builder.mul_extension(filter, t1);
        yield_constr.constraint_transition(builder, t);
    }

    // check input >> shift == lv[AUX_INPUT_REGISTER_2]
    eval_ext_circuit_divmod_helper(
        builder,
        lv,
        nv,
        yield_constr,
        filter,
        INPUT_REGISTER_1,
        INPUT_REGISTER_2,
        AUX_INPUT_REGISTER_2,
        AUX_INPUT_REGISTER_0,
    );

    // next will check lv[AUX_INPUT_REGISTER_2] + is_neg * nv[AUX_INPUT_REGISTER_2] == lv[OUTPUT_REGISTER]
    // There is not overflow for each added limb
    let logic_shifted_input = &lv[AUX_INPUT_REGISTER_2];
    let output = &lv[OUTPUT_REGISTER];
    for (x, (y, z)) in logic_shifted_input
        .iter()
        .zip(([acc_lo, acc_hi].iter()).zip(output.iter()))
    {
        let t0 = builder.sub_extension(*x, *z);
        let t1 = builder.mul_add_extension(*y, is_neg, t0);
        let t = builder.mul_extension(filter, t1);
        yield_constr.constraint_transition(builder, t);
    }
}

/// Compute a polynomial f that satisfies these points:
/// (0,0), (1,2^31),(2,2^31+2^30),...,(31, 2^31+2^32+...+2^1)
fn sign_extend_poly<F: Field>() -> PolynomialCoeffs<F> {
    let mut sum = 0u64;
    let mut points = vec![(F::ZERO, F::ZERO)];
    for i in 1u64..32 {
        sum += 1 << (32 - i);
        points.push((F::from_canonical_u64(i), F::from_canonical_u64(sum)));
    }

    interpolant(&points)
}

fn eval_poly<F: Field>(poly: PolynomialCoeffs<F>, x: F) -> Vec<F> {
    debug_assert_eq!(poly.len() % 2, 0);
    let expected = poly.eval(x);

    let mut results = vec![];
    let mut acc = F::ZERO;
    for chunks in poly.coeffs.chunks(2).rev() {
        let inter_coeff = chunks.iter().chain([acc].iter()).copied().collect_vec();
        let inter_poly = PolynomialCoeffs::new(inter_coeff);
        acc = inter_poly.eval(x);
        results.push(acc);
    }
    debug_assert_eq!(results.len(), poly.len() / 2);
    debug_assert_eq!(expected, results[poly.len() / 2 - 1]);

    results
}

fn eval_aux_sign_extend<F: Field>(x: F) -> Vec<F> {
    let poly = sign_extend_poly();
    eval_poly(poly, x)
}

#[cfg(test)]
mod tests {
    use crate::arithmetic::columns::{IS_SRA, IS_SRAV, NUM_ARITH_COLUMNS};
    use crate::arithmetic::sra::{eval_packed_generic, eval_poly, generate, sign_extend_poly};
    use crate::constraint_consumer::ConstraintConsumer;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::{Field, Sample};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    const N_RND_TESTS: usize = 1000;
    const SRA_OPS: [usize; 2] = [IS_SRA, IS_SRAV];
    #[test]
    fn test_poly() {
        type F = GoldilocksField;
        let x = F::from_canonical_u64(2);
        let poly = sign_extend_poly();
        println!("{:?}", poly);
        let res = eval_poly(poly, x);

        let expected = [
            18260604987135149276u64,
            6641582332263005918,
            4185170977706284464,
            8069729718270694767,
            2720953444603644942,
            9143808191498674830,
            14156617978482227317,
            2619661922624664514,
            9865344867852737688,
            7289981648341815148,
            14234318509450809877,
            15083771169118776894,
            2211192019722872880,
            5624745679944178802,
            15168639727975586488,
            3221225472,
        ]
        .map(F::from_noncanonical_u64);

        assert_eq!(expected.to_vec(), res);
    }

    #[test]
    fn generate_eval_consistency_not_sra() {
        type F = GoldilocksField;

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);
        let mut lv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));
        let nv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));

        // if `IS_SRA, IS_SRAV == 0`, then the constraints should be met even
        // if all values are garbage.
        lv[IS_SRA] = F::ZERO;
        lv[IS_SRAV] = F::ZERO;

        let mut constraint_consumer = ConstraintConsumer::new(
            vec![GoldilocksField(2), GoldilocksField(3), GoldilocksField(5)],
            GoldilocksField::ONE,
            GoldilocksField::ONE,
            GoldilocksField::ONE,
        );
        eval_packed_generic(&lv, &nv, &mut constraint_consumer);
        for &acc in &constraint_consumer.constraint_accs {
            assert_eq!(acc, GoldilocksField::ZERO);
        }
    }

    #[test]
    fn generate_eval_consistency() {
        type F = GoldilocksField;

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);

        for op_filter in SRA_OPS {
            for _ in 0..N_RND_TESTS {
                // set inputs to random values
                let mut lv = [F::default(); NUM_ARITH_COLUMNS]
                    .map(|_| F::from_canonical_u16(rng.gen::<u16>()));
                let mut nv = [F::default(); NUM_ARITH_COLUMNS]
                    .map(|_| F::from_canonical_u16(rng.gen::<u16>()));

                // Reset operation columns, then select one
                for op in SRA_OPS {
                    lv[op] = F::ZERO;
                }
                lv[op_filter] = F::ONE;

                let input0: u32 = rng.gen();
                let input1: u32 = rng.gen_range(0..32);
                let result = ((input0 as i32) >> input1) as u32;

                generate(&mut lv, &mut nv, op_filter, input1, input0, result);

                let mut constraint_consumer = ConstraintConsumer::new(
                    vec![GoldilocksField(2), GoldilocksField(3), GoldilocksField(5)],
                    GoldilocksField::ONE,
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                );
                eval_packed_generic(&lv, &nv, &mut constraint_consumer);
                for &acc in &constraint_consumer.constraint_accs {
                    assert_eq!(acc, GoldilocksField::ZERO);
                }
            }
        }
    }
}
