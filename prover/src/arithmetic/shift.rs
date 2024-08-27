//! Support for the MIPS SLL(V), and SRL(V) instructions.
//!
//! This crate verifies an MIPS shift instruction, which takes two
//! 32-bit inputs S and A, and produces a 32-bit output C satisfying
//!
//!    C = A << S (mod 2^32) for SLL(V) or
//!    C = A >> S (mod 2^32) for SRL(V).
//!
//! The way this computation is carried is by providing a third input
//!    B = 1 << S (mod 2^32)
//! and then computing:
//!    C = A * B (mod 2^32) for SLL(V) or
//!    C = A / B (mod 2^32) for SRL(V)
//!
//! Inputs A, S, and B, and output C, are given as arrays of 16-bit
//! limbs. For example, if the limbs of A are a[0].a[1], then
//!
//!    A = \sum_{i=0}^1 a[i] β^i,
//!
//! where β = 2^16 = 2^LIMB_BITS. To verify that A, S, B and C satisfy
//! the equations, we proceed similarly to MUL for SLL(V) and to DIV for SRL(V).

use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use super::{div, mul};
use crate::arithmetic::columns::*;
use crate::arithmetic::utils::{read_value, read_value_i64_limbs, u32_to_array};
// use crate::arithmetic::utils::*;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

/// Generates a shift operation (either SLL(V) or SRL(V)).
///
/// The inputs are stored in the form `(shift, input, 1 << shift)`.
/// NB: if `shift >= 32`, then the third register holds 0.
/// We leverage the functions in mul.rs and div.rs to carry out
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
    // If `shift >= 32`, the shifted displacement is set to 0.
    // Compute 1 << shift and store it in the third input register.
    let shifted_displacement = 1 << (shift & 0x1F);

    u32_to_array(&mut lv[INPUT_REGISTER_2], shifted_displacement);

    let input0 = read_value_i64_limbs(lv, INPUT_REGISTER_1); // input
    let input1 = read_value_i64_limbs(lv, INPUT_REGISTER_2); // 1 << shift

    match filter {
        IS_SLL | IS_SLLV => {
            // We generate the multiplication input0 * input1 using mul.rs.
            mul::generate_mul(lv, input0, input1);
        }
        IS_SRL | IS_SRLV => {
            // If the operation is IS_SRL(IS_SRLV), we compute: `input / shifted_displacement` if `shifted_displacement == 0`
            // otherwise, the output is 0. We use the logic in div.rs to achieve that.
            div::generate_divu_helper(
                lv,
                nv,
                filter,
                INPUT_REGISTER_1,
                INPUT_REGISTER_2,
                OUTPUT_REGISTER,
                None,
            );
        }
        _ => panic!("expected filter to be IS_SLL(V), or IS_SRL(V) but it was {filter}"),
    }
}

/// Evaluates the constraints for an SLL(V) opcode.
/// The logic is the same as the one for MUL. The only difference is that
/// the inputs are in `INPUT_REGISTER_1`  and `INPUT_REGISTER_2` instead of
/// `INPUT_REGISTER_0` and `INPUT_REGISTER_1`.
fn eval_packed_sll<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let filter = lv[IS_SLL] + lv[IS_SLLV];
    let input0_limbs = read_value::<N_LIMBS, _>(lv, INPUT_REGISTER_1);
    let shifted_limbs = read_value::<N_LIMBS, _>(lv, INPUT_REGISTER_2);

    mul::eval_packed_generic_mul(lv, filter, input0_limbs, shifted_limbs, yield_constr);
}

/// Evaluates the constraints for an SRL(V) opcode.
/// The logic is tha same as the one for DIV. The only difference is that
/// the inputs are in `INPUT_REGISTER_1`  and `INPUT_REGISTER_2` instead of
/// `INPUT_REGISTER_0` and `INPUT_REGISTER_1`.
fn eval_packed_srl<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    nv: &[P; NUM_ARITH_COLUMNS],
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let quo_range = OUTPUT_REGISTER;
    let rem_range = AUX_INPUT_REGISTER_0;

    div::eval_packed_div_helper(
        lv,
        nv,
        yield_constr,
        lv[IS_SRL] + lv[IS_SRLV],
        INPUT_REGISTER_1,
        INPUT_REGISTER_2,
        quo_range,
        rem_range,
    );
}

pub fn eval_packed_generic<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    nv: &[P; NUM_ARITH_COLUMNS],
    yield_constr: &mut ConstraintConsumer<P>,
) {
    eval_packed_sll(lv, yield_constr);
    eval_packed_srl(lv, nv, yield_constr);
}

fn eval_ext_circuit_sll<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let filter = builder.add_extension(lv[IS_SLL], lv[IS_SLLV]);
    let input0_limbs = read_value::<N_LIMBS, _>(lv, INPUT_REGISTER_1);
    let shifted_limbs = read_value::<N_LIMBS, _>(lv, INPUT_REGISTER_2);

    mul::eval_ext_mul_circuit(
        builder,
        lv,
        filter,
        input0_limbs,
        shifted_limbs,
        yield_constr,
    );
}

fn eval_ext_circuit_srl<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    nv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let filter = builder.add_extension(lv[IS_SRL], lv[IS_SRLV]);
    let quo_range = OUTPUT_REGISTER;
    let rem_range = AUX_INPUT_REGISTER_0;

    div::eval_ext_circuit_divmod_helper(
        builder,
        lv,
        nv,
        yield_constr,
        filter,
        INPUT_REGISTER_1,
        INPUT_REGISTER_2,
        quo_range,
        rem_range,
    );
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    nv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    eval_ext_circuit_sll(builder, lv, yield_constr);
    eval_ext_circuit_srl(builder, lv, nv, yield_constr);
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::{Field, Sample};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    const N_RND_TESTS: usize = 1;

    #[test]
    fn generate_eval_consistency_not_shift() {
        type F = GoldilocksField;

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);
        let mut lv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));
        let nv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));

        // if `IS_SLL, IS_SLLV, IS_SRL, IS_SRLV == 0`, then the constraints should be met even
        // if all values are garbage.
        lv[IS_SLL] = F::ZERO;
        lv[IS_SLLV] = F::ZERO;
        lv[IS_SRL] = F::ZERO;
        lv[IS_SRLV] = F::ZERO;

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

    fn generate_eval_consistency_shift(filter: usize) {
        type F = GoldilocksField;

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);
        let mut lv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));
        let mut nv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));

        [IS_SLL, IS_SLLV, IS_SRL, IS_SRLV].map(|filter| lv[filter] = F::ZERO);
        lv[filter] = F::ONE;

        if filter == IS_SRL || filter == IS_SRLV {
            // Set `IS_DIV` to 0 in this case, since we're using the logic of DIV for SHR.
            lv[IS_DIV] = F::ZERO;
        }

        for _i in 0..N_RND_TESTS {
            let shift: u32 = rng.gen_range(0..32);

            let mut full_input = 0;
            // set inputs to random values
            for ai in INPUT_REGISTER_1 {
                lv[ai] = F::from_canonical_u16(rng.gen());
                full_input = lv[ai].to_canonical_u64() as u32 + full_input * (1 << 16);
            }

            let output = if filter == IS_SLL || filter == IS_SLLV {
                full_input << shift
            } else {
                full_input >> shift
            };

            generate(&mut lv, &mut nv, filter, shift, full_input, output);

            let mut constraint_consumer = ConstraintConsumer::new(
                vec![GoldilocksField(2), GoldilocksField(3), GoldilocksField(5)],
                GoldilocksField::ONE,
                GoldilocksField::ONE,
                GoldilocksField::ZERO,
            );
            eval_packed_generic(&lv, &nv, &mut constraint_consumer);
            for &acc in &constraint_consumer.constraint_accs {
                assert_eq!(acc, GoldilocksField::ZERO);
            }
        }
    }

    #[test]
    fn generate_eval_consistency() {
        generate_eval_consistency_shift(IS_SLL);
        generate_eval_consistency_shift(IS_SLLV);
        generate_eval_consistency_shift(IS_SRL);
        generate_eval_consistency_shift(IS_SRLV);
    }

    fn generate_eval_consistency_shift_over_32(filter: usize) {
        type F = GoldilocksField;

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);
        let mut lv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));
        let mut nv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));

        [IS_SLL, IS_SLLV, IS_SRL, IS_SRLV, IS_SRA, IS_SRAV].map(|filter| lv[filter] = F::ZERO);
        lv[filter] = F::ONE;

        if filter == IS_SRL || filter == IS_SRLV {
            // Set `IS_DIV` to 0 in this case, since we're using the logic of DIV for SHR.
            lv[IS_DIV] = F::ZERO;
            lv[IS_DIVU] = F::ZERO;
        }

        for _i in 0..N_RND_TESTS {
            let shift: u32 = rng.gen_range(32..=u32::MAX);
            let mut full_input = 0;
            // set inputs to random values
            for ai in INPUT_REGISTER_1 {
                lv[ai] = F::from_canonical_u16(rng.gen());
                full_input = lv[ai].to_canonical_u64() as u32 + full_input * (1 << 16);
            }

            let output = if filter == IS_SLL || filter == IS_SLLV {
                full_input << (shift & 0x1F)
            } else {
                full_input >> (shift & 0x1F)
            };

            generate(&mut lv, &mut nv, filter, shift, full_input, output);

            let mut constraint_consumer = ConstraintConsumer::new(
                vec![GoldilocksField(2), GoldilocksField(3), GoldilocksField(5)],
                GoldilocksField::ONE,
                GoldilocksField::ONE,
                GoldilocksField::ZERO,
            );
            eval_packed_generic(&lv, &nv, &mut constraint_consumer);
            for &acc in &constraint_consumer.constraint_accs {
                assert_eq!(acc, GoldilocksField::ZERO);
            }
        }
    }

    #[test]
    fn generate_eval_consistency_over_32() {
        generate_eval_consistency_shift_over_32(IS_SLL);
        generate_eval_consistency_shift_over_32(IS_SLLV);
        generate_eval_consistency_shift_over_32(IS_SRL);
        generate_eval_consistency_shift_over_32(IS_SRLV);
    }
}
