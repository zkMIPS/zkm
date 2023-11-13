//! Support for the EVM SHL and SHR instructions.
//!
//! This crate verifies an EVM shift instruction, which takes two
//! 32-bit inputs S and A, and produces a 32-bit output C satisfying
//!
//!    C = A << S (mod 2^32) for SHL or
//!    C = A >> S (mod 2^32) for SHR.
//!
//! The way this computation is carried is by providing a third input
//!    B = 1 << S (mod 2^32)
//! and then computing:
//!    C = A * B (mod 2^32) for SHL or
//!    C = A / B (mod 2^32) for SHR
//!
//! Inputs A, S, and B, and output C, are given as arrays of 16-bit
//! limbs. For example, if the limbs of A are a[0]...a[15], then
//!
//!    A = \sum_{i=0}^15 a[i] β^i,
//!
//! where β = 2^16 = 2^LIMB_BITS. To verify that A, S, B and C satisfy
//! the equations, we proceed similarly to MUL for SHL and to DIV for SHR.

use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

// use super::mul;
use crate::arithmetic::columns::*;
// use crate::arithmetic::utils::*;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

/// Generates a shift operation (either SHL or SHR).
/// The inputs are stored in the form `(shift, input, 1 << shift)`.
/// NB: if `shift >= 32`, then the third register holds 0.
/// We leverage the functions in mul.rs and divmod.rs to carry out
/// the computation.
pub fn generate<F: PrimeField64>(
    _lv: &mut [F],
    _nv: &mut [F],
    _is_shl: bool,
    _shift: u32,
    _input: u32,
    _result: u32,
) {
    /*
    // We use the multiplication logic to generate SHL
    // TODO: It would probably be clearer/cleaner to read the U32
    // into an [i64;N] and then copy that to the lv table.
    // The first input is the shift we need to apply.
    u32_to_array(&mut lv[INPUT_REGISTER_0], shift);
    // The second register holds the input which needs shifting.
    u32_to_array(&mut lv[INPUT_REGISTER_1], input);
    u32_to_array(&mut lv[OUTPUT_REGISTER], result);
    // If `shift >= 32`, the shifted displacement is set to 0.
    // Compute 1 << shift and store it in the third input register.
    let shifted_displacement = if shift > 31 { 0 } else { 1 << shift };

    u32_to_array(&mut lv[INPUT_REGISTER_2], shifted_displacement);

    let input0 = read_value_i64_limbs(lv, INPUT_REGISTER_1); // input
    let input1 = read_value_i64_limbs(lv, INPUT_REGISTER_2); // 1 << shift

    if is_shl {
        // We generate the multiplication input0 * input1 using mul.rs.
        mul::generate_mul(lv, input0, input1);
    } else {
        // If the operation is SHR, we compute: `input / shifted_displacement` if `shifted_displacement == 0`
        // otherwise, the output is 0. We use the logic in divmod.rs to achieve that.
        divmod::generate_divmod(lv, nv, IS_SHR, INPUT_REGISTER_1, INPUT_REGISTER_2);
    }
    */
}

/// Evaluates the constraints for an SHL opcode.
/// The logic is the same as the one for MUL. The only difference is that
/// the inputs are in `INPUT_REGISTER_1`  and `INPUT_REGISTER_2` instead of
/// `INPUT_REGISTER_0` and `INPUT_REGISTER_1`.
fn eval_packed_shl<P: PackedField>(
    _lv: &[P; NUM_ARITH_COLUMNS],
    _yield_constr: &mut ConstraintConsumer<P>,
) {
    /*
    let is_shl = lv[IS_SHL];
    let input0_limbs = read_value::<N_LIMBS, _>(lv, INPUT_REGISTER_1);
    let shifted_limbs = read_value::<N_LIMBS, _>(lv, INPUT_REGISTER_2);

    mul::eval_packed_generic_mul(lv, is_shl, input0_limbs, shifted_limbs, yield_constr);
    */
}

/// Evaluates the constraints for an SHR opcode.
/// The logic is tha same as the one for DIV. The only difference is that
/// the inputs are in `INPUT_REGISTER_1`  and `INPUT_REGISTER_2` instead of
/// `INPUT_REGISTER_0` and `INPUT_REGISTER_1`.
fn eval_packed_shr<P: PackedField>(
    _lv: &[P; NUM_ARITH_COLUMNS],
    _nv: &[P; NUM_ARITH_COLUMNS],
    _yield_constr: &mut ConstraintConsumer<P>,
) {
    /*
    let quo_range = OUTPUT_REGISTER;
    let rem_range = AUX_INPUT_REGISTER_0;
    let filter = lv[IS_SHR];

    divmod::eval_packed_divmod_helper(
        lv,
        nv,
        yield_constr,
        filter,
        INPUT_REGISTER_1,
        INPUT_REGISTER_2,
        quo_range,
        rem_range,
    );
    */
}

pub fn eval_packed_generic<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    nv: &[P; NUM_ARITH_COLUMNS],
    yield_constr: &mut ConstraintConsumer<P>,
) {
    eval_packed_shl(lv, yield_constr);
    eval_packed_shr(lv, nv, yield_constr);
}

fn eval_ext_circuit_shl<F: RichField + Extendable<D>, const D: usize>(
    _builder: &mut CircuitBuilder<F, D>,
    _lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    _yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    /*
    let is_shl = lv[IS_SHL];
    let input0_limbs = read_value::<N_LIMBS, _>(lv, INPUT_REGISTER_1);
    let shifted_limbs = read_value::<N_LIMBS, _>(lv, INPUT_REGISTER_2);

    mul::eval_ext_mul_circuit(
        builder,
        lv,
        is_shl,
        input0_limbs,
        shifted_limbs,
        yield_constr,
    );
    */
}

fn eval_ext_circuit_shr<F: RichField + Extendable<D>, const D: usize>(
    _builder: &mut CircuitBuilder<F, D>,
    _lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    _nv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    _yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    /*
    let filter = lv[IS_SHR];
    let quo_range = OUTPUT_REGISTER;
    let rem_range = AUX_INPUT_REGISTER_0;

    divmod::eval_ext_circuit_divmod_helper(
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
    */
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    nv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    eval_ext_circuit_shl(builder, lv, yield_constr);
    eval_ext_circuit_shr(builder, lv, nv, yield_constr);
}

#[cfg(test)]
mod tests {

    const N_RND_TESTS: usize = 1000;

    // TODO: Should be able to refactor this test to apply to all operations.
    #[test]
    fn generate_eval_consistency_not_shift() {
        /*
        type F = GoldilocksField;

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);
        let mut lv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));
        let nv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));

        // if `IS_SHL == 0` and `IS_SHR == 0`, then the constraints should be met even
        // if all values are garbage.
        lv[IS_SHL] = F::ZERO;
        lv[IS_SHR] = F::ZERO;

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
        */
    }

    fn generate_eval_consistency_shift(_is_shl: bool) {
        /*
        type F = GoldilocksField;

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);
        let mut lv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));
        let mut nv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));

        // set `IS_SHL == 1` or `IS_SHR == 1` and ensure all constraints are satisfied.
        if is_shl {
            lv[IS_SHL] = F::ONE;
            lv[IS_SHR] = F::ZERO;
        } else {
            // Set `IS_DIV` to 0 in this case, since we're using the logic of DIV for SHR.
            lv[IS_DIV] = F::ZERO;
            lv[IS_SHL] = F::ZERO;
            lv[IS_SHR] = F::ONE;
        }

        for _i in 0..N_RND_TESTS {
            let shift = (rng.gen::<u8>() as u32) % 32u32;

            let mut full_input = 0;
            // set inputs to random values
            for ai in INPUT_REGISTER_1 {
                lv[ai] = F::from_canonical_u16(rng.gen());
                full_input = lv[ai].to_canonical_u64() as u32 + full_input * (1 << 16);
            }

            let output = if is_shl {
                full_input << shift
            } else {
                full_input >> shift
            };

            generate(&mut lv, &mut nv, is_shl, shift, full_input, output);

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
        */
    }

    #[test]
    fn generate_eval_consistency_shl() {
        generate_eval_consistency_shift(true);
    }

    #[test]
    fn generate_eval_consistency_shr() {
        generate_eval_consistency_shift(false);
    }

    fn generate_eval_consistency_shift_over_32(_is_shl: bool) {
        /*
        type F = GoldilocksField;

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);
        let mut lv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));
        let mut nv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));

        // set `IS_SHL == 1` or `IS_SHR == 1` and ensure all constraints are satisfied.
        if is_shl {
            lv[IS_SHL] = F::ONE;
            lv[IS_SHR] = F::ZERO;
        } else {
            // Set `IS_DIV` to 0 in this case, since we're using the logic of DIV for SHR.
            lv[IS_DIV] = F::ZERO;
            lv[IS_SHL] = F::ZERO;
            lv[IS_SHR] = F::ONE;
        }

        for _i in 0..N_RND_TESTS {
            let mut shift = rng.gen::<u32>();
            while shift > u32::MAX - 32 {
                shift = rng.gen::<u32>();
            }
            shift += 32;

            let mut full_input = 0;
            // set inputs to random values
            for ai in INPUT_REGISTER_1 {
                lv[ai] = F::from_canonical_u16(rng.gen());
                full_input = lv[ai].to_canonical_u64() as u32 + full_input * (1 << 16);
            }

            let output = 0;
            generate(&mut lv, &mut nv, is_shl, shift, full_input, output);

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
        */
    }

    #[test]
    fn generate_eval_consistency_shl_over_32() {
        generate_eval_consistency_shift_over_32(true);
    }

    #[test]
    fn generate_eval_consistency_shr_over_32() {
        generate_eval_consistency_shift_over_32(false);
    }
}
