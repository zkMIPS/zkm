//! Support for MIPS instructions MFHI, MTHI, MHLO, MTLO

use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::arithmetic::columns::*;
use crate::arithmetic::utils::u32_to_array;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

/// Generate row for MFHI, MTHI, MHLO, and MTLO operations.
pub(crate) fn generate<F: PrimeField64>(lv: &mut [F], filter: usize, input: u32, result: u32) {
    u32_to_array(&mut lv[INPUT_REGISTER_0], input);

    match filter {
        IS_MFHI | IS_MTHI | IS_MFLO | IS_MTLO => {
            u32_to_array(&mut lv[OUTPUT_REGISTER], result);
        }
        _ => panic!("unexpected operation filter"),
    };
}
pub fn eval_packed_generic<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let filter = lv[IS_MFHI] + lv[IS_MTHI] + lv[IS_MFLO] + lv[IS_MTLO];

    let input = &lv[INPUT_REGISTER_0];
    let output = &lv[OUTPUT_REGISTER];
    for (input, output) in input.iter().zip(output) {
        yield_constr.constraint(filter * (*input - *output));
    }
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let filter = builder.add_many_extension([lv[IS_MFHI], lv[IS_MTHI], lv[IS_MFLO], lv[IS_MTLO]]);

    let input = &lv[INPUT_REGISTER_0];
    let output = &lv[OUTPUT_REGISTER];
    for (input, output) in input.iter().zip(output) {
        let sub = builder.sub_extension(*input, *output);
        let t = builder.mul_extension(filter, sub);
        yield_constr.constraint(builder, t);
    }
}

#[cfg(test)]
mod tests {
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::{Field, Sample};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;

    const OPS: [usize; 4] = [IS_MFHI, IS_MTHI, IS_MFLO, IS_MTLO];
    #[test]
    fn generate_eval_consistency_not_lo_hi() {
        type F = GoldilocksField;

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);
        let mut lv = [F::default(); NUM_ARITH_COLUMNS].map(|_| F::sample(&mut rng));

        // if the operation filters are all zero, then the constraints
        // should be met even if all values are garbage.
        OPS.map(|i| lv[i] = F::ZERO);

        let mut constrant_consumer = ConstraintConsumer::new(
            vec![GoldilocksField(2), GoldilocksField(3), GoldilocksField(5)],
            F::ONE,
            F::ONE,
            F::ONE,
        );
        eval_packed_generic(&lv, &mut constrant_consumer);
        for &acc in &constrant_consumer.constraint_accs {
            assert_eq!(acc, F::ZERO);
        }
    }

    #[test]
    fn generate_eval_consistency_addcy() {
        type F = GoldilocksField;

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);
        const N_ITERS: usize = 1000;

        for _ in 0..N_ITERS {
            for op_filter in OPS {
                // set entire row to random 16-bit values
                let mut lv = [F::default(); NUM_ARITH_COLUMNS]
                    .map(|_| F::from_canonical_u16(rng.gen::<u16>()));

                // set operation filter and ensure all constraints are
                // satisfied. We have to explicitly set the other
                // operation filters to zero since all are treated by
                // the call.
                OPS.map(|i| lv[i] = F::ZERO);
                lv[op_filter] = F::ONE;

                let input = rng.gen::<u32>();

                generate(&mut lv, op_filter, input, input);

                let mut constrant_consumer = ConstraintConsumer::new(
                    vec![GoldilocksField(2), GoldilocksField(3), GoldilocksField(5)],
                    F::ONE,
                    F::ONE,
                    F::ONE,
                );
                eval_packed_generic(&lv, &mut constrant_consumer);
                for &acc in &constrant_consumer.constraint_accs {
                    assert_eq!(acc, F::ZERO);
                }

                let mut expected_limbs = [F::ZERO; N_LIMBS];
                u32_to_array(&mut expected_limbs, input);
                assert!(expected_limbs
                    .iter()
                    .zip(&lv[OUTPUT_REGISTER])
                    .all(|(x, y)| x == y));
            }
        }
    }
}
