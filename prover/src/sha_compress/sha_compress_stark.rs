use std::marker::PhantomData;
use std::borrow::Borrow;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::evaluation_frame::{StarkEvaluationFrame, StarkFrame};
use crate::keccak::logic::{xor3_gen, xor3_gen_circuit, xor_gen, xor_gen_circuit};
use crate::sha_compress::columns::{ShaCompressColumnsView, NUM_SHA_COMPRESS_COLUMNS};
use crate::sha_compress::logic::{and_op, and_op_ext_circuit_constraints, and_op_packed_constraints, andn_op, andn_op_ext_circuit_constraints, andn_op_packed_constraints, equal_ext_circuit_constraints, equal_packed_constraint, xor_op};
use crate::sha_extend::logic::{rotate_right, get_input_range, xor3, wrapping_add, rotate_right_packed_constraints, wrapping_add_packed_constraints, rotate_right_ext_circuit_constraint, wrapping_add_ext_circuit_constraints};
use crate::stark::Stark;
use crate::util::trace_rows_to_poly_values;

pub const NUM_ROUND_CONSTANTS: usize = 64;

pub const NUM_INPUTS: usize = 10; // 8 states + w_i + key_i

#[derive(Copy, Clone, Default)]
pub struct ShaCompressStark<F, const D: usize> {
    pub(crate) f: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> ShaCompressStark<F, D> {
    pub(crate) fn generate_trace(
        &self,
        inputs: Vec<([u8; NUM_INPUTS * 32], usize)>,
        min_rows: usize,
    ) -> Vec<PolynomialValues<F>> {
        // Generate the witness row-wise
        let trace_rows = self.generate_trace_rows(inputs, min_rows);
        trace_rows_to_poly_values(trace_rows)
    }

    fn generate_trace_rows(
        &self,
        inputs_and_timestamps: Vec<([u8; NUM_INPUTS * 32], usize)>,
        min_rows: usize,
    ) -> Vec<[F; NUM_SHA_COMPRESS_COLUMNS]> {
        let num_rows = inputs_and_timestamps.len()
            .max(min_rows)
            .next_power_of_two();

        let mut rows = Vec::with_capacity(num_rows);
        for input_and_timestamp in inputs_and_timestamps.iter() {
            let row_for_compress = self.generate_trace_rows_for_compress(*input_and_timestamp);
            rows.push(row_for_compress);
        }

        while rows.len() < num_rows {
            rows.push([F::ZERO; NUM_SHA_COMPRESS_COLUMNS]);
        }
        rows
    }

    fn generate_trace_rows_for_compress(
        &self,
        input_and_timestamp: ([u8; NUM_INPUTS * 32], usize),
    ) -> [F; NUM_SHA_COMPRESS_COLUMNS] {

        let timestamp = input_and_timestamp.1;
        let inputs = input_and_timestamp.0;

        let mut row = ShaCompressColumnsView::<F>::default();
        row.timestamp = F::from_canonical_usize(timestamp);
        // read inputs
        row.input_state = inputs[0..256].iter().map(|x| F::from_canonical_u8(*x)).collect::<Vec<F>>().try_into().unwrap();
        row.w_i = inputs[256..288].iter().map(|x| F::from_canonical_u8(*x)).collect::<Vec<F>>().try_into().unwrap();
        row.k_i = inputs[288..320].iter().map(|x| F::from_canonical_u8(*x)).collect::<Vec<F>>().try_into().unwrap();

        // compute
        row.e_rr_6 = rotate_right(row.input_state[get_input_range(4)].try_into().unwrap(), 6);
        row.e_rr_11 = rotate_right(row.input_state[get_input_range(4)].try_into().unwrap(), 11);
        row.e_rr_25 = rotate_right(row.input_state[get_input_range(4)].try_into().unwrap(), 25);
        row.s_1 = xor3(row.e_rr_6, row.e_rr_11, row.e_rr_25);

        row.e_and_f = and_op(
            row.input_state[get_input_range(4)].try_into().unwrap(),
            row.input_state[get_input_range(5)].try_into().unwrap(),
        );

        row.not_e_and_g = andn_op(
            row.input_state[get_input_range(4)].try_into().unwrap(),
            row.input_state[get_input_range(6)].try_into().unwrap(),
        );

        row.ch = xor_op(row.e_and_f, row.not_e_and_g);

        (row.inter_1, row.carry_1) = wrapping_add(
            row.input_state[get_input_range(7)].try_into().unwrap(),
            row.s_1,
        );

        (row.inter_2, row.carry_2) = wrapping_add(
            row.inter_1,
            row.ch,
        );

        (row.inter_3, row.carry_3) = wrapping_add(
            row.inter_2,
            row.k_i,
        );

        (row.temp1, row.carry_4) = wrapping_add(
            row.inter_3,
            row.w_i,
        );

        row.a_rr_2 = rotate_right(row.input_state[get_input_range(0)].try_into().unwrap(), 2);
        row.a_rr_13 = rotate_right(row.input_state[get_input_range(0)].try_into().unwrap(), 13);
        row.a_rr_22 = rotate_right(row.input_state[get_input_range(0)].try_into().unwrap(), 22);
        row.s_0 = xor3(row.a_rr_2, row.a_rr_13, row.a_rr_22);

        row.b_and_c = and_op(
            row.input_state[get_input_range(1)].try_into().unwrap(),
            row.input_state[get_input_range(2)].try_into().unwrap(),
        );

        row.a_and_b = and_op(
            row.input_state[get_input_range(0)].try_into().unwrap(),
            row.input_state[get_input_range(1)].try_into().unwrap(),
        );

        row.a_and_c = and_op(
            row.input_state[get_input_range(0)].try_into().unwrap(),
            row.input_state[get_input_range(2)].try_into().unwrap(),
        );

        row.maj = xor3(row.a_and_b, row.a_and_c, row.b_and_c);
        (row.temp2, row.carry_5) = wrapping_add(
            row.s_0,
            row.maj,
        );


        for i in 32..256 {
            row.output_state[i] = row.input_state[i - 32];
        }

        let mut new_e;
        let mut new_a;

        (new_e, row.carry_e) = wrapping_add(
            row.input_state[get_input_range(3)].try_into().unwrap(),
            row.temp1,
        );

        (new_a, row.carry_a) = wrapping_add(
            row.temp1,
            row.temp2,
        );

        for i in 0..32 {
            row.output_state[i] = new_a[i];
            row.output_state[i + 32 * 4] = new_e[i];
        }

        row.into()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for ShaCompressStark<F, D> {
    type EvaluationFrame<FE, P, const D2: usize>
    = StarkFrame<P, NUM_SHA_COMPRESS_COLUMNS>
    where
        FE: FieldExtension<D2, BaseField=F>,
        P: PackedField<Scalar=FE>;
    type EvaluationFrameTarget = StarkFrame<ExtensionTarget<D>, NUM_SHA_COMPRESS_COLUMNS>;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: &Self::EvaluationFrame<FE, P, D2>,
        yield_constr: &mut ConstraintConsumer<P>
    ) where
        FE: FieldExtension<D2, BaseField=F>,
        P: PackedField<Scalar=FE>
    {
        todo!()
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: &Self::EvaluationFrameTarget,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>
    ) {
        todo!()
    }

    fn constraint_degree(&self) -> usize {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use plonky2::field::goldilocks_field::GoldilocksField;
    use crate::sha_compress::columns::ShaCompressColumnsView;
    use crate::sha_compress::sha_compress_stark::{ShaCompressStark, NUM_INPUTS};
    use crate::sha_extend::logic::{from_u32_to_be_bits, get_input_range};
    use std::borrow::Borrow;
    use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
    use plonky2::field::polynomial::PolynomialValues;
    use plonky2::field::types::Field;
    use plonky2::fri::oracle::PolynomialBatch;
    use plonky2::iop::challenger::Challenger;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::timed;
    use plonky2::util::timing::TimingTree;
    use crate::config::StarkConfig;
    use crate::cross_table_lookup::{Column, CtlData, CtlZData, Filter, GrandProductChallenge, GrandProductChallengeSet};
    use crate::prover::prove_single_table;
    use crate::sha_compress_sponge::constants::SHA_COMPRESS_K;
    use crate::sha_extend::sha_extend_stark::ShaExtendStark;
    use crate::sha_extend_sponge::columns::NUM_EXTEND_INPUT;
    use crate::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};

    const W: [u32; 64] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 34013193,
        67559435, 1711661200, 3020350282, 1447362251, 3118632270, 4004188394, 690615167,
        6070360, 1105370215, 2385558114, 2348232513, 507799627, 2098764358, 5845374, 823657968,
        2969863067, 3903496557, 4274682881, 2059629362, 1849247231, 2656047431, 835162919,
        2096647516, 2259195856, 1779072524, 3152121987, 4210324067, 1557957044, 376930560,
        982142628, 3926566666, 4164334963, 789545383, 1028256580, 2867933222, 3843938318, 1135234440,
        390334875, 2025924737, 3318322046, 3436065867, 652746999, 4261492214, 2543173532, 3334668051,
        3166416553, 634956631];

    pub const H256_256: [u32;8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    fn get_random_input() -> [u8; NUM_INPUTS * 32] {
        let mut input = [0u8; NUM_INPUTS * 32];
        for i in 0..NUM_INPUTS * 32 {
            input[i] = rand::random::<u8>() % 2;
            debug_assert!(input[i] == 0 || input[i] == 1);
        }
        input
    }

    #[test]
    fn test_generation() -> Result<(), String>{

        const D: usize = 2;
        type F = GoldilocksField;
        type S = ShaCompressStark<F, D>;

        let w = W;
        let h = H256_256;

        let mut input = vec![];
        for hx in h {
            input.extend(from_u32_to_be_bits(hx));
        }
        input.extend(from_u32_to_be_bits(w[0]));
        input.extend(from_u32_to_be_bits(SHA_COMPRESS_K[0]));


        let stark = S::default();
        let row = stark.generate_trace_rows_for_compress((input.try_into().unwrap(), 0));
        let local_values: &ShaCompressColumnsView<F> = row.borrow();

        assert_eq!(
            local_values.output_state[get_input_range(0)],
            from_u32_to_be_bits(4228417613).iter().map(|&x| F::from_canonical_u8(x)).collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_state[get_input_range(1)],
            from_u32_to_be_bits(1779033703).iter().map(|&x| F::from_canonical_u8(x)).collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_state[get_input_range(2)],
            from_u32_to_be_bits(3144134277).iter().map(|&x| F::from_canonical_u8(x)).collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_state[get_input_range(3)],
            from_u32_to_be_bits(1013904242).iter().map(|&x| F::from_canonical_u8(x)).collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_state[get_input_range(4)],
            from_u32_to_be_bits(2563236514).iter().map(|&x| F::from_canonical_u8(x)).collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_state[get_input_range(5)],
            from_u32_to_be_bits(1359893119).iter().map(|&x| F::from_canonical_u8(x)).collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_state[get_input_range(6)],
            from_u32_to_be_bits(2600822924).iter().map(|&x| F::from_canonical_u8(x)).collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_state[get_input_range(7)],
            from_u32_to_be_bits(528734635).iter().map(|&x| F::from_canonical_u8(x)).collect::<Vec<F>>()
        );
        Ok(())
    }
}