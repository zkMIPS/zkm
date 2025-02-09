use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cross_table_lookup::{Column, Filter};
use crate::evaluation_frame::{StarkEvaluationFrame, StarkFrame};
use crate::sha_extend::columns::{
    ShaExtendColumnsView, NUM_SHA_EXTEND_COLUMNS, SHA_EXTEND_COL_MAP,
};
use crate::sha_extend::logic::get_input_range_4;
use crate::sha_extend::rotate_right::{
    rotate_right_ext_circuit_constraint, rotate_right_packed_constraints,
};
use crate::sha_extend::shift_right::{
    shift_right_ext_circuit_constraints, shift_right_packed_constraints,
};
use crate::sha_extend::wrapping_add_4::{
    wrapping_add_4_ext_circuit_constraints, wrapping_add_4_packed_constraints,
};
use crate::stark::Stark;
use crate::util::trace_rows_to_poly_values;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use std::borrow::Borrow;
use std::marker::PhantomData;

pub const NUM_INPUTS: usize = 4 * 4; // w_i_minus_15, w_i_minus_2, w_i_minus_16, w_i_minus_7

pub fn ctl_data_inputs<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_EXTEND_COL_MAP;
    let mut res: Vec<_> = Column::singles(
        [
            cols.w_i_minus_15.as_slice(),
            cols.w_i_minus_2.as_slice(),
            cols.w_i_minus_16.as_slice(),
            cols.w_i_minus_7.as_slice(),
        ]
        .concat(),
    )
    .collect();
    res.push(Column::single(cols.timestamp));
    res
}

pub fn ctl_data_outputs<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_EXTEND_COL_MAP;
    let mut res: Vec<_> = Column::singles(&cols.w_i.value).collect();
    res.push(Column::single(cols.timestamp));
    res
}

pub(crate) fn ctl_s_0_inter_looking_logic<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_EXTEND_COL_MAP;
    let mut res = vec![
        Column::constant(F::from_canonical_u32(0b100110 * (1 << 6))), // is_xor
    ];
    // Input 0
    res.push(Column::le_bytes(cols.w_i_minus_15_rr_7.value));
    // Input 1
    res.push(Column::le_bytes(cols.w_i_minus_15_rr_18.value));
    // The output
    res.push(Column::le_bytes(cols.s_0_inter));
    res
}

pub(crate) fn ctl_s_0_looking_logic<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_EXTEND_COL_MAP;
    let mut res = vec![
        Column::constant(F::from_canonical_u32(0b100110 * (1 << 6))), // is_xor
    ];
    // Input 0
    res.push(Column::le_bytes(cols.s_0_inter));
    // Input 1
    res.push(Column::le_bytes(cols.w_i_minus_15_rs_3.value));
    // The output
    res.push(Column::le_bytes(cols.s_0));
    res
}

pub(crate) fn ctl_s_1_inter_looking_logic<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_EXTEND_COL_MAP;
    let mut res = vec![
        Column::constant(F::from_canonical_u32(0b100110 * (1 << 6))), // is_xor
    ];
    // Input 0
    res.push(Column::le_bytes(cols.w_i_minus_2_rr_17.value));
    // Input 1
    res.push(Column::le_bytes(cols.w_i_minus_2_rr_19.value));
    // The output
    res.push(Column::le_bytes(cols.s_1_inter));
    res
}

pub(crate) fn ctl_s_1_looking_logic<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_EXTEND_COL_MAP;
    let mut res = vec![
        Column::constant(F::from_canonical_u32(0b100110 * (1 << 6))), // is_xor
    ];
    // Input 0
    res.push(Column::le_bytes(cols.s_1_inter));
    // Input 1
    res.push(Column::le_bytes(cols.w_i_minus_2_rs_10.value));
    // The output
    res.push(Column::le_bytes(cols.s_1));
    res
}

pub fn ctl_filter<F: Field>() -> Filter<F> {
    let cols = SHA_EXTEND_COL_MAP;
    // not the padding rows.
    Filter::new_simple(Column::single(cols.is_normal_round))
}

#[derive(Copy, Clone, Default)]
pub struct ShaExtendStark<F, const D: usize> {
    pub(crate) f: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> ShaExtendStark<F, D> {
    pub(crate) fn generate_trace(
        &self,
        inputs_and_timestamps: Vec<([u8; NUM_INPUTS], usize)>,
        min_rows: usize,
    ) -> Vec<PolynomialValues<F>> {
        // Generate the witness row-wise
        let trace_rows = self.generate_trace_rows(inputs_and_timestamps, min_rows);
        trace_rows_to_poly_values(trace_rows)
    }

    fn generate_trace_rows(
        &self,
        inputs_and_timestamps: Vec<([u8; NUM_INPUTS], usize)>,
        min_rows: usize,
    ) -> Vec<[F; NUM_SHA_EXTEND_COLUMNS]> {
        let num_rows = inputs_and_timestamps
            .len()
            .max(min_rows)
            .next_power_of_two();

        let mut rows = Vec::with_capacity(num_rows);
        for input_and_timestamp in inputs_and_timestamps.iter() {
            let rows_for_extend = self.generate_trace_row_for_extend(*input_and_timestamp);
            rows.push(rows_for_extend.into());
        }

        // padding
        while rows.len() < num_rows {
            rows.push([F::ZERO; NUM_SHA_EXTEND_COLUMNS]);
        }

        rows
    }

    fn generate_trace_row_for_extend(
        &self,
        input_and_timestamp: ([u8; NUM_INPUTS], usize),
    ) -> ShaExtendColumnsView<F> {
        let mut row = ShaExtendColumnsView::default();

        row.timestamp = F::from_canonical_usize(input_and_timestamp.1);
        let w_i_minus_15: [u8; 4] = input_and_timestamp.0[get_input_range_4(0)]
            .try_into()
            .unwrap();
        let w_i_minus_2: [u8; 4] = input_and_timestamp.0[get_input_range_4(1)]
            .try_into()
            .unwrap();
        let w_i_minus_16: [u8; 4] = input_and_timestamp.0[get_input_range_4(2)]
            .try_into()
            .unwrap();
        let w_i_minus_7: [u8; 4] = input_and_timestamp.0[get_input_range_4(3)]
            .try_into()
            .unwrap();

        row.w_i_minus_15 = w_i_minus_15
            .iter()
            .map(|&x| F::from_canonical_u8(x))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        row.w_i_minus_2 = w_i_minus_2
            .iter()
            .map(|&x| F::from_canonical_u8(x))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        row.w_i_minus_16 = w_i_minus_16
            .iter()
            .map(|&x| F::from_canonical_u8(x))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        row.w_i_minus_7 = w_i_minus_7
            .iter()
            .map(|&x| F::from_canonical_u8(x))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        row.is_normal_round = F::ONE;

        let w_i_minus_15_rr_7 = row.w_i_minus_15_rr_7.generate_trace(w_i_minus_15, 7);
        let w_i_minus_15_rr_18 = row.w_i_minus_15_rr_18.generate_trace(w_i_minus_15, 18);
        let w_i_minus_15_rs_3 = row.w_i_minus_15_rs_3.generate_trace(w_i_minus_15, 3);

        // s0_inter = (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18)
        let s_0_inter = w_i_minus_15_rr_7 ^ w_i_minus_15_rr_18;
        row.s_0_inter = s_0_inter.to_le_bytes().map(F::from_canonical_u8);

        // s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
        let s_0 = s_0_inter ^ w_i_minus_15_rs_3;
        row.s_0 = s_0.to_le_bytes().map(F::from_canonical_u8);

        let w_i_minus_2_rr_17 = row.w_i_minus_2_rr_17.generate_trace(w_i_minus_2, 17);
        let w_i_minus_2_rr_19 = row.w_i_minus_2_rr_19.generate_trace(w_i_minus_2, 19);
        let w_i_minus_2_rs_10 = row.w_i_minus_2_rs_10.generate_trace(w_i_minus_2, 10);

        // s1_inter = (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19)
        let s_1_inter = w_i_minus_2_rr_17 ^ w_i_minus_2_rr_19;
        row.s_1_inter = s_1_inter.to_le_bytes().map(F::from_canonical_u8);

        // s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
        let s_1 = s_1_inter ^ w_i_minus_2_rs_10;
        row.s_1 = s_1.to_le_bytes().map(F::from_canonical_u8);

        let _ = row.w_i.generate_trace(
            s_1.to_le_bytes(),
            w_i_minus_7,
            s_0.to_le_bytes(),
            w_i_minus_16,
        );

        row
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for ShaExtendStark<F, D> {
    type EvaluationFrame<FE, P, const D2: usize>
        = StarkFrame<P, NUM_SHA_EXTEND_COLUMNS>
    where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>;

    type EvaluationFrameTarget = StarkFrame<ExtensionTarget<D>, NUM_SHA_EXTEND_COLUMNS>;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: &Self::EvaluationFrame<FE, P, D2>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        let local_values: &[P; NUM_SHA_EXTEND_COLUMNS] =
            vars.get_local_values().try_into().unwrap();
        let local_values: &ShaExtendColumnsView<P> = local_values.borrow();

        // check the rotation
        rotate_right_packed_constraints(
            local_values.w_i_minus_15,
            &local_values.w_i_minus_15_rr_7,
            7,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));
        rotate_right_packed_constraints(
            local_values.w_i_minus_15,
            &local_values.w_i_minus_15_rr_18,
            18,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));
        rotate_right_packed_constraints(
            local_values.w_i_minus_2,
            &local_values.w_i_minus_2_rr_17,
            17,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));
        rotate_right_packed_constraints(
            local_values.w_i_minus_2,
            &local_values.w_i_minus_2_rr_19,
            19,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        // check the shift
        shift_right_packed_constraints(
            local_values.w_i_minus_15,
            &local_values.w_i_minus_15_rs_3,
            3,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        shift_right_packed_constraints(
            local_values.w_i_minus_2,
            &local_values.w_i_minus_2_rs_10,
            10,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        //  the XOR ops in s_0, s_1 computations are constrained in logic table.

        // check the wrapping add: w_i = s_1 + w_i_minus_7 + s_0 + w_i_minus_16

        wrapping_add_4_packed_constraints(
            local_values.s_1,
            local_values.w_i_minus_7,
            local_values.s_0,
            local_values.w_i_minus_16,
            &local_values.w_i,
        )
        .into_iter()
        .for_each(|c| {
            let constraint = c * local_values.is_normal_round;
            yield_constr.constraint(constraint)
        });
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: &Self::EvaluationFrameTarget,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        let local_values: &[ExtensionTarget<D>; NUM_SHA_EXTEND_COLUMNS] =
            vars.get_local_values().try_into().unwrap();
        let local_values: &ShaExtendColumnsView<ExtensionTarget<D>> = local_values.borrow();

        // check the rotation
        rotate_right_ext_circuit_constraint(
            builder,
            local_values.w_i_minus_15,
            &local_values.w_i_minus_15_rr_7,
            7,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));
        rotate_right_ext_circuit_constraint(
            builder,
            local_values.w_i_minus_15,
            &local_values.w_i_minus_15_rr_18,
            18,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));
        rotate_right_ext_circuit_constraint(
            builder,
            local_values.w_i_minus_2,
            &local_values.w_i_minus_2_rr_17,
            17,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));
        rotate_right_ext_circuit_constraint(
            builder,
            local_values.w_i_minus_2,
            &local_values.w_i_minus_2_rr_19,
            19,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        // check the shift
        shift_right_ext_circuit_constraints(
            builder,
            local_values.w_i_minus_15,
            &local_values.w_i_minus_15_rs_3,
            3,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        shift_right_ext_circuit_constraints(
            builder,
            local_values.w_i_minus_2,
            &local_values.w_i_minus_2_rs_10,
            10,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        //  the XOR ops in s_0, s_1 computations are constrainted in logic table.

        // check the wrapping add: w_i = s_1 + w_i_minus_7 + s_0 + w_i_minus_16
        wrapping_add_4_ext_circuit_constraints(
            builder,
            local_values.s_1,
            local_values.w_i_minus_7,
            local_values.s_0,
            local_values.w_i_minus_16,
            &local_values.w_i,
        )
        .into_iter()
        .for_each(|c| {
            let constraint = builder.mul_extension(c, local_values.is_normal_round);
            yield_constr.constraint(builder, constraint)
        });
    }

    fn constraint_degree(&self) -> usize {
        3
    }
}

#[cfg(test)]
mod test {
    use crate::config::StarkConfig;
    use crate::cross_table_lookup::{
        Column, CtlData, CtlZData, Filter, GrandProductChallenge, GrandProductChallengeSet,
    };
    use crate::prover::prove_single_table;
    use crate::sha_extend::sha_extend_stark::ShaExtendStark;
    use crate::sha_extend_sponge::columns::NUM_EXTEND_INPUT;
    use crate::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};
    use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::polynomial::PolynomialValues;
    use plonky2::field::types::Field;
    use plonky2::fri::oracle::PolynomialBatch;
    use plonky2::iop::challenger::Challenger;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::timed;
    use plonky2::util::timing::TimingTree;

    fn get_random_input() -> [u8; NUM_EXTEND_INPUT * 4] {
        let mut input_values = vec![];
        let rand = rand::random::<u32>();

        input_values.push(rand.to_le_bytes());
        input_values.push((rand + 1).to_le_bytes());
        input_values.push((rand + 2).to_le_bytes());
        input_values.push((rand + 3).to_le_bytes());

        let input_values = input_values.into_iter().flatten().collect::<Vec<_>>();
        input_values.try_into().unwrap()
    }

    #[test]
    fn test_correction() -> Result<(), String> {
        const D: usize = 2;
        type F = GoldilocksField;

        type S = ShaExtendStark<F, D>;
        let mut input_values = vec![];
        input_values.extend((0..4).map(|i| (i as u32).to_le_bytes()));
        let input_values = input_values.into_iter().flatten().collect::<Vec<_>>();
        let input_values: [u8; 16] = input_values.try_into().unwrap();
        let input_and_timestamp = (input_values, 0);

        let stark = S::default();
        let row = stark.generate_trace_row_for_extend(input_and_timestamp);

        // extend phase
        let w_i_minus_15 = 0_u32;
        let s0 = w_i_minus_15.rotate_right(7) ^ w_i_minus_15.rotate_right(18) ^ (w_i_minus_15 >> 3);

        let w_i_minus_2 = 1_u32;
        // Compute `s1`.
        let s1 = w_i_minus_2.rotate_right(17) ^ w_i_minus_2.rotate_right(19) ^ (w_i_minus_2 >> 10);
        let w_i_minus_16 = 2_u32;
        let w_i_minus_7 = 3_u32;
        // Compute `w_i`.
        let w_i = s1
            .wrapping_add(w_i_minus_16)
            .wrapping_add(s0)
            .wrapping_add(w_i_minus_7);

        let w_i_bin = w_i.to_le_bytes();
        assert_eq!(row.w_i.value, w_i_bin.map(F::from_canonical_u8));

        Ok(())
    }

    #[test]
    fn test_stark_degree() -> anyhow::Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = ShaExtendStark<F, D>;

        let stark = S {
            f: Default::default(),
        };
        test_stark_low_degree(stark)
    }

    #[test]
    fn test_stark_circuit() -> anyhow::Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = ShaExtendStark<F, D>;

        let stark = S {
            f: Default::default(),
        };
        test_stark_circuit_constraints::<F, C, S, D>(stark)
    }

    #[test]
    fn sha_extend_benchmark() -> anyhow::Result<()> {
        const NUM_EXTEND: usize = 48;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = ShaExtendStark<F, D>;
        let stark = S::default();
        let config = StarkConfig::standard_fast_config();

        init_logger();

        let input: Vec<([u8; NUM_EXTEND_INPUT * 4], usize)> =
            (0..NUM_EXTEND).map(|_| (get_random_input(), 0)).collect();

        let mut timing = TimingTree::new("prove", log::Level::Debug);
        let trace_poly_values = stark.generate_trace(input, 8);

        // TODO: Cloning this isn't great; consider having `from_values` accept a reference,
        // or having `compute_permutation_z_polys` read trace values from the `PolynomialBatch`.
        let cloned_trace_poly_values = timed!(timing, "clone", trace_poly_values.clone());

        let trace_commitments = timed!(
            timing,
            "compute trace commitment",
            PolynomialBatch::<F, C, D>::from_values(
                cloned_trace_poly_values,
                config.fri_config.rate_bits,
                false,
                config.fri_config.cap_height,
                &mut timing,
                None,
            )
        );
        let degree = 1 << trace_commitments.degree_log;

        // Fake CTL data.
        let ctl_z_data = CtlZData {
            helper_columns: vec![PolynomialValues::zero(degree)],
            z: PolynomialValues::zero(degree),
            challenge: GrandProductChallenge {
                beta: F::ZERO,
                gamma: F::ZERO,
            },
            columns: vec![],
            filter: vec![Some(Filter::new_simple(Column::constant(F::ZERO)))],
        };
        let ctl_data = CtlData {
            zs_columns: vec![ctl_z_data.clone(); config.num_challenges],
        };

        prove_single_table(
            &stark,
            &config,
            &trace_poly_values,
            &trace_commitments,
            &ctl_data,
            &GrandProductChallengeSet {
                challenges: vec![ctl_z_data.challenge; config.num_challenges],
            },
            &mut Challenger::new(),
            &mut timing,
        )?;

        timing.print();
        Ok(())
    }

    fn init_logger() {
        let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "debug"));
    }
}
