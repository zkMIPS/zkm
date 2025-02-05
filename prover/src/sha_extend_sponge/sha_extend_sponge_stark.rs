use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::membus::NUM_CHANNELS;
use crate::cross_table_lookup::{Column, Filter};
use crate::evaluation_frame::{StarkEvaluationFrame, StarkFrame};
use crate::memory::segments::Segment;
use crate::sha_extend::logic::{from_be_fbits_to_u32, from_u32_to_be_bits, get_input_range};
use crate::sha_extend_sponge::columns::{
    ShaExtendSpongeColumnsView, NUM_EXTEND_INPUT, NUM_SHA_EXTEND_SPONGE_COLUMNS,
    SHA_EXTEND_SPONGE_COL_MAP,
};
use crate::sha_extend_sponge::logic::{
    diff_address_ext_circuit_constraint, round_increment_ext_circuit_constraint,
};
use crate::stark::Stark;
use crate::util::trace_rows_to_poly_values;
use crate::witness::memory::MemoryAddress;
use itertools::Itertools;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use std::borrow::Borrow;
use std::marker::PhantomData;

pub const NUM_ROUNDS: usize = 48;

// pub(crate) fn ctl_looking_sha_extend_inputs<F: Field>() -> Vec<Column<F>> {
//     let cols = SHA_EXTEND_SPONGE_COL_MAP;
//     let mut res: Vec<_> = Column::singles(
//         [
//             cols.w_i_minus_15.as_slice(),
//             cols.w_i_minus_2.as_slice(),
//             cols.w_i_minus_16.as_slice(),
//             cols.w_i_minus_7.as_slice(),
//         ]
//         .concat(),
//     )
//     .collect();
//     res.push(Column::single(cols.timestamp));
//     res
// }
//
// pub(crate) fn ctl_looking_sha_extend_outputs<F: Field>() -> Vec<Column<F>> {
//     let cols = SHA_EXTEND_SPONGE_COL_MAP;
//
//     let mut res = vec![];
//     res.extend(Column::singles(&cols.w_i));
//     res.push(Column::single(cols.timestamp));
//     res
// }
//
// pub(crate) fn ctl_looked_data<F: Field>() -> Vec<Column<F>> {
//     let cols = SHA_EXTEND_SPONGE_COL_MAP;
//     let w_i_usize = Column::linear_combination(
//         cols.w_i
//             .iter()
//             .enumerate()
//             .map(|(i, &b)| (b, F::from_canonical_usize(1 << i))),
//     );
//
//     Column::singles([cols.context, cols.segment, cols.output_virt, cols.timestamp])
//         .chain([w_i_usize])
//         .collect()
// }
//
// pub(crate) fn ctl_looking_memory<F: Field>(i: usize) -> Vec<Column<F>> {
//     let cols = SHA_EXTEND_SPONGE_COL_MAP;
//
//     let mut res = vec![Column::constant(F::ONE)]; // is_read
//
//     res.extend(Column::singles([cols.context, cols.segment]));
//     res.push(Column::single(cols.input_virt[i / 32]));
//
//     // The u32 of i'th input bit being read.
//     let start = i / 32;
//     let le_bit;
//     if start == 0 {
//         le_bit = cols.w_i_minus_15;
//     } else if start == 1 {
//         le_bit = cols.w_i_minus_2;
//     } else if start == 2 {
//         le_bit = cols.w_i_minus_16;
//     } else {
//         le_bit = cols.w_i_minus_7;
//     }
//     // le_bit.reverse();
//     let u32_value: Column<F> = Column::le_bits(le_bit);
//     res.push(u32_value);
//
//     res.push(Column::single(cols.timestamp));
//
//     assert_eq!(
//         res.len(),
//         crate::memory::memory_stark::ctl_data::<F>().len()
//     );
//     res
// }
//
// pub(crate) fn ctl_looking_sha_extend_filter<F: Field>() -> Filter<F> {
//     let cols = SHA_EXTEND_SPONGE_COL_MAP;
//     // not the padding rows.
//     Filter::new_simple(Column::sum(cols.round))
// }

#[derive(Clone, Debug)]
pub(crate) struct ShaExtendSpongeOp {
    /// The base address at which inputs are read
    pub(crate) base_address: Vec<MemoryAddress>,

    /// The timestamp at which inputs are read
    pub(crate) timestamp: usize,

    /// The input that was read.
    /// Values: w_i_minus_15, w_i_minus_2, w_i_minus_16, w_i_minus_7 in big-endian order.
    pub(crate) input: Vec<u8>,

    /// The index of round
    pub(crate) i: usize,

    /// The base address at which the output is written.
    pub(crate) output_address: MemoryAddress,
}

#[derive(Copy, Clone, Default)]
pub struct ShaExtendSpongeStark<F, const D: usize> {
    f: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> ShaExtendSpongeStark<F, D> {
    pub(crate) fn generate_trace(
        &self,
        operations: Vec<ShaExtendSpongeOp>,
        min_rows: usize,
    ) -> Vec<PolynomialValues<F>> {
        // Generate the witness row-wise.
        let trace_rows = self.generate_trace_rows(operations, min_rows);

        trace_rows_to_poly_values(trace_rows)
    }

    fn generate_trace_rows(
        &self,
        operations: Vec<ShaExtendSpongeOp>,
        min_rows: usize,
    ) -> Vec<[F; NUM_SHA_EXTEND_SPONGE_COLUMNS]> {
        let base_len = operations.len();
        let mut rows = Vec::with_capacity(base_len.max(min_rows).next_power_of_two());
        for op in operations {
            rows.push(self.generate_rows_for_op(op).into());
        }

        let padded_rows = rows.len().max(min_rows).next_power_of_two();
        for _ in rows.len()..padded_rows {
            rows.push(ShaExtendSpongeColumnsView::default().into());
        }

        rows
    }

    fn generate_rows_for_op(&self, op: ShaExtendSpongeOp) -> ShaExtendSpongeColumnsView<F> {
        let mut row = ShaExtendSpongeColumnsView::default();
        row.timestamp = F::from_canonical_usize(op.timestamp);
        row.round = [F::ZEROS; 48];
        row.round[op.i] = F::ONE;

        row.context = F::from_canonical_usize(op.base_address[0].context);
        row.segment = F::from_canonical_usize(op.base_address[Segment::Code as usize].segment);
        let virt = (0..op.input.len() / 4)
            .map(|i| op.base_address[i].virt)
            .collect_vec();
        let virt: [usize; 4] = virt.try_into().unwrap();
        row.input_virt = virt.map(F::from_canonical_usize);
        row.output_virt = F::from_canonical_usize(op.output_address.virt);

        let input = op.input.clone();
        row.w_i = self.compute_w_i(input);

        row.w_i_minus_15 = op.input[get_input_range(0)]
            .iter()
            .map(|&x| F::from_canonical_u8(x))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        row.w_i_minus_2 = op.input[get_input_range(1)]
            .iter()
            .map(|&x| F::from_canonical_u8(x))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        row.w_i_minus_16 = op.input[get_input_range(2)]
            .iter()
            .map(|&x| F::from_canonical_u8(x))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        row.w_i_minus_7 = op.input[get_input_range(3)]
            .iter()
            .map(|&x| F::from_canonical_u8(x))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        row
    }

    fn compute_w_i(&self, input: Vec<u8>) -> [F; 4] {
        let w_i_minus_15 = u32::from_le_bytes(input[get_input_range(0)].try_into().unwrap());
        let w_i_minus_2 = u32::from_le_bytes(input[get_input_range(1)].try_into().unwrap());
        let w_i_minus_16 = u32::from_le_bytes(input[get_input_range(2)].try_into().unwrap());
        let w_i_minus_7 = u32::from_le_bytes(input[get_input_range(3)].try_into().unwrap());
        let s0 = w_i_minus_15.rotate_right(7) ^ w_i_minus_15.rotate_right(18) ^ (w_i_minus_15 >> 3);
        let s1 = w_i_minus_2.rotate_right(17) ^ w_i_minus_2.rotate_right(19) ^ (w_i_minus_2 >> 10);
        let w_i_u32 = s1
            .wrapping_add(w_i_minus_16)
            .wrapping_add(s0)
            .wrapping_add(w_i_minus_7);

        w_i_u32.to_le_bytes().map(F::from_canonical_u8)

    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for ShaExtendSpongeStark<F, D> {
    type EvaluationFrame<FE, P, const D2: usize>
        = StarkFrame<P, NUM_SHA_EXTEND_SPONGE_COLUMNS>
    where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>;

    type EvaluationFrameTarget = StarkFrame<ExtensionTarget<D>, NUM_SHA_EXTEND_SPONGE_COLUMNS>;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: &Self::EvaluationFrame<FE, P, D2>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        let local_values: &[P; NUM_SHA_EXTEND_SPONGE_COLUMNS] =
            vars.get_local_values().try_into().unwrap();
        let local_values: &ShaExtendSpongeColumnsView<P> = local_values.borrow();
        let next_values: &[P; NUM_SHA_EXTEND_SPONGE_COLUMNS] =
            vars.get_next_values().try_into().unwrap();
        let next_values: &ShaExtendSpongeColumnsView<P> = next_values.borrow();


        // check the round
        for i in 0..NUM_ROUNDS {
            yield_constr.constraint(local_values.round[i] * (local_values.round[i] - P::ONES));
        }

        // check the filter
        let is_final = local_values.round[NUM_ROUNDS - 1];
        yield_constr.constraint(is_final * (is_final - P::ONES));
        let not_final = P::ONES - is_final;

        let sum_round_flags = (0..NUM_ROUNDS).map(|i| local_values.round[i]).sum::<P>();

        // If this is not the final step or a padding row,
        // the timestamp must be increased by 2 * NUM_CHANNELS.
        yield_constr.constraint(
            sum_round_flags
                * not_final
                * (next_values.timestamp
                    - local_values.timestamp
                    - FE::from_canonical_usize(2 * NUM_CHANNELS)),
        );

        // If this is not the final step or a padding row,
        // round index should be increased by one

        let local_round_index = (0..NUM_ROUNDS)
            .map(|i| local_values.round[i] * FE::from_canonical_u32(i as u32))
            .sum::<P>();
        let next_round_index = (0..NUM_ROUNDS)
            .map(|i| next_values.round[i] * FE::from_canonical_u32(i as u32))
            .sum::<P>();
        yield_constr.constraint(
            sum_round_flags * not_final * (next_round_index - local_round_index - P::ONES),
        );

        // If this is not the final step or a padding row,
        // input and output addresses should be increased by 4 each
        (0..NUM_EXTEND_INPUT).for_each(|i| {
            yield_constr.constraint(
                sum_round_flags
                    * not_final
                    * (next_values.input_virt[i]
                        - local_values.input_virt[i]
                        - FE::from_canonical_u32(4)),
            );
        });
        yield_constr.constraint(
            sum_round_flags
                * not_final
                * (next_values.output_virt - local_values.output_virt - FE::from_canonical_u32(4)),
        );

        // If it's not the padding row, check the virtual addresses
        // The list of input addresses are: w[i-15], w[i-2], w[i-16], w[i-7]

        // add_w[i-15] = add_w[i-16] + 4
        yield_constr.constraint(
            sum_round_flags
                * (local_values.input_virt[0]
                    - local_values.input_virt[2]
                    - FE::from_canonical_u32(4)),
        );
        // add_w[i-2] = add_w[i-16] + 56
        yield_constr.constraint(
            sum_round_flags
                * (local_values.input_virt[1]
                    - local_values.input_virt[2]
                    - FE::from_canonical_u32(56)),
        );
        // add_w[i-7] = add_w[i-16] + 36
        yield_constr.constraint(
            sum_round_flags
                * (local_values.input_virt[3]
                    - local_values.input_virt[2]
                    - FE::from_canonical_u32(36)),
        );
        // add_w[i] = add_w[i-16] + 64
        yield_constr.constraint(
            sum_round_flags
                * (local_values.output_virt
                    - local_values.input_virt[2]
                    - FE::from_canonical_u32(64)),
        );
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: &Self::EvaluationFrameTarget,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        let local_values: &[ExtensionTarget<D>; NUM_SHA_EXTEND_SPONGE_COLUMNS] =
            vars.get_local_values().try_into().unwrap();
        let local_values: &ShaExtendSpongeColumnsView<ExtensionTarget<D>> = local_values.borrow();
        let next_values: &[ExtensionTarget<D>; NUM_SHA_EXTEND_SPONGE_COLUMNS] =
            vars.get_next_values().try_into().unwrap();
        let next_values: &ShaExtendSpongeColumnsView<ExtensionTarget<D>> = next_values.borrow();

        let one_ext = builder.one_extension();
        let four_ext = builder.constant_extension(F::Extension::from_canonical_u32(4));
        let num_channel =
            builder.constant_extension(F::Extension::from_canonical_usize(2 * NUM_CHANNELS));

        // check the round
        for i in 0..NUM_ROUNDS {
            let constraint = builder.mul_sub_extension(
                local_values.round[i],
                local_values.round[i],
                local_values.round[i],
            );
            yield_constr.constraint(builder, constraint);
        }

        // check the filter
        let is_final = local_values.round[NUM_ROUNDS - 1];
        let constraint = builder.mul_sub_extension(is_final, is_final, is_final);
        yield_constr.constraint(builder, constraint);
        let not_final = builder.sub_extension(one_ext, is_final);

        let sum_round_flags =
            builder.add_many_extension((0..NUM_ROUNDS).map(|i| local_values.round[i]));

        // If this is not the final step or a padding row,
        // the timestamp must be increased by 2 * NUM_CHANNELS.
        let diff = builder.sub_extension(next_values.timestamp, local_values.timestamp);
        let diff = builder.sub_extension(diff, num_channel);
        let constraint = builder.mul_many_extension([sum_round_flags, not_final, diff]);
        yield_constr.constraint(builder, constraint);

        // If this is not the final step or a padding row,
        // round index should be increased by one

        let round_increment =
            round_increment_ext_circuit_constraint(builder, local_values.round, next_values.round);
        let constraint = builder.mul_many_extension([sum_round_flags, not_final, round_increment]);
        yield_constr.constraint(builder, constraint);

        // If this is not the final step or a padding row,
        // input and output addresses should be increased by 4 each
        (0..NUM_EXTEND_INPUT).for_each(|i| {
            let increment =
                builder.sub_extension(next_values.input_virt[i], local_values.input_virt[i]);
            let address_increment = builder.sub_extension(increment, four_ext);
            let constraint =
                builder.mul_many_extension([sum_round_flags, not_final, address_increment]);
            yield_constr.constraint(builder, constraint);
        });

        let increment = builder.sub_extension(next_values.output_virt, local_values.output_virt);
        let address_increment = builder.sub_extension(increment, four_ext);
        let constraint =
            builder.mul_many_extension([sum_round_flags, not_final, address_increment]);
        yield_constr.constraint(builder, constraint);

        // If it's not the padding row, check the virtual addresses
        // The list of input addresses are: w[i-15], w[i-2], w[i-16], w[i-7]

        // add_w[i-15] = add_w[i-16] + 4
        let constraint = diff_address_ext_circuit_constraint(
            builder,
            sum_round_flags,
            local_values.input_virt[0],
            local_values.input_virt[2],
            4,
        );
        yield_constr.constraint(builder, constraint);

        // add_w[i-2] = add_w[i-16] + 56
        let constraint = diff_address_ext_circuit_constraint(
            builder,
            sum_round_flags,
            local_values.input_virt[1],
            local_values.input_virt[2],
            56,
        );
        yield_constr.constraint(builder, constraint);

        // add_w[i-7] = add_w[i-16] + 36
        let constraint = diff_address_ext_circuit_constraint(
            builder,
            sum_round_flags,
            local_values.input_virt[3],
            local_values.input_virt[2],
            36,
        );
        yield_constr.constraint(builder, constraint);

        // add_w[i] = add_w[i-16] + 64
        let constraint = diff_address_ext_circuit_constraint(
            builder,
            sum_round_flags,
            local_values.output_virt,
            local_values.input_virt[2],
            64,
        );
        yield_constr.constraint(builder, constraint);
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
    use crate::memory::segments::Segment;
    use crate::memory::NUM_CHANNELS;
    use crate::prover::prove_single_table;
    use crate::sha_extend_sponge::sha_extend_sponge_stark::{
        ShaExtendSpongeOp, ShaExtendSpongeStark,
    };
    use crate::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};
    use crate::witness::memory::MemoryAddress;
    use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::polynomial::PolynomialValues;
    use plonky2::field::types::Field;
    use plonky2::fri::oracle::PolynomialBatch;
    use plonky2::iop::challenger::Challenger;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::timed;
    use plonky2::util::timing::TimingTree;

    #[test]
    fn test_correction() -> Result<(), String> {
        const D: usize = 2;
        type F = GoldilocksField;

        type S = ShaExtendSpongeStark<F, D>;

        let mut input_values = vec![];
        input_values.extend((0..4_u32).map(|i| i.to_le_bytes()));
        let input_values = input_values.into_iter().flatten().collect::<Vec<_>>();

        let op = ShaExtendSpongeOp {
            base_address: vec![
                MemoryAddress {
                    context: 0,
                    segment: Segment::Code as usize,
                    virt: 4,
                },
                MemoryAddress {
                    context: 0,
                    segment: Segment::Code as usize,
                    virt: 56,
                },
                MemoryAddress {
                    context: 0,
                    segment: Segment::Code as usize,
                    virt: 0,
                },
                MemoryAddress {
                    context: 0,
                    segment: Segment::Code as usize,
                    virt: 36,
                },
            ],
            timestamp: 0,
            input: input_values,
            i: 0,
            output_address: MemoryAddress {
                context: 0,
                segment: Segment::Code as usize,
                virt: 64,
            },
        };

        let stark = S::default();
        let row = stark.generate_rows_for_op(op);

        let w_i_bin = 40965_u32.to_le_bytes();
        assert_eq!(row.w_i, w_i_bin.map(F::from_canonical_u8));

        Ok(())
    }

    #[test]
    fn test_stark_circuit() -> anyhow::Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = ShaExtendSpongeStark<F, D>;

        let stark = S::default();
        test_stark_circuit_constraints::<F, C, S, D>(stark)
    }

    #[test]
    fn test_stark_degree() -> anyhow::Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = ShaExtendSpongeStark<F, D>;

        let stark = S {
            f: Default::default(),
        };
        test_stark_low_degree(stark)
    }

    fn get_random_input() -> Vec<ShaExtendSpongeOp> {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = rand::random::<u32>();
        }
        for i in 16..64 {
            let w_i_minus_15 = w[i - 15];
            let s0 =
                w_i_minus_15.rotate_right(7) ^ w_i_minus_15.rotate_right(18) ^ (w_i_minus_15 >> 3);

            // Read w[i-2].
            let w_i_minus_2 = w[i - 2];
            // Compute `s1`.
            let s1 =
                w_i_minus_2.rotate_right(17) ^ w_i_minus_2.rotate_right(19) ^ (w_i_minus_2 >> 10);

            // Read w[i-16].
            let w_i_minus_16 = w[i - 16];
            let w_i_minus_7 = w[i - 7];

            // Compute `w_i`.
            w[i] = s1
                .wrapping_add(w_i_minus_16)
                .wrapping_add(s0)
                .wrapping_add(w_i_minus_7);
        }

        let mut addresses = vec![];
        for i in 0..64 {
            addresses.push(MemoryAddress {
                context: 0,
                segment: Segment::Code as usize,
                virt: i * 4,
            });
        }

        let mut res = vec![];

        let mut time = 0;
        for i in 16..64 {
            let mut input_values = vec![];
            input_values.extend(w[i - 15].to_le_bytes());
            input_values.extend(w[i - 2].to_le_bytes());
            input_values.extend(w[i - 16].to_le_bytes());
            input_values.extend(w[i - 7].to_le_bytes());

            let op = ShaExtendSpongeOp {
                base_address: vec![
                    addresses[i - 15],
                    addresses[i - 2],
                    addresses[i - 16],
                    addresses[i - 7],
                ],
                timestamp: time,
                input: input_values,
                i: i - 16,
                output_address: addresses[i],
            };

            res.push(op);
            time += 2 * NUM_CHANNELS;
        }

        res
    }
    #[test]
    fn sha_extend_sponge_benchmark() -> anyhow::Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = ShaExtendSpongeStark<F, D>;
        let stark = S::default();
        let config = StarkConfig::standard_fast_config();

        init_logger();

        let input = get_random_input();
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
