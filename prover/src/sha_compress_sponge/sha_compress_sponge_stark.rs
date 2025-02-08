use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cross_table_lookup::{Column, Filter};
use crate::evaluation_frame::{StarkEvaluationFrame, StarkFrame};
use crate::memory::segments::Segment;
use crate::sha_compress::wrapping_add_2::{
    wrapping_add_2_ext_circuit_constraints, wrapping_add_2_packed_constraints,
};
use crate::sha_compress_sponge::columns::{
    ShaCompressSpongeColumnsView, NUM_SHA_COMPRESS_SPONGE_COLUMNS, SHA_COMPRESS_SPONGE_COL_MAP,
};
use crate::sha_extend::logic::get_input_range_4;
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

pub(crate) const NUM_ROUNDS: usize = 64;

pub(crate) const SHA_COMPRESS_SPONGE_READ_BYTES: usize = 8 * 4; // h[0],...,h[7].
pub(crate) fn ctl_looking_sha_compress_inputs<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_SPONGE_COL_MAP;
    let mut res: Vec<_> = Column::singles([cols.hx.as_slice()].concat()).collect();
    res.extend(Column::singles([
        cols.timestamp,
        cols.w_start_segment,
        cols.w_start_context,
        cols.w_start_virt,
    ]));
    res
}

pub(crate) fn ctl_looking_sha_compress_outputs<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_SPONGE_COL_MAP;
    let mut res = vec![];
    res.extend(Column::singles(&cols.output_state));
    res.push(Column::single(cols.timestamp));
    res
}

pub(crate) fn ctl_looked_data<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_SPONGE_COL_MAP;
    let mut outputs = Vec::with_capacity(8);

    for i in 0..8 {
        let cur_col = Column::le_bytes(cols.output_hx[i].value);
        outputs.push(cur_col);
    }

    Column::singles([cols.context, cols.segment, cols.hx_virt[0], cols.timestamp])
        .chain(outputs)
        .collect()
}

pub(crate) fn ctl_looking_memory<F: Field>(i: usize) -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_SPONGE_COL_MAP;
    let mut res = vec![Column::constant(F::ONE)]; // is_read

    res.extend(Column::singles([cols.context, cols.segment]));
    let start = i / 4;
    res.push(Column::single(cols.hx_virt[start]));

    // le_bit.reverse();
    let u32_value: Column<F> = Column::le_bytes(&cols.hx[get_input_range_4(start)]);
    res.push(u32_value);
    res.push(Column::single(cols.timestamp));

    assert_eq!(
        res.len(),
        crate::memory::memory_stark::ctl_data::<F>().len()
    );
    res
}

pub(crate) fn ctl_looking_sha_compress_filter<F: Field>() -> Filter<F> {
    let cols = SHA_COMPRESS_SPONGE_COL_MAP;
    // only the normal round
    Filter::new_simple(Column::single(cols.is_normal_round))
}

pub(crate) fn ctl_looked_filter<F: Field>() -> Filter<F> {
    // The CPU table is only interested in our final rows, since those contain the final
    // compress sponge output.
    let cols = SHA_COMPRESS_SPONGE_COL_MAP;
    // only the normal round
    Filter::new_simple(Column::single(cols.is_normal_round))
}

#[derive(Clone, Debug)]
pub(crate) struct ShaCompressSpongeOp {
    /// The base address at which inputs are read.
    /// h[0],...,h[7], w_start_virtual.
    pub(crate) base_address: Vec<MemoryAddress>,

    /// The timestamp at which inputs are read.
    pub(crate) timestamp: usize,

    /// The input that was read.
    /// Values: h[0],..., h[7]  in le bytes order.
    pub(crate) input: Vec<u8>,

    /// The value of w_i used for compute output
    pub(crate) w_i_s: Vec<[u8; 4]>,
}

#[derive(Copy, Clone, Default)]
pub struct ShaCompressSpongeStark<F, const D: usize> {
    f: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> ShaCompressSpongeStark<F, D> {
    pub(crate) fn generate_trace(
        &self,
        operations: Vec<ShaCompressSpongeOp>,
        min_rows: usize,
    ) -> Vec<PolynomialValues<F>> {
        // Generate the witness row-wise.
        let trace_rows = self.generate_trace_rows(operations, min_rows);

        trace_rows_to_poly_values(trace_rows)
    }

    fn generate_trace_rows(
        &self,
        operations: Vec<ShaCompressSpongeOp>,
        min_rows: usize,
    ) -> Vec<[F; NUM_SHA_COMPRESS_SPONGE_COLUMNS]> {
        let base_len = operations.len();
        let mut rows = Vec::with_capacity(base_len.max(min_rows).next_power_of_two());
        for op in operations {
            rows.push(self.generate_rows_for_op(op).into());
        }

        let padded_rows = rows.len().max(min_rows).next_power_of_two();
        for _ in rows.len()..padded_rows {
            rows.push(ShaCompressSpongeColumnsView::default().into());
        }

        rows
    }

    fn generate_rows_for_op(&self, op: ShaCompressSpongeOp) -> ShaCompressSpongeColumnsView<F> {
        let mut row = ShaCompressSpongeColumnsView::default();

        row.timestamp = F::from_canonical_usize(op.timestamp);
        row.context = F::from_canonical_usize(op.base_address[0].context);
        row.segment = F::from_canonical_usize(op.base_address[Segment::Code as usize].segment);
        row.is_normal_round = F::ONE;
        let hx_virt: [usize; 8] = (0..8)
            .map(|i| op.base_address[i].virt)
            .collect_vec()
            .try_into()
            .unwrap();
        row.hx_virt = hx_virt.map(F::from_canonical_usize);
        row.w_start_virt = F::from_canonical_usize(op.base_address[8].virt);
        row.w_start_segment = F::from_canonical_usize(op.base_address[8].segment);
        row.w_start_context = F::from_canonical_usize(op.base_address[8].context);
        row.hx = op
            .input
            .iter()
            .map(|&x| F::from_canonical_u8(x))
            .collect::<Vec<F>>()
            .try_into()
            .unwrap();

        let h_x_t_minus_1 = op
            .input
            .chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();

        let output_state = self.compress(h_x_t_minus_1, op.w_i_s);

        let output_state_bytes = output_state
            .iter()
            .flat_map(|&x| x.to_le_bytes())
            .collect_vec();
        row.output_state = output_state_bytes
            .into_iter()
            .map(F::from_canonical_u8)
            .collect_vec()
            .try_into()
            .unwrap();

        for i in 0..8 {
            let _ = row.output_hx[i].generate_trace(
                h_x_t_minus_1[i].to_le_bytes(),
                output_state[i].to_le_bytes(),
            );
        }

        row
    }

    fn compress(&self, input_state: [u32; 8], w_i: Vec<[u8; 4]>) -> [u32; 8] {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = input_state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let w_i = u32::from_le_bytes(w_i[i]);

            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(crate::sha_compress_sponge::constants::SHA_COMPRESS_K[i])
                .wrapping_add(w_i);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        [a, b, c, d, e, f, g, h]
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for ShaCompressSpongeStark<F, D> {
    type EvaluationFrame<FE, P, const D2: usize>
        = StarkFrame<P, NUM_SHA_COMPRESS_SPONGE_COLUMNS>
    where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>;

    type EvaluationFrameTarget = StarkFrame<ExtensionTarget<D>, NUM_SHA_COMPRESS_SPONGE_COLUMNS>;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: &Self::EvaluationFrame<FE, P, D2>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        let local_values: &[P; NUM_SHA_COMPRESS_SPONGE_COLUMNS] =
            vars.get_local_values().try_into().unwrap();
        let local_values: &ShaCompressSpongeColumnsView<P> = local_values.borrow();

        // check the filter
        let is_normal_round = local_values.is_normal_round;
        yield_constr.constraint(is_normal_round * (is_normal_round - P::ONES));

        // if not the padding row, the hx address must be a sequence of numbers spaced 4 units apart

        for i in 0..7 {
            yield_constr.constraint(
                is_normal_round
                    * (local_values.hx_virt[i + 1]
                        - local_values.hx_virt[i]
                        - FE::from_canonical_u8(4)),
            );
        }

        // wrapping add constraints
        for i in 0..8 {
            wrapping_add_2_packed_constraints(
                local_values.hx[get_input_range_4(i)].try_into().unwrap(),
                local_values.output_state[get_input_range_4(i)]
                    .try_into()
                    .unwrap(),
                &local_values.output_hx[i],
            )
            .into_iter()
            .for_each(|c| yield_constr.constraint(c));
        }
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: &Self::EvaluationFrameTarget,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        let local_values: &[ExtensionTarget<D>; NUM_SHA_COMPRESS_SPONGE_COLUMNS] =
            vars.get_local_values().try_into().unwrap();
        let local_values: &ShaCompressSpongeColumnsView<ExtensionTarget<D>> = local_values.borrow();

        let four_ext = builder.constant_extension(F::Extension::from_canonical_u8(4));

        // check the filter
        let is_normal_round = local_values.is_normal_round;
        let constraint =
            builder.mul_sub_extension(is_normal_round, is_normal_round, is_normal_round);
        yield_constr.constraint(builder, constraint);

        // if not the padding row, the hx address must be a sequence of numbers spaced 4 units apart
        for i in 0..7 {
            let increment =
                builder.sub_extension(local_values.hx_virt[i + 1], local_values.hx_virt[i]);
            let address_increment = builder.sub_extension(increment, four_ext);
            let constraint = builder.mul_extension(is_normal_round, address_increment);
            yield_constr.constraint(builder, constraint);
        }

        // wrapping add constraints
        for i in 0..8 {
            wrapping_add_2_ext_circuit_constraints(
                builder,
                local_values.hx[get_input_range_4(i)].try_into().unwrap(),
                local_values.output_state[get_input_range_4(i)]
                    .try_into()
                    .unwrap(),
                &local_values.output_hx[i],
            )
            .into_iter()
            .for_each(|c| yield_constr.constraint(builder, c));
        }
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
    use crate::sha_compress_sponge::columns::ShaCompressSpongeColumnsView;
    use crate::sha_compress_sponge::sha_compress_sponge_stark::{
        ShaCompressSpongeOp, ShaCompressSpongeStark,
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
    use rand::Rng;
    use std::borrow::Borrow;

    const W: [u32; 64] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 34013193, 67559435, 1711661200,
        3020350282, 1447362251, 3118632270, 4004188394, 690615167, 6070360, 1105370215, 2385558114,
        2348232513, 507799627, 2098764358, 5845374, 823657968, 2969863067, 3903496557, 4274682881,
        2059629362, 1849247231, 2656047431, 835162919, 2096647516, 2259195856, 1779072524,
        3152121987, 4210324067, 1557957044, 376930560, 982142628, 3926566666, 4164334963,
        789545383, 1028256580, 2867933222, 3843938318, 1135234440, 390334875, 2025924737,
        3318322046, 3436065867, 652746999, 4261492214, 2543173532, 3334668051, 3166416553,
        634956631,
    ];

    pub const H256_256: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    #[test]
    fn test_generation() -> Result<(), String> {
        const D: usize = 2;
        type F = GoldilocksField;

        type S = ShaCompressSpongeStark<F, D>;

        let stark = S::default();
        let hx_addresses: Vec<MemoryAddress> = (0..32)
            .step_by(4)
            .map(|i| MemoryAddress {
                context: 0,
                segment: 0,
                virt: i,
            })
            .collect();

        let w_addresses: Vec<MemoryAddress> = (32..288)
            .step_by(4)
            .map(|i| MemoryAddress {
                context: 0,
                segment: 0,
                virt: i,
            })
            .collect();
        let mut input = H256_256
            .iter()
            .flat_map(|x| (*x).to_le_bytes())
            .collect::<Vec<_>>();

        let w_i_s = W.iter().map(|x| x.to_le_bytes()).collect::<Vec<_>>();

        let op = ShaCompressSpongeOp {
            base_address: hx_addresses
                .iter()
                .chain([w_addresses[0]].iter())
                .cloned()
                .collect(),
            // i: 0,
            timestamp: 0,
            // input_states: input_state,
            input,
            w_i_s,
        };

        let row = stark.generate_rows_for_op(op);
        let local_values: &ShaCompressSpongeColumnsView<F> = row.borrow();

        assert_eq!(
            local_values.output_hx[0].value,
            3592665057_u32
                .to_le_bytes()
                .map(|x| F::from_canonical_u8(x))
        );
        assert_eq!(
            local_values.output_hx[1].value,
            2164530888_u32
                .to_le_bytes()
                .map(|x| F::from_canonical_u8(x))
        );
        assert_eq!(
            local_values.output_hx[2].value,
            1223339564_u32
                .to_le_bytes()
                .map(|x| F::from_canonical_u8(x))
        );
        assert_eq!(
            local_values.output_hx[3].value,
            3041196771_u32
                .to_le_bytes()
                .map(|x| F::from_canonical_u8(x))
        );
        assert_eq!(
            local_values.output_hx[4].value,
            2006723467_u32
                .to_le_bytes()
                .map(|x| F::from_canonical_u8(x))
        );
        assert_eq!(
            local_values.output_hx[5].value,
            2963045520_u32
                .to_le_bytes()
                .map(|x| F::from_canonical_u8(x))
        );
        assert_eq!(
            local_values.output_hx[6].value,
            3851824201_u32
                .to_le_bytes()
                .map(|x| F::from_canonical_u8(x))
        );
        assert_eq!(
            local_values.output_hx[7].value,
            3453903005_u32
                .to_le_bytes()
                .map(|x| F::from_canonical_u8(x))
        );
        Ok(())
    }

    #[test]
    fn test_stark_circuit() -> anyhow::Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = ShaCompressSpongeStark<F, D>;

        let stark = S::default();
        test_stark_circuit_constraints::<F, C, S, D>(stark)
    }

    #[test]
    fn test_stark_degree() -> anyhow::Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = ShaCompressSpongeStark<F, D>;

        let stark = S {
            f: Default::default(),
        };
        test_stark_low_degree(stark)
    }

    fn get_random_input() -> ShaCompressSpongeOp {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = ShaCompressSpongeStark<F, D>;
        let stark = S::default();

        let mut rng = rand::thread_rng();
        let hx_start_virt: u32 = rng.gen();
        let hx_addresses: Vec<MemoryAddress> = (hx_start_virt..hx_start_virt + 32)
            .step_by(4)
            .map(|i| MemoryAddress {
                context: 0,
                segment: 0,
                virt: i as usize,
            })
            .collect();

        let w_start_virt: u32 = rng.gen();
        let w_start_address = MemoryAddress {
            context: 0,
            segment: 0,
            virt: w_start_virt as usize,
        };

        let mut rng = rand::thread_rng();
        let hx: Vec<u32> = (0..8).map(|_| rng.gen()).collect();
        let input = hx.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<_>>();
        let w_i = (0..64).map(|_| rng.gen()).collect::<Vec<u32>>();
        let w_i_s = w_i.iter().map(|x| x.to_le_bytes()).collect::<Vec<_>>();
        let op = ShaCompressSpongeOp {
            base_address: hx_addresses
                .iter()
                .chain([w_start_address].iter())
                .cloned()
                .collect(),
            // i,
            timestamp: 0,
            // input_states: input_state,
            input,
            w_i_s,
        };
        op
    }
    #[test]
    fn sha_extend_sponge_benchmark() -> anyhow::Result<()> {
        const NUM_INPUTS: usize = 50;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = ShaCompressSpongeStark<F, D>;

        let stark = S::default();
        let config = StarkConfig::standard_fast_config();

        init_logger();

        let input = (0..NUM_INPUTS).map(|_| get_random_input()).collect();
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
