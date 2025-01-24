use std::marker::PhantomData;
use std::borrow::Borrow;
use itertools::Itertools;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::evaluation_frame::{StarkEvaluationFrame, StarkFrame};
use crate::memory::segments::Segment;
use crate::sha_compress::logic::from_be_bits_to_u32;
use crate::sha_compress_sponge::columns::{ShaCompressSpongeColumnsView, NUM_SHA_COMPRESS_SPONGE_COLUMNS};
use crate::sha_compress_sponge::constants::{NUM_COMPRESS_ROWS, SHA_COMPRESS_K_BINARY};
use crate::sha_extend::logic::{from_u32_to_be_bits, get_input_range, wrapping_add, wrapping_add_ext_circuit_constraints, wrapping_add_packed_constraints};
use crate::sha_extend_sponge::sha_extend_sponge_stark::NUM_ROUNDS;
use crate::stark::Stark;
use crate::util::trace_rows_to_poly_values;
use crate::witness::memory::MemoryAddress;
use crate::witness::operation::SHA_COMPRESS_K;

#[derive(Clone, Debug)]
pub(crate) struct ShaCompressSpongeOp {
    /// The base address at which inputs are read.
    /// h[0],...,h[7], w[i].
    pub(crate) base_address: Vec<MemoryAddress>,

    /// The timestamp at which inputs are read.
    pub(crate) timestamp: usize,

    /// The input state
    pub(crate) input_state: Vec<u8>,

    /// The index of round
    pub(crate) i: usize,

    /// The input that was read.
    /// Values: h[0],..., h[7], w[i]  in big-endian order.
    pub(crate) input: Vec<u8>,
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

    fn generate_rows_for_op(
        &self,
        op: ShaCompressSpongeOp,
    ) -> ShaCompressSpongeColumnsView<F> {
        let mut row = ShaCompressSpongeColumnsView::default();

        row.timestamp = F::from_canonical_usize(op.timestamp);
        row.context = F::from_canonical_usize(op.base_address[0].context);
        row.segment = F::from_canonical_usize(op.base_address[Segment::Code as usize].segment);

        let hx_virt = (0..8)
            .map(|i| op.base_address[i].virt)
            .collect_vec();
        let hx_virt: [usize; 8] = hx_virt.try_into().unwrap();
        row.hx_virt = hx_virt.map(F::from_canonical_usize);

        let w_virt =  op.base_address[8].virt;
        row.w_virt = F::from_canonical_usize(w_virt);

        row.round = [F::ZEROS; 64];
        row.round[op.i] = F::ONE;
        row.k_i = SHA_COMPRESS_K_BINARY[op.i].map(|k| F::from_canonical_u8(k));
        row.w_i = op.input[256..288].iter().map(|&x| F::from_canonical_u8(x)).collect::<Vec<F>>().try_into().unwrap();
        row.hx = op.input[..256].iter().map(|&x| F::from_canonical_u8(x)).collect::<Vec<F>>().try_into().unwrap();
        row.input_state = op.input_state.iter().map(|&x| F::from_canonical_u8(x)).collect::<Vec<F>>().try_into().unwrap();

        let output = self.compress(&op.input_state, &op.input[256..288], op.i);
        row.output_state = output.map(F::from_canonical_u8);

        // We use the result if only we are at the final round.
        // The computation in other rounds are ensure the constraint degree
        // not to be exceeded 3.
        for i in 0..8 {

            let (output_hx, carry) = wrapping_add::<F, D, 32>(
                row.hx[get_input_range(i)].try_into().unwrap(),
                row.output_state[get_input_range(i)].try_into().unwrap()
            );

            row.output_hx[get_input_range(i)].copy_from_slice(&output_hx[0..]);
            row.carry[get_input_range(i)].copy_from_slice(&carry[0..]);
        }

        row
    }

    fn compress(&self, input_state: &[u8], w_i: &[u8], round: usize) -> [u8; 256] {
        let values: Vec<[u8; 32]> = input_state.chunks(32).map(|chunk| chunk.try_into().unwrap()).collect();
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = values.into_iter().map(
            |x| from_be_bits_to_u32(x)
        ).collect::<Vec<_>>().try_into().unwrap();
        let w_i = from_be_bits_to_u32(w_i.try_into().unwrap());

        let t1 = h.wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
            .wrapping_add((e & f) ^ ((!e) & g)).wrapping_add(SHA_COMPRESS_K[round]).wrapping_add(w_i);
        let t2 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
            .wrapping_add((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);

        let mut result = vec![];
        result.extend(from_u32_to_be_bits(a));
        result.extend(from_u32_to_be_bits(b));
        result.extend(from_u32_to_be_bits(c));
        result.extend(from_u32_to_be_bits(d));
        result.extend(from_u32_to_be_bits(e));
        result.extend(from_u32_to_be_bits(f));
        result.extend(from_u32_to_be_bits(g));
        result.extend(from_u32_to_be_bits(h));

        result.try_into().unwrap()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for ShaCompressSpongeStark<F, D> {
    type EvaluationFrame<FE, P, const D2: usize>
    = StarkFrame<P, NUM_SHA_COMPRESS_SPONGE_COLUMNS>
    where
        FE: FieldExtension<D2, BaseField=F>,
        P: PackedField<Scalar=FE>;

    type EvaluationFrameTarget = StarkFrame<ExtensionTarget<D>, NUM_SHA_COMPRESS_SPONGE_COLUMNS>;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: &Self::EvaluationFrame<FE, P, D2>,
        yield_constr: &mut ConstraintConsumer<P>
    ) where
        FE: FieldExtension<D2, BaseField=F>,
        P: PackedField<Scalar=FE>
    {

        let local_values: &[P; NUM_SHA_COMPRESS_SPONGE_COLUMNS] =
            vars.get_local_values().try_into().unwrap();
        let local_values: &ShaCompressSpongeColumnsView<P> = local_values.borrow();

        let next_values: &[P; NUM_SHA_COMPRESS_SPONGE_COLUMNS] =
            vars.get_next_values().try_into().unwrap();
        let next_values: &ShaCompressSpongeColumnsView<P> = next_values.borrow();

        // check the bit values are zero or one in input
        for i in 0..256 {
            yield_constr.constraint(local_values.hx[i] * (local_values.hx[i] - P::ONES));
            yield_constr.constraint(local_values.input_state[i] * (local_values.input_state[i] - P::ONES));
        }
        for i in 0..32 {
            yield_constr.constraint(local_values.w_i[i] * (local_values.w_i[i] - P::ONES));
            yield_constr.constraint(local_values.k_i[i] * (local_values.k_i[i] - P::ONES));
        }

        // check the bit values are zero or one in output
        for i in 0..256 {
            yield_constr.constraint(local_values.output_state[i] * (local_values.output_state[i] - P::ONES));
            yield_constr.constraint(local_values.output_hx[i] * (local_values.output_hx[i] - P::ONES));
            yield_constr.constraint(local_values.carry[i] * (local_values.carry[i] - P::ONES));
        }

        // // check the round
        for i in 0..NUM_ROUNDS {
            yield_constr.constraint(local_values.round[i] * (local_values.round[i] - P::ONES));
        }

        // check the filter
        let is_final = local_values.round[NUM_COMPRESS_ROWS - 1];
        yield_constr.constraint(is_final * (is_final - P::ONES));
        let not_final = P::ONES - is_final;

        let sum_round_flags = (0..NUM_COMPRESS_ROWS)
            .map(|i| local_values.round[i])
            .sum::<P>();
        yield_constr.constraint(sum_round_flags * (sum_round_flags - P::ONES));


        // If this is not the final step or a padding row:

        // the local and next timestamps must match.
        yield_constr.constraint(
            sum_round_flags * not_final * (next_values.timestamp - local_values.timestamp),
        );

        // the local and next context hx_virt must match
        for i in 0..8 {
            yield_constr.constraint(
                sum_round_flags * not_final * (next_values.hx_virt[i] - local_values.hx_virt[i]),
            );
        }

        // the output state of local row must be the input state of next row
        for i in 0..256 {
            yield_constr.constraint(
                sum_round_flags * not_final * (next_values.input_state[i] - local_values.output_state[i])
            );
        }

        // the address of w_i must be increased by 4
        yield_constr.constraint(
            sum_round_flags * not_final * (next_values.w_virt - local_values.w_virt - FE::from_canonical_u8(4)),
        );


        // if not the padding row, the hx address must be a sequence of numbers spaced 4 units apart

        for i in 0..7 {
            yield_constr.constraint(
                sum_round_flags * (local_values.hx_virt[i + 1] - local_values.hx_virt[i] - FE::from_canonical_u8(4)),
            );
        }

        // check the validation of key[i]

        for i in 0..32 {
            let mut bit_i = P::ZEROS;
            for j in 0..64 {
                bit_i = bit_i + local_values.round[j] * FE::from_canonical_u8(SHA_COMPRESS_K_BINARY[j][i]);
            }
            yield_constr.constraint(local_values.k_i[i] - bit_i);
        }

        // wrapping add constraints

        for i in 0..8 {

            wrapping_add_packed_constraints::<P, 32>(
                local_values.hx[get_input_range(i)].try_into().unwrap(),
                local_values.output_state[get_input_range(i)].try_into().unwrap(),
                local_values.carry[get_input_range(i)].try_into().unwrap(),
                local_values.output_hx[get_input_range(i)].try_into().unwrap(),
            ).into_iter().for_each(|c| yield_constr.constraint(c));

        }

    }

    fn eval_ext_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: &Self::EvaluationFrameTarget,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>
    ) {
        let local_values: &[ExtensionTarget<D>; NUM_SHA_COMPRESS_SPONGE_COLUMNS] =
            vars.get_local_values().try_into().unwrap();
        let local_values: &ShaCompressSpongeColumnsView<ExtensionTarget<D>> = local_values.borrow();

        let next_values: &[ExtensionTarget<D>; NUM_SHA_COMPRESS_SPONGE_COLUMNS] =
            vars.get_next_values().try_into().unwrap();
        let next_values: &ShaCompressSpongeColumnsView<ExtensionTarget<D>> = next_values.borrow();

        let one_ext = builder.one_extension();
        let four_ext = builder.constant_extension(F::Extension::from_canonical_u8(4));

        // check the bit values are zero or one in input
        for i in 0..256 {
            let constraint = builder.mul_sub_extension(
                local_values.hx[i], local_values.hx[i], local_values.hx[i]);
            yield_constr.constraint(builder, constraint);

            let constraint = builder.mul_sub_extension(
                local_values.input_state[i], local_values.input_state[i], local_values.input_state[i]);
            yield_constr.constraint(builder, constraint);
        }
        for i in 0..32 {
            let constraint = builder.mul_sub_extension(
                local_values.w_i[i], local_values.w_i[i], local_values.w_i[i]);
            yield_constr.constraint(builder, constraint);

            let constraint = builder.mul_sub_extension(
                local_values.k_i[i], local_values.k_i[i], local_values.k_i[i]);
            yield_constr.constraint(builder, constraint);

        }

        // check the bit values are zero or one in output
        for i in 0..256 {

            let constraint = builder.mul_sub_extension(
                local_values.output_state[i], local_values.output_state[i], local_values.output_state[i]);
            yield_constr.constraint(builder, constraint);

            let constraint = builder.mul_sub_extension(
                local_values.output_hx[i], local_values.output_hx[i], local_values.output_hx[i]);
            yield_constr.constraint(builder, constraint);

            let constraint = builder.mul_sub_extension(
                local_values.carry[i], local_values.carry[i], local_values.carry[i]);
            yield_constr.constraint(builder, constraint);
        }

        // check the round
        for i in 0..NUM_ROUNDS {
            let constraint = builder.mul_sub_extension(
                local_values.round[i], local_values.round[i], local_values.round[i]);
            yield_constr.constraint(builder, constraint);
        }

        // check the filter
        let is_final = local_values.round[NUM_COMPRESS_ROWS - 1];
        let constraint = builder.mul_sub_extension(is_final, is_final, is_final);
        yield_constr.constraint(builder, constraint);
        let not_final = builder.sub_extension(one_ext, is_final);

        let sum_round_flags =
            builder.add_many_extension((0..NUM_COMPRESS_ROWS).map(|i| local_values.round[i]));

        let constraint = builder.mul_sub_extension(
            sum_round_flags, sum_round_flags, sum_round_flags
        );
        yield_constr.constraint(builder, constraint);


        // If this is not the final step or a padding row:

        // the local and next timestamps must match.

        let diff = builder.sub_extension(next_values.timestamp, local_values.timestamp);
        let constraint = builder.mul_many_extension([sum_round_flags, not_final, diff]);
        yield_constr.constraint(builder, constraint);

        // the local and next context hx_virt must match
        for i in 0..8 {
            let diff = builder.sub_extension(next_values.hx_virt[i], local_values.hx_virt[i]);
            let constraint = builder.mul_many_extension([sum_round_flags, not_final, diff]);
            yield_constr.constraint(builder, constraint);
        }

        // the output state of local row must be the input state of next row
        for i in 0..256 {
            let diff = builder.sub_extension(next_values.input_state[i], local_values.output_state[i]);
            let constraint = builder.mul_many_extension([sum_round_flags, not_final, diff]);
            yield_constr.constraint(builder, constraint);
        }

        // the address of w_i must be increased by 4
        let increment = builder.sub_extension(next_values.w_virt, local_values.w_virt);
        let address_increment = builder.sub_extension(increment, four_ext);
        let constraint = builder.mul_many_extension(
            [sum_round_flags, not_final, address_increment]
        );
        yield_constr.constraint(builder, constraint);


        // if not the padding row, the hx address must be a sequence of numbers spaced 4 units apart

        for i in 0..7 {
            let increment = builder.sub_extension(local_values.hx_virt[i + 1], local_values.hx_virt[i]);
            let address_increment = builder.sub_extension(increment, four_ext);
            let constraint = builder.mul_extension(
                sum_round_flags, address_increment
            );
            yield_constr.constraint(builder, constraint);
        }

        // check the validation of key[i]

        for i in 0..32 {

            let bit_i_comp: Vec<_> =  (0..64).map(|j| {
                let k_j_i = builder.constant_extension(F::Extension::from_canonical_u8(SHA_COMPRESS_K_BINARY[j][i]));
                builder.mul_extension(local_values.round[j], k_j_i)
            }).collect();
            let bit_i = builder.add_many_extension(bit_i_comp);
            let constraint = builder.sub_extension(local_values.k_i[i], bit_i);
            yield_constr.constraint(builder, constraint);
        }

        // wrapping add constraints

        for i in 0..8 {
            wrapping_add_ext_circuit_constraints::<F, D, 32>(
                builder,
                local_values.hx[get_input_range(i)].try_into().unwrap(),
                local_values.output_state[get_input_range(i)].try_into().unwrap(),
                local_values.carry[get_input_range(i)].try_into().unwrap(),
                local_values.output_hx[get_input_range(i)].try_into().unwrap(),
            ).into_iter().for_each(|c| yield_constr.constraint(builder, c));

        }
    }

    fn constraint_degree(&self) -> usize {
        3
    }
}


#[cfg(test)]
mod test {
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::{Field};
    use std::borrow::Borrow;
    use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
    use plonky2::field::polynomial::PolynomialValues;
    use plonky2::fri::oracle::PolynomialBatch;
    use plonky2::iop::challenger::Challenger;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::timed;
    use plonky2::util::timing::TimingTree;
    use crate::config::StarkConfig;
    use crate::cross_table_lookup::{Column, CtlData, CtlZData, Filter, GrandProductChallenge, GrandProductChallengeSet};
    use crate::prover::prove_single_table;
    use crate::sha_compress_sponge::columns::ShaCompressSpongeColumnsView;
    use crate::sha_compress_sponge::sha_compress_sponge_stark::{ShaCompressSpongeOp, ShaCompressSpongeStark};
    use crate::sha_extend::logic::{from_u32_to_be_bits, get_input_range};
    use crate::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};
    use crate::witness::memory::MemoryAddress;


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
    #[test]
    fn test_generation() -> Result<(), String> {
        const D: usize = 2;
        type F = GoldilocksField;

        type S = ShaCompressSpongeStark<F, D>;

        let stark = S::default();
        let hx_addresses: Vec<MemoryAddress> = (0..32).step_by(4).map(|i| {
            MemoryAddress {
                context: 0,
                segment: 0,
                virt: i,
            }
        }).collect();

        let w_addresses: Vec<MemoryAddress> = (32..288).step_by(4).map(|i| {
            MemoryAddress {
                context: 0,
                segment: 0,
                virt: i,
            }
        }).collect();
        let mut input = H256_256.iter().map(|x| from_u32_to_be_bits(*x)).flatten().collect::<Vec<_>>();
        input.extend(from_u32_to_be_bits(W[0]));
        let input_state = H256_256.iter().map(|x| from_u32_to_be_bits(*x)).flatten().collect::<Vec<_>>();
        let op = ShaCompressSpongeOp {
            base_address: hx_addresses.iter().chain([w_addresses[0]].iter()).cloned().collect(),
            i: 0,
            timestamp: 0,
            input_state,
            input,
        };
        let row = stark.generate_rows_for_op(op);
        let local_values: &ShaCompressSpongeColumnsView<F> = row.borrow();

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

        let mut input = H256_256.iter().map(|x| from_u32_to_be_bits(*x)).flatten().collect::<Vec<_>>();
        input.extend(from_u32_to_be_bits(W[63]));
        let input_state = H256_256.iter().map(|x| from_u32_to_be_bits(*x)).flatten().collect::<Vec<_>>();
        let op = ShaCompressSpongeOp {
            base_address: hx_addresses.iter().chain([w_addresses[0]].iter()).cloned().collect(),
            i: 63,
            timestamp: 0,
            input_state,
            input,
        };
        let row = stark.generate_rows_for_op(op);
        let local_values: &ShaCompressSpongeColumnsView<F> = row.borrow();


        assert_eq!(
            local_values.output_hx[get_input_range(0)],
            from_u32_to_be_bits(H256_256[0].wrapping_add(2781379838 as u32)).iter().map(|&x| F::from_canonical_u8(x)).collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_hx[get_input_range(1)],
            from_u32_to_be_bits(H256_256[1].wrapping_add(1779033703 as u32)).iter().map(|&x| F::from_canonical_u8(x)).collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_hx[get_input_range(2)],
            from_u32_to_be_bits(H256_256[2].wrapping_add(3144134277 as u32)).iter().map(|&x| F::from_canonical_u8(x)).collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_hx[get_input_range(3)],
            from_u32_to_be_bits(H256_256[3].wrapping_add(1013904242 as u32)).iter().map(|&x| F::from_canonical_u8(x)).collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_hx[get_input_range(4)],
            from_u32_to_be_bits(H256_256[4].wrapping_add(1116198739 as u32)).iter().map(|&x| F::from_canonical_u8(x)).collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_hx[get_input_range(5)],
            from_u32_to_be_bits(H256_256[5].wrapping_add(1359893119 as u32)).iter().map(|&x| F::from_canonical_u8(x)).collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_hx[get_input_range(6)],
            from_u32_to_be_bits(H256_256[6].wrapping_add(2600822924 as u32)).iter().map(|&x| F::from_canonical_u8(x)).collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_hx[get_input_range(7)],
            from_u32_to_be_bits(H256_256[7].wrapping_add(528734635 as u32)).iter().map(|&x| F::from_canonical_u8(x)).collect::<Vec<F>>()
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


    fn get_random_input() -> Vec<ShaCompressSpongeOp> {

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = ShaCompressSpongeStark<F, D>;
        let stark = S::default();

        let hx_addresses: Vec<MemoryAddress> = (0..32).step_by(4).map(|i| {
            MemoryAddress {
                context: 0,
                segment: 0,
                virt: i,
            }
        }).collect();

        let w_addresses: Vec<MemoryAddress> = (32..288).step_by(4).map(|i| {
            MemoryAddress {
                context: 0,
                segment: 0,
                virt: i,
            }
        }).collect();

        let mut res = vec![];
        let mut output_state = H256_256.iter().map(|x| from_u32_to_be_bits(*x)).flatten().collect::<Vec<_>>();
        for i in 0..64 {

            let mut input = H256_256.iter().map(|x| from_u32_to_be_bits(*x)).flatten().collect::<Vec<_>>();
            input.extend(from_u32_to_be_bits(W[i]));
            let input_state = output_state.clone();

            output_state = stark.compress(&input_state, &from_u32_to_be_bits(W[i]), i).to_vec();
            let op = ShaCompressSpongeOp {
                base_address: hx_addresses.iter().chain([w_addresses[i]].iter()).cloned().collect(),
                i: i,
                timestamp: 0,
                input_state,
                input,
            };

            res.push(op);
        }

        res

    }
    #[test]
    fn sha_extend_sponge_benchmark() -> anyhow::Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = ShaCompressSpongeStark<F, D>;
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