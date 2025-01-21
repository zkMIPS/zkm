use std::marker::PhantomData;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::evaluation_frame::StarkFrame;
use crate::sha_compress::columns::{ShaCompressColumnsView, NUM_SHA_COMPRESS_COLUMNS};
use crate::sha_compress::constants::SHA_COMPRESS_K;
use crate::stark::Stark;
use crate::util::trace_rows_to_poly_values;

pub const NUM_ROUND_CONSTANTS: usize = 64;

pub const NUM_INPUTS: usize = 72; // 8 + 64

#[derive(Copy, Clone, Default)]
pub struct ShaCompressStark<F, const D: usize> {
    pub(crate) f: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> ShaCompressStark<F, D> {
    pub(crate) fn generate_trace(
        &self,
        inputs: Vec<([u32; NUM_INPUTS], usize)>,
        min_rows: usize,
    ) -> Vec<PolynomialValues<F>> {
        // Generate the witness row-wise
        let trace_rows = self.generate_trace_rows(inputs, min_rows);
        trace_rows_to_poly_values(trace_rows)
    }

    fn generate_trace_rows(
        &self,
        inputs_and_timestamps: Vec<([u32; NUM_INPUTS], usize)>,
        min_rows: usize,
    ) -> Vec<[F; NUM_SHA_COMPRESS_COLUMNS]> {
        let num_rows = (inputs_and_timestamps.len() * NUM_ROUND_CONSTANTS)
            .max(min_rows)
            .next_power_of_two();

        let mut rows = Vec::with_capacity(num_rows);
        for input_and_timestamp in inputs_and_timestamps.iter() {
            let rows_for_compress = self.generate_trace_rows_for_compress(*input_and_timestamp);
            rows.extend(rows_for_compress);
        }

        while rows.len() < num_rows {
            rows.push([F::ZERO; NUM_SHA_COMPRESS_COLUMNS]);
        }
        rows
    }

    fn generate_trace_rows_for_compress(
        &self,
        input_and_timestamp: ([u32; NUM_INPUTS], usize),
    ) -> Vec<[F; NUM_SHA_COMPRESS_COLUMNS]> {

        let mut rows = vec![ShaCompressColumnsView::default(); NUM_ROUND_CONSTANTS];

        let timestamp = input_and_timestamp.1;
        let inputs = input_and_timestamp.0;

        // set the first row


        for round in 0..NUM_ROUND_CONSTANTS {
            rows[round].timestamp = F::from_canonical_usize(timestamp);
            rows[round].i = F::from_canonical_usize(round);
            rows[round].is_final = F::ZERO;
            if round == NUM_ROUND_CONSTANTS - 1 {
                rows[round].is_final = F::ONE;
            }
        }

        // Populate the round input for the first round.
        [rows[0].a, rows[0].b, rows[0].c, rows[0].d,
            rows[0].e, rows[0].f, rows[0].g, rows[0].h] = inputs[0..8]
            .iter()
            .map(|&x| F::from_canonical_u32(x))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();


        rows[0].w = inputs[8..inputs.len()].iter()
            .map(|&x| F::from_canonical_u32(x))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        self.generate_trace_row_for_round(&mut rows[0], 0);
        for round in 1..NUM_ROUND_CONSTANTS{
            self.copy_output_to_input(&mut rows, round);
            self.generate_trace_row_for_round(&mut rows[round], round);
        }


        rows.into_iter().map(|row| row.into()).collect::<Vec<_>>()
    }

    fn generate_trace_row_for_round(&self, row: &mut ShaCompressColumnsView<F>, round: usize) {
        row.round_i_filter = [F::ZERO; NUM_ROUND_CONSTANTS];
        row.round_i_filter[round] = F::ONE;

        row.k_i = F::from_canonical_u32(SHA_COMPRESS_K[round]);
        row.w_i = row.w[round];

        let e = row.e.to_canonical_u64() as u32;
        let g = row.g.to_canonical_u64() as u32;
        let e_rr_6 = e.rotate_right(6);
        let e_rr_11 = e.rotate_right(11);
        let s_1_inter = e_rr_6 ^ e_rr_11;
        let e_rr_25 = e.rotate_right(25);
        let s_1 = s_1_inter ^ e_rr_25;

        [row.e_rr_6, row.e_rr_11, row.e_rr_25, row.s_1_inter, row.s_1]
            = [e_rr_6, e_rr_11, e_rr_25, s_1_inter, s_1].map(F::from_canonical_u32);

        let e_and_f = e & (row.f.to_canonical_u64() as u32);
        let e_not = !e;
        let e_not_and_g = e_not & g;
        let ch = e_and_f ^  e_not_and_g;
        let temp1 = (row.h.to_canonical_u64() as u32).wrapping_add(s_1)
            .wrapping_add(ch)
            .wrapping_add(row.k_i.to_canonical_u64() as u32)
            .wrapping_add(row.w_i.to_canonical_u64() as u32);

        [row.e_and_f, row.e_not, row.e_not_and_g, row.ch, row.temp1]
            = [e_and_f, e_not, e_not_and_g, ch, temp1].map(F::from_canonical_u32);

        let a = row.a.to_canonical_u64() as u32;
        let a_rr_2 = a.rotate_right(2);
        let a_rr_13 = a.rotate_right(13);
        let a_rr_22 = a.rotate_right(22);
        let s_0_inter = a_rr_2 ^ a_rr_13;
        let s_0 = s_0_inter ^ a_rr_22;

        [row.a_rr_22, row.a_rr_13, row.a_rr_2, row.s_0_inter, row.s_0]
            = [a_rr_22, a_rr_13, a_rr_2, s_0_inter, s_0].map(F::from_canonical_u32);

        let a_and_b = a & (row.b.to_canonical_u64() as u32);
        let a_and_c = a & (row.c.to_canonical_u64() as u32);
        let b_and_c = (row.b.to_canonical_u64() as u32) & (row.c.to_canonical_u64() as u32);
        let maj_inter = a_and_b ^ a_and_c;
        let maj = maj_inter ^ b_and_c;
        let temp2 = s_0.wrapping_add(maj);

        let new_e = (row.d.to_canonical_u64() as u32).wrapping_add(temp1);
        let new_a = temp1.wrapping_add(temp2);
        [row.a_and_b, row.a_and_c, row.b_and_c, row.maj_inter, row.maj, row.temp2]
            = [a_and_b, a_and_c, b_and_c, maj_inter, maj, temp2].map(F::from_canonical_u32);

        row.new_h = row.g;
        row.new_g = row.f;
        row.new_f = row.e;
        row.new_e = F::from_canonical_u32(new_e);
        row.new_d = row.c;
        row.new_c = row.b;
        row.new_b = row.a;
        row.new_a = F::from_canonical_u32(new_a);
    }

    fn copy_output_to_input(&self, rows: &mut Vec<ShaCompressColumnsView<F>>, round: usize) {
        rows[round].a = rows[round-1].new_a;
        rows[round].b = rows[round-1].new_b;
        rows[round].c = rows[round-1].new_c;
        rows[round].d = rows[round-1].new_d;
        rows[round].e = rows[round-1].new_e;
        rows[round].f = rows[round-1].new_f;
        rows[round].g = rows[round-1].new_g;
        rows[round].h = rows[round-1].new_h;
        rows[round].w = rows[round-1].w;
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
    use plonky2::field::types::Field;
    use crate::sha_compress::columns::ShaCompressColumnsView;
    use crate::sha_compress::sha_compress_stark::ShaCompressStark;

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
    fn test_generation() -> Result<(), String>{

        const D: usize = 2;
        type F = GoldilocksField;
        type S = ShaCompressStark<F, D>;

        let w = W;
        let h = H256_256;

        let mut input = vec![];
        input.extend(h);input.extend(w);


        let stark = S::default();
        let rows = stark.generate_trace_rows_for_compress((input.try_into().unwrap(), 0));

        assert_eq!(rows.len(), 64);


        // check first row
        let first_row: ShaCompressColumnsView<F> = rows[0].into();
        assert_eq!(first_row.a, F::from_canonical_u32(0x6a09e667));
        assert_eq!(first_row.new_a, F::from_canonical_u32(4228417613));

        // output
        let last_row: ShaCompressColumnsView<F> = rows[63].into();
        assert_eq!(last_row.is_final, F::ONE);

        assert_eq!(last_row.new_a, F::from_canonical_u32(1813631354));
        assert_eq!(last_row.new_b, F::from_canonical_u32(3315363907));
        assert_eq!(last_row.new_c, F::from_canonical_u32(209435322));
        assert_eq!(last_row.new_d, F::from_canonical_u32(267716009));
        assert_eq!(last_row.new_e, F::from_canonical_u32(646830348));
        assert_eq!(last_row.new_f, F::from_canonical_u32(362222596));
        assert_eq!(last_row.new_g, F::from_canonical_u32(3323089566));
        assert_eq!(last_row.new_h, F::from_canonical_u32(1912443780));
        Ok(())
    }
}