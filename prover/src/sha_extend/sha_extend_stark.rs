use std::marker::PhantomData;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::evaluation_frame::StarkFrame;
use crate::sha_extend::columns::{ShaExtendColumnsView, NUM_SHA_EXTEND_COLUMNS};
use crate::stark::Stark;
use crate::util::trace_rows_to_poly_values;

const NUM_ROUND_CONSTANTS: usize = 48;
const NUM_INPUTS: usize = 4; // w_i_minus_15, w_i_minus_2, w_i_minus_16, w_i_minus_7

#[derive(Copy, Clone, Default)]
pub struct ShaExtendStark<F, const D: usize> {
    pub(crate) f: PhantomData<F>,
}


impl<F: RichField + Extendable<D>, const D: usize> ShaExtendStark<F, D> {
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
    ) -> Vec<[F; NUM_SHA_EXTEND_COLUMNS]> {
        let num_rows = inputs_and_timestamps.len()
            .max(min_rows).next_power_of_two();

        let mut rows = Vec::with_capacity(num_rows);
        for input_and_timestamp in inputs_and_timestamps.iter() {
            let rows_for_extend = self.generate_trace_rows_for_extend(*input_and_timestamp);
            rows.push(rows_for_extend.into());
        }

        // padding
        while rows.len() < num_rows {
            rows.push([F::ZERO; NUM_SHA_EXTEND_COLUMNS]);
        }

        rows
    }

    fn generate_trace_rows_for_extend(
        &self,
        input_and_timestamp: ([u32; NUM_INPUTS], usize),
    ) -> ShaExtendColumnsView<F> {
        let mut row = ShaExtendColumnsView::default();

        row.timestamp = F::from_canonical_usize(input_and_timestamp.1);
        [row.w_i_minus_15, row.w_i_minus_2, row.w_i_minus_16, row.w_i_minus_7]
            = input_and_timestamp.0.map(F::from_canonical_u32);

        self.generate_trace_row_for_round(&mut row);
        row
    }

    fn generate_trace_row_for_round(&self, row: &mut ShaExtendColumnsView<F>) {
        let w_i_minus_15_u32 = row.w_i_minus_15.to_canonical_u64() as u32;
        row.w_i_minus_15_rr_7 = F::from_canonical_u32(w_i_minus_15_u32.rotate_right(7));
        row.w_i_minus_15_rr_18 = F::from_canonical_u32(w_i_minus_15_u32.rotate_right(18));
        row.w_i_minus_15_rs_3 = F::from_canonical_u32(w_i_minus_15_u32 >> 3);

        // (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18)

        row.s_0_inter = F::from_canonical_u32(w_i_minus_15_u32.rotate_right(7) ^ w_i_minus_15_u32.rotate_right(18));
        // s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
        row.s_0 = F::from_canonical_u32((row.s_0_inter.to_canonical_u64() as u32) ^ (w_i_minus_15_u32 >> 3));

        let w_i_minus_2_u32 = row.w_i_minus_2.to_canonical_u64() as u32;
        row.w_i_minus_2_rr_17 = F::from_canonical_u32(w_i_minus_2_u32.rotate_right(17));
        row.w_i_minus_2_rr_19 = F::from_canonical_u32(w_i_minus_2_u32.rotate_right(19));
        row.w_i_minus_2_rs_10 = F::from_canonical_u32(w_i_minus_2_u32 >> 10);

        // (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19)
        row.s_1_inter = F::from_canonical_u32(w_i_minus_2_u32.rotate_right(17) ^  w_i_minus_2_u32.rotate_right(19));
        // s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
        row.s_1 = F::from_canonical_u32((row.s_1_inter.to_canonical_u64() as u32) ^ (w_i_minus_2_u32 >> 10));

        // w_i = w[i-16] + s0 + w[i-7] + s1.
        row.w_i = F::from_canonical_u32((row.w_i_minus_16.to_canonical_u64() as u32)
            .wrapping_add(row.s_0.to_canonical_u64() as u32)
            .wrapping_add(row.w_i_minus_7.to_canonical_u64() as u32)
            .wrapping_add(row.s_1.to_canonical_u64() as u32));
    }
}


impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for ShaExtendStark<F, D> {
    type EvaluationFrame<FE, P, const D2: usize>
    = StarkFrame<P, NUM_SHA_EXTEND_COLUMNS>
    where
        FE: FieldExtension<D2, BaseField=F>,
        P: PackedField<Scalar=FE>;

    type EvaluationFrameTarget =  StarkFrame<ExtensionTarget<D>, NUM_SHA_EXTEND_COLUMNS>;

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
        yield_constr: &mut RecursiveConstraintConsumer<F, D>) {
        todo!()
    }

    fn constraint_degree(&self) -> usize {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::{Field};
    use crate::sha_extend::sha_extend_stark::ShaExtendStark;

    #[test]
    fn test_generation() -> Result<(), String> {
        const D: usize = 2;
        type F = GoldilocksField;

        type S = ShaExtendStark<F, D>;

        let input = ([1, 2, 3, 4 as u32], 0);

        let stark = S::default();
        let row = stark.generate_trace_rows_for_extend(input);


        // extend phase
        let w_i_minus_15 = input.0[0];
        let s0 = w_i_minus_15.rotate_right(7) ^ w_i_minus_15.rotate_right(18) ^ (w_i_minus_15 >> 3);

        let w_i_minus_2 = input.0[1];
        // Compute `s1`.
        let s1 = w_i_minus_2.rotate_right(17) ^ w_i_minus_2.rotate_right(19) ^ (w_i_minus_2 >> 10);
        let w_i_minus_16 = input.0[2];
        let w_i_minus_7 = input.0[3];
        // Compute `w_i`.
        let w_i = s1
            .wrapping_add(w_i_minus_16)
            .wrapping_add(s0)
            .wrapping_add(w_i_minus_7);
        // println!("w_i: {}", w_i);
        assert_eq!(row.w_i, F::from_canonical_u32(w_i));

        Ok(())
    }
}