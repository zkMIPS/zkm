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
use crate::sha_extend::columns::get_input_range;
use crate::sha_extend::logic::{from_be_bits_to_u32, from_u32_to_be_bits};
use crate::sha_extend_sponge::columns::{ShaExtendSpongeColumnsView, NUM_SHA_EXTEND_SPONGE_COLUMNS};
use crate::stark::Stark;
use crate::util::trace_rows_to_poly_values;
use crate::witness::memory::MemoryAddress;

pub const NUM_ROUNDS: usize = 48;

pub(crate) struct  ShaExtendSpongeOp {
    /// The base address at which inputs are read
    pub(crate) base_address: Vec<MemoryAddress>,

    /// The timestamp at which inputs are read and output are written (same for both).
    pub(crate) timestamp: usize,

    /// The input that was read.
    /// Values: w_i_minus_15, w_i_minus_2, w_i_minus_16, w_i_minus_7 in big-endian order.
    pub(crate) input: Vec<u32>,

    /// The index of round
    pub(crate) i: u32,

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

    fn generate_rows_for_op(&self, op: ShaExtendSpongeOp) -> ShaExtendSpongeColumnsView<F>{
        let mut row = ShaExtendSpongeColumnsView::default();
        row.timestamp = F::from_canonical_usize(op.timestamp);
        row.round = [F::ZEROS; 48];
        row.round[op.i as usize] = F::ONE;

        row.context = F::from_canonical_usize(op.base_address[0].context);
        row.segment = F::from_canonical_usize(op.base_address[Segment::Code as usize].segment);
        let virt = (0..op.input.len() / 32)
            .map(|i| op.base_address[i].virt)
            .collect_vec();
        let virt: [usize; 4] = virt.try_into().unwrap();
        row.input_virt = virt.map(F::from_canonical_usize);
        row.output_virt = F::from_canonical_usize(op.output_address.virt);

        row.w_i_minus_15 = op.input[get_input_range(0)]
            .iter().map(|&x| F::from_canonical_u32(x)).collect::<Vec<_>>().try_into().unwrap();
        row.w_i_minus_2 = op.input[get_input_range(1)]
            .iter().map(|&x| F::from_canonical_u32(x)).collect::<Vec<_>>().try_into().unwrap();
        row.w_i_minus_16 = op.input[get_input_range(2)]
            .iter().map(|&x| F::from_canonical_u32(x)).collect::<Vec<_>>().try_into().unwrap();
        row.w_i_minus_7 = op.input[get_input_range(3)]
            .iter().map(|&x| F::from_canonical_u32(x)).collect::<Vec<_>>().try_into().unwrap();

        row.w_i = self.compute_w_i(&mut row);
        row
    }

    fn compute_w_i(&self, row: &mut ShaExtendSpongeColumnsView<F>) -> [F; 32] {
        let w_i_minus_15 = from_be_bits_to_u32(row.w_i_minus_15);
        let w_i_minus_2 = from_be_bits_to_u32(row.w_i_minus_2);
        let w_i_minus_16 = from_be_bits_to_u32(row.w_i_minus_16);
        let w_i_minus_7 = from_be_bits_to_u32(row.w_i_minus_7);
        let s0 = w_i_minus_15.rotate_right(7) ^ w_i_minus_15.rotate_right(18) ^ (w_i_minus_15 >> 3);
        let s1 = w_i_minus_2.rotate_right(17) ^ w_i_minus_2.rotate_right(19) ^ (w_i_minus_2 >> 10);
        let w_i_u32 = s1
            .wrapping_add(w_i_minus_16)
            .wrapping_add(s0)
            .wrapping_add(w_i_minus_7);

        let w_i_bin = from_u32_to_be_bits(w_i_u32);
        w_i_bin.iter().map(|&x| F::from_canonical_u32(x)).collect::<Vec<_>>().try_into().unwrap()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for ShaExtendSpongeStark<F, D> {
    type EvaluationFrame<FE, P, const D2: usize>
    = StarkFrame<P, NUM_SHA_EXTEND_SPONGE_COLUMNS>
    where
        FE: FieldExtension<D2, BaseField=F>,
        P: PackedField<Scalar=FE>;

    type EvaluationFrameTarget = StarkFrame<ExtensionTarget<D>, NUM_SHA_EXTEND_SPONGE_COLUMNS>;

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
    use crate::memory::segments::Segment;
    use crate::sha_extend_sponge::sha_extend_sponge_stark::{ShaExtendSpongeOp, ShaExtendSpongeStark};
    use crate::witness::memory::MemoryAddress;


    fn to_be_bits(value: u32) -> [u32; 32] {
        let mut result = [0; 32];
        for i in 0..32 {
            result[i] = ((value >> i) & 1) as u32;
        }
        result
    }

    #[test]
    fn test_correction() -> Result<(), String> {
        const D: usize = 2;
        type F = GoldilocksField;

        type S = ShaExtendSpongeStark<F, D>;

        let mut input_values = vec![];
        input_values.extend((0..4).map(|i| to_be_bits(i as u32)));
        let input_values = input_values.into_iter().flatten().collect::<Vec<_>>();

        let op = ShaExtendSpongeOp {
            base_address: vec![MemoryAddress {
                context: 0,
                segment: Segment::Code as usize,
                virt: 4,
            }, MemoryAddress {
                context: 0,
                segment: Segment::Code as usize,
                virt: 56,
            }, MemoryAddress {
                context: 0,
                segment: Segment::Code as usize,
                virt: 0,
            }, MemoryAddress {
                context: 0,
                segment: Segment::Code as usize,
                virt: 36,
            }],
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

        let w_i_bin = to_be_bits(40965);
        assert_eq!(row.w_i, w_i_bin.map(F::from_canonical_u32));

        Ok(())
    }
}