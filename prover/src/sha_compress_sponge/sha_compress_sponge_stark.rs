use std::marker::PhantomData;
use itertools::Itertools;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::evaluation_frame::StarkFrame;
use crate::memory::segments::Segment;
use crate::sha_compress_sponge::columns::{ShaCompressSpongeColumnsView, NUM_SHA_COMPRESS_SPONGE_COLUMNS};
use crate::stark::Stark;
use crate::util::trace_rows_to_poly_values;
use crate::witness::memory::MemoryAddress;
use crate::witness::operation::SHA_COMPRESS_K;

#[derive(Clone, Debug)]
pub(crate) struct ShaCompressSpongeOp {
    /// The base address at which inputs are read.
    pub(crate) base_address: Vec<MemoryAddress>,

    /// The timestamp at which inputs are read.
    pub(crate) timestamp: usize,

    /// The input that was read.
    pub(crate) input: Vec<u32>,
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

        let new_buffer = self.compress(&op.input);

        row.hx = op.input[0..8]
            .iter()
            .map(|&x| F::from_canonical_u32(x))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        row.w = op.input[8..op.input.len()]
            .iter()
            .map(|&x| F::from_canonical_u32(x))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        row.context = F::from_canonical_usize(op.base_address[0].context);
        row.segment = F::from_canonical_usize(op.base_address[Segment::Code as usize].segment);

        [row.new_a, row.new_b, row.new_c, row.new_d, row.new_e, row.new_f, row.new_g, row.new_h]
            = new_buffer.iter()
            .map(|&x| F::from_canonical_u32(x))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        row.final_hx = new_buffer.iter().zip(row.hx.iter())
            .map(|(&x, &hx)| F::from_canonical_u32(x.wrapping_add(hx.to_canonical_u64() as u32)))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let hx_virt = (0..8)
            .map(|i| op.base_address[i].virt)
            .collect_vec();
        let hx_virt: [usize; 8] = hx_virt.try_into().unwrap();
        row.hx_virt = hx_virt.map(F::from_canonical_usize);

        let w_virt = (8..op.input.len())
            .map(|i| op.base_address[i].virt)
            .collect_vec();
        let w_virt: [usize; 64] = w_virt.try_into().unwrap();
        row.w_virt = w_virt.map(F::from_canonical_usize);

        row
    }

    fn compress(&self, input: &[u32]) -> [u32; 8] {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h]: [u32; 8] = input[0..8].try_into().unwrap();
        let mut t1: u32;
        let mut t2: u32;

        for i in 0..64 {
            t1 = h.wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
                .wrapping_add((e & f) ^ ((!e) & g)).wrapping_add(SHA_COMPRESS_K[i]).wrapping_add(input[8 + i]);
            t2 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
                .wrapping_add((a & b) ^ (a & c) ^ (b & c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        [a, b, c, d, e, f, g, h]
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
    use crate::sha_compress_sponge::sha_compress_sponge_stark::{ShaCompressSpongeOp, ShaCompressSpongeStark};
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

        let op = ShaCompressSpongeOp {
            base_address: hx_addresses.iter().chain(w_addresses.iter()).cloned().collect(),
            timestamp: 0,
            input: H256_256.iter().chain(W.iter()).cloned().collect(),
        };
        let row = stark.generate_rows_for_op(op);

        assert_eq!(row.new_a, F::from_canonical_u32(1813631354));
        assert_eq!(row.new_b, F::from_canonical_u32(3315363907));
        assert_eq!(row.new_c, F::from_canonical_u32(209435322));
        assert_eq!(row.new_d, F::from_canonical_u32(267716009));
        assert_eq!(row.new_e, F::from_canonical_u32(646830348));
        assert_eq!(row.new_f, F::from_canonical_u32(362222596));
        assert_eq!(row.new_g, F::from_canonical_u32(3323089566));
        assert_eq!(row.new_h, F::from_canonical_u32(1912443780));

        let expected_values: [F; 8] = [3592665057_u32, 2164530888, 1223339564, 3041196771, 2006723467,
            2963045520, 3851824201, 3453903005].into_iter().map(F::from_canonical_u32)
            .collect::<Vec<_>>().try_into().unwrap();


        assert_eq!(row.final_hx, expected_values);
        Ok(())

    }
}