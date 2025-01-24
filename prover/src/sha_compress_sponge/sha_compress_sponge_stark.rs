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
use crate::sha_compress::logic::from_be_bits_to_u32;
use crate::sha_compress_sponge::columns::{ShaCompressSpongeColumnsView, NUM_SHA_COMPRESS_SPONGE_COLUMNS};
use crate::sha_compress_sponge::constants::SHA_COMPRESS_K_BINARY;
use crate::sha_extend::logic::{from_u32_to_be_bits, get_input_range, wrapping_add};
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

        let output = self.compress(&op.input[..288], op.i);
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

    fn compress(&self, input: &[u8], round: usize) -> [u8; 256] {
        let values: Vec<[u8; 32]> = input.chunks(32).map(|chunk| chunk.try_into().unwrap()).collect();
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h, w_i] = values.into_iter().map(
            |x| from_be_bits_to_u32(x)
        ).collect::<Vec<_>>().try_into().unwrap();

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
        //
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
    use plonky2::field::types::{Field};
    use std::borrow::Borrow;
    use crate::sha_compress_sponge::columns::ShaCompressSpongeColumnsView;
    use crate::sha_compress_sponge::sha_compress_sponge_stark::{ShaCompressSpongeOp, ShaCompressSpongeStark};
    use crate::sha_extend::logic::{from_u32_to_be_bits, get_input_range};
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

}