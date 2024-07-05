use std::borrow::Borrow;
use std::cmp::min;
use std::iter::once;
use std::marker::PhantomData;

use itertools::Itertools;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::timed;
use plonky2::util::timing::TimingTree;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cross_table_lookup::{Column, Filter};
use crate::evaluation_frame::{StarkEvaluationFrame, StarkFrame};
use crate::memory::segments::Segment;
use crate::poseidon::constants::{SPONGE_RATE, SPONGE_WIDTH};
use crate::poseidon::poseidon_stark::poseidon_with_witness;
use crate::poseidon_sponge::columns::*;
use crate::stark::Stark;
use crate::util::trace_rows_to_poly_values;
use crate::witness::memory::MemoryAddress;

pub const U8S_PER_CTL: usize = 4;
pub const U32S_PER_CTL: usize = 1;

pub(crate) fn ctl_looked_data<F: Field>() -> Vec<Column<F>> {
    let cols = POSEIDON_SPONGE_COL_MAP;

    Column::singles(
        [
            cols.context,
            cols.segment,
            cols.virt[0],
            cols.len,
            cols.timestamp,
        ]
        .iter()
        .chain(cols.updated_digest_state.iter()),
    )
    .collect()
}

pub(crate) fn ctl_looking_poseidon_inputs<F: Field>() -> Vec<Column<F>> {
    let cols = POSEIDON_SPONGE_COL_MAP;
    let mut res: Vec<_> =
        Column::singles(cols.new_rate.iter().chain(cols.original_capacity.iter())).collect();
    res.push(Column::single(cols.timestamp));

    res
}

pub(crate) fn ctl_looking_poseidon_outputs<F: Field>() -> Vec<Column<F>> {
    let cols = POSEIDON_SPONGE_COL_MAP;

    let mut res = Column::singles(&cols.updated_digest_state).collect_vec();
    res.extend(Column::singles(&cols.partial_updated_state));
    res.push(Column::single(cols.timestamp));

    res
}

pub(crate) fn ctl_looking_memory<F: Field>(i: usize) -> Vec<Column<F>> {
    let cols = POSEIDON_SPONGE_COL_MAP;

    let mut res = vec![Column::constant(F::ONE)]; // is_read

    res.extend(Column::singles([cols.context, cols.segment]));

    // The address of the byte being read is `virt + already_absorbed_bytes + i`.
    /*
    res.push(Column::linear_combination_with_constant(
        [(cols.virt, F::ONE), (cols.already_absorbed_bytes, F::ONE)],
        F::from_canonical_usize(i),
    ));
    */
    res.push(Column::single(cols.virt[i / 4]));

    // The u32 of i'th input byte being read.
    let start = (i / 4) * 4;
    let lc: Column<F> = Column::le_bytes([
        cols.block_bytes[start + 3],
        cols.block_bytes[start + 2],
        cols.block_bytes[start + 1],
        cols.block_bytes[start],
    ]);
    res.push(lc);

    // Since we're reading a single byte, the higher limbs must be zero.
    // res.extend((1..8).map(|_| Column::zero()));

    res.push(Column::single(cols.timestamp));

    assert_eq!(
        res.len(),
        crate::memory::memory_stark::ctl_data::<F>().len()
    );
    res
}

pub(crate) fn ctl_looked_filter<F: Field>() -> Filter<F> {
    // The CPU table is only interested in our final-block rows, since those contain the final
    // sponge output.
    Filter::new_simple(Column::sum(POSEIDON_SPONGE_COL_MAP.is_final_input_len))
}

/// CTL filter for reading the `i`th byte of input from memory.
pub(crate) fn ctl_looking_memory_filter<F: Field>(i: usize) -> Filter<F> {
    // We perform the `i`th read if either
    // - this is a full input block, or
    // - this is a final block of length `i` or greater
    let cols = POSEIDON_SPONGE_COL_MAP;
    if i == POSEIDON_RATE_BYTES - 1 {
        Filter::new_simple(Column::single(cols.is_full_input_block))
    } else {
        Filter::new_simple(Column::sum(
            once(&cols.is_full_input_block).chain(&cols.is_final_input_len[i + 1..]),
        ))
    }
}

pub(crate) fn ctl_looking_poseidon_filter<F: Field>() -> Filter<F> {
    let cols = POSEIDON_SPONGE_COL_MAP;
    Filter::new_simple(Column::sum(
        once(&cols.is_full_input_block).chain(&cols.is_final_input_len),
    ))
}

pub fn poseidon<F: PrimeField64>(inputs: &[u8]) -> [u64; POSEIDON_DIGEST] {
    let l = inputs.len();
    let chunks = l / POSEIDON_RATE_BYTES + 1;
    let mut input = inputs.to_owned();
    input.resize(chunks * POSEIDON_RATE_BYTES, 0);

    // pad10*1 rule
    if l % POSEIDON_RATE_BYTES == POSEIDON_RATE_BYTES - 1 {
        // Both 1s are placed in the same byte.
        input[l] = 0b10000001;
    } else {
        input[l] = 1;
        input[chunks * POSEIDON_RATE_BYTES - 1] = 0b10000000;
    }

    let mut state = [F::ZEROS; SPONGE_WIDTH];
    for block in input.chunks(POSEIDON_RATE_BYTES) {
        let block_u32s = (0..SPONGE_RATE)
            .map(|i| {
                F::from_canonical_u32(u32::from_le_bytes(
                    block[i * 4..(i + 1) * 4].to_vec().try_into().unwrap(),
                ))
            })
            .collect_vec();
        state[..SPONGE_RATE].copy_from_slice(&block_u32s);
        let (output, _) = poseidon_with_witness(&state);
        state.copy_from_slice(&output);
    }

    let hash = state
        .iter()
        .take(POSEIDON_DIGEST)
        .map(|x| x.to_canonical_u64())
        .collect_vec();

    hash.try_into().unwrap()
}

/// Information about a Poseidon sponge operation needed for witness generation.
#[derive(Clone, Debug)]
pub(crate) struct PoseidonSpongeOp {
    /// The base address at which inputs are read.
    pub(crate) base_address: Vec<MemoryAddress>,

    /// The timestamp at which inputs are read.
    pub(crate) timestamp: usize,

    /// The input that was read.
    pub(crate) input: Vec<u8>,
}

#[derive(Copy, Clone, Default)]
pub struct PoseidonSpongeStark<F, const D: usize> {
    f: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> PoseidonSpongeStark<F, D> {
    pub(crate) fn generate_trace(
        &self,
        operations: Vec<PoseidonSpongeOp>,
        min_rows: usize,
        timing: &mut TimingTree,
    ) -> Vec<PolynomialValues<F>> {
        // Generate the witness row-wise.
        let trace_rows = timed!(
            timing,
            "generate trace rows",
            self.generate_trace_rows(operations, min_rows)
        );

        let trace_polys = timed!(
            timing,
            "convert to PolynomialValues",
            trace_rows_to_poly_values(trace_rows)
        );

        trace_polys
    }

    fn generate_trace_rows(
        &self,
        operations: Vec<PoseidonSpongeOp>,
        min_rows: usize,
    ) -> Vec<[F; NUM_POSEIDON_SPONGE_COLUMNS]> {
        let base_len: usize = operations
            .iter()
            .map(|op| op.input.len() / POSEIDON_RATE_BYTES + 1)
            .sum();
        let mut rows = Vec::with_capacity(base_len.max(min_rows).next_power_of_two());
        for op in operations {
            rows.extend(self.generate_rows_for_op(op));
        }
        let padded_rows = rows.len().max(min_rows).next_power_of_two();
        for _ in rows.len()..padded_rows {
            rows.push(self.generate_padding_row());
        }
        rows
    }

    fn generate_rows_for_op(&self, op: PoseidonSpongeOp) -> Vec<[F; NUM_POSEIDON_SPONGE_COLUMNS]> {
        let mut rows = Vec::with_capacity(op.input.len() / POSEIDON_RATE_BYTES + 1);

        let mut sponge_state = [F::ZEROS; SPONGE_WIDTH];

        let mut input_blocks = op.input.chunks_exact(POSEIDON_RATE_BYTES);
        let mut already_absorbed_bytes = 0;
        for block in input_blocks.by_ref() {
            let row = self.generate_full_input_row(
                &op,
                already_absorbed_bytes,
                sponge_state,
                block.try_into().unwrap(),
            );

            sponge_state[..POSEIDON_DIGEST].copy_from_slice(&row.updated_digest_state);
            sponge_state[POSEIDON_DIGEST..].copy_from_slice(&row.partial_updated_state);

            rows.push(row.into());
            already_absorbed_bytes += POSEIDON_RATE_BYTES;
        }

        rows.push(
            self.generate_final_row(
                &op,
                already_absorbed_bytes,
                sponge_state,
                input_blocks.remainder(),
            )
            .into(),
        );

        rows
    }

    fn generate_full_input_row(
        &self,
        op: &PoseidonSpongeOp,
        already_absorbed_bytes: usize,
        sponge_state: [F; SPONGE_WIDTH],
        block: [u8; POSEIDON_RATE_BYTES],
    ) -> PoseidonSpongeColumnsView<F> {
        let mut row = PoseidonSpongeColumnsView {
            is_full_input_block: F::ONE,
            ..Default::default()
        };

        row.block_bytes = block.map(F::from_canonical_u8);

        Self::generate_common_fields(&mut row, op, already_absorbed_bytes, sponge_state);
        row
    }

    fn generate_final_row(
        &self,
        op: &PoseidonSpongeOp,
        already_absorbed_bytes: usize,
        sponge_state: [F; SPONGE_WIDTH],
        final_inputs: &[u8],
    ) -> PoseidonSpongeColumnsView<F> {
        assert_eq!(already_absorbed_bytes + final_inputs.len(), op.input.len());

        let mut row = PoseidonSpongeColumnsView::default();

        for (block_byte, input_byte) in row.block_bytes.iter_mut().zip(final_inputs) {
            *block_byte = F::from_canonical_u8(*input_byte);
        }

        // pad10*1 rule
        if final_inputs.len() == POSEIDON_RATE_BYTES - 1 {
            // Both 1s are placed in the same byte.
            row.block_bytes[final_inputs.len()] = F::from_canonical_u8(0b10000001);
        } else {
            row.block_bytes[final_inputs.len()] = F::ONE;
            row.block_bytes[POSEIDON_RATE_BYTES - 1] = F::from_canonical_u8(0b10000000);
        }

        row.is_final_input_len[final_inputs.len()] = F::ONE;

        Self::generate_common_fields(&mut row, op, already_absorbed_bytes, sponge_state);
        row
    }

    /// Generate fields that are common to both full-input-block rows and final-block rows.
    /// Also updates the sponge state with a single absorption.
    fn generate_common_fields(
        row: &mut PoseidonSpongeColumnsView<F>,
        op: &PoseidonSpongeOp,
        already_absorbed_bytes: usize,
        mut sponge_state: [F; SPONGE_WIDTH],
    ) {
        let idx = already_absorbed_bytes / 4;
        let end_index = min(
            (already_absorbed_bytes + POSEIDON_RATE_BYTES) / 4,
            op.base_address.len(),
        );
        let mut virt = (idx..end_index)
            .map(|i| op.base_address[i].virt)
            .collect_vec();
        virt.resize(SPONGE_RATE, 0);
        let virt: [usize; SPONGE_RATE] = virt.try_into().unwrap();

        row.context = F::from_canonical_usize(op.base_address[0].context);
        row.segment = F::from_canonical_usize(op.base_address[Segment::Code as usize].segment);
        row.virt = virt.map(F::from_canonical_usize);
        row.timestamp = F::from_canonical_usize(op.timestamp);
        row.len = F::from_canonical_usize(op.input.len());
        row.already_absorbed_bytes = F::from_canonical_usize(already_absorbed_bytes);

        row.original_rate
            .copy_from_slice(&sponge_state[..SPONGE_RATE]);
        row.original_capacity
            .copy_from_slice(&sponge_state[SPONGE_RATE..]);

        let block_u32s = (0..SPONGE_RATE)
            .map(|i| {
                F::from_canonical_u32(u32::from_le_bytes(
                    row.block_bytes[i * 4..(i + 1) * 4]
                        .iter()
                        .map(|x| x.to_canonical_u64() as u8)
                        .collect_vec()
                        .try_into()
                        .unwrap(),
                ))
            })
            .collect_vec();

        row.new_rate.copy_from_slice(&block_u32s);
        sponge_state[..SPONGE_RATE].copy_from_slice(&block_u32s);

        let (output, _) = poseidon_with_witness(&sponge_state);
        sponge_state.copy_from_slice(&output);

        // Store all but the first `POSEIDON_DIGEST` limbs in the updated state.
        // Those missing limbs will be stored separately.
        row.partial_updated_state
            .copy_from_slice(&output[POSEIDON_DIGEST..]);
        row.updated_digest_state
            .copy_from_slice(&output[..POSEIDON_DIGEST]);
    }

    fn generate_padding_row(&self) -> [F; NUM_POSEIDON_SPONGE_COLUMNS] {
        // The default instance has is_full_input_block = is_final_block = 0,
        // indicating that it's a dummy/padding row.
        PoseidonSpongeColumnsView::default().into()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for PoseidonSpongeStark<F, D> {
    type EvaluationFrame<FE, P, const D2: usize> = StarkFrame<P, NUM_POSEIDON_SPONGE_COLUMNS>
        where
            FE: FieldExtension<D2, BaseField = F>,
            P: PackedField<Scalar = FE>;

    type EvaluationFrameTarget = StarkFrame<ExtensionTarget<D>, NUM_POSEIDON_SPONGE_COLUMNS>;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: &Self::EvaluationFrame<FE, P, D2>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        let local_values: &[P; NUM_POSEIDON_SPONGE_COLUMNS] =
            vars.get_local_values().try_into().unwrap();
        let local_values: &PoseidonSpongeColumnsView<P> = local_values.borrow();
        let next_values: &[P; NUM_POSEIDON_SPONGE_COLUMNS] =
            vars.get_next_values().try_into().unwrap();
        let next_values: &PoseidonSpongeColumnsView<P> = next_values.borrow();

        // Each flag (full-input block, final block or implied dummy flag) must be boolean.
        let is_full_input_block = local_values.is_full_input_block;
        yield_constr.constraint(is_full_input_block * (is_full_input_block - P::ONES));

        let is_final_block: P = local_values.is_final_input_len.iter().copied().sum();
        yield_constr.constraint(is_final_block * (is_final_block - P::ONES));

        for &is_final_len in local_values.is_final_input_len.iter() {
            yield_constr.constraint(is_final_len * (is_final_len - P::ONES));
        }

        // Ensure that full-input block and final block flags are not set to 1 at the same time.
        yield_constr.constraint(is_final_block * is_full_input_block);

        // If this is the first row, the original sponge state should be 0 and already_absorbed_bytes = 0.
        let already_absorbed_bytes = local_values.already_absorbed_bytes;
        yield_constr.constraint_first_row(already_absorbed_bytes);
        for &original_rate_elem in local_values.original_rate.iter() {
            yield_constr.constraint_first_row(original_rate_elem);
        }
        for &original_capacity_elem in local_values.original_capacity.iter() {
            yield_constr.constraint_first_row(original_capacity_elem);
        }

        // If this is a final block, the next row's original sponge state should be 0 and already_absorbed_bytes = 0.
        yield_constr.constraint_transition(is_final_block * next_values.already_absorbed_bytes);
        for &original_rate_elem in next_values.original_rate.iter() {
            yield_constr.constraint_transition(is_final_block * original_rate_elem);
        }
        for &original_capacity_elem in next_values.original_capacity.iter() {
            yield_constr.constraint_transition(is_final_block * original_capacity_elem);
        }

        // If this is a full-input block, the next row's address, time and len must match as well as its timestamp.
        yield_constr.constraint_transition(
            is_full_input_block * (local_values.context - next_values.context),
        );
        yield_constr.constraint_transition(
            is_full_input_block * (local_values.segment - next_values.segment),
        );
        yield_constr.constraint_transition(
            is_full_input_block * (local_values.timestamp - next_values.timestamp),
        );

        // If this is a full-input block, the next row's "before" should match our "after" state.
        for (current_after, next_before) in local_values
            .updated_digest_state
            .iter()
            .zip_eq(&next_values.original_rate[..POSEIDON_DIGEST])
        {
            yield_constr
                .constraint_transition(is_full_input_block * (*next_before - *current_after));
        }
        for (&current_after, &next_before) in local_values
            .partial_updated_state
            .iter()
            .zip(next_values.original_rate[POSEIDON_DIGEST..].iter())
        {
            yield_constr.constraint_transition(is_full_input_block * (next_before - current_after));
        }
        for (&current_after, &next_before) in local_values
            .partial_updated_state
            .iter()
            .skip(SPONGE_RATE - POSEIDON_DIGEST)
            .zip(next_values.original_capacity.iter())
        {
            yield_constr.constraint_transition(is_full_input_block * (next_before - current_after));
        }

        // If this is a full-input block, the next row's already_absorbed_bytes should be ours plus `POSEIDON_RATE_BYTES`.
        yield_constr.constraint_transition(
            is_full_input_block
                * (already_absorbed_bytes + P::from(FE::from_canonical_usize(POSEIDON_RATE_BYTES))
                    - next_values.already_absorbed_bytes),
        );

        // A dummy row is always followed by another dummy row, so the prover can't put dummy rows "in between" to avoid the above checks.
        let is_dummy = P::ONES - is_full_input_block - is_final_block;
        let next_is_final_block: P = next_values.is_final_input_len.iter().copied().sum();
        yield_constr.constraint_transition(
            is_dummy * (next_values.is_full_input_block + next_is_final_block),
        );

        // If this is a final block, is_final_input_len implies `len - already_absorbed == i`.
        let offset = local_values.len - already_absorbed_bytes;
        for (i, &is_final_len) in local_values.is_final_input_len.iter().enumerate() {
            let entry_match = offset - P::from(FE::from_canonical_usize(i));
            yield_constr.constraint(is_final_len * entry_match);
        }
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
        vars: &Self::EvaluationFrameTarget,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        let local_values: &[ExtensionTarget<D>; NUM_POSEIDON_SPONGE_COLUMNS] =
            vars.get_local_values().try_into().unwrap();
        let local_values: &PoseidonSpongeColumnsView<ExtensionTarget<D>> = local_values.borrow();
        let next_values: &[ExtensionTarget<D>; NUM_POSEIDON_SPONGE_COLUMNS] =
            vars.get_next_values().try_into().unwrap();
        let next_values: &PoseidonSpongeColumnsView<ExtensionTarget<D>> = next_values.borrow();

        let one = builder.one_extension();

        // Each flag (full-input block, final block or implied dummy flag) must be boolean.
        let is_full_input_block = local_values.is_full_input_block;
        let constraint = builder.mul_sub_extension(
            is_full_input_block,
            is_full_input_block,
            is_full_input_block,
        );
        yield_constr.constraint(builder, constraint);

        let is_final_block = builder.add_many_extension(local_values.is_final_input_len);
        let constraint = builder.mul_sub_extension(is_final_block, is_final_block, is_final_block);
        yield_constr.constraint(builder, constraint);

        for &is_final_len in local_values.is_final_input_len.iter() {
            let constraint = builder.mul_sub_extension(is_final_len, is_final_len, is_final_len);
            yield_constr.constraint(builder, constraint);
        }

        // Ensure that full-input block and final block flags are not set to 1 at the same time.
        let constraint = builder.mul_extension(is_final_block, is_full_input_block);
        yield_constr.constraint(builder, constraint);

        // If this is the first row, the original sponge state should be 0 and already_absorbed_bytes = 0.
        let already_absorbed_bytes = local_values.already_absorbed_bytes;
        yield_constr.constraint_first_row(builder, already_absorbed_bytes);
        for &original_rate_elem in local_values.original_rate.iter() {
            yield_constr.constraint_first_row(builder, original_rate_elem);
        }
        for &original_capacity_elem in local_values.original_capacity.iter() {
            yield_constr.constraint_first_row(builder, original_capacity_elem);
        }

        // If this is a final block, the next row's original sponge state should be 0 and already_absorbed_bytes = 0.
        let constraint = builder.mul_extension(is_final_block, next_values.already_absorbed_bytes);
        yield_constr.constraint_transition(builder, constraint);
        for &original_rate_elem in next_values.original_rate.iter() {
            let constraint = builder.mul_extension(is_final_block, original_rate_elem);
            yield_constr.constraint_transition(builder, constraint);
        }
        for &original_capacity_elem in next_values.original_capacity.iter() {
            let constraint = builder.mul_extension(is_final_block, original_capacity_elem);
            yield_constr.constraint_transition(builder, constraint);
        }

        // If this is a full-input block, the next row's address, time and len must match as well as its timestamp.
        let context_diff = builder.sub_extension(local_values.context, next_values.context);
        let constraint = builder.mul_extension(is_full_input_block, context_diff);
        yield_constr.constraint_transition(builder, constraint);

        let segment_diff = builder.sub_extension(local_values.segment, next_values.segment);
        let constraint = builder.mul_extension(is_full_input_block, segment_diff);
        yield_constr.constraint_transition(builder, constraint);

        let timestamp_diff = builder.sub_extension(local_values.timestamp, next_values.timestamp);
        let constraint = builder.mul_extension(is_full_input_block, timestamp_diff);
        yield_constr.constraint_transition(builder, constraint);

        // If this is a full-input block, the next row's "before" should match our "after" state.
        for (current_after, next_before) in local_values
            .updated_digest_state
            .iter()
            .zip_eq(&next_values.original_rate[..POSEIDON_DIGEST])
        {
            let diff = builder.sub_extension(*next_before, *current_after);
            let constraint = builder.mul_extension(is_full_input_block, diff);
            yield_constr.constraint_transition(builder, constraint);
        }
        for (&current_after, &next_before) in local_values
            .partial_updated_state
            .iter()
            .zip(next_values.original_rate[POSEIDON_DIGEST..].iter())
        {
            let diff = builder.sub_extension(next_before, current_after);
            let constraint = builder.mul_extension(is_full_input_block, diff);
            yield_constr.constraint_transition(builder, constraint);
        }
        for (&current_after, &next_before) in local_values
            .partial_updated_state
            .iter()
            .skip(SPONGE_RATE - POSEIDON_DIGEST)
            .zip(next_values.original_capacity.iter())
        {
            let diff = builder.sub_extension(next_before, current_after);
            let constraint = builder.mul_extension(is_full_input_block, diff);
            yield_constr.constraint_transition(builder, constraint);
        }

        // If this is a full-input block, the next row's already_absorbed_bytes should be ours plus `POSEIDON_RATE_BYTES`.
        let absorbed_bytes = builder.add_const_extension(
            already_absorbed_bytes,
            F::from_canonical_usize(POSEIDON_RATE_BYTES),
        );
        let absorbed_diff =
            builder.sub_extension(absorbed_bytes, next_values.already_absorbed_bytes);
        let constraint = builder.mul_extension(is_full_input_block, absorbed_diff);
        yield_constr.constraint_transition(builder, constraint);

        // A dummy row is always followed by another dummy row, so the prover can't put dummy rows "in between" to avoid the above checks.
        let is_dummy = {
            let tmp = builder.sub_extension(one, is_final_block);
            builder.sub_extension(tmp, is_full_input_block)
        };
        let next_is_final_block = builder.add_many_extension(next_values.is_final_input_len);
        let constraint = {
            let tmp = builder.add_extension(next_is_final_block, next_values.is_full_input_block);
            builder.mul_extension(is_dummy, tmp)
        };
        yield_constr.constraint_transition(builder, constraint);

        // If this is a final block, is_final_input_len implies `len - already_absorbed == i`.
        let offset = builder.sub_extension(local_values.len, already_absorbed_bytes);
        for (i, &is_final_len) in local_values.is_final_input_len.iter().enumerate() {
            let index = builder.constant_extension(F::from_canonical_usize(i).into());
            let entry_match = builder.sub_extension(offset, index);

            let constraint = builder.mul_extension(is_final_len, entry_match);
            yield_constr.constraint(builder, constraint);
        }
    }

    fn constraint_degree(&self) -> usize {
        3
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Borrow;

    use anyhow::Result;
    use itertools::Itertools;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::PrimeField64;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use crate::memory::segments::Segment;
    use crate::poseidon_sponge::columns::PoseidonSpongeColumnsView;
    use crate::poseidon_sponge::poseidon_sponge_stark::{
        poseidon, PoseidonSpongeOp, PoseidonSpongeStark,
    };
    use crate::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};
    use crate::witness::memory::MemoryAddress;

    #[test]
    fn test_stark_degree() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = PoseidonSpongeStark<F, D>;

        let stark = S::default();
        test_stark_low_degree(stark)
    }

    #[test]
    fn test_stark_circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = PoseidonSpongeStark<F, D>;

        let stark = S::default();
        test_stark_circuit_constraints::<F, C, S, D>(stark)
    }

    #[test]
    fn test_generation() -> Result<()> {
        const D: usize = 2;
        type F = GoldilocksField;
        type S = PoseidonSpongeStark<F, D>;

        let input = vec![1, 2, 3];
        let expected_output = poseidon::<F>(&input);

        let op = PoseidonSpongeOp {
            base_address: vec![MemoryAddress {
                context: 0,
                segment: Segment::Code as usize,
                virt: 0,
            }],
            timestamp: 0,
            input,
        };
        let stark = S::default();
        let rows = stark.generate_rows_for_op(op);
        assert_eq!(rows.len(), 1);
        let last_row: &PoseidonSpongeColumnsView<F> = rows.last().unwrap().borrow();
        let output = last_row
            .updated_digest_state
            .iter()
            .map(|x| x.to_canonical_u64())
            .collect_vec();

        assert_eq!(output, expected_output);
        Ok(())
    }
}
