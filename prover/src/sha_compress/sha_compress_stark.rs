use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cross_table_lookup::{Column, Filter};
use crate::evaluation_frame::{StarkEvaluationFrame, StarkFrame};
use crate::sha_compress::columns::{
    ShaCompressColumnsView, NUM_SHA_COMPRESS_COLUMNS, SHA_COMPRESS_COL_MAP,
};
use crate::sha_compress::logic::{equal_ext_circuit_constraints, equal_packed_constraint};
use crate::sha_compress::not_operation::{
    not_operation_ext_circuit_constraints, not_operation_packed_constraints,
};
use crate::sha_compress::wrapping_add_2::{
    wrapping_add_2_ext_circuit_constraints, wrapping_add_2_packed_constraints,
};
use crate::sha_compress::wrapping_add_5::{
    wrapping_add_5_ext_circuit_constraints, wrapping_add_5_packed_constraints,
};
use crate::sha_compress_sponge::constants::{NUM_COMPRESS_ROWS, SHA_COMPRESS_K_LE_BYTES};
use crate::sha_extend::logic::get_input_range_4;
use crate::sha_extend::rotate_right::{
    rotate_right_ext_circuit_constraint, rotate_right_packed_constraints,
};
use crate::stark::Stark;
use crate::util::trace_rows_to_poly_values;
use crate::witness::memory::MemoryAddress;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use std::borrow::Borrow;
use std::marker::PhantomData;

pub const NUM_ROUND_CONSTANTS: usize = 65;

pub const NUM_INPUTS: usize = 10 * 4 + 1; // (states (a, b, ..., h) + w_i + key_i) + i

pub fn ctl_data_inputs<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_COL_MAP;
    let mut res: Vec<_> = Column::singles([cols.state.as_slice()].concat()).collect();
    res.extend(Column::singles([
        cols.timestamp,
        cols.segment,
        cols.context,
        cols.w_i_virt,
    ]));
    res
}

pub fn ctl_data_outputs<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_COL_MAP;
    let mut res: Vec<_> = Column::singles(&cols.state).collect();
    res.push(Column::single(cols.timestamp));
    res
}

// logic
pub(crate) fn ctl_s_1_inter_looking_logic<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_COL_MAP;
    let mut res = vec![
        Column::constant(F::from_canonical_u32(0b100110 * (1 << 6))), // is_xor
    ];
    res.push(Column::le_bytes(cols.e_rr_6.value));
    res.push(Column::le_bytes(cols.e_rr_11.value));
    res.push(Column::le_bytes(cols.s_1_inter));
    res
}

pub(crate) fn ctl_s_1_looking_logic<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_COL_MAP;
    let mut res = vec![
        Column::constant(F::from_canonical_u32(0b100110 * (1 << 6))), // is_xor
    ];
    res.push(Column::le_bytes(cols.s_1_inter));
    res.push(Column::le_bytes(cols.e_rr_25.value));
    res.push(Column::le_bytes(cols.s_1));
    res
}

pub(crate) fn ctl_e_and_f_looking_logic<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_COL_MAP;
    let mut res = vec![
        Column::constant(F::from_canonical_u32(0b100100 * (1 << 6))), // is_and
    ];
    res.push(Column::le_bytes(&cols.state[get_input_range_4(4)]));
    res.push(Column::le_bytes(&cols.state[get_input_range_4(5)]));
    res.push(Column::le_bytes(cols.e_and_f));
    res
}

pub(crate) fn ctl_not_e_and_g_looking_logic<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_COL_MAP;
    let mut res = vec![
        Column::constant(F::from_canonical_u32(0b100100 * (1 << 6))), // is_and
    ];
    res.push(Column::le_bytes(cols.e_not.value));
    res.push(Column::le_bytes(&cols.state[get_input_range_4(6)]));
    res.push(Column::le_bytes(cols.e_not_and_g));
    res
}
pub(crate) fn ctl_ch_looking_logic<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_COL_MAP;
    let mut res = vec![
        Column::constant(F::from_canonical_u32(0b100110 * (1 << 6))), // is_xor
    ];
    res.push(Column::le_bytes(cols.e_and_f));
    res.push(Column::le_bytes(cols.e_not_and_g));
    res.push(Column::le_bytes(cols.ch));
    res
}
pub(crate) fn ctl_s_0_inter_looking_logic<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_COL_MAP;
    let mut res = vec![
        Column::constant(F::from_canonical_u32(0b100110 * (1 << 6))), // is_xor
    ];
    res.push(Column::le_bytes(cols.a_rr_2.value));
    res.push(Column::le_bytes(cols.a_rr_13.value));
    res.push(Column::le_bytes(cols.s_0_inter));
    res
}

pub(crate) fn ctl_s_0_looking_logic<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_COL_MAP;
    let mut res = vec![
        Column::constant(F::from_canonical_u32(0b100110 * (1 << 6))), // is_xor
    ];
    res.push(Column::le_bytes(cols.s_0_inter));
    res.push(Column::le_bytes(cols.a_rr_22.value));
    res.push(Column::le_bytes(cols.s_0));
    res
}

pub(crate) fn ctl_a_and_b_looking_logic<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_COL_MAP;
    let mut res = vec![
        Column::constant(F::from_canonical_u32(0b100100 * (1 << 6))), // is_and
    ];
    res.push(Column::le_bytes(&cols.state[get_input_range_4(0)]));
    res.push(Column::le_bytes(&cols.state[get_input_range_4(1)]));
    res.push(Column::le_bytes(cols.a_and_b));
    res
}

pub(crate) fn ctl_a_and_c_looking_logic<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_COL_MAP;
    let mut res = vec![
        Column::constant(F::from_canonical_u32(0b100100 * (1 << 6))), // is_and
    ];
    res.push(Column::le_bytes(&cols.state[get_input_range_4(0)]));
    res.push(Column::le_bytes(&cols.state[get_input_range_4(2)]));
    res.push(Column::le_bytes(cols.a_and_c));
    res
}

pub(crate) fn ctl_b_and_c_looking_logic<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_COL_MAP;
    let mut res = vec![
        Column::constant(F::from_canonical_u32(0b100100 * (1 << 6))), // is_and
    ];
    res.push(Column::le_bytes(&cols.state[get_input_range_4(1)]));
    res.push(Column::le_bytes(&cols.state[get_input_range_4(2)]));
    res.push(Column::le_bytes(cols.b_and_c));
    res
}

pub(crate) fn ctl_maj_inter_looking_logic<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_COL_MAP;
    let mut res = vec![
        Column::constant(F::from_canonical_u32(0b100110 * (1 << 6))), // is_xor
    ];
    res.push(Column::le_bytes(cols.a_and_b));
    res.push(Column::le_bytes(cols.a_and_c));
    res.push(Column::le_bytes(cols.maj_inter));
    res
}

pub(crate) fn ctl_maj_looking_logic<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_COL_MAP;
    let mut res = vec![
        Column::constant(F::from_canonical_u32(0b100110 * (1 << 6))), // is_xor
    ];
    res.push(Column::le_bytes(cols.maj_inter));
    res.push(Column::le_bytes(cols.b_and_c));
    res.push(Column::le_bytes(cols.maj));
    res
}

// read w_i ctl

pub(crate) fn ctl_looking_memory<F: Field>(_: usize) -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_COL_MAP;
    let mut res = vec![Column::constant(F::ONE)]; // is_read

    res.extend(Column::singles([cols.context, cols.segment]));
    res.push(Column::single(cols.w_i_virt));

    // le_bit.reverse();
    let u32_value: Column<F> = Column::le_bytes(cols.w_i);
    res.push(u32_value);
    res.push(Column::single(cols.timestamp));

    assert_eq!(
        res.len(),
        crate::memory::memory_stark::ctl_data::<F>().len()
    );
    res
}

pub fn ctl_filter_inputs<F: Field>() -> Filter<F> {
    let cols = SHA_COMPRESS_COL_MAP;
    // The first row only
    Filter::new_simple(Column::single(cols.round[0]))
}

pub fn ctl_filter_outputs<F: Field>() -> Filter<F> {
    let cols = SHA_COMPRESS_COL_MAP;
    // the final round
    Filter::new_simple(Column::single(cols.round[NUM_COMPRESS_ROWS - 1]))
}

pub fn ctl_logic_filter<F: Field>() -> Filter<F> {
    let cols = SHA_COMPRESS_COL_MAP;
    // not the padding rows.
    Filter::new_simple(Column::sum(&cols.round[..NUM_COMPRESS_ROWS - 1]))
}

#[derive(Copy, Clone, Default)]
pub struct ShaCompressStark<F, const D: usize> {
    pub(crate) f: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> ShaCompressStark<F, D> {
    pub(crate) fn generate_trace(
        &self,
        inputs: Vec<([u8; NUM_INPUTS], MemoryAddress, usize)>,
        min_rows: usize,
    ) -> Vec<PolynomialValues<F>> {
        // Generate the witness row-wise
        let trace_rows = self.generate_trace_rows(inputs, min_rows);
        trace_rows_to_poly_values(trace_rows)
    }

    fn generate_trace_rows(
        &self,
        inputs_and_timestamps: Vec<([u8; NUM_INPUTS], MemoryAddress, usize)>,
        min_rows: usize,
    ) -> Vec<[F; NUM_SHA_COMPRESS_COLUMNS]> {
        let num_rows = inputs_and_timestamps
            .len()
            .max(min_rows)
            .next_power_of_two();

        let mut rows = Vec::with_capacity(num_rows);
        for input_and_timestamp in inputs_and_timestamps.iter() {
            let row_for_compress = self.generate_trace_rows_for_compress(*input_and_timestamp);
            rows.push(row_for_compress);
        }

        while rows.len() < num_rows {
            rows.push([F::ZERO; NUM_SHA_COMPRESS_COLUMNS]);
        }
        rows
    }

    fn generate_trace_rows_for_compress(
        &self,
        input_and_timestamp: ([u8; NUM_INPUTS], MemoryAddress, usize),
    ) -> [F; NUM_SHA_COMPRESS_COLUMNS] {
        let timestamp = input_and_timestamp.2;
        let w_i_address = input_and_timestamp.1;
        let inputs = input_and_timestamp.0;

        let mut row = ShaCompressColumnsView::<F>::default();
        row.timestamp = F::from_canonical_usize(timestamp);
        row.segment = F::from_canonical_usize(w_i_address.segment);
        row.context = F::from_canonical_usize(w_i_address.context);
        row.w_i_virt = F::from_canonical_usize(w_i_address.virt);
        let i = inputs[40] as usize;

        row.round = [F::ZERO; NUM_ROUND_CONSTANTS];
        row.round[i] = F::ONE;

        // read inputs
        row.state = inputs[0..32]
            .iter()
            .map(|x| F::from_canonical_u8(*x))
            .collect::<Vec<F>>()
            .try_into()
            .unwrap();
        row.w_i = inputs[get_input_range_4(8)]
            .iter()
            .map(|x| F::from_canonical_u8(*x))
            .collect::<Vec<F>>()
            .try_into()
            .unwrap();
        row.k_i = inputs[get_input_range_4(9)]
            .iter()
            .map(|x| F::from_canonical_u8(*x))
            .collect::<Vec<F>>()
            .try_into()
            .unwrap();

        // compute

        let e_rr_6 = row
            .e_rr_6
            .generate_trace(inputs[get_input_range_4(4)].try_into().unwrap(), 6);
        let e_rr_11 = row
            .e_rr_11
            .generate_trace(inputs[get_input_range_4(4)].try_into().unwrap(), 11);
        let e_rr_25 = row
            .e_rr_25
            .generate_trace(inputs[get_input_range_4(4)].try_into().unwrap(), 25);
        let s_1_inter = e_rr_6 ^ e_rr_11;
        // log::info!("GENE: e_rr_6: {:?}, e_rr_11: {:?}, s_1_inter {:?}", e_rr_6, e_rr_11, s_1_inter);
        row.s_1_inter = s_1_inter.to_le_bytes().map(F::from_canonical_u8);

        let s_1 = s_1_inter ^ e_rr_25;
        row.s_1 = s_1.to_le_bytes().map(F::from_canonical_u8);

        let e = u32::from_le_bytes(inputs[get_input_range_4(4)].try_into().unwrap());
        let f = u32::from_le_bytes(inputs[get_input_range_4(5)].try_into().unwrap());
        let e_and_f = e & f;
        row.e_and_f = e_and_f.to_le_bytes().map(F::from_canonical_u8);

        let e_not = row
            .e_not
            .generate_trace(inputs[get_input_range_4(4)].try_into().unwrap());

        let g = u32::from_le_bytes(inputs[get_input_range_4(6)].try_into().unwrap());
        let e_not_and_g = e_not & g;
        row.e_not_and_g = e_not_and_g.to_le_bytes().map(F::from_canonical_u8);

        let ch = e_and_f ^ e_not_and_g;
        row.ch = ch.to_le_bytes().map(F::from_canonical_u8);

        let temp1 = row.temp1.generate_trace(
            inputs[get_input_range_4(7)].try_into().unwrap(),
            s_1.to_le_bytes(),
            ch.to_le_bytes(),
            inputs[get_input_range_4(9)].try_into().unwrap(),
            inputs[get_input_range_4(8)].try_into().unwrap(),
        );

        let a_rr_2 = row
            .a_rr_2
            .generate_trace(inputs[get_input_range_4(0)].try_into().unwrap(), 2);
        let a_rr_13 = row
            .a_rr_13
            .generate_trace(inputs[get_input_range_4(0)].try_into().unwrap(), 13);
        let a_rr_22 = row
            .a_rr_22
            .generate_trace(inputs[get_input_range_4(0)].try_into().unwrap(), 22);
        let s_0_inter = a_rr_2 ^ a_rr_13;
        let s_0 = s_0_inter ^ a_rr_22;
        row.s_0_inter = s_0_inter.to_le_bytes().map(F::from_canonical_u8);
        row.s_0 = s_0.to_le_bytes().map(F::from_canonical_u8);

        let a = u32::from_le_bytes(inputs[get_input_range_4(0)].try_into().unwrap());
        let b = u32::from_le_bytes(inputs[get_input_range_4(1)].try_into().unwrap());
        let c = u32::from_le_bytes(inputs[get_input_range_4(2)].try_into().unwrap());

        let a_and_b = a & b;
        row.a_and_b = a_and_b.to_le_bytes().map(F::from_canonical_u8);
        let a_and_c = a & c;
        row.a_and_c = a_and_c.to_le_bytes().map(F::from_canonical_u8);
        let b_and_c = b & c;
        row.b_and_c = b_and_c.to_le_bytes().map(F::from_canonical_u8);

        let maj_inter = a_and_b ^ a_and_c;
        let maj = maj_inter ^ b_and_c;
        row.maj_inter = maj_inter.to_le_bytes().map(F::from_canonical_u8);
        row.maj = maj.to_le_bytes().map(F::from_canonical_u8);

        let temp2 = row
            .temp2
            .generate_trace(s_0.to_le_bytes(), maj.to_le_bytes());

        // next value of e
        let _ = row.d_add_temp1.generate_trace(
            inputs[get_input_range_4(3)].try_into().unwrap(),
            temp1.to_le_bytes(),
        );

        // next value of a
        let _ = row
            .temp1_add_temp2
            .generate_trace(temp1.to_le_bytes(), temp2.to_le_bytes());

        row.into()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for ShaCompressStark<F, D> {
    type EvaluationFrame<FE, P, const D2: usize>
        = StarkFrame<P, NUM_SHA_COMPRESS_COLUMNS>
    where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>;
    type EvaluationFrameTarget = StarkFrame<ExtensionTarget<D>, NUM_SHA_COMPRESS_COLUMNS>;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: &Self::EvaluationFrame<FE, P, D2>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        let local_values: &[P; NUM_SHA_COMPRESS_COLUMNS] =
            vars.get_local_values().try_into().unwrap();
        let local_values: &ShaCompressColumnsView<P> = local_values.borrow();

        let next_values: &[P; NUM_SHA_COMPRESS_COLUMNS] =
            vars.get_next_values().try_into().unwrap();
        let next_values: &ShaCompressColumnsView<P> = next_values.borrow();

        // filter
        let is_final = local_values.round[NUM_COMPRESS_ROWS - 1];
        yield_constr.constraint(is_final * (is_final - P::ONES));
        let not_final = P::ONES - is_final;

        let sum_round_flags = (0..NUM_COMPRESS_ROWS)
            .map(|i| local_values.round[i])
            .sum::<P>();
        yield_constr.constraint(sum_round_flags * (sum_round_flags - P::ONES));

        // check the value of k_i
        for i in 0..4 {
            let mut bit_i = P::ZEROS;
            for j in 0..64 {
                bit_i +=
                    local_values.round[j] * FE::from_canonical_u8(SHA_COMPRESS_K_LE_BYTES[j][i])
            }
            let diff = local_values.k_i[i] - bit_i;
            yield_constr.constraint(sum_round_flags * not_final * diff);
        }

        // check the rotation
        rotate_right_packed_constraints(
            local_values.state[get_input_range_4(4)].try_into().unwrap(),
            &local_values.e_rr_6,
            6,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        rotate_right_packed_constraints(
            local_values.state[get_input_range_4(4)].try_into().unwrap(),
            &local_values.e_rr_11,
            11,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        rotate_right_packed_constraints(
            local_values.state[get_input_range_4(4)].try_into().unwrap(),
            &local_values.e_rr_25,
            25,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        rotate_right_packed_constraints(
            local_values.state[get_input_range_4(0)].try_into().unwrap(),
            &local_values.a_rr_2,
            2,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        rotate_right_packed_constraints(
            local_values.state[get_input_range_4(0)].try_into().unwrap(),
            &local_values.a_rr_13,
            13,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        rotate_right_packed_constraints(
            local_values.state[get_input_range_4(0)].try_into().unwrap(),
            &local_values.a_rr_22,
            22,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        // The XOR, AND checks are in the logic table

        // The NOT check
        not_operation_packed_constraints(
            local_values.state[get_input_range_4(4)].try_into().unwrap(),
            &local_values.e_not,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(sum_round_flags * c));

        // wrapping add constraints

        wrapping_add_5_packed_constraints(
            local_values.state[get_input_range_4(7)].try_into().unwrap(),
            local_values.s_1,
            local_values.ch,
            local_values.k_i,
            local_values.w_i,
            &local_values.temp1,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(sum_round_flags * c));

        wrapping_add_2_packed_constraints(local_values.s_0, local_values.maj, &local_values.temp2)
            .into_iter()
            .for_each(|c| yield_constr.constraint(c));

        wrapping_add_2_packed_constraints(
            local_values.state[get_input_range_4(3)].try_into().unwrap(),
            local_values.temp1.value,
            &local_values.d_add_temp1,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        wrapping_add_2_packed_constraints(
            local_values.temp1.value,
            local_values.temp2.value,
            &local_values.temp1_add_temp2,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        // If this is not the final step or a padding row:

        // the local and next timestamps must match.
        yield_constr.constraint(
            sum_round_flags * not_final * (next_values.timestamp - local_values.timestamp),
        );

        // the address of w_i must be increased by 4
        yield_constr.constraint(
            sum_round_flags
                * not_final
                * (next_values.w_i_virt - local_values.w_i_virt - FE::from_canonical_u8(4)),
        );

        // Output constraint when it is not the final round or padding row
        // local.temp1 + local.temp2 = next.a
        equal_packed_constraint::<P, 4>(
            local_values.temp1_add_temp2.value,
            next_values.state[get_input_range_4(0)].try_into().unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(sum_round_flags * not_final * c));

        // local.a = next.b
        equal_packed_constraint::<P, 4>(
            local_values.state[get_input_range_4(0)].try_into().unwrap(),
            next_values.state[get_input_range_4(1)].try_into().unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(sum_round_flags * not_final * c));

        // local.b = next.c
        equal_packed_constraint::<P, 4>(
            local_values.state[get_input_range_4(1)].try_into().unwrap(),
            next_values.state[get_input_range_4(2)].try_into().unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(sum_round_flags * not_final * c));

        // local.c = next.d
        equal_packed_constraint::<P, 4>(
            local_values.state[get_input_range_4(2)].try_into().unwrap(),
            next_values.state[get_input_range_4(3)].try_into().unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(sum_round_flags * not_final * c));

        // local.d + local.temp1 = next.e
        equal_packed_constraint::<P, 4>(
            local_values.d_add_temp1.value,
            next_values.state[get_input_range_4(4)].try_into().unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(sum_round_flags * not_final * c));

        // local.e = next.f
        equal_packed_constraint::<P, 4>(
            local_values.state[get_input_range_4(4)].try_into().unwrap(),
            next_values.state[get_input_range_4(5)].try_into().unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(sum_round_flags * not_final * c));

        // local.f = next.g
        equal_packed_constraint::<P, 4>(
            local_values.state[get_input_range_4(5)].try_into().unwrap(),
            next_values.state[get_input_range_4(6)].try_into().unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(sum_round_flags * not_final * c));

        // local.g = next.h
        equal_packed_constraint::<P, 4>(
            local_values.state[get_input_range_4(6)].try_into().unwrap(),
            next_values.state[get_input_range_4(7)].try_into().unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(sum_round_flags * not_final * c));
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: &Self::EvaluationFrameTarget,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        let local_values: &[ExtensionTarget<D>; NUM_SHA_COMPRESS_COLUMNS] =
            vars.get_local_values().try_into().unwrap();
        let local_values: &ShaCompressColumnsView<ExtensionTarget<D>> = local_values.borrow();

        let next_values: &[ExtensionTarget<D>; NUM_SHA_COMPRESS_COLUMNS] =
            vars.get_next_values().try_into().unwrap();
        let next_values: &ShaCompressColumnsView<ExtensionTarget<D>> = next_values.borrow();

        let one_extension = builder.one_extension();

        // filter
        let is_final = local_values.round[NUM_COMPRESS_ROWS - 1];
        let constraint = builder.mul_sub_extension(is_final, is_final, is_final);
        yield_constr.constraint(builder, constraint);
        let not_final = builder.sub_extension(one_extension, is_final);

        let sum_round_flags =
            builder.add_many_extension((0..NUM_COMPRESS_ROWS).map(|i| local_values.round[i]));

        let constraint =
            builder.mul_sub_extension(sum_round_flags, sum_round_flags, sum_round_flags);
        yield_constr.constraint(builder, constraint);

        // check the value of k_i
        for i in 0..4 {
            let bit_i_comp: Vec<_> = (0..64)
                .map(|j| {
                    let k_j_i = builder.constant_extension(F::Extension::from_canonical_u8(
                        SHA_COMPRESS_K_LE_BYTES[j][i],
                    ));
                    builder.mul_extension(local_values.round[j], k_j_i)
                })
                .collect();
            let bit_i = builder.add_many_extension(bit_i_comp);
            let diff = builder.sub_extension(local_values.k_i[i], bit_i);
            let constraint = builder.mul_many_extension([sum_round_flags, not_final, diff]);
            yield_constr.constraint(builder, constraint);
        }

        // check the rotation
        rotate_right_ext_circuit_constraint(
            builder,
            local_values.state[get_input_range_4(4)].try_into().unwrap(),
            &local_values.e_rr_6,
            6,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        rotate_right_ext_circuit_constraint(
            builder,
            local_values.state[get_input_range_4(4)].try_into().unwrap(),
            &local_values.e_rr_11,
            11,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        rotate_right_ext_circuit_constraint(
            builder,
            local_values.state[get_input_range_4(4)].try_into().unwrap(),
            &local_values.e_rr_25,
            25,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        rotate_right_ext_circuit_constraint(
            builder,
            local_values.state[get_input_range_4(0)].try_into().unwrap(),
            &local_values.a_rr_2,
            2,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        rotate_right_ext_circuit_constraint(
            builder,
            local_values.state[get_input_range_4(0)].try_into().unwrap(),
            &local_values.a_rr_13,
            13,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        rotate_right_ext_circuit_constraint(
            builder,
            local_values.state[get_input_range_4(0)].try_into().unwrap(),
            &local_values.a_rr_22,
            22,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        // The XOR, AND checks are in the logic table

        // The NOT check
        not_operation_ext_circuit_constraints(
            builder,
            local_values.state[get_input_range_4(4)].try_into().unwrap(),
            &local_values.e_not,
        )
        .into_iter()
        .for_each(|c| {
            let constraint = builder.mul_extension(sum_round_flags, c);
            yield_constr.constraint(builder, constraint)
        });

        // wrapping add constraints

        wrapping_add_5_ext_circuit_constraints(
            builder,
            local_values.state[get_input_range_4(7)].try_into().unwrap(),
            local_values.s_1,
            local_values.ch,
            local_values.k_i,
            local_values.w_i,
            &local_values.temp1,
        )
        .into_iter()
        .for_each(|c| {
            let constraint = builder.mul_extension(c, sum_round_flags);
            yield_constr.constraint(builder, constraint)
        });

        wrapping_add_2_ext_circuit_constraints(
            builder,
            local_values.s_0,
            local_values.maj,
            &local_values.temp2,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        wrapping_add_2_ext_circuit_constraints(
            builder,
            local_values.state[get_input_range_4(3)].try_into().unwrap(),
            local_values.temp1.value,
            &local_values.d_add_temp1,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        wrapping_add_2_ext_circuit_constraints(
            builder,
            local_values.temp1.value,
            local_values.temp2.value,
            &local_values.temp1_add_temp2,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        // If this is not the final step or a padding row:
        let normal_round = builder.mul_extension(sum_round_flags, not_final);
        // the local and next timestamps must match.

        let diff = builder.sub_extension(next_values.timestamp, local_values.timestamp);
        let constraint = builder.mul_many_extension([sum_round_flags, not_final, diff]);
        yield_constr.constraint(builder, constraint);

        // the address of w_i must be increased by 4, except the last round
        let four_ext = builder.constant_extension(F::Extension::from_canonical_u8(4));
        let increment = builder.sub_extension(next_values.w_i_virt, local_values.w_i_virt);
        let address_increment = builder.sub_extension(increment, four_ext);
        let constraint = builder.mul_extension(normal_round, address_increment);
        yield_constr.constraint(builder, constraint);

        // Output constraint when it is not the final round or padding row
        // local.temp1 + local.temp2 = next.a
        equal_ext_circuit_constraints::<F, D, 4>(
            builder,
            local_values.temp1_add_temp2.value,
            next_values.state[get_input_range_4(0)].try_into().unwrap(),
        )
        .into_iter()
        .for_each(|c| {
            let constraint = builder.mul_extension(normal_round, c);
            yield_constr.constraint(builder, constraint)
        });

        // local.a = next.b
        equal_ext_circuit_constraints::<F, D, 4>(
            builder,
            local_values.state[get_input_range_4(0)].try_into().unwrap(),
            next_values.state[get_input_range_4(1)].try_into().unwrap(),
        )
        .into_iter()
        .for_each(|c| {
            let constraint = builder.mul_extension(normal_round, c);
            yield_constr.constraint(builder, constraint)
        });

        // local.b = next.c
        equal_ext_circuit_constraints::<F, D, 4>(
            builder,
            local_values.state[get_input_range_4(1)].try_into().unwrap(),
            next_values.state[get_input_range_4(2)].try_into().unwrap(),
        )
        .into_iter()
        .for_each(|c| {
            let constraint = builder.mul_extension(normal_round, c);
            yield_constr.constraint(builder, constraint)
        });

        // local.c = next.d
        equal_ext_circuit_constraints::<F, D, 4>(
            builder,
            local_values.state[get_input_range_4(2)].try_into().unwrap(),
            next_values.state[get_input_range_4(3)].try_into().unwrap(),
        )
        .into_iter()
        .for_each(|c| {
            let constraint = builder.mul_extension(normal_round, c);
            yield_constr.constraint(builder, constraint)
        });

        // local.d + local.temp1 = next.e
        equal_ext_circuit_constraints::<F, D, 4>(
            builder,
            local_values.d_add_temp1.value,
            next_values.state[get_input_range_4(4)].try_into().unwrap(),
        )
        .into_iter()
        .for_each(|c| {
            let constraint = builder.mul_extension(normal_round, c);
            yield_constr.constraint(builder, constraint)
        });

        // local.e = next.f
        equal_ext_circuit_constraints::<F, D, 4>(
            builder,
            local_values.state[get_input_range_4(4)].try_into().unwrap(),
            next_values.state[get_input_range_4(5)].try_into().unwrap(),
        )
        .into_iter()
        .for_each(|c| {
            let constraint = builder.mul_extension(normal_round, c);
            yield_constr.constraint(builder, constraint)
        });

        // local.f = next.g
        equal_ext_circuit_constraints::<F, D, 4>(
            builder,
            local_values.state[get_input_range_4(5)].try_into().unwrap(),
            next_values.state[get_input_range_4(6)].try_into().unwrap(),
        )
        .into_iter()
        .for_each(|c| {
            let constraint = builder.mul_extension(normal_round, c);
            yield_constr.constraint(builder, constraint)
        });

        // local.g = next.h
        equal_ext_circuit_constraints::<F, D, 4>(
            builder,
            local_values.state[get_input_range_4(6)].try_into().unwrap(),
            next_values.state[get_input_range_4(7)].try_into().unwrap(),
        )
        .into_iter()
        .for_each(|c| {
            let constraint = builder.mul_extension(normal_round, c);
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
    use crate::memory::segments::Segment;
    use crate::prover::prove_single_table;
    use crate::sha_compress::columns::ShaCompressColumnsView;
    use crate::sha_compress::sha_compress_stark::{ShaCompressStark, NUM_INPUTS};
    use crate::sha_compress_sponge::constants::{SHA_COMPRESS_K, SHA_COMPRESS_K_LE_BYTES};
    use crate::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};
    use crate::witness::memory::MemoryAddress;
    use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
    use itertools::Itertools;
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
        type S = ShaCompressStark<F, D>;

        let w = W;
        let h = H256_256;

        let mut input = vec![];
        for hx in h {
            input.extend(hx.to_le_bytes());
        }
        input.extend(w[0].to_le_bytes());
        input.extend(SHA_COMPRESS_K_LE_BYTES[0]);
        input.push(0);

        let w_0_address = MemoryAddress::new(0, Segment::Code, 123);

        let stark = S::default();
        let row =
            stark.generate_trace_rows_for_compress((input.try_into().unwrap(), w_0_address, 0));
        let local_values: &ShaCompressColumnsView<F> = row.borrow();

        assert_eq!(
            local_values.temp1_add_temp2.value,
            4228417613_u32.to_le_bytes().map(F::from_canonical_u8)
        );
        assert_eq!(
            local_values.d_add_temp1.value,
            2563236514_u32.to_le_bytes().map(F::from_canonical_u8)
        );

        Ok(())
    }

    #[test]
    fn test_stark_degree() -> anyhow::Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = ShaCompressStark<F, D>;

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
        type S = ShaCompressStark<F, D>;

        let stark = S {
            f: Default::default(),
        };
        test_stark_circuit_constraints::<F, C, S, D>(stark)
    }

    fn get_random_input() -> Vec<([u8; NUM_INPUTS], MemoryAddress, usize)> {
        let w_addresses: Vec<MemoryAddress> = (32..500)
            .step_by(4)
            .map(|i| MemoryAddress {
                context: 0,
                segment: 0,
                virt: i,
            })
            .collect();

        let mut res = vec![];

        let mut rng = rand::thread_rng();
        let hx: Vec<u32> = (0..8).map(|_| rng.gen()).collect();
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h]: [u32; 8] =
            hx.try_into().unwrap();

        for i in 0..64 {
            let state = [a, b, c, d, e, f, g, h]
                .iter()
                .flat_map(|x| (*x).to_le_bytes())
                .collect_vec();

            let mut input = vec![];
            input.extend(state.clone());
            input.extend(W[i].to_le_bytes());
            input.extend(SHA_COMPRESS_K_LE_BYTES[i]);
            input.push(i as u8);
            res.push((input.try_into().unwrap(), w_addresses[i], 1));

            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let w_i = W[i];

            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA_COMPRESS_K[i])
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

        let state = [a, b, c, d, e, f, g, h]
            .iter()
            .flat_map(|x| (*x).to_le_bytes())
            .collect_vec();

        let mut input = vec![];
        input.extend(state.clone());
        input.extend(0_u32.to_le_bytes());
        input.extend(0_u32.to_le_bytes());
        input.push(64_u8);

        res.push((input.try_into().unwrap(), w_addresses[64], 1));
        res
    }

    #[test]
    fn sha_extend_benchmark() -> anyhow::Result<()> {
        const NUM_EXTEND: usize = 64;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = ShaCompressStark<F, D>;
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
