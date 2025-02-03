use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cross_table_lookup::{Column, Filter};
use crate::evaluation_frame::{StarkEvaluationFrame, StarkFrame};
use crate::keccak::logic::{xor3_gen, xor3_gen_circuit, xor_gen, xor_gen_circuit};
use crate::sha_compress::columns::{
    ShaCompressColumnsView, NUM_SHA_COMPRESS_COLUMNS, SHA_COMPRESS_COL_MAP,
};
use crate::sha_compress::logic::{
    and_op, and_op_ext_circuit_constraints, and_op_packed_constraints, andn_op,
    andn_op_ext_circuit_constraints, andn_op_packed_constraints, equal_ext_circuit_constraints,
    equal_packed_constraint, xor_op,
};
use crate::sha_extend::logic::{
    get_input_range, rotate_right, rotate_right_ext_circuit_constraint,
    rotate_right_packed_constraints, wrapping_add, wrapping_add_ext_circuit_constraints,
    wrapping_add_packed_constraints, xor3,
};
use crate::stark::Stark;
use crate::util::trace_rows_to_poly_values;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use std::borrow::Borrow;
use std::marker::PhantomData;

pub const NUM_ROUND_CONSTANTS: usize = 64;

pub const NUM_INPUTS: usize = 10 * 32; // 8 states (a, b, ..., h) + w_i + key_i

pub fn ctl_data_inputs<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_COL_MAP;
    let mut res: Vec<_> = Column::singles(
        [
            cols.input_state.as_slice(),
            cols.w_i.as_slice(),
            cols.k_i.as_slice(),
        ]
        .concat(),
    )
    .collect();
    res.push(Column::single(cols.timestamp));
    res
}

pub fn ctl_data_outputs<F: Field>() -> Vec<Column<F>> {
    let cols = SHA_COMPRESS_COL_MAP;
    let mut res: Vec<_> = Column::singles(&cols.output_state).collect();
    res.push(Column::single(cols.timestamp));
    res
}

pub fn ctl_filter_inputs<F: Field>() -> Filter<F> {
    let cols = SHA_COMPRESS_COL_MAP;
    // not the padding rows.
    Filter::new_simple(Column::single(cols.is_normal_round))
}

pub fn ctl_filter_outputs<F: Field>() -> Filter<F> {
    let cols = SHA_COMPRESS_COL_MAP;
    // not the padding rows.
    Filter::new_simple(Column::single(cols.is_normal_round))
}

#[derive(Copy, Clone, Default)]
pub struct ShaCompressStark<F, const D: usize> {
    pub(crate) f: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> ShaCompressStark<F, D> {
    pub(crate) fn generate_trace(
        &self,
        inputs: Vec<([u8; NUM_INPUTS], usize)>,
        min_rows: usize,
    ) -> Vec<PolynomialValues<F>> {
        // Generate the witness row-wise
        let trace_rows = self.generate_trace_rows(inputs, min_rows);
        trace_rows_to_poly_values(trace_rows)
    }

    fn generate_trace_rows(
        &self,
        inputs_and_timestamps: Vec<([u8; NUM_INPUTS], usize)>,
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
        input_and_timestamp: ([u8; NUM_INPUTS], usize),
    ) -> [F; NUM_SHA_COMPRESS_COLUMNS] {
        let timestamp = input_and_timestamp.1;
        let inputs = input_and_timestamp.0;

        let mut row = ShaCompressColumnsView::<F>::default();
        row.timestamp = F::from_canonical_usize(timestamp);
        row.is_normal_round = F::ONE;
        // read inputs
        row.input_state = inputs[0..256]
            .iter()
            .map(|x| F::from_canonical_u8(*x))
            .collect::<Vec<F>>()
            .try_into()
            .unwrap();
        row.w_i = inputs[256..288]
            .iter()
            .map(|x| F::from_canonical_u8(*x))
            .collect::<Vec<F>>()
            .try_into()
            .unwrap();
        row.k_i = inputs[288..320]
            .iter()
            .map(|x| F::from_canonical_u8(*x))
            .collect::<Vec<F>>()
            .try_into()
            .unwrap();

        // compute
        row.e_rr_6 = rotate_right(row.input_state[get_input_range(4)].try_into().unwrap(), 6);
        row.e_rr_11 = rotate_right(row.input_state[get_input_range(4)].try_into().unwrap(), 11);
        row.e_rr_25 = rotate_right(row.input_state[get_input_range(4)].try_into().unwrap(), 25);
        row.s_1 = xor3(row.e_rr_6, row.e_rr_11, row.e_rr_25);

        row.e_and_f = and_op(
            row.input_state[get_input_range(4)].try_into().unwrap(),
            row.input_state[get_input_range(5)].try_into().unwrap(),
        );

        row.not_e_and_g = andn_op(
            row.input_state[get_input_range(4)].try_into().unwrap(),
            row.input_state[get_input_range(6)].try_into().unwrap(),
        );

        row.ch = xor_op(row.e_and_f, row.not_e_and_g);

        (row.inter_1, row.carry_1) = wrapping_add(
            row.input_state[get_input_range(7)].try_into().unwrap(),
            row.s_1,
        );

        (row.inter_2, row.carry_2) = wrapping_add(row.inter_1, row.ch);

        (row.inter_3, row.carry_3) = wrapping_add(row.inter_2, row.k_i);

        (row.temp1, row.carry_4) = wrapping_add(row.inter_3, row.w_i);

        row.a_rr_2 = rotate_right(row.input_state[get_input_range(0)].try_into().unwrap(), 2);
        row.a_rr_13 = rotate_right(row.input_state[get_input_range(0)].try_into().unwrap(), 13);
        row.a_rr_22 = rotate_right(row.input_state[get_input_range(0)].try_into().unwrap(), 22);
        row.s_0 = xor3(row.a_rr_2, row.a_rr_13, row.a_rr_22);

        row.b_and_c = and_op(
            row.input_state[get_input_range(1)].try_into().unwrap(),
            row.input_state[get_input_range(2)].try_into().unwrap(),
        );

        row.a_and_b = and_op(
            row.input_state[get_input_range(0)].try_into().unwrap(),
            row.input_state[get_input_range(1)].try_into().unwrap(),
        );

        row.a_and_c = and_op(
            row.input_state[get_input_range(0)].try_into().unwrap(),
            row.input_state[get_input_range(2)].try_into().unwrap(),
        );

        row.maj = xor3(row.a_and_b, row.a_and_c, row.b_and_c);
        (row.temp2, row.carry_5) = wrapping_add(row.s_0, row.maj);

        for i in 32..256 {
            row.output_state[i] = row.input_state[i - 32];
        }

        let new_e;
        let new_a;

        (new_e, row.carry_e) = wrapping_add(
            row.input_state[get_input_range(3)].try_into().unwrap(),
            row.temp1,
        );

        (new_a, row.carry_a) = wrapping_add(row.temp1, row.temp2);

        for i in 0..32 {
            row.output_state[i] = new_a[i];
            row.output_state[i + 32 * 4] = new_e[i];
        }

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

        // check the input binary form
        for i in 0..256 {
            yield_constr
                .constraint(local_values.input_state[i] * (local_values.input_state[i] - P::ONES));
        }
        for i in 0..32 {
            yield_constr.constraint(local_values.w_i[i] * (local_values.w_i[i] - P::ONES));
            yield_constr.constraint(local_values.k_i[i] * (local_values.k_i[i] - P::ONES));
        }

        // check the bit values are zero or one in output
        for i in 0..256 {
            yield_constr.constraint(
                local_values.output_state[i] * (local_values.output_state[i] - P::ONES),
            );
        }

        // check the rotation
        rotate_right_packed_constraints(
            local_values.input_state[get_input_range(4)]
                .try_into()
                .unwrap(),
            local_values.e_rr_6,
            6,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));
        rotate_right_packed_constraints(
            local_values.input_state[get_input_range(4)]
                .try_into()
                .unwrap(),
            local_values.e_rr_11,
            11,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));
        rotate_right_packed_constraints(
            local_values.input_state[get_input_range(4)]
                .try_into()
                .unwrap(),
            local_values.e_rr_25,
            25,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        rotate_right_packed_constraints(
            local_values.input_state[get_input_range(0)]
                .try_into()
                .unwrap(),
            local_values.a_rr_2,
            2,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));
        rotate_right_packed_constraints(
            local_values.input_state[get_input_range(0)]
                .try_into()
                .unwrap(),
            local_values.a_rr_13,
            13,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));
        rotate_right_packed_constraints(
            local_values.input_state[get_input_range(0)]
                .try_into()
                .unwrap(),
            local_values.a_rr_22,
            22,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        // check the xor
        for i in 0..32 {
            let s1 = xor3_gen(
                local_values.e_rr_6[i],
                local_values.e_rr_11[i],
                local_values.e_rr_25[i],
            );
            yield_constr.constraint(local_values.s_1[i] - s1);

            let s0 = xor3_gen(
                local_values.a_rr_2[i],
                local_values.a_rr_13[i],
                local_values.a_rr_22[i],
            );
            yield_constr.constraint(local_values.s_0[i] - s0);

            let ch = xor_gen(local_values.e_and_f[i], local_values.not_e_and_g[i]);
            yield_constr.constraint(local_values.ch[i] - ch);

            let maj = xor3_gen(
                local_values.a_and_b[i],
                local_values.a_and_c[i],
                local_values.b_and_c[i],
            );
            yield_constr.constraint(local_values.maj[i] - maj);
        }

        // wrapping add constraints

        wrapping_add_packed_constraints(
            local_values.input_state[get_input_range(7)]
                .try_into()
                .unwrap(),
            local_values.s_1,
            local_values.carry_1,
            local_values.inter_1,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        wrapping_add_packed_constraints(
            local_values.inter_1,
            local_values.ch,
            local_values.carry_2,
            local_values.inter_2,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        wrapping_add_packed_constraints(
            local_values.inter_2,
            local_values.k_i,
            local_values.carry_3,
            local_values.inter_3,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        wrapping_add_packed_constraints(
            local_values.inter_3,
            local_values.w_i,
            local_values.carry_4,
            local_values.temp1,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        wrapping_add_packed_constraints(
            local_values.s_0,
            local_values.maj,
            local_values.carry_5,
            local_values.temp2,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        wrapping_add_packed_constraints(
            local_values.input_state[get_input_range(3)]
                .try_into()
                .unwrap(),
            local_values.temp1,
            local_values.carry_e,
            local_values.output_state[get_input_range(4)]
                .try_into()
                .unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        wrapping_add_packed_constraints(
            local_values.temp1,
            local_values.temp2,
            local_values.carry_a,
            local_values.output_state[get_input_range(0)]
                .try_into()
                .unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        // The op constraints
        and_op_packed_constraints(
            local_values.input_state[get_input_range(4)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(5)]
                .try_into()
                .unwrap(),
            local_values.e_and_f,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        and_op_packed_constraints(
            local_values.input_state[get_input_range(0)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(1)]
                .try_into()
                .unwrap(),
            local_values.a_and_b,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        and_op_packed_constraints(
            local_values.input_state[get_input_range(0)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(2)]
                .try_into()
                .unwrap(),
            local_values.a_and_c,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        and_op_packed_constraints(
            local_values.input_state[get_input_range(1)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(2)]
                .try_into()
                .unwrap(),
            local_values.b_and_c,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        andn_op_packed_constraints(
            local_values.input_state[get_input_range(4)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(6)]
                .try_into()
                .unwrap(),
            local_values.not_e_and_g,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        // output constraint
        equal_packed_constraint::<P, 32>(
            local_values.output_state[get_input_range(1)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(0)]
                .try_into()
                .unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        equal_packed_constraint::<P, 32>(
            local_values.output_state[get_input_range(2)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(1)]
                .try_into()
                .unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        equal_packed_constraint::<P, 32>(
            local_values.output_state[get_input_range(3)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(2)]
                .try_into()
                .unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        // equal_packed_constraint(
        //     local_values.output_state[get_input_range(4)].try_into().unwrap(),
        //     local_values.input_state[get_input_range(3)].try_into().unwrap(),
        // ).into_iter().for_each(|c| yield_constr.constraint(c));

        equal_packed_constraint::<P, 32>(
            local_values.output_state[get_input_range(5)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(4)]
                .try_into()
                .unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        equal_packed_constraint::<P, 32>(
            local_values.output_state[get_input_range(6)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(5)]
                .try_into()
                .unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));

        equal_packed_constraint::<P, 32>(
            local_values.output_state[get_input_range(7)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(6)]
                .try_into()
                .unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(c));
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

        // check the input binary form
        for i in 0..256 {
            let constraint = builder.mul_sub_extension(
                local_values.input_state[i],
                local_values.input_state[i],
                local_values.input_state[i],
            );
            yield_constr.constraint(builder, constraint);
        }
        for i in 0..32 {
            let constraint = builder.mul_sub_extension(
                local_values.w_i[i],
                local_values.w_i[i],
                local_values.w_i[i],
            );
            yield_constr.constraint(builder, constraint);

            let constraint = builder.mul_sub_extension(
                local_values.k_i[i],
                local_values.k_i[i],
                local_values.k_i[i],
            );
            yield_constr.constraint(builder, constraint);
        }

        // check the bit values are zero or one in output
        for i in 0..256 {
            let constraint = builder.mul_sub_extension(
                local_values.output_state[i],
                local_values.output_state[i],
                local_values.output_state[i],
            );
            yield_constr.constraint(builder, constraint);
        }

        // check the rotation
        rotate_right_ext_circuit_constraint(
            builder,
            local_values.input_state[get_input_range(4)]
                .try_into()
                .unwrap(),
            local_values.e_rr_6,
            6,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));
        rotate_right_ext_circuit_constraint(
            builder,
            local_values.input_state[get_input_range(4)]
                .try_into()
                .unwrap(),
            local_values.e_rr_11,
            11,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));
        rotate_right_ext_circuit_constraint(
            builder,
            local_values.input_state[get_input_range(4)]
                .try_into()
                .unwrap(),
            local_values.e_rr_25,
            25,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        rotate_right_ext_circuit_constraint(
            builder,
            local_values.input_state[get_input_range(0)]
                .try_into()
                .unwrap(),
            local_values.a_rr_2,
            2,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));
        rotate_right_ext_circuit_constraint(
            builder,
            local_values.input_state[get_input_range(0)]
                .try_into()
                .unwrap(),
            local_values.a_rr_13,
            13,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));
        rotate_right_ext_circuit_constraint(
            builder,
            local_values.input_state[get_input_range(0)]
                .try_into()
                .unwrap(),
            local_values.a_rr_22,
            22,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        // check the xor
        for i in 0..32 {
            let s1 = xor3_gen_circuit(
                builder,
                local_values.e_rr_6[i],
                local_values.e_rr_11[i],
                local_values.e_rr_25[i],
            );
            let constraint = builder.sub_extension(local_values.s_1[i], s1);
            yield_constr.constraint(builder, constraint);

            let s0 = xor3_gen_circuit(
                builder,
                local_values.a_rr_2[i],
                local_values.a_rr_13[i],
                local_values.a_rr_22[i],
            );
            let constraint = builder.sub_extension(local_values.s_0[i], s0);
            yield_constr.constraint(builder, constraint);

            let ch = xor_gen_circuit(
                builder,
                local_values.e_and_f[i],
                local_values.not_e_and_g[i],
            );
            let constraint = builder.sub_extension(local_values.ch[i], ch);
            yield_constr.constraint(builder, constraint);

            let maj = xor3_gen_circuit(
                builder,
                local_values.a_and_b[i],
                local_values.a_and_c[i],
                local_values.b_and_c[i],
            );
            let constraint = builder.sub_extension(local_values.maj[i], maj);
            yield_constr.constraint(builder, constraint);
        }

        // wrapping add constraints

        wrapping_add_ext_circuit_constraints(
            builder,
            local_values.input_state[get_input_range(7)]
                .try_into()
                .unwrap(),
            local_values.s_1,
            local_values.carry_1,
            local_values.inter_1,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        wrapping_add_ext_circuit_constraints(
            builder,
            local_values.inter_1,
            local_values.ch,
            local_values.carry_2,
            local_values.inter_2,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        wrapping_add_ext_circuit_constraints(
            builder,
            local_values.inter_2,
            local_values.k_i,
            local_values.carry_3,
            local_values.inter_3,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        wrapping_add_ext_circuit_constraints(
            builder,
            local_values.inter_3,
            local_values.w_i,
            local_values.carry_4,
            local_values.temp1,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        wrapping_add_ext_circuit_constraints(
            builder,
            local_values.s_0,
            local_values.maj,
            local_values.carry_5,
            local_values.temp2,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        wrapping_add_ext_circuit_constraints(
            builder,
            local_values.input_state[get_input_range(3)]
                .try_into()
                .unwrap(),
            local_values.temp1,
            local_values.carry_e,
            local_values.output_state[get_input_range(4)]
                .try_into()
                .unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        wrapping_add_ext_circuit_constraints(
            builder,
            local_values.temp1,
            local_values.temp2,
            local_values.carry_a,
            local_values.output_state[get_input_range(0)]
                .try_into()
                .unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        // The op constraints
        and_op_ext_circuit_constraints(
            builder,
            local_values.input_state[get_input_range(4)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(5)]
                .try_into()
                .unwrap(),
            local_values.e_and_f,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        and_op_ext_circuit_constraints(
            builder,
            local_values.input_state[get_input_range(0)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(1)]
                .try_into()
                .unwrap(),
            local_values.a_and_b,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        and_op_ext_circuit_constraints(
            builder,
            local_values.input_state[get_input_range(0)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(2)]
                .try_into()
                .unwrap(),
            local_values.a_and_c,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        and_op_ext_circuit_constraints(
            builder,
            local_values.input_state[get_input_range(1)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(2)]
                .try_into()
                .unwrap(),
            local_values.b_and_c,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        andn_op_ext_circuit_constraints(
            builder,
            local_values.input_state[get_input_range(4)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(6)]
                .try_into()
                .unwrap(),
            local_values.not_e_and_g,
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        // output constraint
        equal_ext_circuit_constraints::<F, D, 32>(
            builder,
            local_values.output_state[get_input_range(1)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(0)]
                .try_into()
                .unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        equal_ext_circuit_constraints::<F, D, 32>(
            builder,
            local_values.output_state[get_input_range(2)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(1)]
                .try_into()
                .unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        equal_ext_circuit_constraints::<F, D, 32>(
            builder,
            local_values.output_state[get_input_range(3)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(2)]
                .try_into()
                .unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        // equal_packed_constraint(
        //     local_values.output_state[get_input_range(4)].try_into().unwrap(),
        //     local_values.input_state[get_input_range(3)].try_into().unwrap(),
        // ).into_iter().for_each(|c| yield_constr.constraint(c));

        equal_ext_circuit_constraints::<F, D, 32>(
            builder,
            local_values.output_state[get_input_range(5)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(4)]
                .try_into()
                .unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        equal_ext_circuit_constraints::<F, D, 32>(
            builder,
            local_values.output_state[get_input_range(6)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(5)]
                .try_into()
                .unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));

        equal_ext_circuit_constraints::<F, D, 32>(
            builder,
            local_values.output_state[get_input_range(7)]
                .try_into()
                .unwrap(),
            local_values.input_state[get_input_range(6)]
                .try_into()
                .unwrap(),
        )
        .into_iter()
        .for_each(|c| yield_constr.constraint(builder, c));
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
    use crate::sha_compress::columns::ShaCompressColumnsView;
    use crate::sha_compress::sha_compress_stark::{ShaCompressStark, NUM_INPUTS};
    use crate::sha_compress_sponge::constants::SHA_COMPRESS_K;
    use crate::sha_extend::logic::{from_u32_to_be_bits, get_input_range};
    use crate::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};
    use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::polynomial::PolynomialValues;
    use plonky2::field::types::Field;
    use plonky2::fri::oracle::PolynomialBatch;
    use plonky2::iop::challenger::Challenger;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::timed;
    use plonky2::util::timing::TimingTree;
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

    fn get_random_input() -> [u8; NUM_INPUTS] {
        let mut input = [0u8; NUM_INPUTS];
        for i in 0..NUM_INPUTS {
            input[i] = rand::random::<u8>() % 2;
            debug_assert!(input[i] == 0 || input[i] == 1);
        }
        input
    }

    #[test]
    fn test_generation() -> Result<(), String> {
        const D: usize = 2;
        type F = GoldilocksField;
        type S = ShaCompressStark<F, D>;

        let w = W;
        let h = H256_256;

        let mut input = vec![];
        for hx in h {
            input.extend(from_u32_to_be_bits(hx));
        }
        input.extend(from_u32_to_be_bits(w[0]));
        input.extend(from_u32_to_be_bits(SHA_COMPRESS_K[0]));

        let stark = S::default();
        let row = stark.generate_trace_rows_for_compress((input.try_into().unwrap(), 0));
        let local_values: &ShaCompressColumnsView<F> = row.borrow();

        assert_eq!(
            local_values.output_state[get_input_range(0)],
            from_u32_to_be_bits(4228417613)
                .iter()
                .map(|&x| F::from_canonical_u8(x))
                .collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_state[get_input_range(1)],
            from_u32_to_be_bits(1779033703)
                .iter()
                .map(|&x| F::from_canonical_u8(x))
                .collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_state[get_input_range(2)],
            from_u32_to_be_bits(3144134277)
                .iter()
                .map(|&x| F::from_canonical_u8(x))
                .collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_state[get_input_range(3)],
            from_u32_to_be_bits(1013904242)
                .iter()
                .map(|&x| F::from_canonical_u8(x))
                .collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_state[get_input_range(4)],
            from_u32_to_be_bits(2563236514)
                .iter()
                .map(|&x| F::from_canonical_u8(x))
                .collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_state[get_input_range(5)],
            from_u32_to_be_bits(1359893119)
                .iter()
                .map(|&x| F::from_canonical_u8(x))
                .collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_state[get_input_range(6)],
            from_u32_to_be_bits(2600822924)
                .iter()
                .map(|&x| F::from_canonical_u8(x))
                .collect::<Vec<F>>()
        );
        assert_eq!(
            local_values.output_state[get_input_range(7)],
            from_u32_to_be_bits(528734635)
                .iter()
                .map(|&x| F::from_canonical_u8(x))
                .collect::<Vec<F>>()
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

        let input: Vec<([u8; NUM_INPUTS], usize)> =
            (0..NUM_EXTEND).map(|_| (get_random_input(), 0)).collect();

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
