use std::marker::PhantomData;

use itertools::Itertools;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::timed;
use plonky2::util::timing::TimingTree;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cross_table_lookup::{Column, Filter};
use crate::evaluation_frame::{StarkEvaluationFrame, StarkFrame};
use crate::poseidon::columns::{
    reg_full0_s0, reg_full0_s1, reg_full1_s0, reg_full1_s1, reg_in, reg_out, reg_partial_s0,
    reg_partial_s1, FILTER, NUM_COLUMNS, TIMESTAMP,
};
use crate::poseidon::constants::{
    ALL_ROUND_CONSTANTS, FAST_PARTIAL_FIRST_ROUND_CONSTANT, FAST_PARTIAL_ROUND_CONSTANTS,
    FAST_PARTIAL_ROUND_INITIAL_MATRIX, FAST_PARTIAL_ROUND_VS, FAST_PARTIAL_ROUND_W_HATS,
    HALF_N_FULL_ROUNDS, MDS_MATRIX_CIRC, MDS_MATRIX_DIAG, N_PARTIAL_ROUNDS, N_ROUNDS, SPONGE_WIDTH,
};

use crate::stark::Stark;
use crate::util::trace_rows_to_poly_values;

pub fn ctl_data_inputs<F: Field>() -> Vec<Column<F>> {
    let mut res: Vec<_> = (0..SPONGE_WIDTH).map(reg_in).collect();
    res.push(TIMESTAMP);

    Column::singles(res).collect()
}

pub fn ctl_data_outputs<F: Field>() -> Vec<Column<F>> {
    let mut res: Vec<_> = (0..SPONGE_WIDTH).map(reg_out).collect();
    res.push(TIMESTAMP);

    Column::singles(res).collect()
}

pub fn ctl_filter_inputs<F: Field>() -> Filter<F> {
    Filter::new_simple(Column::single(FILTER))
}

pub fn ctl_filter_outputs<F: Field>() -> Filter<F> {
    Filter::new_simple(Column::single(FILTER))
}

pub fn poseidon_with_witness<F: PrimeField64>(
    input: &[F; SPONGE_WIDTH],
) -> ([F; SPONGE_WIDTH], [F; NUM_COLUMNS]) {
    let mut state = *input;
    let mut witness = [F::ZEROS; NUM_COLUMNS];
    let mut round_ctr = 0;

    full_rounds(&mut state, &mut witness, &mut round_ctr, true);
    partial_rounds(&mut state, &mut witness, &mut round_ctr);
    full_rounds(&mut state, &mut witness, &mut round_ctr, false);
    debug_assert_eq!(round_ctr, N_ROUNDS);

    (state, witness)
}
fn full_rounds<F: PrimeField64>(
    state: &mut [F; SPONGE_WIDTH],
    witness: &mut [F; NUM_COLUMNS],
    round_ctr: &mut usize,
    is_first_full_round: bool,
) {
    for r in 0..HALF_N_FULL_ROUNDS {
        constant_layer(state, *round_ctr);
        sbox_layer(state, witness, r, is_first_full_round);
        *state = mds_layer(state);
        *round_ctr += 1;
    }
}

fn partial_rounds<F: PrimeField64>(
    state: &mut [F; SPONGE_WIDTH],
    witness: &mut [F; NUM_COLUMNS],
    round_ctr: &mut usize,
) {
    partial_first_constant_layer(state);
    *state = mds_partial_layer_init(state);

    for i in 0..N_PARTIAL_ROUNDS {
        state[0] = sbox_monomial(state[0], witness, reg_partial_s0(i), reg_partial_s1(i));
        unsafe {
            state[0] = state[0].add_canonical_u64(FAST_PARTIAL_ROUND_CONSTANTS[i]);
        }
        *state = mds_partial_layer_fast(state, i);
    }
    *round_ctr += N_PARTIAL_ROUNDS;
}

#[derive(Copy, Clone, Default)]
pub struct PoseidonStark<F, const D: usize> {
    pub(crate) f: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> PoseidonStark<F, D> {
    /// Generate the rows of the trace. Note that this does not generate the permuted columns used
    /// in our lookup arguments, as those are computed after transposing to column-wise form.
    fn generate_trace_rows(
        &self,
        inputs_and_timestamps: Vec<([F; SPONGE_WIDTH], usize)>,
        min_rows: usize,
    ) -> Vec<[F; NUM_COLUMNS]> {
        let num_rows = inputs_and_timestamps
            .len()
            .max(min_rows)
            .next_power_of_two();

        let mut rows = Vec::with_capacity(num_rows);
        for input_and_timestamp in inputs_and_timestamps.iter() {
            let rows_for_perm = self.generate_trace_rows_for_perm(*input_and_timestamp, true);
            rows.push(rows_for_perm);
        }

        let default_row = self.generate_trace_rows_for_perm(([F::ZEROS; SPONGE_WIDTH], 0), false);
        while rows.len() < num_rows {
            rows.push(default_row);
        }
        rows
    }

    fn generate_trace_rows_for_perm(
        &self,
        input_and_timestamp: ([F; SPONGE_WIDTH], usize),
        need_ctl: bool,
    ) -> [F; NUM_COLUMNS] {
        let (hash, mut rows) = poseidon_with_witness(&input_and_timestamp.0);
        rows[FILTER] = F::from_bool(need_ctl);
        for i in 0..SPONGE_WIDTH {
            rows[reg_in(i)] = input_and_timestamp.0[i];
            rows[reg_out(i)] = hash[i];
        }
        // Set the timestamp of the current input.
        // It will be checked against the value in `KeccakSponge`.
        // The timestamp is used to link the input and output of
        // the same permutation together.
        rows[TIMESTAMP] = F::from_canonical_usize(input_and_timestamp.1);
        rows
    }

    pub fn generate_trace(
        &self,
        inputs: Vec<([F; SPONGE_WIDTH], usize)>,
        min_rows: usize,
        timing: &mut TimingTree,
    ) -> Vec<PolynomialValues<F>> {
        // Generate the witness, except for permuted columns in the lookup argument.
        let trace_rows = timed!(
            timing,
            "generate trace rows",
            self.generate_trace_rows(inputs, min_rows)
        );
        let trace_polys = timed!(
            timing,
            "convert to PolynomialValues",
            trace_rows_to_poly_values(trace_rows)
        );
        trace_polys
    }
}

fn constant_layer<F: Field>(state: &mut [F; SPONGE_WIDTH], round_ctr: usize) {
    for i in 0..SPONGE_WIDTH {
        let round_constant = ALL_ROUND_CONSTANTS[i + SPONGE_WIDTH * round_ctr];
        state[i] += F::from_canonical_u64(round_constant);
    }
}

fn constant_layer_field<P: PackedField>(state: &mut [P], round_ctr: usize) {
    for i in 0..SPONGE_WIDTH {
        state[i] +=
            P::Scalar::from_canonical_u64(ALL_ROUND_CONSTANTS[i + SPONGE_WIDTH * round_ctr]);
    }
}

fn constant_layer_circuit<F: RichField + Extendable<D>, const D: usize>(
    state: &mut [ExtensionTarget<D>],
    round_ctr: usize,
    builder: &mut CircuitBuilder<F, D>,
) {
    for i in 0..SPONGE_WIDTH {
        let c = F::Extension::from_canonical_u64(ALL_ROUND_CONSTANTS[i + SPONGE_WIDTH * round_ctr]);
        let c = builder.constant_extension(c);
        state[i] = builder.add_extension(state[i], c);
    }
}

fn sbox_field<P: PackedField>(
    input: P,
    inter: P,
    output: P,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    yield_constr.constraint(input * input * input - inter);
    yield_constr.constraint(input * inter * inter - output);
}

fn sbox_circuit<F: RichField + Extendable<D>, const D: usize>(
    input: ExtensionTarget<D>,
    inter: ExtensionTarget<D>,
    output: ExtensionTarget<D>,
    builder: &mut CircuitBuilder<F, D>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let cube = builder.cube_extension(input);
    let constraint = builder.sub_extension(cube, inter);
    yield_constr.constraint(builder, constraint);

    let out = builder.mul_many_extension([input, inter, inter]);
    let constraint = builder.sub_extension(out, output);
    yield_constr.constraint(builder, constraint);
}

fn sbox_layer<F: PrimeField64>(
    state: &mut [F; SPONGE_WIDTH],
    witness: &mut [F; NUM_COLUMNS],
    r: usize,
    is_first_full_round: bool,
) {
    for i in 0..SPONGE_WIDTH {
        let idx0 = if is_first_full_round {
            reg_full0_s0(r, i)
        } else {
            reg_full1_s0(r, i)
        };
        let idx1 = if is_first_full_round {
            reg_full0_s1(r, i)
        } else {
            reg_full1_s1(r, i)
        };
        state[i] = sbox_monomial(state[i], witness, idx0, idx1);
    }
}

fn sbox_monomial<F: PrimeField64>(
    x: F,
    witness: &mut [F; NUM_COLUMNS],
    idx0: usize,
    idx1: usize,
) -> F {
    let x3 = x.cube();
    let x6 = x3.square();
    let out = x.mul(x6);
    witness[idx0] = x3;
    witness[idx1] = out;
    out
}

fn sbox_layer_field<P: PackedField>(
    lv: &[P],
    state: &mut [P],
    r: usize,
    is_first_full_round: bool,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    for i in 0..SPONGE_WIDTH {
        let sbox_tmp = lv[if is_first_full_round {
            reg_full0_s0(r, i)
        } else {
            reg_full1_s0(r, i)
        }];
        let sbox_out = lv[if is_first_full_round {
            reg_full0_s1(r, i)
        } else {
            reg_full1_s1(r, i)
        }];
        sbox_field(state[i], sbox_tmp, sbox_out, yield_constr);

        state[i] = sbox_out;
    }
}

fn sbox_layer_circuit<F: RichField + Extendable<D>, const D: usize>(
    lv: &[ExtensionTarget<D>],
    state: &mut [ExtensionTarget<D>],
    r: usize,
    is_first_full_round: bool,
    builder: &mut CircuitBuilder<F, D>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    for i in 0..SPONGE_WIDTH {
        let sbox_tmp = lv[if is_first_full_round {
            reg_full0_s0(r, i)
        } else {
            reg_full1_s0(r, i)
        }];
        let sbox_out = lv[if is_first_full_round {
            reg_full0_s1(r, i)
        } else {
            reg_full1_s1(r, i)
        }];
        sbox_circuit(state[i], sbox_tmp, sbox_out, builder, yield_constr);

        state[i] = sbox_out;
    }
}

fn mds_layer_field<P: PackedField>(state: &mut [P]) {
    let res = (0..SPONGE_WIDTH)
        .map(|i| {
            (0..SPONGE_WIDTH)
                .map(|j| {
                    state[(j + i) % SPONGE_WIDTH]
                        * P::Scalar::from_canonical_u64(MDS_MATRIX_CIRC[j])
                })
                .chain([state[i] * P::Scalar::from_canonical_u64(MDS_MATRIX_DIAG[i])])
                .sum()
        })
        .collect_vec();

    state.copy_from_slice(&res);
}

fn mds_layer<F: PrimeField64>(state_: &[F; SPONGE_WIDTH]) -> [F; SPONGE_WIDTH] {
    let mut result = [F::ZERO; SPONGE_WIDTH];

    let mut state = [0u64; SPONGE_WIDTH];
    for r in 0..SPONGE_WIDTH {
        state[r] = state_[r].to_noncanonical_u64();
    }

    // This is a hacky way of fully unrolling the loop.
    for r in 0..12 {
        if r < SPONGE_WIDTH {
            let sum = mds_row_shf(r, &state);
            let sum_lo = sum as u64;
            let sum_hi = (sum >> 64) as u32;
            result[r] = F::from_noncanonical_u96((sum_lo, sum_hi));
        }
    }

    result
}

fn mds_row_shf(r: usize, v: &[u64; SPONGE_WIDTH]) -> u128 {
    debug_assert!(r < SPONGE_WIDTH);
    let mut res = 0u128;

    for i in 0..12 {
        if i < SPONGE_WIDTH {
            res += (v[(i + r) % SPONGE_WIDTH] as u128) * (MDS_MATRIX_CIRC[i] as u128);
        }
    }
    res += (v[r] as u128) * (MDS_MATRIX_DIAG[r] as u128);

    res
}

fn mds_layer_circuit<F: RichField + Extendable<D>, const D: usize>(
    state: &mut [ExtensionTarget<D>],
    builder: &mut CircuitBuilder<F, D>,
) {
    let res = (0..SPONGE_WIDTH)
        .map(|i| {
            let mut sum = (0..SPONGE_WIDTH)
                .map(|j| {
                    builder.mul_const_extension(
                        F::from_canonical_u64(MDS_MATRIX_CIRC[j]),
                        state[(j + i) % SPONGE_WIDTH],
                    )
                })
                .collect_vec();

            sum.push(
                builder.mul_const_extension(F::from_canonical_u64(MDS_MATRIX_DIAG[i]), state[i]),
            );

            builder.add_many_extension(sum)
        })
        .collect_vec();

    state.copy_from_slice(&res);
}

fn partial_first_constant_layer<P: PackedField>(state: &mut [P]) {
    for i in 0..SPONGE_WIDTH {
        state[i] += P::Scalar::from_canonical_u64(FAST_PARTIAL_FIRST_ROUND_CONSTANT[i]);
    }
}

fn partial_first_constant_layer_circuit<F: RichField + Extendable<D>, const D: usize>(
    state: &mut [ExtensionTarget<D>],
    builder: &mut CircuitBuilder<F, D>,
) {
    for i in 0..SPONGE_WIDTH {
        state[i] = builder.add_const_extension(
            state[i],
            F::from_canonical_u64(FAST_PARTIAL_FIRST_ROUND_CONSTANT[i]),
        );
    }
}

fn mds_partial_layer_init<F: PrimeField64>(state: &mut [F; SPONGE_WIDTH]) -> [F; SPONGE_WIDTH] {
    let mut result = [F::ZEROS; SPONGE_WIDTH];
    result[0] = state[0];

    for r in 1..SPONGE_WIDTH {
        for c in 1..SPONGE_WIDTH {
            let t = F::from_canonical_u64(FAST_PARTIAL_ROUND_INITIAL_MATRIX[r - 1][c - 1]);
            result[c] += state[r] * t;
        }
    }
    result
}

fn mds_partial_layer_init_field<P: PackedField>(state: &mut [P]) {
    let mut result = [P::default(); SPONGE_WIDTH];
    result[0] = state[0];

    for r in 1..12 {
        for c in 1..12 {
            let t = P::Scalar::from_canonical_u64(FAST_PARTIAL_ROUND_INITIAL_MATRIX[r - 1][c - 1]);
            result[c] += state[r] * t;
        }
    }

    state.copy_from_slice(&result);
}

fn mds_partial_layer_init_circuit<F: RichField + Extendable<D>, const D: usize>(
    state: &mut [ExtensionTarget<D>],
    builder: &mut CircuitBuilder<F, D>,
) {
    let mut result = [builder.zero_extension(); SPONGE_WIDTH];
    result[0] = state[0];

    for r in 1..12 {
        for c in 1..12 {
            result[c] = builder.mul_const_add_extension(
                F::from_canonical_u64(FAST_PARTIAL_ROUND_INITIAL_MATRIX[r - 1][c - 1]),
                state[r],
                result[c],
            );
        }
    }

    state.copy_from_slice(&result);
}

fn partial_sbox_layer<P: PackedField>(
    lv: &[P],
    state: &mut [P],
    r: usize,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let sbox_inter = lv[reg_partial_s0(r)];
    let sbox_out = lv[reg_partial_s1(r)];

    sbox_field(state[0], sbox_inter, sbox_out, yield_constr);

    state[0] = sbox_out;
}

fn partial_sbox_layer_circuit<F: RichField + Extendable<D>, const D: usize>(
    lv: &[ExtensionTarget<D>],
    state: &mut [ExtensionTarget<D>],
    r: usize,
    builder: &mut CircuitBuilder<F, D>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let sbox_inter = lv[reg_partial_s0(r)];
    let sbox_out = lv[reg_partial_s1(r)];
    sbox_circuit(state[0], sbox_inter, sbox_out, builder, yield_constr);
    state[0] = sbox_out;
}

fn mds_partial_layer_fast<F: PrimeField64>(
    state: &mut [F; SPONGE_WIDTH],
    r: usize,
) -> [F; SPONGE_WIDTH] {
    let mut d_sum = (0u128, 0u32); // u160 accumulator
    for i in 1..SPONGE_WIDTH {
        let t = FAST_PARTIAL_ROUND_W_HATS[r][i - 1] as u128;
        let si = state[i].to_noncanonical_u64() as u128;
        d_sum = add_u160_u128(d_sum, si * t);
    }
    let s0 = state[0].to_noncanonical_u64() as u128;
    let mds0to0 = (MDS_MATRIX_CIRC[0] + MDS_MATRIX_DIAG[0]) as u128;
    d_sum = add_u160_u128(d_sum, s0 * mds0to0);
    let d = reduce_u160::<F>(d_sum);

    let mut result = [F::ZEROS; SPONGE_WIDTH];
    result[0] = d;
    for i in 1..12 {
        if i < SPONGE_WIDTH {
            let t = F::from_canonical_u64(FAST_PARTIAL_ROUND_VS[r][i - 1]);
            result[i] = state[i].multiply_accumulate(state[0], t);
        }
    }
    result
}

const fn add_u160_u128((x_lo, x_hi): (u128, u32), y: u128) -> (u128, u32) {
    let (res_lo, over) = x_lo.overflowing_add(y);
    let res_hi = x_hi + (over as u32);
    (res_lo, res_hi)
}

fn reduce_u160<F: PrimeField64>((n_lo, n_hi): (u128, u32)) -> F {
    let n_lo_hi = (n_lo >> 64) as u64;
    let n_lo_lo = n_lo as u64;
    let reduced_hi: u64 = F::from_noncanonical_u96((n_lo_hi, n_hi)).to_noncanonical_u64();
    let reduced128: u128 = ((reduced_hi as u128) << 64) + (n_lo_lo as u128);
    F::from_noncanonical_u128(reduced128)
}

fn mds_partial_layer_fast_field<P: PackedField>(state: &mut [P], r: usize) {
    let s0 = state[0];
    let mds0to0 = MDS_MATRIX_CIRC[0] + MDS_MATRIX_DIAG[0];
    let mut d = s0 * P::Scalar::from_canonical_u64(mds0to0);
    for i in 1..SPONGE_WIDTH {
        let t = P::Scalar::from_canonical_u64(FAST_PARTIAL_ROUND_W_HATS[r][i - 1]);
        d += state[i] * t;
    }

    let mut result = [P::default(); SPONGE_WIDTH];
    result[0] = d;
    for i in 1..SPONGE_WIDTH {
        let t = P::Scalar::from_canonical_u64(FAST_PARTIAL_ROUND_VS[r][i - 1]);
        result[i] = state[0] * t + state[i];
    }
    state.copy_from_slice(&result);
}

fn mds_partial_layer_fast_circuit<F: RichField + Extendable<D>, const D: usize>(
    state: &mut [ExtensionTarget<D>],
    r: usize,
    builder: &mut CircuitBuilder<F, D>,
) {
    let s0 = state[0];
    let mds0to0 = MDS_MATRIX_CIRC[0] + MDS_MATRIX_DIAG[0];

    let mut d = (1..SPONGE_WIDTH)
        .map(|i| {
            builder.mul_const_extension(
                F::from_canonical_u64(FAST_PARTIAL_ROUND_W_HATS[r][i - 1]),
                state[i],
            )
        })
        .collect_vec();
    d.push(builder.mul_const_extension(F::from_canonical_u64(mds0to0), s0));
    let d = builder.add_many_extension(d);

    let result = (1..SPONGE_WIDTH)
        .map(|i| {
            builder.mul_const_add_extension(
                F::from_canonical_u64(FAST_PARTIAL_ROUND_VS[r][i - 1]),
                state[0],
                state[i],
            )
        })
        .collect_vec();

    state[0] = d;
    state[1..].copy_from_slice(&result);
}

fn eval_packed_generic<P: PackedField>(lv: &[P], yield_constr: &mut ConstraintConsumer<P>) {
    let mut state = [P::default(); SPONGE_WIDTH];
    let input = (0..SPONGE_WIDTH).map(|i| lv[reg_in(i)]).collect_vec();
    state.copy_from_slice(&input);

    let mut round_ctr = 0;
    // First set of full rounds.
    for r in 0..HALF_N_FULL_ROUNDS {
        constant_layer_field(&mut state, round_ctr);
        sbox_layer_field(lv, &mut state, r, true, yield_constr);
        mds_layer_field(&mut state);

        round_ctr += 1;
    }

    // partial rounds
    partial_first_constant_layer(&mut state);
    mds_partial_layer_init_field(&mut state);
    for r in 0..N_PARTIAL_ROUNDS - 1 {
        partial_sbox_layer(lv, &mut state, r, yield_constr);
        state[0] += P::Scalar::from_canonical_u64(FAST_PARTIAL_ROUND_CONSTANTS[r]);
        mds_partial_layer_fast_field(&mut state, r);
    }
    partial_sbox_layer(lv, &mut state, N_PARTIAL_ROUNDS - 1, yield_constr);
    mds_partial_layer_fast_field(&mut state, N_PARTIAL_ROUNDS - 1);

    round_ctr += N_PARTIAL_ROUNDS;

    // full round
    for r in 0..HALF_N_FULL_ROUNDS {
        constant_layer_field(&mut state, round_ctr);
        sbox_layer_field(lv, &mut state, r, false, yield_constr);
        mds_layer_field(&mut state);

        round_ctr += 1;
    }

    for i in 0..SPONGE_WIDTH {
        yield_constr.constraint(state[i] - lv[reg_out(i)]);
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for PoseidonStark<F, D> {
    type EvaluationFrame<FE, P, const D2: usize> = StarkFrame<P, NUM_COLUMNS>
        where
            FE: FieldExtension<D2, BaseField = F>,
            P: PackedField<Scalar = FE>;

    type EvaluationFrameTarget = StarkFrame<ExtensionTarget<D>, NUM_COLUMNS>;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: &Self::EvaluationFrame<FE, P, D2>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        let lv = vars.get_local_values();
        eval_packed_generic(lv, yield_constr);
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: &Self::EvaluationFrameTarget,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        let lv = vars.get_local_values();

        let zero = builder.zero_extension();
        let mut state = [zero; SPONGE_WIDTH];
        let input = (0..SPONGE_WIDTH).map(|i| lv[reg_in(i)]).collect_vec();
        state.copy_from_slice(&input);

        let mut round_ctr = 0;
        // First set of full rounds.
        for r in 0..HALF_N_FULL_ROUNDS {
            constant_layer_circuit(&mut state, round_ctr, builder);
            sbox_layer_circuit(lv, &mut state, r, true, builder, yield_constr);
            mds_layer_circuit(&mut state, builder);

            round_ctr += 1;
        }

        // partial rounds
        partial_first_constant_layer_circuit(&mut state, builder);
        mds_partial_layer_init_circuit(&mut state, builder);
        for r in 0..N_PARTIAL_ROUNDS - 1 {
            partial_sbox_layer_circuit(lv, &mut state, r, builder, yield_constr);
            state[0] = builder.add_const_extension(
                state[0],
                F::from_canonical_u64(FAST_PARTIAL_ROUND_CONSTANTS[r]),
            );
            mds_partial_layer_fast_circuit(&mut state, r, builder);
        }
        partial_sbox_layer_circuit(lv, &mut state, N_PARTIAL_ROUNDS - 1, builder, yield_constr);
        mds_partial_layer_fast_circuit(&mut state, N_PARTIAL_ROUNDS - 1, builder);

        round_ctr += N_PARTIAL_ROUNDS;

        // full round
        for r in 0..HALF_N_FULL_ROUNDS {
            constant_layer_circuit(&mut state, round_ctr, builder);
            sbox_layer_circuit(lv, &mut state, r, false, builder, yield_constr);
            mds_layer_circuit(&mut state, builder);

            round_ctr += 1;
        }

        for i in 0..SPONGE_WIDTH {
            let z = builder.sub_extension(state[i], lv[reg_out(i)]);
            yield_constr.constraint(builder, z);
        }
    }

    fn constraint_degree(&self) -> usize {
        3
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::polynomial::PolynomialValues;
    use plonky2::field::types::{Field, Sample};
    use plonky2::fri::oracle::PolynomialBatch;
    use plonky2::iop::challenger::Challenger;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::timed;
    use plonky2::util::timing::TimingTree;

    use crate::config::StarkConfig;
    use crate::constraint_consumer::ConstraintConsumer;
    use crate::cross_table_lookup::{
        Column, CtlData, CtlZData, Filter, GrandProductChallenge, GrandProductChallengeSet,
    };
    use crate::poseidon::constants::SPONGE_WIDTH;
    use crate::poseidon::poseidon_stark::{eval_packed_generic, PoseidonStark};
    use crate::prover::prove_single_table;
    use crate::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};

    #[test]
    fn test_stark_degree() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = PoseidonStark<F, D>;

        let stark = S {
            f: Default::default(),
        };
        test_stark_low_degree(stark)
    }

    #[test]
    fn test_stark_circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = PoseidonStark<F, D>;

        let stark = S {
            f: Default::default(),
        };
        test_stark_circuit_constraints::<F, C, S, D>(stark)
    }

    #[test]
    fn test_eval_consistency() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = PoseidonStark<F, D>;
        let stark = S::default();

        init_logger();

        let input: ([F; SPONGE_WIDTH], usize) = (F::rand_array(), 0);
        let rows = stark.generate_trace_rows(vec![input], 4);

        let mut constraint_consumer = ConstraintConsumer::new(
            vec![GoldilocksField(2), GoldilocksField(3), GoldilocksField(5)],
            GoldilocksField::ONE,
            GoldilocksField::ZERO,
            GoldilocksField::ZERO,
        );
        eval_packed_generic(&rows[0], &mut constraint_consumer);
        for &acc in &constraint_consumer.constraint_accs {
            assert_eq!(acc, GoldilocksField::ZERO);
        }
    }

    #[test]
    fn poseidon_benchmark() -> Result<()> {
        const NUM_PERMS: usize = 100;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = PoseidonStark<F, D>;
        let stark = S::default();
        let config = StarkConfig::standard_fast_config();

        init_logger();

        let input: Vec<([F; SPONGE_WIDTH], usize)> =
            (0..NUM_PERMS).map(|_| (F::rand_array(), 0)).collect();

        let mut timing = TimingTree::new("prove", log::Level::Debug);
        let trace_poly_values = timed!(
            timing,
            "generate trace",
            stark.generate_trace(input, 8, &mut timing)
        );

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
