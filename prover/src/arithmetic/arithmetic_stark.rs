use std::marker::PhantomData;
use std::ops::Range;

use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::util::transpose;
use static_assertions::const_assert;

use super::columns::{NUM_ARITH_COLUMNS, NUM_SHARED_COLS};
use super::shift;
use crate::all_stark::Table;
use crate::arithmetic::columns::{RANGE_COUNTER, RC_FREQUENCIES, SHARED_COLS};
use crate::arithmetic::{addcy, columns, div, lo_hi, lui, mul, mult, slt, sra, Operation};
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cross_table_lookup::{Column, Filter, TableWithColumns};
use crate::evaluation_frame::{StarkEvaluationFrame, StarkFrame};
use crate::lookup::Lookup;
use crate::stark::Stark;

/// Link the 16-bit columns of the arithmetic table, split into groups
/// of N_LIMBS at a time in `regs`, with the corresponding 32-bit
/// columns of the CPU table. Does this for all ops in `ops`.
///
/// This is done by taking pairs of columns (x, y) of the arithmetic
/// table and combining them as x + y*2^16 to ensure they equal the
/// corresponding 32-bit number in the CPU table.
fn cpu_arith_data_link<F: Field>(
    combined_ops: &[(usize, u32)],
    regs: &[Range<usize>],
) -> Vec<Column<F>> {
    let limb_base = F::from_canonical_u64(1 << columns::LIMB_BITS);

    let mut res = vec![Column::linear_combination(
        combined_ops
            .iter()
            .map(|&(col, code)| (col, F::from_canonical_u32(code))),
    )];

    // The inner for loop below assumes N_LIMBS is even.
    const_assert!(columns::N_LIMBS % 2 == 0);

    for reg_cols in regs {
        // Loop below assumes we're operating on a "register" of N_LIMBS columns.
        debug_assert_eq!(reg_cols.len(), columns::N_LIMBS);

        for i in 0..(columns::N_LIMBS / 2) {
            let c0 = reg_cols.start + 2 * i;
            let c1 = reg_cols.start + 2 * i + 1;
            res.push(Column::linear_combination([(c0, F::ONE), (c1, limb_base)]));
        }
    }

    res
}

pub fn ctl_arithmetic_rows<F: Field>() -> TableWithColumns<F> {
    // We scale each filter flag with the associated opcode value.
    // If an arithmetic operation is happening on the CPU side,
    // the CTL will enforce that the reconstructed opcode value
    // from the opcode bits matches.
    const COMBINED_OPS: [(usize, u32); 26] = [
        (columns::IS_ADD, 0b100000 * (1 << 6)),
        (columns::IS_ADDU, 0b100001 * (1 << 6)),
        (columns::IS_ADDI, 0b001000),
        (columns::IS_ADDIU, 0b001001),
        (columns::IS_SUB, 0b100010 * (1 << 6)),
        (columns::IS_SUBU, 0b100011 * (1 << 6)),
        (columns::IS_MULT, 0b011000 * (1 << 6)),
        (columns::IS_MULTU, 0b011001 * (1 << 6)),
        (columns::IS_MUL, 0b011100 + 0b000010 * (1 << 6)),
        (columns::IS_DIV, 0b011010 * (1 << 6)),
        (columns::IS_DIVU, 0b011011 * (1 << 6)),
        (columns::IS_SLLV, 0b000100 * (1 << 6)),
        (columns::IS_SRLV, 0b000110 * (1 << 6)),
        (columns::IS_SRAV, 0b000111 * (1 << 6)),
        #[allow(clippy::erasing_op)]
        (columns::IS_SLL, 0b000000 * (1 << 6)),
        (columns::IS_SRL, 0b000010 * (1 << 6)),
        (columns::IS_SRA, 0b000011 * (1 << 6)),
        (columns::IS_SLT, 0b101010 * (1 << 6)),
        (columns::IS_SLTU, 0b101011 * (1 << 6)),
        (columns::IS_SLTI, 0b001010),
        (columns::IS_SLTIU, 0b001011),
        (columns::IS_LUI, 0b001111),
        (columns::IS_MFHI, 0b010000 * (1 << 6)),
        (columns::IS_MTHI, 0b010001 * (1 << 6)),
        (columns::IS_MFLO, 0b010010 * (1 << 6)),
        (columns::IS_MTLO, 0b010011 * (1 << 6)),
    ];

    const REGISTER_MAP: [Range<usize>; 3] = [
        columns::INPUT_REGISTER_0,
        columns::INPUT_REGISTER_1,
        columns::OUTPUT_REGISTER,
    ];

    let filter = Some(Filter::new_simple(Column::sum(
        COMBINED_OPS.iter().map(|(c, _v)| *c),
    )));

    // Create the Arithmetic Table whose columns are those of the
    // operations listed in `ops` whose inputs and outputs are given
    // by `regs`, where each element of `regs` is a range of columns
    // corresponding to a 256-bit input or output register (also `ops`
    // is used as the operation filter).
    TableWithColumns::new(
        Table::Arithmetic,
        cpu_arith_data_link(&COMBINED_OPS, &REGISTER_MAP),
        filter,
    )
}

#[derive(Copy, Clone, Default)]
pub struct ArithmeticStark<F, const D: usize> {
    pub f: PhantomData<F>,
}

const RANGE_MAX: usize = 1usize << 16; // Range check strict upper bound

impl<F: RichField, const D: usize> ArithmeticStark<F, D> {
    /// Expects input in *column*-major layout
    fn generate_range_checks(&self, cols: &mut [Vec<F>]) {
        debug_assert!(cols.len() == columns::NUM_ARITH_COLUMNS);

        let n_rows = cols[0].len();
        debug_assert!(cols.iter().all(|col| col.len() == n_rows));

        for i in 0..RANGE_MAX {
            cols[RANGE_COUNTER][i] = F::from_canonical_usize(i);
        }
        for i in RANGE_MAX..n_rows {
            cols[RANGE_COUNTER][i] = F::from_canonical_usize(RANGE_MAX - 1);
        }

        // Generate the frequencies column.
        for col in SHARED_COLS {
            for i in 0..n_rows {
                let x = cols[col][i].to_canonical_u64() as usize;
                assert!(
                    x < RANGE_MAX,
                    "column value {} exceeds the max range value {}",
                    x,
                    RANGE_MAX
                );
                cols[RC_FREQUENCIES][x] += F::ONE;
            }
        }
    }

    pub(crate) fn generate_trace(&self, operations: Vec<Operation>) -> Vec<PolynomialValues<F>> {
        // The number of rows reserved is the smallest value that's
        // guaranteed to avoid a reallocation: The only ops that use
        // two rows are the modular operations and DIV, so the only
        // way to reach capacity is when every op is modular or DIV
        // (which is obviously unlikely in normal
        // circumstances). (Also need at least RANGE_MAX rows to
        // accommodate range checks.)
        let max_rows = std::cmp::max(2 * operations.len(), RANGE_MAX);
        let mut trace_rows = Vec::with_capacity(max_rows);

        for op in operations {
            let (row1, maybe_row2) = op.to_rows();
            trace_rows.push(row1);

            if let Some(row2) = maybe_row2 {
                trace_rows.push(row2);
            }
        }

        // Pad the trace with zero rows if it doesn't have enough rows
        // to accommodate the range check columns. Also make sure the
        // trace length is a power of two.
        let padded_len = trace_rows.len().next_power_of_two();
        for _ in trace_rows.len()..std::cmp::max(padded_len, RANGE_MAX) {
            trace_rows.push(vec![F::ZERO; columns::NUM_ARITH_COLUMNS]);
        }

        let mut trace_cols = transpose(&trace_rows);
        self.generate_range_checks(&mut trace_cols);

        trace_cols.into_iter().map(PolynomialValues::new).collect()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for ArithmeticStark<F, D> {
    type EvaluationFrame<FE, P, const D2: usize> = StarkFrame<P, NUM_ARITH_COLUMNS>
    where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>;

    type EvaluationFrameTarget = StarkFrame<ExtensionTarget<D>, NUM_ARITH_COLUMNS>;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: &Self::EvaluationFrame<FE, P, D2>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        let lv: &[P; NUM_ARITH_COLUMNS] = vars.get_local_values().try_into().unwrap();
        let nv: &[P; NUM_ARITH_COLUMNS] = vars.get_next_values().try_into().unwrap();

        // Check the range column: First value must be 0, last row
        // must be 2^16-1, and intermediate rows must increment by 0
        // or 1.
        let rc1 = lv[RANGE_COUNTER];
        let rc2 = nv[RANGE_COUNTER];
        yield_constr.constraint_first_row(rc1);
        let incr = rc2 - rc1;
        yield_constr.constraint_transition(incr * incr - incr);
        let range_max = P::Scalar::from_canonical_u64((RANGE_MAX - 1) as u64);
        yield_constr.constraint_last_row(rc1 - range_max);

        mul::eval_packed_generic(lv, yield_constr);
        mult::eval_packed_generic(lv, yield_constr);
        addcy::eval_packed_generic(lv, yield_constr);
        slt::eval_packed_generic(lv, yield_constr);
        lui::eval_packed_generic(lv, nv, yield_constr);
        div::eval_packed(lv, nv, yield_constr);
        shift::eval_packed_generic(lv, nv, yield_constr);
        sra::eval_packed_generic(lv, nv, yield_constr);
        lo_hi::eval_packed_generic(lv, yield_constr);
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: &Self::EvaluationFrameTarget,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        let lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS] =
            vars.get_local_values().try_into().unwrap();
        let nv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS] =
            vars.get_next_values().try_into().unwrap();

        let rc1 = lv[RANGE_COUNTER];
        let rc2 = nv[RANGE_COUNTER];
        yield_constr.constraint_first_row(builder, rc1);
        let incr = builder.sub_extension(rc2, rc1);
        let t = builder.mul_sub_extension(incr, incr, incr);
        yield_constr.constraint_transition(builder, t);
        let range_max =
            builder.constant_extension(F::Extension::from_canonical_usize(RANGE_MAX - 1));
        let t = builder.sub_extension(rc1, range_max);
        yield_constr.constraint_last_row(builder, t);

        mul::eval_ext_circuit(builder, lv, yield_constr);
        mult::eval_ext_circuit(builder, lv, yield_constr);
        addcy::eval_ext_circuit(builder, lv, yield_constr);
        slt::eval_ext_circuit(builder, lv, yield_constr);
        lui::eval_ext_circuit(builder, lv, nv, yield_constr);
        div::eval_ext_circuit(builder, lv, nv, yield_constr);
        shift::eval_ext_circuit(builder, lv, nv, yield_constr);
        sra::eval_ext_circuit(builder, lv, nv, yield_constr);
        lo_hi::eval_ext_circuit(builder, lv, yield_constr);
    }

    fn constraint_degree(&self) -> usize {
        3
    }

    fn lookups(&self) -> Vec<Lookup<F>> {
        vec![Lookup {
            columns: Column::singles(SHARED_COLS).collect(),
            table_column: Column::single(RANGE_COUNTER),
            frequencies_column: Column::single(RC_FREQUENCIES),
            filter_columns: vec![None; NUM_SHARED_COLS],
        }]
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use itertools::Itertools;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use crate::arithmetic::arithmetic_stark::ArithmeticStark;
    use crate::arithmetic::columns::OUTPUT_REGISTER;
    use crate::arithmetic::*;
    use crate::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};

    #[test]
    fn degree() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = ArithmeticStark<F, D>;

        let stark = S {
            f: Default::default(),
        };
        test_stark_low_degree(stark)
    }

    #[test]
    fn circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = ArithmeticStark<F, D>;

        let stark = S {
            f: Default::default(),
        };
        test_stark_circuit_constraints::<F, C, S, D>(stark)
    }

    #[test]
    fn basic_trace() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = ArithmeticStark<F, D>;

        let stark = S {
            f: Default::default(),
        };

        // 123 + 456 == 579
        let add = Operation::binary(BinaryOperator::ADD, 123, 456);
        // 123 * 456 == 56088
        let mul = Operation::binary(BinaryOperator::MUL, 123, 456);
        // 128 / 13 == 9
        let div0 = Operation::binary(BinaryOperator::DIV, 128, 13);
        // -128 / 13 == -9
        let div1 = Operation::binary(BinaryOperator::DIV, -128i32 as u32, 13);
        // 3526433982 / 14202 == 248305
        let divu = Operation::binary(BinaryOperator::DIVU, 3526433982, 14202);
        // 123 * 456 == 56088
        let mult0 = Operation::binary(BinaryOperator::MULT, 123, 456);
        // -123 * 456 == -56088
        let mult1 = Operation::binary(BinaryOperator::MULT, -123i32 as u32, 456);
        // 123 * 456 == 56088
        let multu = Operation::binary(BinaryOperator::MULTU, 123, 456);

        let ops: Vec<Operation> = vec![add, mul, div0, div1, divu, mult0, mult1, multu];

        let pols = stark.generate_trace(ops);

        // Trace should always have NUM_ARITH_COLUMNS columns and
        // min(RANGE_MAX, operations.len()) rows. In this case there
        // are only 6 rows, so we should have RANGE_MAX rows.
        assert!(
            pols.len() == columns::NUM_ARITH_COLUMNS
                && pols.iter().all(|v| v.len() == super::RANGE_MAX)
        );

        // Each operation has a single word answer that we can check
        let expected_output = [
            // Row (some ops take two rows), expected
            (0, [579u64, 0]), // ADD_OUTPUT
            (1, [56088, 0]),
            (2, [9, 0]),
            (4, [65527, 65535]),
            (6, [51697, 3]),
            (8, [56088, 0]),
            (9, [9448, 65535]),
            (10, [56088, 0]),
        ];

        for (row, expected) in expected_output {
            // OUTPUT registers should match expected value...
            for (expected, col) in expected.into_iter().zip_eq(OUTPUT_REGISTER) {
                let out = pols[col].values[row].to_canonical_u64();
                assert_eq!(
                    out, expected,
                    "expected column {} on row {} to be {} but it was {}",
                    col, row, expected, out,
                );
            }
        }
    }

    #[test]
    fn big_traces() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = ArithmeticStark<F, D>;

        let stark = S {
            f: Default::default(),
        };

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);

        let ops = (0..super::RANGE_MAX)
            .map(|_| Operation::binary(BinaryOperator::MULT, rng.gen::<u32>(), rng.gen::<u32>()))
            .collect::<Vec<_>>();

        let pols = stark.generate_trace(ops);

        // Trace should always have NUM_ARITH_COLUMNS columns and
        // min(RANGE_MAX, operations.len()) rows. In this case there
        // are RANGE_MAX operations with one row each, so RANGE_MAX.
        assert!(
            pols.len() == columns::NUM_ARITH_COLUMNS
                && pols.iter().all(|v| v.len() == super::RANGE_MAX)
        );
    }
}
