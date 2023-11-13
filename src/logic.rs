use std::marker::PhantomData;

use itertools::izip;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2_util::ceil_div_usize;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cross_table_lookup::Column;
use crate::evaluation_frame::{StarkEvaluationFrame, StarkFrame};
use crate::logic::columns::NUM_COLUMNS;
use crate::stark::Stark;
use crate::util::{limb_from_bits_le, limb_from_bits_le_recursive, trace_rows_to_poly_values};

const VAL_BITS: usize = 32;
// Number of bits stored per field element. Ensure that this fits; it is not checked.
pub(crate) const PACKED_LIMB_BITS: usize = 32;
// Number of field elements needed to store each input/output at the specified packing.
const PACKED_LEN: usize = ceil_div_usize(VAL_BITS, PACKED_LIMB_BITS);

pub(crate) mod columns {
    use std::cmp::min;
    use std::ops::Range;

    use super::{PACKED_LEN, PACKED_LIMB_BITS, VAL_BITS};

    pub const IS_AND: usize = 0;
    pub const IS_OR: usize = IS_AND + 1;
    pub const IS_XOR: usize = IS_OR + 1;
    pub const IS_NOR: usize = IS_XOR + 1;
    // The inputs are decomposed into bits.
    pub const INPUT0: Range<usize> = (IS_XOR + 1)..(IS_XOR + 1) + VAL_BITS;
    pub const INPUT1: Range<usize> = INPUT0.end..INPUT0.end + VAL_BITS;
    // The result is packed in limbs of `PACKED_LIMB_BITS` bits.
    pub const RESULT: Range<usize> = INPUT1.end..INPUT1.end + PACKED_LEN;

    pub fn limb_bit_cols_for_input(input_bits: Range<usize>) -> impl Iterator<Item = Range<usize>> {
        (0..PACKED_LEN).map(move |i| {
            let start = input_bits.start + i * PACKED_LIMB_BITS;
            let end = min(start + PACKED_LIMB_BITS, input_bits.end);
            start..end
        })
    }

    pub const NUM_COLUMNS: usize = RESULT.end;
}

pub fn ctl_data<F: Field>() -> Vec<Column<F>> {
    // We scale each filter flag with the associated opcode value.
    // If a logic operation is happening on the CPU side, the CTL
    // will enforce that the reconstructed opcode value from the
    // opcode bits matches.
    let mut res = vec![Column::linear_combination([
        (
            columns::IS_AND,
            F::from_canonical_u32(0b000000 + 0b100100 * (1 << 6)),
        ),
        (
            columns::IS_OR,
            F::from_canonical_u32(0b000000 + 0b100101 * (1 << 6)),
        ),
        (
            columns::IS_XOR,
            F::from_canonical_u32(0b000000 + 0b100110 * (1 << 6)),
        ),
        (
            columns::IS_NOR,
            F::from_canonical_u32(0b000000 + 0b100111 * (1 << 6)),
        ),
    ])];
    res.extend(columns::limb_bit_cols_for_input(columns::INPUT0).map(Column::le_bits));
    res.extend(columns::limb_bit_cols_for_input(columns::INPUT1).map(Column::le_bits));
    res.extend(columns::RESULT.map(Column::single));
    res
}

pub fn ctl_filter<F: Field>() -> Column<F> {
    Column::sum([
        columns::IS_AND,
        columns::IS_OR,
        columns::IS_XOR,
        columns::IS_NOR,
    ])
}

#[derive(Copy, Clone, Default)]
pub struct LogicStark<F, const D: usize> {
    pub f: PhantomData<F>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Op {
    And,
    Or,
    Xor,
    Nor,
}

impl Op {
    pub(crate) fn result(&self, a: u32, b: u32) -> u32 {
        match self {
            Op::And => a & b,
            Op::Or => a | b,
            Op::Xor => a ^ b,
            Op::Nor => !(a | b),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Operation {
    operator: Op,
    input0: u32,
    input1: u32,
    pub(crate) result: u32,
}

impl Operation {
    pub(crate) fn new(operator: Op, input0: u32, input1: u32) -> Self {
        let result = operator.result(input0, input1);
        println!("{:?}: {} {} => {}", operator, input0, input1, result);
        Operation {
            operator,
            input0,
            input1,
            result,
        }
    }

    fn into_row<F: Field>(self) -> [F; NUM_COLUMNS] {
        let Operation {
            operator,
            input0,
            input1,
            result,
        } = self;
        let mut row = [F::ZERO; NUM_COLUMNS];
        row[match operator {
            Op::And => columns::IS_AND,
            Op::Or => columns::IS_OR,
            Op::Xor => columns::IS_XOR,
            Op::Nor => columns::IS_NOR,
        }] = F::ONE;
        for i in 0..32 {
            row[columns::INPUT0.start + i] = F::from_canonical_u32((input0 >> i) & 1);
            row[columns::INPUT1.start + i] = F::from_canonical_u32((input1 >> i) & 1);
        }
        row[columns::RESULT.start] = F::from_canonical_u32(result);
        println!("row: {:?}, result: {}", row, result);
        row
    }
}

impl<F: RichField, const D: usize> LogicStark<F, D> {
    pub(crate) fn generate_trace(
        &self,
        operations: Vec<Operation>,
        min_rows: usize,
        timing: &mut TimingTree,
    ) -> Vec<PolynomialValues<F>> {
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
        operations: Vec<Operation>,
        min_rows: usize,
    ) -> Vec<[F; NUM_COLUMNS]> {
        let len = operations.len();
        let padded_len = len.max(min_rows).next_power_of_two();

        let mut rows = Vec::with_capacity(padded_len);
        for op in operations {
            rows.push(op.into_row());
        }

        // Pad to a power of two.
        for _ in len..padded_len {
            rows.push([F::ZERO; NUM_COLUMNS]);
        }

        rows
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for LogicStark<F, D> {
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

        // IS_AND, IS_OR, and IS_XOR come from the CPU table, so we assume they're valid.
        let is_and = lv[columns::IS_AND];
        let is_or = lv[columns::IS_OR];
        let is_xor = lv[columns::IS_XOR];
        let is_nor = lv[columns::IS_NOR];

        // The result will be `in0 OP in1 = sum_coeff * (in0 + in1) + and_coeff * (in0 AND in1) + not_coeff * 1`.
        // `AND => sum_coeff = 0, and_coeff = 1, not_coeff=0`
        // `OR  => sum_coeff = 1, and_coeff = -1, not_coeff=0`
        // `XOR => sum_coeff = 1, and_coeff = -2, not_coeff=0`
        // `NOR => sum_coeff = -1, and_coeff = 1, not_coeff=1`
        let sum_coeff = is_or + is_xor - is_nor;
        let and_coeff = is_and - is_or - is_xor * FE::TWO + is_nor;
        let not_coeff = is_nor;

        // Ensure that all bits are indeed bits.
        for input_bits_cols in [columns::INPUT0, columns::INPUT1] {
            for i in input_bits_cols {
                let bit = lv[i];
                yield_constr.constraint(bit * (bit - P::ONES));
            }
        }

        // Form the result
        for (result_col, x_bits_cols, y_bits_cols) in izip!(
            columns::RESULT,
            columns::limb_bit_cols_for_input(columns::INPUT0),
            columns::limb_bit_cols_for_input(columns::INPUT1),
        ) {
            let x: P = limb_from_bits_le(x_bits_cols.clone().map(|col| lv[col]));
            let y: P = limb_from_bits_le(y_bits_cols.clone().map(|col| lv[col]));

            let x_bits = x_bits_cols.map(|i| lv[i]);
            let y_bits = y_bits_cols.map(|i| lv[i]);

            let x_land_y: P = izip!(0.., x_bits, y_bits)
                .map(|(i, x_bit, y_bit)| x_bit * y_bit * FE::from_canonical_u64(1 << i))
                .sum();
            let x_op_y = sum_coeff * (x + y) + and_coeff * x_land_y + not_coeff;

            yield_constr.constraint(lv[result_col] - x_op_y);
        }
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
        vars: &Self::EvaluationFrameTarget,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        let lv = vars.get_local_values();

        // IS_AND, IS_OR, and IS_XOR come from the CPU table, so we assume they're valid.
        let is_and = lv[columns::IS_AND];
        let is_or = lv[columns::IS_OR];
        let is_xor = lv[columns::IS_XOR];
        let is_nor = lv[columns::IS_NOR];

        // The result will be `in0 OP in1 = sum_coeff * (in0 + in1) + and_coeff * (in0 AND in1) + not_coeff * 1`.
        // `AND => sum_coeff = 0, and_coeff = 1, not_coeff=0`
        // `OR  => sum_coeff = 1, and_coeff = -1, not_coeff=0`
        // `XOR => sum_coeff = 1, and_coeff = -2, not_coeff=0`
        // `NOR => sum_coeff = -1, and_coeff = 1, not_coeff=1`
        let sum_coeff = {
            let sum_coeff = builder.add_extension(is_or, is_xor);
            builder.sub_extension(sum_coeff, is_nor)
        };

        let and_coeff = {
            let and_coeff = builder.sub_extension(is_and, is_or);
            let and_coeff = builder.mul_const_add_extension(-F::TWO, is_xor, and_coeff);
            builder.add_extension(and_coeff, is_nor)
        };

        let not_coeff = is_nor;

        // Ensure that all bits are indeed bits.
        for input_bits_cols in [columns::INPUT0, columns::INPUT1] {
            for i in input_bits_cols {
                let bit = lv[i];
                let constr = builder.mul_sub_extension(bit, bit, bit);
                yield_constr.constraint(builder, constr);
            }
        }

        // Form the result
        for (result_col, x_bits_cols, y_bits_cols) in izip!(
            columns::RESULT,
            columns::limb_bit_cols_for_input(columns::INPUT0),
            columns::limb_bit_cols_for_input(columns::INPUT1),
        ) {
            let x = limb_from_bits_le_recursive(builder, x_bits_cols.clone().map(|i| lv[i]));
            let y = limb_from_bits_le_recursive(builder, y_bits_cols.clone().map(|i| lv[i]));
            let x_bits = x_bits_cols.map(|i| lv[i]);
            let y_bits = y_bits_cols.map(|i| lv[i]);

            let x_land_y = izip!(0usize.., x_bits, y_bits).fold(
                builder.zero_extension(),
                |acc, (i, x_bit, y_bit)| {
                    builder.arithmetic_extension(
                        F::from_canonical_u64(1 << i),
                        F::ONE,
                        x_bit,
                        y_bit,
                        acc,
                    )
                },
            );
            let x_op_y = {
                let x_op_y = builder.mul_extension(sum_coeff, x);
                let x_op_y = builder.mul_add_extension(sum_coeff, y, x_op_y);
                let tmp = builder.mul_add_extension(and_coeff, x_land_y, x_op_y);
                builder.add_extension(tmp, not_coeff)
            };
            let constr = builder.sub_extension(lv[result_col], x_op_y);
            yield_constr.constraint(builder, constr);
        }
    }

    fn constraint_degree(&self) -> usize {
        3
    }
}

#[cfg(test)]
mod tests {
    use crate::all_stark::ctl_logic;
    use crate::all_stark::Table;
    use crate::config::StarkConfig;
    use crate::cross_table_lookup::{
        cross_table_lookup_data, get_grand_product_challenge_set, CtlCheckVars, CtlData,
        GrandProductChallengeSet,
    };
    use crate::logic::{LogicStark, Op, Operation};
    use crate::prover::prove_single_table;
    use crate::stark::Stark;
    use crate::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};
    use crate::verifier::verify_stark_proof_with_challenges;
    use anyhow::Result;
    use itertools::Itertools;
    use plonky2::fri::oracle::PolynomialBatch;
    use plonky2::iop::challenger::Challenger;
    use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::timed;
    use plonky2::util::timing::TimingTree;

    #[test]
    fn test_stark_degree() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = LogicStark<F, D>;

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
        type S = LogicStark<F, D>;

        let stark = S {
            f: Default::default(),
        };
        test_stark_circuit_constraints::<F, C, S, D>(stark)
    }

    #[test]
    #[ignore]
    fn test_stark_verifier() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = LogicStark<F, D>;

        let config = StarkConfig::standard_fast_config();
        let stark = S {
            f: Default::default(),
        };
        let ops = vec![
            //Operation::new(Op::Nor, 0, 1),
            //Operation::new(Op::Nor, 1, 1),
            //Operation::new(Op::Nor, 0, 0),
            Operation::new(Op::And, 0, 1),
            //Operation::new(Op::And, 1, 1),
            //Operation::new(Op::And, 0, 0),
            //Operation::new(Op::Or, 0, 1),
            //Operation::new(Op::Or, 1, 1),
            //Operation::new(Op::Or, 0, 0),
            //Operation::new(Op::Xor, 0, 1),
            //Operation::new(Op::Xor, 1, 1),
            //Operation::new(Op::Xor, 0, 0),
        ];
        let num_rows = 1 << 5;

        let mut timing = TimingTree::new("Logic", log::Level::Debug);
        let trace_poly_value = stark.generate_trace(ops, num_rows, &mut timing);

        let all_tables = [
            Table::Arithmetic,
            Table::Arithmetic,
            Table::Arithmetic,
            Table::Arithmetic,
            Table::Arithmetic,
            Table::Arithmetic,
        ];
        let rate_bits = config.fri_config.rate_bits;
        let cap_height = config.fri_config.cap_height;

        let trace_poly_values = [
            trace_poly_value.clone(),
            trace_poly_value.clone(),
            trace_poly_value.clone(),
            trace_poly_value.clone(),
            trace_poly_value.clone(),
            trace_poly_value.clone(),
        ];

        let trace_commitments = timed!(
            timing,
            "compute all trace commitments",
            trace_poly_values
                .iter()
                .zip_eq(all_tables)
                .map(|(trace, table)| {
                    timed!(
                        timing,
                        &format!("compute trace commitment for {:?}", table),
                        PolynomialBatch::<F, C, D>::from_values(
                            // TODO: Cloning this isn't great; consider having `from_values` accept a reference,
                            // or having `compute_permutation_z_polys` read trace values from the `PolynomialBatch`.
                            trace.clone(),
                            rate_bits,
                            false,
                            cap_height,
                            &mut timing,
                            None,
                        )
                    )
                })
                .collect::<Vec<_>>()
        );

        log::debug!("trace_commitments: {}", trace_commitments.len());

        let trace_caps = trace_commitments
            .iter()
            .map(|c| c.merkle_tree.cap.clone())
            .collect::<Vec<_>>();
        let mut challenger = Challenger::<F, <C as GenericConfig<D>>::Hasher>::new();
        for cap in &trace_caps {
            challenger.observe_cap(cap);
        }

        let cross_table_lookups = [
            ctl_logic(),
            ctl_logic(),
            ctl_logic(),
            ctl_logic(),
            ctl_logic(),
            ctl_logic(),
        ];

        let ctl_challenges =
            get_grand_product_challenge_set(&mut challenger, config.num_challenges);
        let ctl_data_per_table = timed!(
            timing,
            "compute CTL data",
            cross_table_lookup_data::<F, D>(
                &trace_poly_values,
                &cross_table_lookups,
                &ctl_challenges,
            )
        );

        let proof = prove_single_table::<F, C, S, D>(
            &stark,
            &config,
            &trace_poly_values[0],
            &trace_commitments[0],
            &ctl_data_per_table[0],
            &ctl_challenges,
            &mut challenger,
            &mut timing,
        )
        .unwrap();

        let num_lookup_columns = stark.num_lookup_helper_columns(&config);
        let proofs = [
            proof.clone(),
            proof.clone(),
            proof.clone(),
            proof.clone(),
            proof.clone(),
            proof.clone(),
        ];
        let ctl_vars_per_table = CtlCheckVars::from_proofs(
            &proofs,
            &cross_table_lookups,
            &ctl_challenges,
            &[num_lookup_columns; 6],
        );

        let mut challenger = Challenger::<F, <C as GenericConfig<D>>::Hasher>::new();
        let ctl_challenges =
            get_grand_product_challenge_set(&mut challenger, config.num_challenges);

        let stark_challenger: crate::proof::StarkProofChallenges<F, D> = {
            challenger.compact();
            proof.proof.get_challenges(&mut challenger, &config)
        };

        verify_stark_proof_with_challenges::<F, C, S, D>(
            &stark,
            &proof.proof,
            &stark_challenger,
            &ctl_vars_per_table[0],
            &ctl_challenges,
            &config,
        )
        .unwrap();
    }
}
