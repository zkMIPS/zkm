pub mod addcy;
pub mod arithmetic_stark;
pub mod columns;
pub mod mul;
pub mod shift;
pub mod utils;

use crate::util::*;
use crate::witness::util::sign_extend;
use num::Zero;
use plonky2::field::types::PrimeField64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BinaryOperator {
    ADD,
    ADDU,
    ADDI,
    ADDIU,
    SUB,
    SUBU,
    MULT,
    MULTU,
    DIV,
    DIVU,
    SLLV,
    SRLV,
    SRAV,
    SLL,
    SRL,
    SRA,
    SLTI,
    SLTIU,
    LUI,
}

impl BinaryOperator {
    pub(crate) fn result(&self, input0: u32, input1: u32) -> u32 {
        match self {
            BinaryOperator::ADD => input0.overflowing_add(input1).0, // FIXME
            BinaryOperator::ADDU => input0.overflowing_add(input1).0,
            BinaryOperator::ADDI => {
                let sein = sign_extend::<16>(input1);
                input0.overflowing_add(sein).0
            }
            BinaryOperator::ADDIU => {
                let sein = sign_extend::<16>(input1);
                input0.overflowing_add(sein).0
            }
            BinaryOperator::SUB => input0.overflowing_sub(input1).0,
            BinaryOperator::SUBU => input0.overflowing_sub(input1).0,
            BinaryOperator::MULT => input0.overflowing_mul(input1).0, //FIXME
            BinaryOperator::MULTU => input0.overflowing_mul(input1).0,
            BinaryOperator::DIV => {
                if input1.is_zero() {
                    0
                } else {
                    input0 / input1
                }
            }
            BinaryOperator::DIVU => {
                if input1.is_zero() {
                    0
                } else {
                    input0 / input1
                }
            }

            BinaryOperator::SLL => input0.overflowing_shl(input1).0,
            BinaryOperator::SRL => input0.overflowing_shr(input1).0,
            BinaryOperator::SRA => input0.overflowing_shr(input1).0,
            BinaryOperator::SLLV => {
                let low_4bits = input1 & 0xF;
                input0.overflowing_shl(low_4bits).0
            }
            BinaryOperator::SRLV => {
                let low_4bits = input1 & 0xF;
                input0.overflowing_shr(low_4bits).0
            }
            BinaryOperator::SRAV => {
                let low_4bits = input1 & 0xF;
                input0.overflowing_shr(low_4bits).0
            }
            BinaryOperator::SLTIU => {
                let out = sign_extend::<16>(input1);
                input0.overflowing_shl(out).0
            }
            BinaryOperator::SLTI => {
                let out = sign_extend::<16>(input1);
                input0.overflowing_shl(out).0
            }
            BinaryOperator::LUI => {
                let out = sign_extend::<16>(input1);
                out.overflowing_shl(16).0
            }
        }
    }

    pub(crate) fn row_filter(&self) -> usize {
        match self {
            BinaryOperator::ADD => columns::IS_ADD,
            BinaryOperator::ADDU => columns::IS_ADDU,
            BinaryOperator::ADDI => columns::IS_ADDI,
            BinaryOperator::ADDIU => columns::IS_ADDIU,
            BinaryOperator::SUB => columns::IS_SUB,
            BinaryOperator::SUBU => columns::IS_SUBU,
            BinaryOperator::MULT => columns::IS_MULT,
            BinaryOperator::MULTU => columns::IS_MULTU,
            BinaryOperator::DIV => columns::IS_DIV,
            BinaryOperator::DIVU => columns::IS_DIVU,
            BinaryOperator::SLL => columns::IS_SLL,
            BinaryOperator::SRL => columns::IS_SRL,
            BinaryOperator::SRA => columns::IS_SRA,
            BinaryOperator::SLLV => columns::IS_SLLV,
            BinaryOperator::SRLV => columns::IS_SRLV,
            BinaryOperator::SRAV => columns::IS_SRAV,
            BinaryOperator::SLTIU => columns::IS_SLTIU,
            BinaryOperator::SLTI => columns::IS_SLTI,
            BinaryOperator::LUI => columns::IS_LUI,
        }
    }
}

/// An enum representing arithmetic operations that can be either binary.
#[derive(Debug)]
pub(crate) enum Operation {
    BinaryOperation {
        operator: BinaryOperator,
        input0: u32,
        input1: u32,
        result: u32,
    },
}

impl Operation {
    /// Create a binary operator with given inputs.
    ///
    /// NB: This works as you would expect, EXCEPT for SHL and SHR,
    /// whose inputs need a small amount of preprocessing. Specifically,
    /// to create `SHL(shift, value)`, call (note the reversal of
    /// argument order):
    ///
    ///    `Operation::binary(BinaryOperator::Shl, value, 1 << shift)`
    ///
    /// Similarly, to create `SHR(shift, value)`, call
    ///
    ///    `Operation::binary(BinaryOperator::Shr, value, 1 << shift)`
    ///
    /// See witness/operation.rs::append_shift() for an example (indeed
    /// the only call site for such inputs).
    pub(crate) fn binary(operator: BinaryOperator, input0: u32, input1: u32) -> Self {
        let result = operator.result(input0, input1);
        Self::BinaryOperation {
            operator,
            input0,
            input1,
            result,
        }
    }

    pub(crate) fn result(&self) -> u32 {
        match self {
            Operation::BinaryOperation { result, .. } => *result,
        }
    }

    /// Convert operation into one or two rows of the trace.
    ///
    /// Morally these types should be [F; NUM_ARITH_COLUMNS], but we
    /// use vectors because that's what utils::transpose (who consumes
    /// the result of this function as part of the range check code)
    /// expects.
    ///
    /// The `is_simulated` bool indicates whether we use a native arithmetic
    /// operation or simulate one with another. This is used to distinguish
    /// SHL and SHR operations that are simulated through MUL and DIV respectively.
    fn to_rows<F: PrimeField64>(&self) -> (Vec<F>, Option<Vec<F>>) {
        match *self {
            Operation::BinaryOperation {
                operator,
                input0,
                input1,
                result,
            } => binary_op_to_rows(operator, input0, input1, result),
        }
    }
}

fn binary_op_to_rows<F: PrimeField64>(
    op: BinaryOperator,
    input0: u32,
    input1: u32,
    result: u32,
) -> (Vec<F>, Option<Vec<F>>) {
    let mut row = vec![F::ZERO; columns::NUM_ARITH_COLUMNS];
    row[op.row_filter()] = F::ONE;

    match op {
        BinaryOperator::ADD | BinaryOperator::SUB => {
            addcy::generate(&mut row, op.row_filter(), input0, input1);
            (row, None)
        }
        BinaryOperator::MULT => {
            mul::generate(&mut row, input0, input1);
            (row, None)
        }
        /*
        BinaryOperator::DIV => {
            let mut nv = vec![F::ZERO; columns::NUM_ARITH_COLUMNS];
            divmod::generate(&mut row, &mut nv, op.row_filter(), input0, input1, result);
            (row, Some(nv))
        }
        */
        _ => panic!("Unimplemented"),
    }
}
