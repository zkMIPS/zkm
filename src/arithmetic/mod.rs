pub mod addcy;
pub mod arithmetic_stark;
pub mod columns;
pub mod mul;
pub mod shift;
pub mod utils;

use crate::util::*;
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
    BEQ,
    BNE,

    SLLV, // simulated with MUL
    SRLV, // simulated with DIV
    SRAV, // simulated with DIV

    SLL, // simulated with MUL
    SRL, // simulated with DIV
    SRA, // simulated with DIV
}

impl BinaryOperator {
    pub(crate) fn result(&self, input0: u32, input1: u32) -> u32 {
        match self {
            BinaryOperator::ADD => input0.overflowing_add(input1).0, // FIXME
            BinaryOperator::ADDU => input0.overflowing_add(input1).0,
            BinaryOperator::MULT => input0.overflowing_mul(input1).0, //FIXME
            BinaryOperator::MULTU => input0.overflowing_mul(input1).0,
            BinaryOperator::SLL => input0.overflowing_shl(input1).0,
            BinaryOperator::SRL => input0.overflowing_shr(input1).0,
            _ => panic!("Unimplemented"),
            /*
            BinaryOperator::Shl => {
                if input0 < 32 {
                    input1 << input0
                } else {
                    u32::zero()
                }
            }
            BinaryOperator::Sub => input0.overflowing_sub(input1).0,
            BinaryOperator::Div => {
                if input1.is_zero() {
                    u32::zero()
                } else {
                    input0 / input1
                }
            }
            BinaryOperator::Shr => {
                if input0 < 32 {
                    input1 >> input0
                } else {
                    u32::zero()
                }
            }
            BinaryOperator::Mod => {
                if input1.is_zero() {
                    u32::zero()
                } else {
                    input0 % input1
                }
            }
            BinaryOperator::Lt => u32::from((input0 < input1) as u8),
            BinaryOperator::Gt => u32::from((input0 > input1) as u8),
            BinaryOperator::Byte => {
                if input0 >= 32.into() {
                    u32::zero()
                } else {
                    input1.byte(31 - input0.as_usize()).into()
                }
            }
            */
        }
    }

    pub(crate) fn row_filter(&self) -> usize {
        match self {
            BinaryOperator::ADD => columns::IS_ADD,
            BinaryOperator::ADDU => columns::IS_ADDU,
            BinaryOperator::MULT => columns::IS_MULT,
            BinaryOperator::MULTU => columns::IS_MULTU,
            BinaryOperator::SUB => columns::IS_SUB,
            BinaryOperator::SUBU => columns::IS_SUBU,
            BinaryOperator::DIV => columns::IS_DIV,
            BinaryOperator::DIVU => columns::IS_DIVU,
            BinaryOperator::SLL => columns::IS_SLL,
            _ => panic!("Unimplemented {:?}", self),
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

fn ternary_op_to_rows<F: PrimeField64>(
    row_filter: usize,
    input0: u32,
    input1: u32,
    input2: u32,
    _result: u32,
) -> (Vec<F>, Option<Vec<F>>) {
    let mut row1 = vec![F::ZERO; columns::NUM_ARITH_COLUMNS];
    let mut row2 = vec![F::ZERO; columns::NUM_ARITH_COLUMNS];

    row1[row_filter] = F::ONE;

    // modular::generate(&mut row1, &mut row2, row_filter, input0, input1, input2);

    (row1, Some(row2))
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
