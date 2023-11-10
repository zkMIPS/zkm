pub mod addcy;
pub mod arithmetic_stark;
pub mod columns;
pub mod mul;
pub mod shift;
pub mod slt;
pub mod utils;

use crate::util::*;
use crate::witness::util::sign_extend;
use crate::witness::util::u32_from_u64;
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
    MUL,
    DIV,
    DIVU,
    SLLV,
    SRLV,
    SRAV,
    SLL,
    SRL,
    SRA,
    SLT,
    SLTU,
    SLTI,
    SLTIU,
    LUI,
}

impl BinaryOperator {
    pub(crate) fn result(&self, input0: u32, input1: u32) -> (u32, u32) {
        match self {
            BinaryOperator::ADD => (input0.overflowing_add(input1).0, 0),
            BinaryOperator::ADDU => (input0.overflowing_add(input1).0, 0),
            BinaryOperator::ADDI => {
                let sein = sign_extend::<16>(input1);
                (input0.overflowing_add(sein).0, 0)
            }
            BinaryOperator::ADDIU => {
                let sein = sign_extend::<16>(input1);
                (input0.overflowing_add(sein).0, 0)
            }
            BinaryOperator::SUB => (input0.overflowing_sub(input1).0, 0),
            BinaryOperator::SUBU => (input0.overflowing_sub(input1).0, 0),

            BinaryOperator::SLL => (input0.overflowing_shl(input1).0, 0),
            BinaryOperator::SRL => (input0.overflowing_shr(input1).0, 0),
            BinaryOperator::SRA => {
                let sin = input0 as i32;
                let sout = sin >> input1;
                (sout as u32, 0)
            }

            BinaryOperator::SLLV => (input0.overflowing_shl(input1).0, 0),
            BinaryOperator::SRLV => (input0.overflowing_shr(input1).0, 0),
            BinaryOperator::SRAV => {
                // same as SRA
                let sin = input0 as i32;
                let sout = sin >> input1;
                (sout as u32, 0)
            }
            BinaryOperator::MUL => (input0.overflowing_mul(input1).0, 0),
            BinaryOperator::SLTU => {
                if input0 < input1 {
                    (1, 0)
                } else {
                    (0, 0)
                }
            }
            BinaryOperator::SLT => {
                if (input0 as i32) < (input1 as i32) {
                    (1, 0)
                } else {
                    (0, 0)
                }
            }
            BinaryOperator::SLTIU => {
                let out = sign_extend::<16>(input1);
                if input0 < out {
                    (1, 0)
                } else {
                    (0, 0)
                }
            }
            BinaryOperator::SLTI => {
                let out = sign_extend::<16>(input1);
                if (input0 as i32) < (out as i32) {
                    (1, 0)
                } else {
                    (0, 0)
                }
            }
            BinaryOperator::LUI => {
                let out = sign_extend::<16>(input1);
                (out.overflowing_shl(16).0, 0)
            }

            BinaryOperator::MULT => {
                let out = (input0 as i64 * input1 as i64) as u64;
                u32_from_u64(out)
            }
            BinaryOperator::MULTU => {
                let out = input0 as u64 * input1 as u64;
                u32_from_u64(out)
            }
            BinaryOperator::DIV => (
                ((input0 as i32) % (input1 as i32)) as u32,
                ((input0 as i32) / (input1 as i32)) as u32,
            ),
            BinaryOperator::DIVU => (input0 % input1, input0 / input1),
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
            BinaryOperator::MUL => columns::IS_MUL,
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
            BinaryOperator::SLTU => columns::IS_SLTU,
            BinaryOperator::SLT => columns::IS_SLT,
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
        result0: u32,
        result1: u32,
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
        let (result0, result1) = operator.result(input0, input1);
        Self::BinaryOperation {
            operator,
            input0,
            input1,
            result0,
            result1,
        }
    }

    pub(crate) fn result(&self) -> (u32, u32) {
        match self {
            Operation::BinaryOperation {
                result0, result1, ..
            } => (*result0, *result1),
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
                result0,
                result1,
            } => binary_op_to_rows(operator, input0, input1, result0, result1),
        }
    }
}

fn binary_op_to_rows<F: PrimeField64>(
    op: BinaryOperator,
    input0: u32,
    input1: u32,
    result0: u32,
    result1: u32,
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
        _ => (row, None),
    }
}
