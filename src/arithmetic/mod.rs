pub mod addcy;
pub mod arithmetic_stark;
pub mod columns;
pub mod div;
pub mod lo_hi;
pub mod lui;
pub mod mul;
pub mod mult;
pub mod shift;
pub mod slt;
pub mod sra;
pub mod utils;

use crate::witness::util::sign_extend;
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
    MFHI,
    MTHI,
    MFLO,
    MTLO,
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

            BinaryOperator::SLL => (if input1 > 31 { 0 } else { input0 << input1 }, 0),
            BinaryOperator::SRL => (if input1 > 31 { 0 } else { input0 >> input1 }, 0),
            BinaryOperator::SRA => {
                let sin = input0 as i32;
                let sout = if input1 > 31 { 0 } else { sin >> input1 };
                (sout as u32, 0)
            }

            BinaryOperator::SLLV => (input0 << (input1 & 0x1f), 0),
            BinaryOperator::SRLV => (input0 >> (input1 & 0x1F), 0),
            BinaryOperator::SRAV => {
                // same as SRA
                let sin = input0 as i32;
                let sout = sin >> (input1 & 0x1f);
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
                let out = sign_extend::<16>(input0);
                (out.overflowing_shl(16).0, 0)
            }

            BinaryOperator::MULT => {
                let out = (((input0 as i32) as i64) * ((input1 as i32) as i64)) as u64;
                (out as u32, (out >> 32) as u32) // lo,hi
            }
            BinaryOperator::MULTU => {
                let out = input0 as u64 * input1 as u64;
                (out as u32, (out >> 32) as u32) //lo,hi
            }
            BinaryOperator::DIV => (
                ((input0 as i32) / (input1 as i32)) as u32, // lo
                ((input0 as i32) % (input1 as i32)) as u32, // hi
            ),
            BinaryOperator::DIVU => (input0 / input1, input0 % input1), //lo,hi
            BinaryOperator::MFHI
            | BinaryOperator::MTHI
            | BinaryOperator::MFLO
            | BinaryOperator::MTLO => (input0, 0),
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
            BinaryOperator::MFHI => columns::IS_MFHI,
            BinaryOperator::MTHI => columns::IS_MTHI,
            BinaryOperator::MFLO => columns::IS_MFLO,
            BinaryOperator::MTLO => columns::IS_MTLO,
        }
    }
}

/// An enum representing arithmetic operations that can be either binary.
#[derive(Debug, Clone)]
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
        BinaryOperator::ADD
        | BinaryOperator::SUB
        | BinaryOperator::ADDI
        | BinaryOperator::ADDIU
        | BinaryOperator::ADDU
        | BinaryOperator::SUBU => {
            addcy::generate(&mut row, op.row_filter(), input0, input1);
            (row, None)
        }
        BinaryOperator::MUL => {
            mul::generate(&mut row, input0, input1);
            (row, None)
        }
        BinaryOperator::SLT
        | BinaryOperator::SLTI
        | BinaryOperator::SLTU
        | BinaryOperator::SLTIU => {
            slt::generate(&mut row, op.row_filter(), input0, input1, result0);
            (row, None)
        }
        BinaryOperator::MULT | BinaryOperator::MULTU => {
            mult::generate(&mut row, op.row_filter(), input0, input1);
            (row, None)
        }
        BinaryOperator::DIV | BinaryOperator::DIVU => {
            let mut nv = vec![F::ZERO; columns::NUM_ARITH_COLUMNS];
            div::generate(
                &mut row,
                &mut nv,
                op.row_filter(),
                input0,
                input1,
                result0,
                result1,
            );
            (row, Some(nv))
        }
        BinaryOperator::LUI => {
            let mut nv = vec![F::ZERO; columns::NUM_ARITH_COLUMNS];
            lui::generate(&mut row, &mut nv, op.row_filter(), input0, result0);
            (row, None)
        }
        BinaryOperator::SLL | BinaryOperator::SLLV => {
            let mut nv = vec![F::ZERO; columns::NUM_ARITH_COLUMNS];
            shift::generate(&mut row, &mut nv, op.row_filter(), input1, input0, result0);
            (row, None)
        }
        BinaryOperator::SRL | BinaryOperator::SRLV => {
            let mut nv = vec![F::ZERO; columns::NUM_ARITH_COLUMNS];
            shift::generate(&mut row, &mut nv, op.row_filter(), input1, input0, result0);
            (row, Some(nv))
        }
        BinaryOperator::SRA | BinaryOperator::SRAV => {
            let mut nv = vec![F::ZERO; columns::NUM_ARITH_COLUMNS];
            sra::generate(&mut row, &mut nv, op.row_filter(), input1, input0, result0);
            (row, Some(nv))
        }
        BinaryOperator::MFHI
        | BinaryOperator::MTHI
        | BinaryOperator::MFLO
        | BinaryOperator::MTLO => {
            lo_hi::generate(&mut row, op.row_filter(), input0, result0);
            (row, None)
        }
    }
}
