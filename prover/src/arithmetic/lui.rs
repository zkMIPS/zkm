//! Support for the LUI instructions. rt = imm << 16
//!
//! This crate verifies an LUI instruction, which takes two
//! 32-bit inputs S and A, and produces a 32-bit output C satisfying
//!
//!    C = A << 16 (mod 2^32) for LUI
//!
//! The way this computation is carried is by providing a third input
//!    B = 1 << 16 (mod 2^32)
//! and then computing:
//!    C = A * B (mod 2^32) for LUI
//!
//! Inputs A, S, and B, and output C, are given as arrays of 16-bit
//! limbs. For example, if the limbs of A are a[0]...a[15], then
//!
//!    A = \sum_{i=0}^15 a[i] β^i,
//!
//! where β = 2^16 = 2^LIMB_BITS. To verify that A, S, B and C satisfy
//! the equations, we proceed similarly to MUL for LUI.

use crate::arithmetic::columns::{
    INPUT_REGISTER_0, INPUT_REGISTER_1, IS_LUI, NUM_ARITH_COLUMNS, N_LIMBS, OUTPUT_REGISTER,
};
use crate::arithmetic::mul;
use crate::arithmetic::utils::{read_value, read_value_i64_limbs, u32_to_array};
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

pub fn generate<F: PrimeField64>(lv: &mut [F], _nv: &mut [F], filter: usize, imm: u32, rt: u32) {
    u32_to_array(&mut lv[INPUT_REGISTER_0], imm);
    u32_to_array(&mut lv[INPUT_REGISTER_1], 1u32 << 16);
    u32_to_array(&mut lv[OUTPUT_REGISTER], rt);

    let input0 = read_value_i64_limbs(lv, INPUT_REGISTER_0); // imm
    let input1 = read_value_i64_limbs(lv, INPUT_REGISTER_1); // 1 << 16

    match filter {
        IS_LUI => {
            // We generate the multiplication 1 * (imm << 16) using mul.rs.
            mul::generate_mul(lv, input0, input1);
        }
        _ => panic!("unexpected operation filter"),
    };
}

pub(crate) fn eval_packed_generic<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    _nv: &[P; NUM_ARITH_COLUMNS],
    yield_constr: &mut ConstraintConsumer<P>,
) {
    eval_packed_lui(lv, yield_constr);
}

/// Evaluates the constraints for an SHL opcode.
/// The logic is the same as the one for MUL. The only difference is that
/// the inputs are in `INPUT_REGISTER_0`  and `INPUT_REGISTER_2` instead of
/// `INPUT_REGISTER_0` and `INPUT_REGISTER_1`.
fn eval_packed_lui<P: PackedField>(
    lv: &[P; NUM_ARITH_COLUMNS],
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let is_lui = lv[IS_LUI];
    let left_limbs = read_value::<N_LIMBS, _>(lv, INPUT_REGISTER_0);
    let right_limbs = read_value::<N_LIMBS, _>(lv, INPUT_REGISTER_1);

    mul::eval_packed_generic_mul(lv, is_lui, left_limbs, right_limbs, yield_constr);
}

pub(crate) fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    _nv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    eval_ext_circuit_lui(builder, lv, yield_constr);
}

fn eval_ext_circuit_lui<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &[ExtensionTarget<D>; NUM_ARITH_COLUMNS],
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let is_lui = lv[IS_LUI];
    let left_limbs = read_value::<N_LIMBS, _>(lv, INPUT_REGISTER_0);
    let right_limbs = read_value::<N_LIMBS, _>(lv, INPUT_REGISTER_1);

    mul::eval_ext_mul_circuit(builder, lv, is_lui, left_limbs, right_limbs, yield_constr);
}
