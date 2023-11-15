use itertools::izip;
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::columns::CpuColumnsView;
// use crate::cpu::stack::{self, EQ_STACK_BEHAVIOR, IS_ZERO_STACK_BEHAVIOR};

/*
fn limbs(x: U256) -> [u32; 8] {
    let mut res = [0; 8];
    let x_u64: [u64; 4] = x.0;
    for i in 0..4 {
        res[2 * i] = x_u64[i] as u32;
        res[2 * i + 1] = (x_u64[i] >> 32) as u32;
    }
    res
}
*/

pub fn generate_pinv_diff<F: Field>(
    val0: u32,
    val1: u32,
    lv: &mut CpuColumnsView<F>,
) {
    let num_unequal_limbs = if val0 != val1 { 1 } else { 0 };
    let _equal = num_unequal_limbs == 0;

    // Form `diff_pinv`.
    // Let `diff = val0 - val1`. Consider `x[i] = diff[i]^-1` if `diff[i] != 0` and 0 otherwise.
    // Then `diff @ x = num_unequal_limbs`, where `@` denotes the dot product. We set
    // `diff_pinv = num_unequal_limbs^-1 * x` if `num_unequal_limbs != 0` and 0 otherwise. We have
    // `diff @ diff_pinv = 1 - equal` as desired.
    let logic = lv.general.logic_mut();
    let num_unequal_limbs_inv = F::from_canonical_usize(num_unequal_limbs)
        .try_inverse()
        .unwrap_or(F::ZERO);
    let val0_f = F::from_canonical_u32(val0);
    let val1_f = F::from_canonical_u32(val1);
    logic.diff_pinv =
        (val0_f - val1_f).try_inverse().unwrap_or(F::ZERO) * num_unequal_limbs_inv;
}

pub fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    _nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let logic = lv.general.logic();
    let input0 = lv.mem_channels[0].value;
    let input1 = lv.mem_channels[1].value;
    let output = lv.mem_channels[2].value;

    // EQ (0x14) and ISZERO (0x15) are differentiated by their first opcode bit.
    let _eq_filter = lv.op.eq_iszero * (P::ONES - lv.opcode_bits[0]);
    let iszero_filter = lv.op.eq_iszero * lv.opcode_bits[0];
    let eq_or_iszero_filter = lv.op.eq_iszero;

    let equal = output;
    let unequal = P::ONES - equal;

    // Handle `EQ` and `ISZERO`. Most limbs of the output are 0, but the least-significant one is
    // either 0 or 1.
    yield_constr.constraint(eq_or_iszero_filter * equal * unequal);
    /*
    for &limb in &output[1..] {
        yield_constr.constraint(eq_or_iszero_filter * limb);
    }
    */

    // If `ISZERO`, constrain input1 to be zero, effectively implementing ISZERO(x) as EQ(x, 0).
    yield_constr.constraint(iszero_filter * input1);

    // `equal` implies `input0[i] == input1[i]` for all `i`.
    let diff = input0 - input1;
    yield_constr.constraint(eq_or_iszero_filter * equal * diff);

    // `input0[i] == input1[i]` for all `i` implies `equal`.
    // If `unequal`, find `diff_pinv` such that `(input0 - input1) @ diff_pinv == 1`, where `@`
    // denotes the dot product (there will be many such `diff_pinv`). This can only be done if
    // `input0 != input1`.
    let dot: P = (input0 - input1) * logic.diff_pinv;
    yield_constr.constraint(eq_or_iszero_filter * (dot - unequal));

    /*
    // Stack constraints.
    stack::eval_packed_one(lv, nv, eq_filter, EQ_STACK_BEHAVIOR.unwrap(), yield_constr);
    stack::eval_packed_one(
        lv,
        nv,
        iszero_filter,
        IS_ZERO_STACK_BEHAVIOR.unwrap(),
        yield_constr,
    );
    */
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    _nv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let zero = builder.zero_extension();
    let one = builder.one_extension();

    let logic = lv.general.logic();
    let input0 = lv.mem_channels[0].value;
    let input1 = lv.mem_channels[1].value;
    let output = lv.mem_channels[2].value;

    // EQ (0x14) and ISZERO (0x15) are differentiated by their first opcode bit.
    let eq_filter = builder.mul_extension(lv.op.eq_iszero, lv.opcode_bits[0]);
    let _eq_filter = builder.sub_extension(lv.op.eq_iszero, eq_filter);

    let iszero_filter = builder.mul_extension(lv.op.eq_iszero, lv.opcode_bits[0]);
    let eq_or_iszero_filter = lv.op.eq_iszero;

    let equal = output;
    let unequal = builder.sub_extension(one, equal);

    // Handle `EQ` and `ISZERO`. Most limbs of the output are 0, but the least-significant one is
    // either 0 or 1.
    {
        let constr = builder.mul_extension(equal, unequal);
        let constr = builder.mul_extension(eq_or_iszero_filter, constr);
        yield_constr.constraint(builder, constr);
    }
    /*
    for &limb in &output[1..] {
        let constr = builder.mul_extension(eq_or_iszero_filter, limb);
        yield_constr.constraint(builder, constr);
    }
    */

    // If `ISZERO`, constrain input1 to be zero, effectively implementing ISZERO(x) as EQ(x, 0).
        let constr = builder.mul_extension(iszero_filter, input1);
        yield_constr.constraint(builder, constr);

    // `equal` implies `input0[i] == input1[i]` for all `i`.
        let diff = builder.sub_extension(input0, input1);
        let constr = builder.mul_extension(equal, diff);
        let constr = builder.mul_extension(eq_or_iszero_filter, constr);
        yield_constr.constraint(builder, constr);

    // `input0[i] == input1[i]` for all `i` implies `equal`.
    // If `unequal`, find `diff_pinv` such that `(input0 - input1) @ diff_pinv == 1`, where `@`
    // denotes the dot product (there will be many such `diff_pinv`). This can only be done if
    // `input0 != input1`.
    {
        let dot: ExtensionTarget<D> = {
                let diff = builder.sub_extension(input0, input1);
                builder.mul_add_extension(diff, logic.diff_pinv, zero)
        };
        let constr = builder.sub_extension(dot, unequal);
        let constr = builder.mul_extension(eq_or_iszero_filter, constr);
        yield_constr.constraint(builder, constr);
    }

    /*
    // Stack constraints.
    stack::eval_ext_circuit_one(
        builder,
        lv,
        nv,
        eq_filter,
        EQ_STACK_BEHAVIOR.unwrap(),
        yield_constr,
    );
    stack::eval_ext_circuit_one(
        builder,
        lv,
        nv,
        iszero_filter,
        IS_ZERO_STACK_BEHAVIOR.unwrap(),
        yield_constr,
    );
    */
}
