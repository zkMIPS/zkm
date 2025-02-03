use crate::keccak::logic::andn_gen_circuit;
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

pub(crate) fn and_op<F: RichField + Extendable<D>, const D: usize, const N: usize>(
    x: [F; N],
    y: [F; N],
) -> [F; N] {
    let mut result = [F::ZERO; N];
    for i in 0..N {
        debug_assert!(x[i].is_zero() || x[i].is_one());
        debug_assert!(y[i].is_zero() || y[i].is_one());
        result[i] = x[i] * y[i];
    }
    result
}

pub(crate) fn and_op_packed_constraints<P: PackedField, const N: usize>(
    x: [P; N],
    y: [P; N],
    out: [P; N],
) -> Vec<P> {
    let mut result = vec![];
    for i in 0..N {
        let out_constraint = x[i] * y[i] - out[i];
        result.push(out_constraint);
    }
    result
}

pub(crate) fn and_op_ext_circuit_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    const N: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    x: [ExtensionTarget<D>; N],
    y: [ExtensionTarget<D>; N],
    out: [ExtensionTarget<D>; N],
) -> Vec<ExtensionTarget<D>> {
    let mut result = vec![];
    for i in 0..N {
        let expected_out = builder.mul_extension(x[i], y[i]);
        let out_constraint = builder.sub_extension(expected_out, out[i]);
        result.push(out_constraint);
    }
    result
}

pub(crate) fn andn_op<F: RichField + Extendable<D>, const D: usize, const N: usize>(
    x: [F; N],
    y: [F; N],
) -> [F; N] {
    let mut result = [F::ZERO; N];
    for i in 0..N {
        debug_assert!(x[i].is_zero() || x[i].is_one());
        debug_assert!(y[i].is_zero() || y[i].is_one());
        result[i] = crate::keccak::logic::andn(x[i], y[i]);
    }
    result
}

pub(crate) fn andn_op_packed_constraints<P: PackedField, const N: usize>(
    x: [P; N],
    y: [P; N],
    out: [P; N],
) -> Vec<P> {
    let mut result = vec![];
    for i in 0..N {
        let out_constraint = crate::keccak::logic::andn_gen(x[i], y[i]) - out[i];
        result.push(out_constraint);
    }
    result
}

pub(crate) fn andn_op_ext_circuit_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    const N: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    x: [ExtensionTarget<D>; N],
    y: [ExtensionTarget<D>; N],
    out: [ExtensionTarget<D>; N],
) -> Vec<ExtensionTarget<D>> {
    let mut result = vec![];
    for i in 0..N {
        let expected_out = andn_gen_circuit(builder, x[i], y[i]);
        let out_constraint = builder.sub_extension(expected_out, out[i]);
        result.push(out_constraint);
    }
    result
}

pub(crate) fn xor_op<F: RichField + Extendable<D>, const D: usize, const N: usize>(
    x: [F; N],
    y: [F; N],
) -> [F; N] {
    let mut result = [F::ZERO; N];
    for i in 0..N {
        debug_assert!(x[i].is_zero() || x[i].is_one());
        debug_assert!(y[i].is_zero() || y[i].is_one());
        result[i] = crate::keccak::logic::xor([x[i], y[i]]);
    }
    result
}

pub(crate) fn equal_packed_constraint<P: PackedField, const N: usize>(
    x: [P; N],
    y: [P; N],
) -> Vec<P> {
    let mut result = vec![];
    for i in 0..N {
        result.push(x[i] - y[i]);
    }
    result
}

pub(crate) fn equal_ext_circuit_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    const N: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    x: [ExtensionTarget<D>; N],
    y: [ExtensionTarget<D>; N],
) -> Vec<ExtensionTarget<D>> {
    let mut result = vec![];
    for i in 0..N {
        let out_constraint = builder.sub_extension(x[i], y[i]);
        result.push(out_constraint);
    }
    result
}

pub(crate) fn from_be_bits_to_u32(bits: [u8; 32]) -> u32 {
    let mut result = 0;
    for i in 0..32 {
        result |= (bits[i] as u32) << i;
    }
    result
}
