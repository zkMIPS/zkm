use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

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