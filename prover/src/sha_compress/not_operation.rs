use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

pub struct NotOperation<T: Copy> {
    /// The result of `!x`.
    pub value: [T; 4],
}

impl <F: Field> NotOperation<F> {
    pub fn generate_trace(&mut self, x: [u8; 4]) -> u32{
        let x_u32 = u32::from_le_bytes(x);
        let expected = !x_u32;
        self.value = expected.to_le_bytes().map(F::from_canonical_u8);

        expected
    }
}

pub(crate) fn not_operation_packed_constraints<P: PackedField>(
    original_value: [P; 4],
    cols: &NotOperation<P>,
) -> Vec<P> {
    let mut result = vec![];
    let u8_max = P::from(P::Scalar::from_canonical_u8(255));
    for i in 0..4 {
        result.push(original_value[i] + cols.value[i] - u8_max);
    }
    result
}

pub(crate) fn not_operation_ext_circuit_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    original_value: [ExtensionTarget<D>; 4],
    cols: &NotOperation<ExtensionTarget<D>>,
) -> Vec<ExtensionTarget<D>> {
    let mut result = vec![];
    let u8_max = builder.constant_extension(F::Extension::from_canonical_u8(255));
    for i in 0..4 {
        let tmp1 = builder.add_extension(original_value[i], cols.value[i]);
        result.push(builder.sub_extension(tmp1, u8_max));
    }
    result
}