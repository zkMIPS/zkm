use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

pub struct RotateRightOp<T: Copy> {
    pub value: [T; 4],
    pub shift: T,
    pub carry: T,
}

impl<F: Field> RotateRightOp<F> {
    pub fn generate_trace(&mut self, le_input_bytes: [u8; 4], rotation: usize) -> u32 {
        let input_u32 = u32::from_le_bytes(le_input_bytes);
        let rotation_u32 = (rotation % 32) as u32;
        let expected = input_u32.rotate_right(rotation_u32);
        let (shift, carry) = shr_carry(input_u32, rotation_u32);

        self.shift = F::from_canonical_u32(shift);
        self.carry = F::from_canonical_u32(carry);
        self.value = expected.to_le_bytes().map(F::from_canonical_u8);

        expected
    }
}

pub(crate) fn rotate_right_packed_constraints<P: PackedField>(
    input_bytes: [P; 4],
    rotated_value: &RotateRightOp<P>,
    rotation: usize,
) -> Vec<P> {
    let mut result = Vec::new();
    let rotation_u32 = (rotation % 32) as u32;

    let two_pow_8 = P::from(P::Scalar::from_canonical_u32(2u32.pow(8)));
    let two_pow_16 = P::from(P::Scalar::from_canonical_u32(2u32.pow(16)));
    let two_pow_24 = P::from(P::Scalar::from_canonical_u32(2u32.pow(24)));

    let rotated_value_from_bytes = rotated_value.value[0]
        + two_pow_8 * rotated_value.value[1]
        + two_pow_16 * rotated_value.value[2]
        + two_pow_24 * rotated_value.value[3];
    let input_value_from_bytes = input_bytes[0]
        + two_pow_8 * input_bytes[1]
        + two_pow_16 * input_bytes[2]
        + two_pow_24 * input_bytes[3];

    let carry_multiplier = P::from(P::Scalar::from_canonical_u32(2u32.pow(32 - rotation_u32)));
    let shift_multiplier = P::from(P::Scalar::from_canonical_u32(2u32.pow(rotation_u32)));

    let constraint =
        rotated_value_from_bytes - rotated_value.carry * carry_multiplier - rotated_value.shift;
    result.push(constraint);

    let constraint =
        input_value_from_bytes - rotated_value.shift * shift_multiplier - rotated_value.carry;
    result.push(constraint);

    result
}

pub(crate) fn rotate_right_ext_circuit_constraint<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input_bytes: [ExtensionTarget<D>; 4],
    rotated_value: &RotateRightOp<ExtensionTarget<D>>,
    rotation: usize,
) -> Vec<ExtensionTarget<D>> {
    let mut result = Vec::new();
    let rotation_u32 = (rotation % 32) as u32;

    let two_pow_8 = builder.constant_extension(F::Extension::from_canonical_u32(2u32.pow(8)));
    let two_pow_16 = builder.constant_extension(F::Extension::from_canonical_u32(2u32.pow(16)));
    let two_pow_24 = builder.constant_extension(F::Extension::from_canonical_u32(2u32.pow(24)));

    let tmp = builder.mul_extension(rotated_value.value[1], two_pow_8);
    let tmp2 = builder.mul_extension(rotated_value.value[2], two_pow_16);
    let tmp3 = builder.mul_extension(rotated_value.value[3], two_pow_24);
    let rotated_value_from_bytes =
        builder.add_many_extension([rotated_value.value[0], tmp, tmp2, tmp3]);

    let tmp = builder.mul_extension(input_bytes[1], two_pow_8);
    let tmp2 = builder.mul_extension(input_bytes[2], two_pow_16);
    let tmp3 = builder.mul_extension(input_bytes[3], two_pow_24);
    let input_value_from_bytes = builder.add_many_extension([input_bytes[0], tmp, tmp2, tmp3]);

    let carry_multiplier = builder.constant_extension(F::Extension::from_canonical_u32(
        2u32.pow(32 - rotation_u32),
    ));
    let shift_multiplier =
        builder.constant_extension(F::Extension::from_canonical_u32(2u32.pow(rotation_u32)));

    let tmp = builder.mul_extension(rotated_value.carry, carry_multiplier);
    let tmp2 = builder.add_extension(tmp, rotated_value.shift);
    let constraint = builder.sub_extension(rotated_value_from_bytes, tmp2);
    result.push(constraint);

    let tmp = builder.mul_extension(rotated_value.shift, shift_multiplier);
    let tmp2 = builder.add_extension(tmp, rotated_value.carry);
    let constraint = builder.sub_extension(input_value_from_bytes, tmp2);
    result.push(constraint);

    result
}

/// Shifts a byte to the right and returns both the shifted byte and the bits that carried.
pub const fn shr_carry(input: u32, rotation: u32) -> (u32, u32) {
    let c_mod = rotation % 32;
    if c_mod != 0 {
        let res = input >> c_mod;
        let carry = (input << (32 - c_mod)) >> (32 - c_mod);
        (res, carry)
    } else {
        (input, 0u32)
    }
}
