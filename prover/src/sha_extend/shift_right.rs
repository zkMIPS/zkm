use crate::sha_extend::rotate_right::{carry_multiplier, shifted_bits, shifted_bytes, shr_carry};
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

pub struct ShiftRightOp<T: Copy> {
    pub value: [T; 4],
    pub shift: [T; 4],
    pub carry: [T; 4],
}

impl<F: Field> ShiftRightOp<F> {
    pub fn generate_trace(&mut self, le_input_bytes: [u8; 4], rotation: usize) -> u32 {
        let input_bytes = le_input_bytes.map(F::from_canonical_u8);

        // Compute some constants with respect to the rotation needed for the rotation.
        let shifted_bytes = shifted_bytes(rotation);
        let shifted_bits = shifted_bits(rotation);
        let carry_multiplier = F::from_canonical_u32(carry_multiplier(rotation));

        // Perform the byte shift.
        let mut input_bytes_rotated = [F::ZERO; 4];
        for i in 0..4 {
            if i + shifted_bytes < 4 {
                input_bytes_rotated[i] = input_bytes[(i + shifted_bytes) % 4];
            }
        }

        // For each byte, calculate the shift and carry. If it's not the first byte, calculate the
        // new byte value using the current shifted byte and the last carry.
        let mut first_shift = F::ZERO;
        let mut last_carry = F::ZERO;
        for i in (0..4).rev() {
            let b = input_bytes_rotated[i].to_string().parse::<u8>().unwrap();
            let c = shifted_bits as u8;
            let (shift, carry) = shr_carry(b, c);

            self.shift[i] = F::from_canonical_u8(shift);
            self.carry[i] = F::from_canonical_u8(carry);

            if i == 3 {
                first_shift = self.shift[i];
            } else {
                self.value[i] = self.shift[i] + last_carry * carry_multiplier;
            }
            last_carry = self.carry[i];
        }

        // For the first byte, we don't move over the carry as this is a shift, not a rotate.
        self.value[3] = first_shift;

        // Check that the value is correct.
        let input = u32::from_le_bytes(le_input_bytes);
        let expected = input >> rotation as u32;
        let expected_le_bytes = expected.to_le_bytes().map(F::from_canonical_u8);
        assert_eq!(self.value, expected_le_bytes);

        expected
    }
}

pub(crate) fn shift_right_packed_constraints<P: PackedField>(
    input_bytes: [P; 4],
    shifted_value: &ShiftRightOp<P>,
    rotation: usize,
) -> Vec<P> {
    let mut result = Vec::new();

    // Compute some constants with respect to the rotation needed for the rotation.
    let shifted_bytes = shifted_bytes(rotation);
    let shifted_bits = shifted_bits(rotation);
    let carry_multiplier = P::from(P::Scalar::from_canonical_u32(carry_multiplier(rotation)));
    let shifted_bits_power = P::from(P::Scalar::from_canonical_u32(2u32.pow(shifted_bits as u32)));

    // Perform the byte shift.
    let mut input_bytes_rotated = [P::ZEROS; 4];
    for i in 0..4 {
        if i + shifted_bytes < 4 {
            input_bytes_rotated[i] = input_bytes[(i + shifted_bytes) % 4];
        }
    }

    let mut first_shift = P::ZEROS;
    let mut last_carry = P::ZEROS;
    for i in (0..4).rev() {
        let constraint = input_bytes_rotated[i]
            - shifted_value.shift[i].mul(shifted_bits_power)
            - shifted_value.carry[i];
        result.push(constraint);

        if i == 3 {
            first_shift = shifted_value.shift[i].into();
        } else {
            result.push(
                shifted_value.value[i] - shifted_value.shift[i] - last_carry * carry_multiplier,
            );
        }

        last_carry = shifted_value.carry[i].into();
    }
    result.push(shifted_value.value[3] - first_shift);
    result
}

pub(crate) fn shift_right_ext_circuit_constraints<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input_bytes: [ExtensionTarget<D>; 4],
    shifted_value: &ShiftRightOp<ExtensionTarget<D>>,
    rotation: usize,
) -> Vec<ExtensionTarget<D>> {
    let mut result = Vec::new();

    // Compute some constants with respect to the rotation needed for the rotation.
    let shifted_bytes = shifted_bytes(rotation);
    let shifted_bits = shifted_bits(rotation);
    let carry_multiplier =
        builder.constant_extension(F::Extension::from_canonical_u32(carry_multiplier(rotation)));

    let shifted_bits_power = builder.constant_extension(F::Extension::from_canonical_u32(
        2u32.pow(shifted_bits as u32),
    ));

    // Perform the byte shift.
    let mut input_bytes_rotated = [builder.zero_extension(); 4];
    for i in 0..4 {
        if i + shifted_bytes < 4 {
            input_bytes_rotated[i] = input_bytes[(i + shifted_bytes) % 4];
        }
    }

    let mut first_shift = builder.zero_extension();
    let mut last_carry = builder.zero_extension();
    for i in (0..4).rev() {
        let tmp1 = builder.mul_extension(shifted_value.shift[i], shifted_bits_power);
        let tmp2 = builder.add_extension(shifted_value.carry[i], tmp1);

        let constraint = builder.sub_extension(input_bytes_rotated[i], tmp2);
        result.push(constraint);

        if i == 3 {
            first_shift = shifted_value.shift[i];
        } else {
            let tmp1 = builder.mul_extension(last_carry, carry_multiplier);
            let tmp2 = builder.add_extension(shifted_value.shift[i], tmp1);
            result.push(builder.sub_extension(shifted_value.value[i], tmp2));
        }

        last_carry = shifted_value.carry[i];
    }
    result.push(builder.sub_extension(shifted_value.value[3], first_shift));
    result
}
