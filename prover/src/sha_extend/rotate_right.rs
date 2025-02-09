use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

pub struct RotateRightOp<T: Copy> {
    pub value: [T; 4],
    pub shift: [T; 4],
    pub carry: [T; 4],
}

impl<F: Field> RotateRightOp<F> {
    pub fn generate_trace(&mut self, le_input_bytes: [u8; 4], rotation: usize) -> u32 {
        let input_bytes = le_input_bytes.map(F::from_canonical_u8);

        // Compute some constants with respect to the rotation needed for the rotation.
        let shifted_bytes = shifted_bytes(rotation);
        let shifted_bits = shifted_bits(rotation);
        let carry_multiplier = F::from_canonical_u32(carry_multiplier(rotation));

        // Perform the byte shift.
        let input_bytes_rotated = [
            input_bytes[shifted_bytes % 4],
            input_bytes[(1 + shifted_bytes) % 4],
            input_bytes[(2 + shifted_bytes) % 4],
            input_bytes[(3 + shifted_bytes) % 4],
        ];

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

        // For the first byte, we didn't know the last carry so compute the rotated byte here.
        self.value[3] = first_shift + last_carry * carry_multiplier;

        // Check that the value is correct.
        let input = u32::from_le_bytes(le_input_bytes);
        let expected = input.rotate_right(rotation as u32);
        let expected_le_bytes = expected.to_le_bytes().map(F::from_canonical_u8);
        assert_eq!(self.value, expected_le_bytes);

        expected
    }
}

pub(crate) fn rotate_right_packed_constraints<P: PackedField>(
    input_bytes: [P; 4],
    rotated_value: &RotateRightOp<P>,
    rotation: usize,
) -> Vec<P> {
    let mut result = Vec::new();

    // Compute some constants with respect to the rotation needed for the rotation.
    let shifted_bytes = shifted_bytes(rotation);
    let shifted_bits = shifted_bits(rotation);
    let carry_multiplier = P::from(P::Scalar::from_canonical_u32(carry_multiplier(rotation)));
    let shifted_bits_power = P::from(P::Scalar::from_canonical_u32(2u32.pow(shifted_bits as u32)));

    // Perform the byte shift.
    let input_bytes_rotated = [
        input_bytes[shifted_bytes % 4],
        input_bytes[(1 + shifted_bytes) % 4],
        input_bytes[(2 + shifted_bytes) % 4],
        input_bytes[(3 + shifted_bytes) % 4],
    ];

    let mut first_shift = P::ZEROS;
    let mut last_carry = P::ZEROS;
    for i in (0..4).rev() {
        let constraint = input_bytes_rotated[i]
            - rotated_value.shift[i].mul(shifted_bits_power)
            - rotated_value.carry[i];
        result.push(constraint);

        if i == 3 {
            first_shift = rotated_value.shift[i];
        } else {
            result.push(
                rotated_value.value[i] - rotated_value.shift[i] - last_carry * carry_multiplier,
            );
        }

        last_carry = rotated_value.carry[i];
    }
    result.push(rotated_value.value[3] - (first_shift + last_carry * carry_multiplier));
    result
}

pub(crate) fn rotate_right_ext_circuit_constraint<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input_bytes: [ExtensionTarget<D>; 4],
    rotated_value: &RotateRightOp<ExtensionTarget<D>>,
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
    let input_bytes_rotated = [
        input_bytes[shifted_bytes % 4],
        input_bytes[(1 + shifted_bytes) % 4],
        input_bytes[(2 + shifted_bytes) % 4],
        input_bytes[(3 + shifted_bytes) % 4],
    ];

    let mut first_shift = builder.zero_extension();
    let mut last_carry = builder.zero_extension();
    for i in (0..4).rev() {
        let tmp1 = builder.mul_extension(rotated_value.shift[i], shifted_bits_power);
        let tmp2 = builder.add_extension(rotated_value.carry[i], tmp1);

        let constraint = builder.sub_extension(input_bytes_rotated[i], tmp2);
        result.push(constraint);

        if i == 3 {
            first_shift = rotated_value.shift[i];
        } else {
            let tmp1 = builder.mul_extension(last_carry, carry_multiplier);
            let tmp2 = builder.add_extension(rotated_value.shift[i], tmp1);
            result.push(builder.sub_extension(rotated_value.value[i], tmp2));
        }

        last_carry = rotated_value.carry[i];
    }

    let tmp1 = builder.mul_extension(last_carry, carry_multiplier);
    let tmp2 = builder.add_extension(first_shift, tmp1);
    result.push(builder.sub_extension(rotated_value.value[3], tmp2));
    result
}

/// Shifts a byte to the right and returns both the shifted byte and the bits that carried.
pub const fn shr_carry(input: u8, rotation: u8) -> (u8, u8) {
    let c_mod = rotation & 0x7;
    if c_mod != 0 {
        let res = input >> c_mod;
        let carry = (input << (8 - c_mod)) >> (8 - c_mod);
        (res, carry)
    } else {
        (input, 0u8)
    }
}

pub const fn shifted_bytes(rotation: usize) -> usize {
    rotation / 8
}

pub const fn shifted_bits(rotation: usize) -> usize {
    rotation % 8
}

pub const fn carry_multiplier(rotation: usize) -> u32 {
    let nb_bits_to_shift = shifted_bits(rotation);
    1 << (8 - nb_bits_to_shift)
}
