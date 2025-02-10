use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

pub struct WrappingAdd2Op<T> {
    /// The result of `a + b`.
    pub value: [T; 4],

    /// The carry. Each digit is carry == 0, 1.
    pub carry: [T; 2],
}

impl<F: Field> WrappingAdd2Op<F> {
    pub fn generate_trace(&mut self, a: [u8; 4], b: [u8; 4]) -> u32 {
        let a_u32 = u32::from_le_bytes(a);
        let b_u32 = u32::from_le_bytes(b);

        let expected = a_u32.wrapping_add(b_u32);

        let overflowed_result = a_u32 as u64 + b_u32 as u64;
        let carry = overflowed_result >> 32;

        assert_eq!(carry * 2_u64.pow(32) + expected as u64, overflowed_result);
        assert!(carry < 2);
        self.carry = [F::ZERO; 2];
        self.carry[carry as usize] = F::ONE;
        self.value = expected.to_le_bytes().map(F::from_canonical_u8);

        expected
    }
}

pub(crate) fn wrapping_add_2_packed_constraints<P: PackedField>(
    a: [P; 4],
    b: [P; 4],
    cols: &WrappingAdd2Op<P>,
) -> Vec<P> {
    let mut result = vec![];

    let two_pow_8 = P::from(P::Scalar::from_canonical_u32(2u32.pow(8)));
    let two_pow_16 = P::from(P::Scalar::from_canonical_u32(2u32.pow(16)));
    let two_pow_24 = P::from(P::Scalar::from_canonical_u32(2u32.pow(24)));
    let two_pow_32 = P::from(P::Scalar::from_canonical_u64(2u64.pow(32)));

    let wrapping_added_result = cols.value[0]
        + two_pow_8 * cols.value[1]
        + two_pow_16 * cols.value[2]
        + two_pow_24 * cols.value[3];
    // Each value in carry_{0,1} is 0 or 1, and exactly one of them is 1 per digit.
    for i in 0..2 {
        result.push(cols.carry[i] * (P::ONES - cols.carry[i]));
    }
    result.push(cols.carry[0] + cols.carry[1] - P::ONES);

    // Calculates carry from carry_{0,1}.
    let carry = cols.carry[1];

    // Wrapping added constraint
    let overflowed_result = (a[0] + b[0])
        + (a[1] + b[1]) * two_pow_8
        + (a[2] + b[2]) * two_pow_16
        + (a[3] + b[3]) * two_pow_24;

    let constraint = overflowed_result - carry * two_pow_32 - wrapping_added_result;
    result.push(constraint);

    result
}
pub(crate) fn wrapping_add_2_ext_circuit_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    a: [ExtensionTarget<D>; 4],
    b: [ExtensionTarget<D>; 4],
    cols: &WrappingAdd2Op<ExtensionTarget<D>>,
) -> Vec<ExtensionTarget<D>> {
    let mut result = vec![];

    let one = builder.one_extension();
    let two_pow_8 = builder.constant_extension(F::Extension::from_canonical_u32(2u32.pow(8)));
    let two_pow_16 = builder.constant_extension(F::Extension::from_canonical_u32(2u32.pow(16)));
    let two_pow_24 = builder.constant_extension(F::Extension::from_canonical_u32(2u32.pow(24)));
    let two_pow_32 = builder.constant_extension(F::Extension::from_canonical_u64(2u64.pow(32)));

    let tmp = builder.mul_extension(cols.value[1], two_pow_8);
    let tmp2 = builder.mul_extension(cols.value[2], two_pow_16);
    let tmp3 = builder.mul_extension(cols.value[3], two_pow_24);
    let wrapping_added_result = builder.add_many_extension([cols.value[0], tmp, tmp2, tmp3]);

    // Each value in carry_{0,1} is 0 or 1, and exactly one of them is 1 per digit.
    for i in 0..2 {
        let tmp = builder.sub_extension(one, cols.carry[i]);
        result.push(builder.mul_extension(cols.carry[i], tmp));
    }

    let tmp = builder.add_many_extension(cols.carry);
    result.push(builder.sub_extension(tmp, one));

    // Calculates carry from carry_{0,1}.
    let carry = cols.carry[1];

    // Wrapping added constraint
    let byte_0 = builder.add_many_extension([a[0], b[0]]);
    let byte_1 = builder.add_many_extension([a[1], b[1]]);
    let byte_2 = builder.add_many_extension([a[2], b[2]]);
    let byte_3 = builder.add_many_extension([a[3], b[3]]);

    let tmp1 = builder.mul_extension(byte_1, two_pow_8);
    let tmp2 = builder.mul_extension(byte_2, two_pow_16);
    let tmp3 = builder.mul_extension(byte_3, two_pow_24);
    let overflowed_result = builder.add_many_extension([byte_0, tmp1, tmp2, tmp3]);

    let carry_mul = builder.mul_extension(carry, two_pow_32);
    let computed_overflowed_result = builder.add_extension(carry_mul, wrapping_added_result);
    let constraint = builder.sub_extension(overflowed_result, computed_overflowed_result);
    result.push(constraint);

    result
}
