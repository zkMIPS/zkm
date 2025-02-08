use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

pub struct WrappingAdd2Op<T> {
    /// The result of `a + b`.
    pub value: [T; 4],

    /// Trace.
    pub carry: [T; 3],
}

impl<F: Field> WrappingAdd2Op<F> {
    pub fn generate_trace(&mut self, a: [u8; 4], b: [u8; 4]) -> u32 {
        let a_u32 = u32::from_le_bytes(a);
        let b_u32 = u32::from_le_bytes(b);
        let expected = a_u32.wrapping_add(b_u32);
        self.value = expected.to_le_bytes().map(F::from_canonical_u8);

        let mut carry = [0u8, 0u8, 0u8];
        if (a[0] as u32) + (b[0] as u32) > 255 {
            carry[0] = 1;
            self.carry[0] = F::ONE;
        }
        if (a[1] as u32) + (b[1] as u32) + (carry[0] as u32) > 255 {
            carry[1] = 1;
            self.carry[1] = F::ONE;
        }
        if (a[2] as u32) + (b[2] as u32) + (carry[1] as u32) > 255 {
            carry[2] = 1;
            self.carry[2] = F::ONE;
        }

        let base = 256u32;
        let overflow = a[0]
            .wrapping_add(b[0])
            .wrapping_sub(expected.to_le_bytes()[0]) as u32;
        debug_assert_eq!(overflow.wrapping_mul(overflow.wrapping_sub(base)), 0);

        expected
    }
}

pub(crate) fn wrapping_add_2_packed_constraints<P: PackedField>(
    a: [P; 4],
    b: [P; 4],
    cols: &WrappingAdd2Op<P>,
) -> Vec<P> {
    let mut result = vec![];
    let base = P::from(P::Scalar::from_canonical_u32(256));
    // For each limb, assert that difference between the carried result and the non-carried
    // result is either zero or the base.
    let overflow_0 = a[0] + b[0] - cols.value[0];
    let overflow_1 = a[1] + b[1] - cols.value[1] + cols.carry[0];
    let overflow_2 = a[2] + b[2] - cols.value[2] + cols.carry[1];
    let overflow_3 = a[3] + b[3] - cols.value[3] + cols.carry[2];
    result.push(overflow_0 * (overflow_0 - base));
    result.push(overflow_1 * (overflow_1 - base));
    result.push(overflow_2 * (overflow_2 - base));
    result.push(overflow_3 * (overflow_3 - base));

    // If the carry is one, then the overflow must be the base.
    result.push(cols.carry[0] * (overflow_0 - base));
    result.push(cols.carry[1] * (overflow_1 - base));
    result.push(cols.carry[2] * (overflow_2 - base));

    // If the carry is not one, then the overflow must be zero.
    result.push((cols.carry[0] - P::ONES) * overflow_0);
    result.push((cols.carry[1] - P::ONES) * overflow_1);
    result.push((cols.carry[2] - P::ONES) * overflow_2);

    // Assert that the carry is either zero or one.
    result.push(cols.carry[0] * (cols.carry[0] - P::ONES));
    result.push(cols.carry[1] * (cols.carry[1] - P::ONES));
    result.push(cols.carry[2] * (cols.carry[2] - P::ONES));

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

    let base = builder.constant_extension(F::Extension::from_canonical_u32(256));
    let one = builder.one_extension();
    // For each limb, assert that difference between the carried result and the non-carried
    // result is either zero or the base.
    let tmp = builder.add_extension(a[0], b[0]);
    let overflow_0 = builder.sub_extension(tmp, cols.value[0]);
    let tmp = builder.sub_extension(overflow_0, base);
    result.push(builder.mul_extension(overflow_0, tmp));

    let tmp1 = builder.add_extension(a[1], b[1]);
    let tmp1 = builder.add_extension(tmp1, cols.carry[0]);
    let overflow_1 = builder.sub_extension(tmp1, cols.value[1]);
    let tmp1 = builder.sub_extension(overflow_1, base);
    result.push(builder.mul_extension(overflow_1, tmp1));

    let tmp2 = builder.add_extension(a[2], b[2]);
    let tmp2 = builder.add_extension(tmp2, cols.carry[1]);
    let overflow_2 = builder.sub_extension(tmp2, cols.value[2]);
    let tmp2 = builder.sub_extension(overflow_2, base);
    result.push(builder.mul_extension(overflow_2, tmp2));

    let tmp3 = builder.add_extension(a[3], b[3]);
    let tmp3 = builder.add_extension(tmp3, cols.carry[2]);
    let overflow_3 = builder.sub_extension(tmp3, cols.value[3]);
    let tmp3 = builder.sub_extension(overflow_3, base);
    result.push(builder.mul_extension(overflow_3, tmp3));

    // If the carry is one, then the overflow must be the base.
    result.push(builder.mul_extension(cols.carry[0], tmp));
    result.push(builder.mul_extension(cols.carry[1], tmp1));
    result.push(builder.mul_extension(cols.carry[2], tmp2));

    // If the carry is not one, then the overflow must be zero.
    let tmp = builder.sub_extension(cols.carry[0], one);
    result.push(builder.mul_extension(tmp, overflow_0));

    let tmp1 = builder.sub_extension(cols.carry[1], one);
    result.push(builder.mul_extension(tmp1, overflow_1));

    let tmp2 = builder.sub_extension(cols.carry[2], one);
    result.push(builder.mul_extension(tmp2, overflow_2));

    // Assert that the carry is either zero or one.
    result.push(builder.mul_extension(cols.carry[0], tmp));
    result.push(builder.mul_extension(cols.carry[1], tmp1));
    result.push(builder.mul_extension(cols.carry[2], tmp2));

    result
}
