use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

pub struct WrappingAdd5Op<T> {
    /// The result of `a + b + c + d + e`.
    pub value: [T; 4],

    /// Indicates if the carry for the `i`th digit is 0.
    pub is_carry_0: [T; 4],

    /// Indicates if the carry for the `i`th digit is 1.
    pub is_carry_1: [T; 4],

    /// Indicates if the carry for the `i`th digit is 2.
    pub is_carry_2: [T; 4],

    /// Indicates if the carry for the `i`th digit is 3.
    pub is_carry_3: [T; 4],

    /// Indicates if the carry for the `i`th limb is 4. The carry when adding 5 words is at most 4.
    pub is_carry_4: [T; 4],

    /// The carry for the `i`th digit.
    pub carry: [T; 4],
}

impl<F: Field> WrappingAdd5Op<F> {
    pub fn generate_trace(
        &mut self,
        a: [u8; 4],
        b: [u8; 4],
        c: [u8; 4],
        d: [u8; 4],
        e: [u8; 4],
    ) -> u32 {
        let base = 256;
        let mut carry = [0u8, 0u8, 0u8, 0u8, 0u8];

        for i in 0..4 {
            let mut res =
                (a[i] as u32) + (b[i] as u32) + (c[i] as u32) + (d[i] as u32) + (e[i] as u32);
            if i > 0 {
                res += carry[i - 1] as u32;
            }
            carry[i] = (res / base) as u8;
            self.is_carry_0[i] = F::from_bool(carry[i] == 0);
            self.is_carry_1[i] = F::from_bool(carry[i] == 1);
            self.is_carry_2[i] = F::from_bool(carry[i] == 2);
            self.is_carry_3[i] = F::from_bool(carry[i] == 3);
            self.is_carry_4[i] = F::from_bool(carry[i] == 4);
            self.carry[i] = F::from_canonical_u8(carry[i]);
            debug_assert!(carry[i] <= 4);
            self.value[i] = F::from_canonical_u32(res % base);
        }

        let a_u32 = u32::from_le_bytes(a);
        let b_u32 = u32::from_le_bytes(b);
        let c_u32 = u32::from_le_bytes(c);
        let d_u32 = u32::from_le_bytes(d);
        let e_u32 = u32::from_le_bytes(e);
        a_u32
            .wrapping_add(b_u32)
            .wrapping_add(c_u32)
            .wrapping_add(d_u32)
            .wrapping_add(e_u32)
    }
}

pub(crate) fn wrapping_add_5_packed_constraints<P: PackedField>(
    a: [P; 4],
    b: [P; 4],
    c: [P; 4],
    d: [P; 4],
    e: [P; 4],
    cols: &WrappingAdd5Op<P>,
) -> Vec<P> {
    let mut result = vec![];
    // Each value in is_carry_{0,1,2,3,4} is 0 or 1, and exactly one of them is 1 per digit.
    for i in 0..4 {
        result.push(cols.is_carry_0[i] * (P::ONES - cols.is_carry_0[i]));
        result.push(cols.is_carry_1[i] * (P::ONES - cols.is_carry_1[i]));
        result.push(cols.is_carry_2[i] * (P::ONES - cols.is_carry_2[i]));
        result.push(cols.is_carry_3[i] * (P::ONES - cols.is_carry_3[i]));
        result.push(cols.is_carry_4[i] * (P::ONES - cols.is_carry_4[i]));
        result.push(
            cols.is_carry_0[i]
                + cols.is_carry_1[i]
                + cols.is_carry_2[i]
                + cols.is_carry_3[i]
                + cols.is_carry_4[i]
                - P::ONES,
        );
    }

    // Calculates carry from is_carry_{0,1,2,3,4}.
    let one = P::ONES;
    let two = P::from(P::Scalar::from_canonical_u32(2));
    let three = P::from(P::Scalar::from_canonical_u32(3));
    let four = P::from(P::Scalar::from_canonical_u32(4));

    for i in 0..4 {
        result.push(
            cols.carry[i]
                - cols.is_carry_1[i] * one
                - cols.is_carry_2[i] * two
                - cols.is_carry_3[i] * three
                - cols.is_carry_4[i] * four,
        );
    }

    // Compare the sum and summands by looking at carry.
    let base = P::from(P::Scalar::from_canonical_u32(256));
    // For each limb, assert that difference between the carried result and the non-carried
    // result is the product of carry and base.
    for i in 0..4 {
        let mut overflow = a[i] + b[i] + c[i] + d[i] + e[i] - cols.value[i];
        if i > 0 {
            overflow = overflow + cols.carry[i - 1];
        }
        result.push(cols.carry[i] * base - overflow);
    }
    result
}

pub(crate) fn wrapping_add_5_ext_circuit_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    a: [ExtensionTarget<D>; 4],
    b: [ExtensionTarget<D>; 4],
    c: [ExtensionTarget<D>; 4],
    d: [ExtensionTarget<D>; 4],
    e: [ExtensionTarget<D>; 4],
    cols: &WrappingAdd5Op<ExtensionTarget<D>>,
) -> Vec<ExtensionTarget<D>> {
    let mut result = vec![];
    let one = builder.one_extension();
    let two = builder.constant_extension(F::Extension::from_canonical_u32(2));
    let three = builder.constant_extension(F::Extension::from_canonical_u32(3));
    let four = builder.constant_extension(F::Extension::from_canonical_u32(4));
    // Each value in is_carry_{0,1,2,3, 4} is 0 or 1, and exactly one of them is 1 per digit.
    for i in 0..4 {
        let tmp = builder.sub_extension(one, cols.is_carry_0[i]);
        result.push(builder.mul_extension(cols.is_carry_0[i], tmp));

        let tmp = builder.sub_extension(one, cols.is_carry_1[i]);
        result.push(builder.mul_extension(cols.is_carry_1[i], tmp));

        let tmp = builder.sub_extension(one, cols.is_carry_2[i]);
        result.push(builder.mul_extension(cols.is_carry_2[i], tmp));

        let tmp = builder.sub_extension(one, cols.is_carry_3[i]);
        result.push(builder.mul_extension(cols.is_carry_3[i], tmp));

        let tmp = builder.sub_extension(one, cols.is_carry_4[i]);
        result.push(builder.mul_extension(cols.is_carry_4[i], tmp));

        let tmp = builder.add_extension(cols.is_carry_0[i], cols.is_carry_1[i]);
        let tmp = builder.add_extension(tmp, cols.is_carry_2[i]);
        let tmp = builder.add_extension(tmp, cols.is_carry_3[i]);
        let tmp = builder.add_extension(tmp, cols.is_carry_4[i]);
        result.push(builder.sub_extension(tmp, one));
    }

    // Calculates carry from is_carry_{0,1,2,3, 4}.
    for i in 0..4 {
        let tmp = builder.mul_extension(cols.is_carry_1[i], one);
        let tmp2 = builder.mul_extension(cols.is_carry_2[i], two);
        let tmp3 = builder.mul_extension(cols.is_carry_3[i], three);
        let tmp4 = builder.mul_extension(cols.is_carry_4[i], four);
        let tmp5 = builder.add_extension(tmp, tmp2);
        let tmp5 = builder.add_extension(tmp5, tmp3);
        let tmp5 = builder.add_extension(tmp5, tmp4);
        result.push(builder.sub_extension(cols.carry[i], tmp5));
    }

    // Compare the sum and summands by looking at carry.
    let base = builder.constant_extension(F::Extension::from_canonical_u32(256));
    // For each limb, assert that difference between the carried result and the non-carried
    // result is the product of carry and base.
    for i in 0..4 {
        let tmp1 = builder.add_extension(a[i], b[i]);
        let tmp2 = builder.add_extension(tmp1, c[i]);
        let tmp3 = builder.add_extension(tmp2, d[i]);
        let tmp4 = builder.add_extension(tmp3, e[i]);
        let mut overflow = builder.sub_extension(tmp4, cols.value[i]);
        if i > 0 {
            overflow = builder.add_extension(overflow, cols.carry[i - 1]);
        }
        let tmp5 = builder.mul_extension(cols.carry[i], base);
        result.push(builder.sub_extension(tmp5, overflow));
    }

    result
}
