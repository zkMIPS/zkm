use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;


pub(crate) fn get_input_range(i: usize) -> std::ops::Range<usize> {
    (0 + i * 32)..(32 + i * 32)
}


// these operators are applied in big-endian form
pub(crate) fn rotate_right<F: RichField + Extendable<D>, const D: usize>(value: [F; 32], amount: usize) -> [F; 32] {
    let mut result = [F::ZERO; 32];
    for i in 0..32 {
        result[i] = value[(i + amount) % 32];
    }
    result
}

pub(crate) fn rotate_right_packed_constraints<P: PackedField>(
    value: [P; 32],
    rotated_value: [P;32],
    amount: usize,
) -> Vec<P> {
    let mut result = Vec::new();
    for i in 0..32 {
        result.push(value[i] - rotated_value[(i + 32 - amount) % 32]);
    }
    result
}

pub(crate) fn rotate_right_ext_circuit_constraint<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value: [ExtensionTarget<D>;32],
    rotated_value: [ExtensionTarget<D>; 32],
    amount: usize
) -> Vec<ExtensionTarget<D>> {
    let mut result = Vec::new();
    for i in 0..32 {
        result.push(builder.sub_extension(value[i], rotated_value[(i + 32 - amount) % 32]));
    }
    result
}

pub(crate) fn shift_right<F: RichField + Extendable<D>, const D: usize>(value: [F; 32], amount: usize) -> [F; 32] {
    let mut result = [F::ZERO; 32];
    if amount < 32 {
        for i in 0..32 - amount {
            result[i] = value[i + amount];
        }
    }
    result
}

pub(crate) fn shift_right_packed_constraints<P: PackedField>(
    value: [P; 32],
    shifted_value: [P;32],
    amount: usize,
) -> Vec<P> {
    let mut result = Vec::new();
    for i in 0..32 - amount {
        result.push(value[i + amount] - shifted_value[i]);
    }
    for i in (32 - 3)..32 {
        result.push(shifted_value[i]);
    }
    result
}

pub(crate) fn shift_right_ext_circuit_constraints<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value: [ExtensionTarget<D>;32],
    shifted_value: [ExtensionTarget<D>; 32],
    amount: usize
) -> Vec<ExtensionTarget<D>> {
    let mut result = Vec::new();
    for i in 0..32 - amount {
        result.push(builder.sub_extension(value[i + amount], shifted_value[i]));
    }
    for i in (32 - 3)..32 {
        result.push(shifted_value[i]);
    }
    result
}

pub(crate) fn xor3 <F: RichField + Extendable<D>, const D: usize, const N: usize>(a: [F; N], b: [F; N], c: [F; N]) -> [F; N] {
    let mut result = [F::ZERO; N];
    for i in 0..N {
        result[i] = crate::keccak::logic::xor([a[i], b[i], c[i]]);
    }
    result
}

pub(crate) fn wrapping_add<F: RichField + Extendable<D>, const D: usize, const N: usize>(
    a: [F; N],
    b: [F; N]
) -> ([F; N], [F; N]) {
    let mut result = [F::ZERO; N];
    let mut carries = [F::ZERO; N];
    let mut sum = F::ZERO;
    let mut carry = F::ZERO;
    for i in 0..N {
        debug_assert!(a[i].is_zero() || a[i].is_one());
        debug_assert!(b[i].is_zero() || b[i].is_one());

        let tmp = (a[i] + b[i] + carry).to_canonical_u64();
        sum = F::from_canonical_u64(tmp & 1);
        carry = F::from_canonical_u64(tmp >> 1);
        carries[i] = carry;
        result[i] = sum;
    }
    (result, carries)
}

pub(crate) fn from_be_bits_to_u32<F: RichField + Extendable<D>, const D: usize>(value: [F; 32]) -> u32 {
    let mut result = 0;
    for i in 0..32 {
        debug_assert!(value[i].is_zero() || value[i].is_one());
        result |= (value[i].to_canonical_u64() as u32) << i;
    }
    result
}

pub(crate) fn from_u32_to_be_bits(value: u32) -> [u32; 32] {
    let mut result = [0; 32];
    for i in 0..32 {
        result[i] = ((value >> i) & 1) as u32;
    }
    result
}

/// Computes the constraints of wrapping add
pub(crate) fn wrapping_add_packed_constraints<P: PackedField, const N: usize>(
    x: [P; N],
    y: [P; N],
    carry: [P; N],
    out: [P; N]
) -> Vec<P> {

    let mut result = vec![];
    let mut pre_carry = P::ZEROS;
    for i in 0..N {
        let sum = x[i] + y[i] + pre_carry;

        let out_constraint = (sum - P::ONES) * (sum - P::ONES - P::ONES - P::ONES) * out[i]
            + sum * (sum - P::ONES - P::ONES) * (out[i] - P::ONES);

        let carry_constraint = carry[i] + carry[i] + out[i] - sum;
        result.push(out_constraint);
        result.push(carry_constraint);
        pre_carry = carry[i];
    }
    result
}

pub(crate) fn wrapping_add_ext_circuit_constraints<F: RichField + Extendable<D>, const D: usize, const N: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: [ExtensionTarget<D>; N],
    y: [ExtensionTarget<D>; N],
    carry: [ExtensionTarget<D>; N],
    out: [ExtensionTarget<D>; N]
) -> Vec<ExtensionTarget<D>> {

    let mut result = vec![];
    let mut pre_carry= builder.zero_extension();
    let one_ext = builder.one_extension();
    let two_ext = builder.two_extension();
    let three_ext = builder.constant_extension(F::Extension::from_canonical_u8(3));
    for i in 0..N {
        let sum = builder.add_many_extension([x[i], y[i], pre_carry]);

        let inner_1 = builder.sub_extension(sum, one_ext);
        let inner_2 = builder.sub_extension(sum, three_ext);
        let tmp1 = builder.mul_many_extension(
            [inner_1, inner_2, out[i]]
        );

        let inner_1 = builder.sub_extension(sum, two_ext);
        let inner_2 = builder.sub_extension(out[i], one_ext);
        let tmp2 = builder.mul_many_extension(
            [sum, inner_1, inner_2]
        );
        result.push(builder.add_extension(tmp1, tmp2));

        let tmp3 = builder.add_many_extension(
            [carry[i], carry[i], out[i]]
        );
        result.push(builder.sub_extension(tmp3, sum));

        pre_carry = carry[i];
    }
    result
}