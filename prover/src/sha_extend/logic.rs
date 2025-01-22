use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
// these operators are applied in big-endian form

pub fn rotate_right<F: RichField + Extendable<D>, const D: usize>(value: [F; 32], amount: usize) -> [F; 32] {
    let mut result = [F::ZERO; 32];
    for i in 0..32 {
        result[i] = value[(i + amount) % 32];
    }
    result
}

pub fn shift_right<F: RichField + Extendable<D>, const D: usize>(value: [F; 32], amount: usize) -> [F; 32] {
    let mut result = [F::ZERO; 32];
    if amount < 32 {
        for i in 0..32 - amount {
            result[i] = value[i + amount];
        }
    }
    result
}

pub fn xor3 <F: RichField + Extendable<D>, const D: usize>(a: [F; 32], b: [F; 32], c: [F; 32]) -> [F; 32] {
    let mut result = [F::ZERO; 32];
    for i in 0..32 {
        result[i] = crate::keccak::logic::xor([a[i], b[i], c[i]]);
    }
    result
}

pub fn wrapping_add<F: RichField + Extendable<D>, const D: usize>(a: [F; 32], b: [F; 32]) -> ([F; 32], [F; 32]) {
    let mut result = [F::ZERO; 32];
    let mut carries = [F::ZERO; 32];
    let mut sum = F::ZERO;
    let mut carry = F::ZERO;
    for i in 0..32 {
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

pub fn from_be_bits_to_u32<F: RichField + Extendable<D>, const D: usize>(value: [F; 32]) -> u32 {
    let mut result = 0;
    for i in 0..32 {
        debug_assert!(value[i].is_zero() || value[i].is_one());
        result |= (value[i].to_canonical_u64() as u32) << i;
    }
    result
}

pub fn from_u32_to_be_bits(value: u32) -> [u32; 32] {
    let mut result = [0; 32];
    for i in 0..32 {
        result[i] = ((value >> i) & 1) as u32;
    }
    result
}