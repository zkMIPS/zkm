use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use crate::keccak::logic::andn_gen_circuit;

pub(crate) fn and_op<F: RichField + Extendable<D>, const D: usize, const N: usize>(
    x: [F; N],
    y: [F; N]
) -> [F; N] {
    let mut result = [F::ZERO; N];
    for i in 0..N {
        debug_assert!(x[i].is_zero() || x[i].is_one());
        debug_assert!(y[i].is_zero() || y[i].is_one());
        result[i] = x[i] * y[i];
    }
    result
}

pub(crate) fn andn_op<F: RichField + Extendable<D>, const D: usize, const N: usize>(
    x: [F; N],
    y: [F; N]
) -> [F; N] {
    let mut result = [F::ZERO; N];
    for i in 0..N {
        debug_assert!(x[i].is_zero() || x[i].is_one());
        debug_assert!(y[i].is_zero() || y[i].is_one());
        result[i] = crate::keccak::logic::andn(x[i], y[i]);
    }
    result
}

pub(crate) fn xor_op<F: RichField + Extendable<D>, const D: usize, const N: usize>(
    x: [F; N],
    y: [F; N]
) -> [F; N] {
    let mut result = [F::ZERO; N];
    for i in 0..N {
        debug_assert!(x[i].is_zero() || x[i].is_one());
        debug_assert!(y[i].is_zero() || y[i].is_one());
        result[i] = crate::keccak::logic::xor([x[i], y[i]]);
    }
    result
}

pub(crate) fn from_be_bits_to_u32( bits: [u8; 32]) -> u32 {
    let mut result = 0;
    for i in 0..32 {
        result |= (bits[i] as u32) << i;
    }
    result
}