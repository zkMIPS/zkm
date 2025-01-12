use itertools::Itertools;
use std::mem::{size_of, transmute_copy, ManuallyDrop};

use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::util::transpose;

/// Construct an integer from its constituent bits (in little-endian order)
pub fn limb_from_bits_le<P: PackedField>(iter: impl IntoIterator<Item = P>) -> P {
    // TODO: This is technically wrong, as 1 << i won't be canonical for all fields...
    iter.into_iter()
        .enumerate()
        .map(|(i, bit)| bit * P::Scalar::from_canonical_u64(1 << i))
        .sum()
}

/// Construct an integer from its constituent bits (in little-endian order): recursive edition
pub fn limb_from_bits_le_recursive<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    iter: impl IntoIterator<Item = ExtensionTarget<D>>,
) -> ExtensionTarget<D> {
    iter.into_iter()
        .enumerate()
        .fold(builder.zero_extension(), |acc, (i, bit)| {
            // TODO: This is technically wrong, as 1 << i won't be canonical for all fields...
            builder.mul_const_add_extension(F::from_canonical_u64(1 << i), bit, acc)
        })
}

/// A helper function to transpose a row-wise trace and put it in the format that `prove` expects.
pub fn trace_rows_to_poly_values<F: Field, const COLUMNS: usize>(
    trace_rows: Vec<[F; COLUMNS]>,
) -> Vec<PolynomialValues<F>> {
    let trace_row_vecs = trace_rows.into_iter().map(|row| row.to_vec()).collect_vec();
    let trace_col_vecs: Vec<Vec<F>> = transpose(&trace_row_vecs);
    trace_col_vecs
        .into_iter()
        .map(|column| PolynomialValues::new(column))
        .collect()
}

pub(crate) const fn indices_arr<const N: usize>() -> [usize; N] {
    let mut indices_arr = [0; N];
    let mut i = 0;
    while i < N {
        indices_arr[i] = i;
        i += 1;
    }
    indices_arr
}

pub(crate) unsafe fn transmute_no_compile_time_size_checks<T, U>(value: T) -> U {
    debug_assert_eq!(size_of::<T>(), size_of::<U>());
    // Need ManuallyDrop so that `value` is not dropped by this function.
    let value = ManuallyDrop::new(value);
    // Copy the bit pattern. The original value is no longer safe to use.
    transmute_copy(&value)
}

pub fn u32_array_to_u8_vec(u32_array: &[u32; 8]) -> Vec<u8> {
    let mut u8_vec = Vec::with_capacity(u32_array.len() * 4);
    for &item in u32_array {
        u8_vec.extend_from_slice(&item.to_le_bytes());
    }
    u8_vec
}

#[doc(hidden)]
pub use plonky2_maybe_rayon::rayon as __rayon_reexport;

// might improve error message on type error
#[doc(hidden)]
pub fn __requires_sendable_closure<R, F: FnOnce() -> R + Send>(x: F) -> F {
    x
}

macro_rules! __join_implementation {
    ($len:expr; $($f:ident $r:ident $a:expr),*; $b:expr, $($c:expr,)*) => {
        crate::util::__join_implementation!{$len + 1; $($f $r $a,)* f r $b; $($c,)* }
    };
    ($len:expr; $($f:ident $r:ident $a:expr),* ;) => {
        match ($(Some(crate::util::__requires_sendable_closure($a)),)*) {
            ($(mut $f,)*) => {
                $(let mut $r = None;)*
                let array: [&mut (dyn FnMut() + Send); $len] = [
                    $(&mut || $r = Some((&mut $f).take().unwrap()())),*
                ];
                crate::util::__rayon_reexport::iter::ParallelIterator::for_each(
                    crate::util::__rayon_reexport::iter::IntoParallelIterator::into_par_iter(array),
                    |f| f(),
                );
                ($($r.unwrap(),)*)
            }
        }
    };
}

pub(crate) use __join_implementation;

macro_rules! join {
    ($($($a:expr),+$(,)?)?) => {
        crate::util::__join_implementation!{0;;$($($a,)+)?}
    };
}

pub(crate) use join;
