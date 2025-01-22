use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use crate::sha_extend_sponge::sha_extend_sponge_stark::NUM_ROUNDS;


// Compute (x - y - diff) * sum_round_flags
pub(crate) fn diff_address_ext_circuit_constraint<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    sum_round_flags: ExtensionTarget<D>,
    x: ExtensionTarget<D>,
    y: ExtensionTarget<D>,
    diff: usize
) -> ExtensionTarget<D> {
    let inter_1 = builder.sub_extension(x, y);
    let diff_ext = builder.constant_extension(F::Extension::from_canonical_u32(diff as u32));
    let address_diff = builder.sub_extension(inter_1, diff_ext);
    builder.mul_extension(sum_round_flags, address_diff)
}

// Compute nxt_round - local_round - 1
pub(crate) fn round_increment_ext_circuit_constraint<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    local_round: [ExtensionTarget<D>; NUM_ROUNDS],
    next_round: [ExtensionTarget<D>; NUM_ROUNDS],
) -> ExtensionTarget<D> {

    let one_ext = builder.one_extension();
    let local_round_indices: Vec<_> =
        (0..NUM_ROUNDS).map(|i| {
            let index = builder.constant_extension(F::Extension::from_canonical_u32(i as u32));
            builder.mul_extension(local_round[i], index)
        }).collect();

    let local_round_index = builder.add_many_extension(local_round_indices);

    let next_round_indices: Vec<_> =
        (0..NUM_ROUNDS).map(|i| {
            let index = builder.constant_extension(F::Extension::from_canonical_u32(i as u32));
            builder.mul_extension(next_round[i], index)
        }).collect();

    let next_round_index = builder.add_many_extension(next_round_indices);

    let increment = builder.sub_extension(next_round_index, local_round_index);
    builder.sub_extension(increment, one_ext)

}