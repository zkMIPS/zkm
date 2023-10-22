use crate::generation::state::GenerationState;
use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::columns::CpuColumnsView;

pub(crate) fn generate_bootstrap_kernel<F: Field>(state: &mut GenerationState<F>) {

    // let mut final_cpu_row = CpuColumnsView::default();
}
