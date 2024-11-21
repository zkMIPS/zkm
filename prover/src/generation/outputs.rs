use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::GenericConfig;
use std::collections::HashMap;

use crate::generation::state::GenerationState;
use crate::witness::errors::ProgramError;

#[derive(Clone, Debug)]
pub struct GenerationOutputs {
    pub new_state: HashMap<i32, i32>,
}

pub(crate) fn get_outputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    _state: &mut GenerationState<F, C, D>,
) -> Result<GenerationOutputs, ProgramError> {
    // FIXME
    Ok(GenerationOutputs {
        new_state: HashMap::new(),
    })
}
