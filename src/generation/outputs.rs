use plonky2::field::types::Field;
use std::collections::HashMap;

use crate::generation::state::GenerationState;
use crate::witness::errors::ProgramError;

#[derive(Clone, Debug)]
pub struct GenerationOutputs {
    pub new_state: HashMap<i32, i32>,
}

pub(crate) fn get_outputs<F: Field>(
    _state: &mut GenerationState<F>,
) -> Result<GenerationOutputs, ProgramError> {
    // FIXME
    Ok(GenerationOutputs {
        new_state: HashMap::new(),
    })
}
