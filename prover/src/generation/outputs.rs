use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::GenericConfig;

use crate::generation::state::GenerationState;
use crate::witness::errors::ProgramError;

#[derive(Clone, Debug)]
pub struct GenerationOutputs {
    pub output: Vec<u8>,
}

pub(crate) fn get_outputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    state: &mut GenerationState<F, C, D>,
) -> Result<GenerationOutputs, ProgramError> {
    Ok(GenerationOutputs {
        output: state.public_values_stream.clone(),
    })
}
