pub(crate) mod outputs;
use crate::generation::outputs::GenerationOutputs;
use crate::proof::{BlockHashes, BlockMetadata, ExtraBlockData, PublicValues, TrieRoots};
use anyhow::anyhow;
use ethereum_types::{Address, BigEndianHash, H256, U256};
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::RichField;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::all_stark::{AllStark, NUM_TABLES};
use crate::config::StarkConfig;
use crate::cpu::columns::CpuColumnsView;

/// Inputs needed for trace generation.
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct GenerationInputs {}

pub fn generate_traces<F: RichField + Extendable<D>, const D: usize>(
    all_stark: &AllStark<F, D>,
    inputs: GenerationInputs,
    config: &StarkConfig,
    timing: &mut TimingTree,
) -> anyhow::Result<(
    [Vec<PolynomialValues<F>>; NUM_TABLES],
    PublicValues,
    GenerationOutputs,
)> {
    panic!("Unimpls");
}
