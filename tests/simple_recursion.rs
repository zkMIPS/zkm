#![allow(clippy::upper_case_acronyms)]
use std::time::Duration;

use mips_circuits::all_stark::AllStark;
use mips_circuits::config::StarkConfig;
use mips_circuits::fixed_recursive_verifier::AllRecursiveCircuits;
use mips_circuits::generation::GenerationInputs;
use mips_circuits::proof::{MemsRoot, PublicValues};

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::timing::TimingTree;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

// Tests proving two transactions, one of which with logs, and aggregating them.
#[test]
fn test_mips_with_aggreg() -> anyhow::Result<()> {
    env_logger::try_init().unwrap_or_default();

    let inputs_first = GenerationInputs {};

    let all_stark = AllStark::<F, D>::default();
    let mut config = StarkConfig::standard_fast_config();
    config.fri_config.rate_bits = 3;
    // Preprocess all circuits.
    let all_circuits = AllRecursiveCircuits::<F, C, D>::new(
        &all_stark,
        &[16..20, 17..22, 12..20, 19..22],
        &config,
    );

    let mut timing = TimingTree::new("prove root first", log::Level::Info);
    let (root_proof_first, first_public_values) =
        all_circuits.prove_root(&all_stark, &config, inputs_first, &mut timing)?;

    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(root_proof_first.clone())?;

    let inputs = GenerationInputs {};

    let mut timing = TimingTree::new("prove root second", log::Level::Info);
    let (root_proof, public_values) =
        all_circuits.prove_root(&all_stark, &config, inputs, &mut timing)?;
    timing.filter(Duration::from_millis(100)).print();

    all_circuits.verify_root(root_proof.clone())?;

    // Update public values for the aggregation.
    let agg_public_values = PublicValues {
        roots_before: MemsRoot { root: 0 },
        roots_after: MemsRoot { root: 0 },
    };

    // We can duplicate the proofs here because the state hasn't mutated.
    let (agg_proof, updated_agg_public_values) = all_circuits.prove_aggregation(
        false,
        &root_proof_first,
        false,
        &root_proof,
        agg_public_values,
    )?;
    all_circuits.verify_aggregation(&agg_proof)?;
    let (block_proof, _block_public_values) =
        all_circuits.prove_block(None, &agg_proof, updated_agg_public_values)?;
    all_circuits.verify_block(&block_proof)
}
