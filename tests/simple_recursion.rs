#![allow(clippy::upper_case_acronyms)]
use std::time::Duration;

use mips_circuits::all_stark::AllStark;
use mips_circuits::config::StarkConfig;
use mips_circuits::cpu::kernel::assembler::TEST_KERNEL;
use mips_circuits::fixed_recursive_verifier::AllRecursiveCircuits;
use mips_circuits::proof::PublicValues;
//use mips_circuits::cpu::kernel::assembler::segment_kernel;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::timing::TimingTree;
use mips_circuits::backend::circuit::Groth16WrapperParameters;
use mips_circuits::backend::wrapper::wrap::WrappedCircuit;
use mips_circuits::frontend::builder::CircuitBuilder;
use mips_circuits::prelude::DefaultParameters;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

// Tests proving two transactions, one of which with logs, and aggregating them.
#[test]
fn test_mips_with_aggreg() -> anyhow::Result<()> {
    type InnerParameters = DefaultParameters;
    type OuterParameters = Groth16WrapperParameters;

    env_logger::try_init().unwrap_or_default();

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    // Preprocess all circuits.
    let all_circuits = AllRecursiveCircuits::<F, C, D>::new(
        &all_stark,
        &[16..20, 17..22, 12..20, 19..22],
        &config,
    );

    let input_first = &TEST_KERNEL; //segment_kernel();
    let mut timing = TimingTree::new("prove root first", log::Level::Info);
    let (root_proof_first, first_public_values) =
        all_circuits.prove_root(&all_stark, input_first, &config, &mut timing)?;

    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(root_proof_first.clone())?;

    let input = &TEST_KERNEL; //segment_kernel();
    let mut timing = TimingTree::new("prove root second", log::Level::Info);
    let (root_proof, public_values) =
        all_circuits.prove_root(&all_stark, input, &config, &mut timing)?;
    timing.filter(Duration::from_millis(100)).print();

    all_circuits.verify_root(root_proof.clone())?;

    // Update public values for the aggregation.
    let agg_public_values = PublicValues {
        roots_before: first_public_values.roots_before,
        roots_after: public_values.roots_after,
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

    log::info!(
        "proof size: {:?}",
        serde_json::to_string(&block_proof.proof).unwrap().len()
    );
    all_circuits.verify_block(&block_proof);

    let build_path = "../verifier/data".to_string();
    let path = format!("{}/test_circuit/", build_path);
    let mut builder = CircuitBuilder::<DefaultParameters, 2>::new();
    let mut circuit = builder.build();
    circuit.set_data(all_circuits.block.circuit);
    let wrapped_circuit = WrappedCircuit::<InnerParameters, OuterParameters, D>::build(circuit);
    let wrapped_proof = wrapped_circuit.prove(&proof).unwrap();
    wrapped_proof.save(path).unwrap();
}
