mod snark;
pub use snark::*;

use std::marker::PhantomData;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::timing::TimingTree;
use std::time::Duration;
use plonky2x::backend::circuit::Groth16WrapperParameters;
use plonky2x::backend::wrapper::wrap::WrappedCircuit;
use plonky2x::frontend::builder::CircuitBuilder as WrapperBuilder;
use plonky2x::prelude::DefaultParameters;

use plonky2::plonk::circuit_data::CircuitData;
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};

use zkm_prover::all_stark::AllStark;
use zkm_prover::fixed_recursive_verifier::AllRecursiveCircuits;
use zkm_prover::generation::state::Receipt;
use zkm_prover::config::StarkConfig;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type InnerParameters = DefaultParameters;
type OuterParameters = Groth16WrapperParameters;

/// This can be used for all external host program, like zkm-project-template and zkm-proof-network etc.
pub const DEGREE_BITS_RANGE: [std::ops::Range<usize>; 12] =
    [10..21, 12..22, 11..21, 8..21, 6..10, 6..10, 6..16, 6..16, 6..16, 6..16, 6..21, 13..23];

pub fn create_recursive_circuit() -> AllRecursiveCircuits<F, C, D>{
    let timing = TimingTree::new("agg init all_circuits", log::Level::Info);
    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    let all_circuits =
        AllRecursiveCircuits::<F, C, D>::new(&all_stark, &DEGREE_BITS_RANGE, &config);
    timing.filter(Duration::from_millis(100)).print();
    all_circuits
}

pub fn aggregate_proof(all_circuits: AllRecursiveCircuits<F, C, D>, left: Receipt<F, C, D>, right: Receipt<F, C, D>, is_left_agg: bool, is_right_agg: bool) -> anyhow::Result<Receipt<F, C, D>> {
    let timing = TimingTree::new("agg agg", log::Level::Info);
    // We can duplicate the proofs here because the state hasn't mutated.
    let new_agg_receipt =
        all_circuits.prove_aggregation(is_left_agg, &left, is_right_agg, &right)?;
    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_aggregation(&new_agg_receipt)?;
    Ok(new_agg_receipt)
}

pub fn wrap_stark_bn254(all_circuits: AllRecursiveCircuits<F, C, D>, new_agg_receipt: Receipt<F, C, D>, output_dir: &str) -> anyhow::Result<()> {
    let mut timing = TimingTree::new("agg prove_block", log::Level::Info);

    let block_receipt = all_circuits.prove_block(None, &new_agg_receipt)?;
    all_circuits.verify_block(&block_receipt)?;
    timing.filter(Duration::from_millis(100)).print();
    timing = TimingTree::new("agg circuit_data", log::Level::Info);
    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer {
        _phantom: PhantomData::<C>,
    };
    let circuit_data = all_circuits
        .block
        .circuit
        .to_bytes(&gate_serializer, &generator_serializer)
        .unwrap();
    let circuit_data = CircuitData::<F, C, D>::from_bytes(
        circuit_data.as_slice(),
        &gate_serializer,
        &generator_serializer,
    )
        .unwrap();

    let builder = WrapperBuilder::<DefaultParameters, 2>::new();
    let mut circuit = builder.build();
    circuit.set_data(circuit_data);
    let mut bit_size = vec![32usize; 16];
    bit_size.extend(vec![8; 32]);
    bit_size.extend(vec![64; 68]);
    let wrapped_circuit = WrappedCircuit::<InnerParameters, OuterParameters, D>::build(
        circuit,
        Some((vec![], bit_size)),
    );

    std::fs::create_dir_all(output_dir)?;

    let wrapped_proof = wrapped_circuit.prove(&block_receipt.proof()).unwrap();
    wrapped_proof.save(&output_dir)?;

    let src_public_inputs = match &block_receipt {
        Receipt::Segments(receipt) => &receipt.proof.public_inputs,
        Receipt::Composite(recepit) => &recepit.program_receipt.proof.public_inputs,
    };

    let outdir_path = std::path::Path::new(&output_dir);

    let public_values_file = outdir_path.join("public_values.json");
    std::fs::write(public_values_file, serde_json::to_string(&block_receipt.values())?)?;

    let block_public_inputs = serde_json::json!({
            "public_inputs": src_public_inputs,
        });
    let block_public_inputs_file = outdir_path.join("block_public_inputs.json");
    std::fs::write(block_public_inputs_file, serde_json::to_string(&block_public_inputs)?)?;

    timing.filter(Duration::from_millis(100)).print();
    Ok(())
}

// TODO: all the wrapped proof and groth16 proof are written into the disk, which is not friendly for distribution across the cloud
pub fn as_groth16(key_path: &str, input_dir: &str, output_dir: &str) -> anyhow::Result<()> {
    snark::prove_snark(
       key_path,
       input_dir,
       output_dir,
    )
}

pub fn groth16_setup(input_dir: &str) -> anyhow::Result<()> {
    snark::setup_and_generate_sol_verifier(input_dir)
}

pub mod tests {
    use super::*;
    #[test]
    fn sha2_test_e2e() {
        println!("Should run an e2e");
    }
}
