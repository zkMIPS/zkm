#![allow(clippy::upper_case_acronyms)]
use std::time::Duration;

use mips_circuits::all_stark::AllStark;
use mips_circuits::config::StarkConfig;
use mips_circuits::cpu::kernel::assembler::TEST_KERNEL;
use mips_circuits::fixed_recursive_verifier::AllRecursiveCircuits;
use mips_circuits::proof::PublicValues;
//use mips_circuits::cpu::kernel::assembler::segment_kernel;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::timing::TimingTree;

use plonky2x::backend::circuit::Groth16WrapperParameters;
use plonky2x::backend::wrapper::plonky2_config::PoseidonBN128GoldilocksConfig;
use plonky2x::backend::wrapper::wrap::{WrappedCircuit, WrappedOutput};
use plonky2x::frontend::builder::CircuitBuilder as WrapperBuilder;
use plonky2x::frontend::vars::ByteVariable;
use plonky2x::prelude::DefaultParameters;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

// Tests proving two transactions, one of which with logs, and aggregating them.
#[test]
#[ignore = "Too slow"]
fn test_mips_with_aggreg_fibo() -> anyhow::Result<()> {
    type InnerParameters = DefaultParameters;
    type OuterParameters = Groth16WrapperParameters;

    env_logger::try_init().unwrap_or_default();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // The arithmetic circuit.
    let initial_a = builder.add_virtual_target();
    let initial_b = builder.add_virtual_target();
    let mut prev_target = initial_a;
    let mut cur_target = initial_b;
    for _ in 0..5 {
        let temp = builder.add(prev_target, cur_target);
        prev_target = cur_target;
        cur_target = temp;
    }

    // Public inputs are the two initial values (provided below) and the result (which is generated).
    builder.register_public_input(initial_a);
    builder.register_public_input(initial_b);
    builder.register_public_input(cur_target);

    // Provide initial values.
    let mut pw = PartialWitness::new();
    pw.set_target(initial_a, F::ZERO);
    pw.set_target(initial_b, F::ONE);

    let data = builder.build::<C>();
    let proof = data.prove(pw.clone())?;

    println!(
        "100th Fibonacci number mod |F| (starting with {}, {}) is: {}",
        proof.public_inputs[0], proof.public_inputs[1], proof.public_inputs[2]
    );

    data.verify(proof.clone());

    println!("pw.target_values.len() {:?}", pw.target_values.len());
    println!(
        "proof.public_inputs: {:?},proof.public_inputs.len(): {:?}",
        proof.public_inputs,
        proof.public_inputs.len()
    );
    println!(
        "circuit.data.common.num_public_inputs {:?}",
        data.common.num_public_inputs
    );

    let mut builder = WrapperBuilder::<DefaultParameters, 2>::new();
    let mut circuit2 = builder.build();
    circuit2.set_data(data);

    let wrapped_circuit = WrappedCircuit::<InnerParameters, OuterParameters, D>::build(circuit2);

    let build_path = "../verifier/data".to_string();
    let path = format!("{}/test_circuit/", build_path);

    let wrapped_proof = wrapped_circuit.prove(&proof).unwrap();
    wrapped_proof.save(path).unwrap();
    /*
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
    println!("all_circuits.block.circuit.common.num_public_inputs {:?}", all_circuits.block.circuit.common.num_public_inputs);
    println!("block_proof.public_inputs {:?}", block_proof.public_inputs);

    let build_path = "../verifier/data".to_string();
    let path = format!("{}/test_circuit/", build_path);
    let mut builder = CircuitBuilder::<DefaultParameters, 2>::new();
    let mut circuit = builder.build();
    circuit.set_data(all_circuits.block.circuit);
    let wrapped_circuit = WrappedCircuit::<InnerParameters, OuterParameters, D>::build(circuit);
    println!("build finish");
    let wrapped_proof = wrapped_circuit.prove(&block_proof).unwrap();
    wrapped_proof.save(path).unwrap();
    */

    Ok(())
}

#[test]
#[ignore = "Too slow"]
fn test_mips_with_aggreg() -> anyhow::Result<()> {
    type InnerParameters = DefaultParameters;
    type OuterParameters = Groth16WrapperParameters;

    env_logger::try_init().unwrap_or_default();

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    // Preprocess all circuits.
    let all_circuits = AllRecursiveCircuits::<F, C, D>::new(
        &all_stark,
        &[16..20, 17..22, 14..19, 9..15, 12..20, 19..22],
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
    println!(
        "all_circuits.block.circuit.common.num_public_inputs {:?}",
        all_circuits.block.circuit.common.num_public_inputs
    );
    println!("block_proof.public_inputs {:?}", block_proof.public_inputs);

    let build_path = "../verifier/data".to_string();
    let path = format!("{}/test_circuit/", build_path);
    let mut builder = WrapperBuilder::<DefaultParameters, 2>::new();
    let mut circuit = builder.build();
    circuit.set_data(all_circuits.block.circuit);
    let wrapped_circuit = WrappedCircuit::<InnerParameters, OuterParameters, D>::build(circuit);
    println!("build finish");

    // let (proof_inputs,_) = block_proof.public_inputs.split_at(2);
    // let proof_conv =  ProofWithPublicInputs {
    //     proof:block_proof.proof,
    //     public_inputs: Vec::from(proof_inputs),
    // };

    let wrapped_proof = wrapped_circuit.prove(&block_proof).unwrap();
    wrapped_proof.save(path).unwrap();

    Ok(())
}
