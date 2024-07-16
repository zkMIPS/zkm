#![allow(clippy::upper_case_acronyms)]
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

// Tests proving two transactions, one of which with logs, and aggregating them.
#[test]
fn test_mips_with_aggreg_fibo() -> anyhow::Result<()> {
    use plonky2x::backend::circuit::Groth16WrapperParameters;
    use plonky2x::backend::wrapper::wrap::WrappedCircuit;
    use plonky2x::frontend::builder::CircuitBuilder as WrapperBuilder;
    use plonky2x::prelude::DefaultParameters;

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

    let _ = data.verify(proof.clone());

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

    let builder = WrapperBuilder::<DefaultParameters, 2>::new();
    let mut circuit2 = builder.build();
    circuit2.set_data(data);

    let wrapped_circuit = WrappedCircuit::<InnerParameters, OuterParameters, D>::build(
        circuit2,
        Some((vec![], vec![8, 8, 8])), // bit length of public inputs
    );

    let build_path = "../verifier/data".to_string();
    let path = format!("{}/test_circuit/", build_path);

    let wrapped_proof = wrapped_circuit.prove(&proof).unwrap();
    wrapped_proof.save(path).unwrap();
    Ok(())
}
