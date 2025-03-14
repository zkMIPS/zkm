mod snark;

pub use snark::*;
use std::env;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::timing::TimingTree;
use plonky2x::backend::circuit::Groth16WrapperParameters;
use plonky2x::backend::wrapper::wrap::WrappedCircuit;
use plonky2x::frontend::builder::CircuitBuilder as WrapperBuilder;
use plonky2x::prelude::DefaultParameters;
use std::marker::PhantomData;
use std::ops::Range;
use std::time::Duration;

use plonky2::plonk::circuit_data::CircuitData;
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};

use zkm_prover::all_stark::AllStark;
use zkm_prover::config::StarkConfig;
use zkm_prover::fixed_recursive_verifier::AllRecursiveCircuits;
use zkm_prover::generation::state::Receipt;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type InnerParameters = DefaultParameters;
type OuterParameters = Groth16WrapperParameters;

/// This can be used for all external host program, like zkm-project-template and zkm-proof-network etc.
pub const DEFAULT_DEGREE_BITS_RANGE: [Range<usize>; 12] = [
    10..11,
    12..13,
    11..12,
    8..21,
    10..11,
    10..11,
    10..16,
    10..16,
    6..16,
    6..16,
    6..21,
    13..23,
];

pub const RANGE_TABLES: [&str; 12] = [
    "ARITHMETIC",
    "CPU",
    "POSEIDON",
    "POSEIDON_SPONGE",
    "KECCAK",
    "KECCAK_SPONGE",
    "SHA_EXTEND",
    "SHA_EXTEND_SPONGE",
    "SHA_COMPRESS",
    "SHA_COMPRESS_SPONGE",
    "LOGIC",
    "MEMORY",
];

const PUBLIC_INPUT_PATH: &str = "public_values.json";
const BLOCK_PUBLIC_INPUTS_PATH: &str = "block_public_inputs.json";

pub fn create_recursive_circuit() -> AllRecursiveCircuits<F, C, D> {
    let degree_bits_range = degree_from_env();
    let timing = TimingTree::new("agg init all_circuits", log::Level::Info);
    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    let all_circuits =
        AllRecursiveCircuits::<F, C, D>::new(&all_stark, &degree_bits_range, &config);
    timing.filter(Duration::from_millis(100)).print();
    all_circuits
}

pub fn aggregate_proof(
    all_circuits: &AllRecursiveCircuits<F, C, D>,
    left: Receipt<F, C, D>,
    right: Receipt<F, C, D>,
    is_left_agg: bool,
    is_right_agg: bool,
) -> anyhow::Result<Receipt<F, C, D>> {
    let timing = TimingTree::new("agg agg", log::Level::Info);
    // We can duplicate the proofs here because the state hasn't mutated.
    let new_agg_receipt =
        all_circuits.prove_aggregation(is_left_agg, &left, is_right_agg, &right)?;
    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_aggregation(&new_agg_receipt)?;
    Ok(new_agg_receipt)
}

pub fn wrap_stark_bn254(
    all_circuits: &AllRecursiveCircuits<F, C, D>,
    new_agg_receipt: Receipt<F, C, D>,
    output_dir: &str,
) -> anyhow::Result<()> {
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
    wrapped_proof.save(output_dir)?;

    let src_public_inputs = match &block_receipt {
        Receipt::Segments(receipt) => &receipt.proof.public_inputs,
        Receipt::Composite(recepit) => &recepit.program_receipt.proof.public_inputs,
    };

    let outdir_path = std::path::Path::new(&output_dir);

    let public_values_file = outdir_path.join(PUBLIC_INPUT_PATH);
    std::fs::write(
        public_values_file,
        serde_json::to_string(&block_receipt.values())?,
    )?;

    let block_public_inputs = serde_json::json!({
        "public_inputs": src_public_inputs,
    });
    let block_public_inputs_file = outdir_path.join(BLOCK_PUBLIC_INPUTS_PATH);
    std::fs::write(
        block_public_inputs_file,
        serde_json::to_string(&block_public_inputs)?,
    )?;

    timing.filter(Duration::from_millis(100)).print();
    Ok(())
}

// TODO: all the wrapped proof and groth16 proof are written into the disk, which is not friendly for distribution across the cloud
pub fn as_groth16(key_path: &str, input_dir: &str, output_dir: &str) -> anyhow::Result<()> {
    snark::prove_snark(key_path, input_dir, output_dir)
}

// TODO: should setup the output path
pub fn groth16_setup(input_dir: &str) -> anyhow::Result<()> {
    snark::setup_and_generate_sol_verifier(input_dir)
}

fn degree_from_env() -> [Range<usize>; 12] {
    RANGE_TABLES.map(|table| {
        env::var(table)
            .ok()
            .and_then(|val| {
                let bounds: Vec<usize> = val
                    .split("..")
                    .map(|s| s.trim().parse().ok())
                    .collect::<Option<Vec<usize>>>()?;

                if bounds.len() == 2 {
                    Some(Range {
                        start: bounds[0],
                        end: bounds[1],
                    })
                } else {
                    None
                }
            })
            .unwrap_or_else(|| {
                let index = RANGE_TABLES.iter().position(|&r| r == table).unwrap();
                DEFAULT_DEGREE_BITS_RANGE[index].clone()
            })
    })
}

#[allow(dead_code)]
#[cfg(test)]
pub mod tests {
    use super::*;
    use ethers::utils::hex::hex;
    use std::fs::File;
    use std::io::BufReader;
    use zkm_emulator::utils::{load_elf_with_patch, split_prog_into_segs};
    use zkm_prover::cpu::kernel::assembler::segment_kernel;

    const ELF_PATH: &str = "./elf-files/sha2-elf";
    #[test]
    fn sha2_test_e2e() -> anyhow::Result<()> {
        env_logger::try_init().unwrap_or_default();
        let seg_path = "/tmp/output";
        let seg_size: usize = 8192;
        let mut state = load_elf_with_patch(ELF_PATH, vec![]);

        let public_input: Vec<u8> =
            hex::decode("711e9609339e92b03ddc0a211827dba421f38f9ed8b9d806e1ffdd8c15ffa03d")?;
        state.add_input_stream(&public_input);
        let private_input = "world!".as_bytes().to_vec();
        state.add_input_stream(&private_input);

        let (_total_steps, seg_num, _state) = split_prog_into_segs(state, seg_path, "", seg_size);

        let all_stark = AllStark::<F, D>::default();
        let config = StarkConfig::standard_fast_config();
        let all_circuits = create_recursive_circuit();

        let seg_start_id = 0;
        let assumptions = vec![];
        let seg_file = format!("{}/{}", seg_path, seg_start_id);
        log::info!("Process segment {}", seg_file);
        let seg_reader = BufReader::new(File::open(seg_file)?);
        let input_first = segment_kernel("", "", "", seg_reader);
        let mut timing = TimingTree::new("prove root first", log::Level::Info);
        let mut agg_receipt = all_circuits.prove_root_with_assumption(
            &all_stark,
            &input_first,
            &config,
            &mut timing,
            assumptions.clone(),
        )?;

        let mut base_seg = seg_start_id + 1;
        let seg_file_number = seg_num;
        let mut seg_num = seg_file_number - 1;
        let mut is_agg = false;

        println!("seg_file_number: {:?}", seg_file_number);
        if seg_file_number % 2 == 0 {
            let seg_file = format!("{}/{}", seg_path, seg_start_id + 1);
            log::info!("Process segment {}", seg_file);
            let seg_reader = BufReader::new(File::open(seg_file)?);
            let input = segment_kernel("", "", "", seg_reader);
            timing = TimingTree::new("prove root second", log::Level::Info);
            let receipt = all_circuits.prove_root_with_assumption(
                &all_stark,
                &input,
                &config,
                &mut timing,
                assumptions.clone(),
            )?;
            timing.filter(Duration::from_millis(100)).print();

            all_circuits.verify_root(receipt.clone())?;

            // We can duplicate the proofs here because the state hasn't mutated.
            agg_receipt = aggregate_proof(&all_circuits, agg_receipt, receipt, false, false)?;

            is_agg = true;
            base_seg = seg_start_id + 2;
            seg_num -= 1;
        }

        for i in 0..seg_num / 2 {
            let seg_file = format!("{}/{}", seg_path, base_seg + (i << 1));
            log::info!("Process segment {}", seg_file);
            let seg_reader = BufReader::new(File::open(&seg_file)?);
            let input_first = segment_kernel("", "", "", seg_reader);
            let mut timing = TimingTree::new("prove root first", log::Level::Info);
            let root_receipt_first = all_circuits.prove_root_with_assumption(
                &all_stark,
                &input_first,
                &config,
                &mut timing,
                assumptions.clone(),
            )?;

            timing.filter(Duration::from_millis(100)).print();
            all_circuits.verify_root(root_receipt_first.clone())?;

            let seg_file = format!("{}/{}", seg_path, base_seg + (i << 1) + 1);
            log::info!("Process segment {}", seg_file);
            let seg_reader = BufReader::new(File::open(&seg_file)?);
            let input = segment_kernel("", "", "", seg_reader);
            let mut timing = TimingTree::new("prove root second", log::Level::Info);
            let root_receipt = all_circuits.prove_root_with_assumption(
                &all_stark,
                &input,
                &config,
                &mut timing,
                assumptions.clone(),
            )?;
            timing.filter(Duration::from_millis(100)).print();

            all_circuits.verify_root(root_receipt.clone())?;

            // We can duplicate the proofs here because the state hasn't mutated.
            let new_agg_receipt = aggregate_proof(
                &all_circuits,
                root_receipt_first,
                root_receipt,
                false,
                false,
            )?;

            // We can duplicate the proofs here because the state hasn't mutated.
            agg_receipt =
                aggregate_proof(&all_circuits, agg_receipt, new_agg_receipt, is_agg, true)?;
            is_agg = true;
        }

        log::info!(
            "proof size: {:?}",
            serde_json::to_string(&agg_receipt.proof().proof)
                .unwrap()
                .len()
        );

        if seg_file_number > 1 {
            wrap_stark_bn254(&all_circuits, agg_receipt, "/tmp/input")?;
        }
        log::info!("build finish");

        groth16_setup("/tmp/input")?;
        as_groth16("/tmp/input", "/tmp/input", "/tmp/output")?;

        Ok(())
    }
}
