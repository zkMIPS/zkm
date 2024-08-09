use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::ops::Range;
use std::time::Duration;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;
use plonky2x::backend::circuit::Groth16WrapperParameters;
use plonky2x::backend::wrapper::wrap::WrappedCircuit;
use plonky2x::frontend::builder::CircuitBuilder as WrapperBuilder;
use plonky2x::prelude::DefaultParameters;
use zkm_emulator::utils::{
    get_block_path, load_elf_with_patch, split_prog_into_segs, SEGMENT_STEPS,
};
use zkm_prover::all_stark::AllStark;
use zkm_prover::config::StarkConfig;
use zkm_prover::cpu::kernel::assembler::segment_kernel;
use zkm_prover::fixed_recursive_verifier::AllRecursiveCircuits;
use zkm_prover::proof;
use zkm_prover::proof::PublicValues;
use zkm_prover::prover::prove;
use zkm_prover::verifier::verify_proof;

const DEGREE_BITS_RANGE: [Range<usize>; 6] = [10..21, 12..22, 12..21, 8..21, 6..21, 13..23];

fn split_segs(load_preimage: bool) {
    // 1. split ELF into segs
    let basedir = env::var("BASEDIR").unwrap_or("/tmp/cannon".to_string());
    let elf_path = env::var("ELF_PATH").expect("ELF file is missing");
    let block_no = env::var("BLOCK_NO").unwrap_or("".to_string());
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or(format!("{SEGMENT_STEPS}"));
    let seg_size = seg_size.parse::<_>().unwrap_or(SEGMENT_STEPS);
    let args = env::var("ARGS").unwrap_or("".to_string());
    let args = args.split_whitespace().collect();

    let mut state = load_elf_with_patch(&elf_path, args);
    let block_path = get_block_path(&basedir, &block_no, "");
    if load_preimage {
        state.load_input(&block_path);
    }
    let _ = split_prog_into_segs(state, &seg_path, &block_path, seg_size);
}

fn prove_single_seg_common(
    seg_file: &str,
    basedir: &str,
    block: &str,
    file: &str,
    seg_size: usize,
) {
    let seg_reader = BufReader::new(File::open(seg_file).unwrap());
    let kernel = segment_kernel(basedir, block, file, seg_reader, seg_size);

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let allstark: AllStark<F, D> = AllStark::default();
    let config = StarkConfig::standard_fast_config();
    let mut timing = TimingTree::new("prove", log::Level::Info);
    let allproof: proof::AllProof<GoldilocksField, C, D> =
        prove(&allstark, &kernel, &config, &mut timing).unwrap();
    let mut count_bytes = 0;
    for (row, proof) in allproof.stark_proofs.clone().iter().enumerate() {
        let proof_str = serde_json::to_string(&proof.proof).unwrap();
        log::info!("row:{} proof bytes:{}", row, proof_str.len());
        count_bytes += proof_str.len();
    }
    timing.filter(Duration::from_millis(100)).print();
    log::info!("total proof bytes:{}KB", count_bytes / 1024);
    verify_proof(&allstark, allproof, &config).unwrap();
    log::info!("Prove done");
}

fn prove_groth16() {
    todo!()
}

fn main() {
    let _ = plonky2::get_unflatten_buf(134217728);
    plonky2::create_ctx(13, 13);
    env_logger::try_init().unwrap_or_default();
    let args: Vec<String> = env::args().collect();
    let helper = || {
        log::info!(
            "Help: {} split | split_without_preimage | prove | aggregate_proof | aggregate_proof_all | prove_groth16 | bench",
            args[0]
        );
        std::process::exit(-1);
    };
    if args.len() < 2 {
        helper();
    }
    match args[1].as_str() {
        "split" => split_segs(true),
        "split_without_preimage" => split_segs(false),
        "prove" => prove_single_seg(),
        "aggregate_proof" => aggregate_proof().unwrap(),
        "aggregate_proof_all" => aggregate_proof_all().unwrap(),
        "prove_groth16" => prove_groth16(),
        "bench" => prove_sha2_bench(),
        _ => helper(),
    };
    plonky2::destroy_ctx();
}

fn aggregate_proof() -> anyhow::Result<()> {
    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    let basedir = env::var("BASEDIR").unwrap_or("/tmp/cannon".to_string());
    let block = env::var("BLOCK_NO").unwrap_or("".to_string());
    let file = env::var("BLOCK_FILE").unwrap_or(String::from(""));
    let seg_file = env::var("SEG_FILE").expect("first segment file is missing");
    let seg_file2 = env::var("SEG_FILE2").expect("The next segment file is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or(format!("{SEGMENT_STEPS}"));
    let seg_size = seg_size.parse::<_>().unwrap_or(SEGMENT_STEPS);
    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    // Preprocess all circuits.
    let all_circuits =
        AllRecursiveCircuits::<F, C, D>::new(&all_stark, &DEGREE_BITS_RANGE, &config);

    let seg_reader = BufReader::new(File::open(seg_file)?);
    let input_first = segment_kernel(&basedir, &block, &file, seg_reader, seg_size);
    let mut timing = TimingTree::new("prove root first", log::Level::Info);
    let (root_proof_first, first_public_values) =
        all_circuits.prove_root(&all_stark, &input_first, &config, &mut timing)?;

    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(root_proof_first.clone())?;

    let seg_reader = BufReader::new(File::open(seg_file2)?);
    let input = segment_kernel(&basedir, &block, &file, seg_reader, seg_size);
    let mut timing = TimingTree::new("prove root second", log::Level::Info);
    let (root_proof, public_values) =
        all_circuits.prove_root(&all_stark, &input, &config, &mut timing)?;
    timing.filter(Duration::from_millis(100)).print();

    all_circuits.verify_root(root_proof.clone())?;

    // Update public values for the aggregation.
    let agg_public_values = PublicValues {
        roots_before: first_public_values.roots_before,
        roots_after: public_values.roots_after,
        userdata: public_values.userdata,
    };

    // We can duplicate the proofs here because the state hasn't mutated.
    let timing = TimingTree::new("prove aggregation", log::Level::Info);
    let (agg_proof, updated_agg_public_values) = all_circuits.prove_aggregation(
        false,
        &root_proof_first,
        false,
        &root_proof,
        agg_public_values,
    )?;
    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_aggregation(&agg_proof)?;

    let timing = TimingTree::new("prove block", log::Level::Info);
    let (block_proof, _block_public_values) =
        all_circuits.prove_block(None, &agg_proof, updated_agg_public_values)?;
    timing.filter(Duration::from_millis(100)).print();

    log::info!(
        "proof size: {:?}",
        serde_json::to_string(&block_proof.proof).unwrap().len()
    );
    all_circuits.verify_block(&block_proof)
}

fn prove_multi_seg_common(
    seg_dir: &str,
    basedir: &str,
    block: &str,
    file: &str,
    seg_size: usize,
    seg_file_number: usize,
) -> anyhow::Result<()> {
    type InnerParameters = DefaultParameters;
    type OuterParameters = Groth16WrapperParameters;

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    if seg_file_number < 2 {
        panic!("seg file number must >= 2\n");
    }

    let total_timing = TimingTree::new("prove total time", log::Level::Info);
    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    // Preprocess all circuits.
    let all_circuits =
        AllRecursiveCircuits::<F, C, D>::new(&all_stark, &DEGREE_BITS_RANGE, &config);

    let seg_file = format!("{}/{}", seg_dir, 0);
    log::info!("Process segment 0");
    let seg_reader = BufReader::new(File::open(seg_file)?);
    let input_first = segment_kernel(basedir, block, file, seg_reader, seg_size);
    let mut timing = TimingTree::new("prove root first", log::Level::Info);
    let (mut agg_proof, mut updated_agg_public_values) =
        all_circuits.prove_root(&all_stark, &input_first, &config, &mut timing)?;

    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(agg_proof.clone())?;

    let mut base_seg = 1;
    let mut is_agg = false;

    if seg_file_number % 2 == 0 {
        let seg_file = format!("{}/{}", seg_dir, 1);
        log::info!("Process segment 1");
        let seg_reader = BufReader::new(File::open(seg_file)?);
        let input = segment_kernel(basedir, block, file, seg_reader, seg_size);
        timing = TimingTree::new("prove root second", log::Level::Info);
        let (root_proof, public_values) =
            all_circuits.prove_root(&all_stark, &input, &config, &mut timing)?;
        timing.filter(Duration::from_millis(100)).print();

        all_circuits.verify_root(root_proof.clone())?;

        // Update public values for the aggregation.
        let agg_public_values = PublicValues {
            roots_before: updated_agg_public_values.roots_before,
            roots_after: public_values.roots_after,
            userdata: public_values.userdata,
        };
        timing = TimingTree::new("prove aggression", log::Level::Info);
        // We can duplicate the proofs here because the state hasn't mutated.
        (agg_proof, updated_agg_public_values) = all_circuits.prove_aggregation(
            false,
            &agg_proof,
            false,
            &root_proof,
            agg_public_values.clone(),
        )?;
        timing.filter(Duration::from_millis(100)).print();
        all_circuits.verify_aggregation(&agg_proof)?;

        is_agg = true;
        base_seg = 2;
    }

    for i in 0..(seg_file_number - base_seg) / 2 {
        let seg_file = format!("{}/{}", seg_dir, base_seg + (i << 1));
        log::info!("Process segment {}", base_seg + (i << 1));
        let seg_reader = BufReader::new(File::open(&seg_file)?);
        let input_first = segment_kernel(basedir, block, file, seg_reader, seg_size);
        let mut timing = TimingTree::new("prove root first", log::Level::Info);
        let (root_proof_first, first_public_values) =
            all_circuits.prove_root(&all_stark, &input_first, &config, &mut timing)?;

        timing.filter(Duration::from_millis(100)).print();
        all_circuits.verify_root(root_proof_first.clone())?;

        let seg_file = format!("{}/{}", seg_dir, base_seg + (i << 1) + 1);
        log::info!("Process segment {}", base_seg + (i << 1) + 1);
        let seg_reader = BufReader::new(File::open(&seg_file)?);
        let input = segment_kernel(basedir, block, file, seg_reader, seg_size);
        let mut timing = TimingTree::new("prove root second", log::Level::Info);
        let (root_proof, public_values) =
            all_circuits.prove_root(&all_stark, &input, &config, &mut timing)?;
        timing.filter(Duration::from_millis(100)).print();

        all_circuits.verify_root(root_proof.clone())?;

        // Update public values for the aggregation.
        let new_agg_public_values = PublicValues {
            roots_before: first_public_values.roots_before,
            roots_after: public_values.roots_after,
            userdata: public_values.userdata,
        };
        timing = TimingTree::new("prove aggression", log::Level::Info);
        // We can duplicate the proofs here because the state hasn't mutated.
        let (new_agg_proof, new_updated_agg_public_values) = all_circuits.prove_aggregation(
            false,
            &root_proof_first,
            false,
            &root_proof,
            new_agg_public_values,
        )?;
        timing.filter(Duration::from_millis(100)).print();
        all_circuits.verify_aggregation(&new_agg_proof)?;

        // Update public values for the nested aggregation.
        let agg_public_values = PublicValues {
            roots_before: updated_agg_public_values.roots_before,
            roots_after: new_updated_agg_public_values.roots_after,
            userdata: new_updated_agg_public_values.userdata,
        };
        timing = TimingTree::new("prove nested aggression", log::Level::Info);

        // We can duplicate the proofs here because the state hasn't mutated.
        (agg_proof, updated_agg_public_values) = all_circuits.prove_aggregation(
            is_agg,
            &agg_proof,
            true,
            &new_agg_proof,
            agg_public_values.clone(),
        )?;
        is_agg = true;
        timing.filter(Duration::from_millis(100)).print();

        all_circuits.verify_aggregation(&agg_proof)?;
    }

    let (block_proof, _block_public_values) =
        all_circuits.prove_block(None, &agg_proof, updated_agg_public_values)?;

    log::info!(
        "proof size: {:?}",
        serde_json::to_string(&block_proof.proof).unwrap().len()
    );
    let result = all_circuits.verify_block(&block_proof);

    let build_path = "../verifier/data".to_string();
    let path = format!("{}/test_circuit/", build_path);
    let builder = WrapperBuilder::<DefaultParameters, 2>::new();
    let mut circuit = builder.build();
    circuit.set_data(all_circuits.block.circuit);
    let mut bit_size = vec![32usize; 16];
    bit_size.extend(vec![8; 32]);
    bit_size.extend(vec![64; 68]);
    let wrapped_circuit = WrappedCircuit::<InnerParameters, OuterParameters, D>::build(
        circuit,
        Some((vec![], bit_size)),
    );
    log::info!("build finish");

    let wrapped_proof = wrapped_circuit.prove(&block_proof).unwrap();
    wrapped_proof.save(path).unwrap();

    total_timing.filter(Duration::from_millis(100)).print();
    result
}

fn prove_sha2_bench() {
    // 1. split ELF into segs
    let elf_path = env::var("ELF_PATH").expect("ELF file is missing");
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");

    let mut state = load_elf_with_patch(&elf_path, vec![]);
    // load input
    let args = env::var("ARGS").unwrap_or("data-to-hash".to_string());
    // assume the first arg is the hash output(which is a public input), and the second is the input.
    let args: Vec<&str> = args.split_whitespace().collect();
    assert_eq!(args.len(), 2);

    let public_input: Vec<u8> = hex::decode(args[0]).unwrap();
    state.add_input_stream(&public_input);
    log::info!("expected public value in hex: {:X?}", args[0]);
    log::info!("expected public value: {:X?}", public_input);

    let private_input = args[1].as_bytes().to_vec();
    log::info!("private input value: {:X?}", private_input);
    state.add_input_stream(&private_input);

    let (total_steps, mut state) = split_prog_into_segs(state, &seg_path, "", 0);

    let value = state.read_public_values::<[u8; 32]>();
    log::info!("public value: {:X?}", value);
    log::info!("public value: {} in hex", hex::encode(value));

    let seg_file = format!("{seg_path}/{}", 0);
    prove_single_seg_common(&seg_file, "", "", "", total_steps);
}

fn prove_revm() {
    // 1. split ELF into segs
    let elf_path = env::var("ELF_PATH").expect("ELF file is missing");
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");
    let json_path = env::var("JSON_PATH").expect("JSON file is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or("0".to_string());
    let seg_size = seg_size.parse::<_>().unwrap_or(0);
    let mut f = File::open(json_path).unwrap();
    let mut data = vec![];
    f.read_to_end(&mut data).unwrap();

    let mut state = load_elf_with_patch(&elf_path, vec![]);
    // load input
    state.add_input_stream(&data);

    let (total_steps, mut _state) = split_prog_into_segs(state, &seg_path, "", seg_size);

    let mut seg_num = 1usize;
    if seg_size != 0 {
        seg_num = (total_steps + seg_size - 1) / seg_size;
    }

    if seg_num == 1 {
        let seg_file = format!("{seg_path}/{}", 0);
        prove_single_seg_common(&seg_file, "", "", "", total_steps)
    } else {
        prove_multi_seg_common(&seg_path, "", "", "", seg_size, seg_num).unwrap()
    }
}

fn prove_single_seg() {
    let basedir = env::var("BASEDIR").unwrap_or("/tmp/cannon".to_string());
    let block = env::var("BLOCK_NO").unwrap_or("".to_string());
    let file = env::var("BLOCK_FILE").unwrap_or(String::from(""));
    let seg_file = env::var("SEG_FILE").expect("Segment file is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or(format!("{SEGMENT_STEPS}"));
    let seg_size = seg_size.parse::<_>().unwrap_or(SEGMENT_STEPS);
    prove_single_seg_common(&seg_file, &basedir, &block, &file, seg_size)
}

fn prove_groth16() {
    todo!()
}

fn main() {
    env_logger::try_init().unwrap_or_default();
    let args: Vec<String> = env::args().collect();
    let helper = || {
        log::info!(
            "Help: {} split | split_without_preimage | prove | aggregate_proof | aggregate_proof_all | prove_groth16 | bench | revm",
            args[0]
        );
        std::process::exit(-1);
    };
    if args.len() < 2 {
        helper();
    }
    match args[1].as_str() {
        "split" => split_segs(true),
        "split_without_preimage" => split_segs(false),
        "prove" => prove_single_seg(),
        "aggregate_proof" => aggregate_proof().unwrap(),
        "aggregate_proof_all" => aggregate_proof_all().unwrap(),
        "prove_groth16" => prove_groth16(),
        "bench" => prove_sha2_bench(),
        "revm" => prove_revm(),
        _ => helper(),
    };
}

fn aggregate_proof() -> anyhow::Result<()> {
    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    let basedir = env::var("BASEDIR").unwrap_or("/tmp/cannon".to_string());
    let block = env::var("BLOCK_NO").unwrap_or("".to_string());
    let file = env::var("BLOCK_FILE").unwrap_or(String::from(""));
    let seg_file = env::var("SEG_FILE").expect("first segment file is missing");
    let seg_file2 = env::var("SEG_FILE2").expect("The next segment file is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or(format!("{SEGMENT_STEPS}"));
    let seg_size = seg_size.parse::<_>().unwrap_or(SEGMENT_STEPS);
    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    // Preprocess all circuits.
    let all_circuits =
        AllRecursiveCircuits::<F, C, D>::new(&all_stark, &DEGREE_BITS_RANGE, &config);

    let seg_reader = BufReader::new(File::open(seg_file)?);
    let input_first = segment_kernel(&basedir, &block, &file, seg_reader, seg_size);
    let mut timing = TimingTree::new("prove root first", log::Level::Info);
    let (root_proof_first, first_public_values) =
        all_circuits.prove_root(&all_stark, &input_first, &config, &mut timing)?;

    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(root_proof_first.clone())?;

    let seg_reader = BufReader::new(File::open(seg_file2)?);
    let input = segment_kernel(&basedir, &block, &file, seg_reader, seg_size);
    let mut timing = TimingTree::new("prove root second", log::Level::Info);
    let (root_proof, public_values) =
        all_circuits.prove_root(&all_stark, &input, &config, &mut timing)?;
    timing.filter(Duration::from_millis(100)).print();

    all_circuits.verify_root(root_proof.clone())?;

    // Update public values for the aggregation.
    let agg_public_values = PublicValues {
        roots_before: first_public_values.roots_before,
        roots_after: public_values.roots_after,
        userdata: public_values.userdata,
    };

    // We can duplicate the proofs here because the state hasn't mutated.
    let timing = TimingTree::new("prove aggregation", log::Level::Info);
    let (agg_proof, updated_agg_public_values) = all_circuits.prove_aggregation(
        false,
        &root_proof_first,
        false,
        &root_proof,
        agg_public_values,
    )?;
    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_aggregation(&agg_proof)?;

    let timing = TimingTree::new("prove block", log::Level::Info);
    let (block_proof, _block_public_values) =
        all_circuits.prove_block(None, &agg_proof, updated_agg_public_values)?;
    timing.filter(Duration::from_millis(100)).print();

    log::info!(
        "proof size: {:?}",
        serde_json::to_string(&block_proof.proof).unwrap().len()
    );
    all_circuits.verify_block(&block_proof)
}

fn aggregate_proof_all() -> anyhow::Result<()> {
    let basedir = env::var("BASEDIR").unwrap_or("/tmp/cannon".to_string());
    let block = env::var("BLOCK_NO").unwrap_or("".to_string());
    let file = env::var("BLOCK_FILE").unwrap_or(String::from(""));
    let seg_dir = env::var("SEG_FILE_DIR").expect("segment file dir is missing");
    let seg_file_number = env::var("SEG_FILE_NUM").expect("The segment file number is missing");
    let seg_file_number = seg_file_number.parse::<_>().unwrap_or(2usize);
    let seg_size = env::var("SEG_SIZE").unwrap_or(format!("{SEGMENT_STEPS}"));
    let seg_size = seg_size.parse::<_>().unwrap_or(SEGMENT_STEPS);
    prove_multi_seg_common(&seg_dir, &basedir, &block, &file, seg_size, seg_file_number)
}
