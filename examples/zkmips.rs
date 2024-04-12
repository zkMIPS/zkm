use elf::{endian::AnyEndian, ElfBytes};
use std::env;
use std::fs;
use std::time::Duration;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;
use plonky2x::backend::circuit::Groth16WrapperParameters;
use plonky2x::backend::wrapper::wrap::WrappedCircuit;
use plonky2x::frontend::builder::CircuitBuilder as WrapperBuilder;
use plonky2x::prelude::DefaultParameters;
use zkm::all_stark::AllStark;
use zkm::config::StarkConfig;
use zkm::cpu::kernel::assembler::segment_kernel;
use zkm::fixed_recursive_verifier::AllRecursiveCircuits;
use zkm::mips_emulator::state::{InstrumentedState, State, SEGMENT_STEPS};
use zkm::mips_emulator::utils::get_block_path;
use zkm::proof;
use zkm::proof::PublicValues;
use zkm::prover::prove;
use zkm::verifier::verify_proof;

const DEGREE_BITS_RANGE: [[std::ops::Range<usize>; 6]; 5] = [
    [16..17, 12..13, 12..16, 8..12, 14..17, 17..19],
    [16..17, 15..17, 15..17, 9..12, 15..17, 19..20],
    [16..17, 15..17, 16..19, 11..14, 16..19, 19..21],
    [16..17, 17..18, 16..19, 11..14, 16..19, 21..22],
    [16..18, 16..20, 18..21, 13..16, 18..21, 21..23],
];

fn select_degree_bits(seg_size: usize) -> [std::ops::Range<usize>; 6] {
    let seg_size_to_bits = std::collections::BTreeMap::from([
        (1024, 0),
        (16384, 1),
        (32768, 2),
        (65536, 3),
        (262144, 4),
    ]);
    match seg_size_to_bits.get(&seg_size) {
        Some(s) => DEGREE_BITS_RANGE[*s].clone(),
        None => panic!(
            "Invalid segment size, supported: {:?}",
            seg_size_to_bits.keys()
        ),
    }
}

fn split_elf_into_segs() {
    // 1. split ELF into segs
    let basedir = env::var("BASEDIR").unwrap_or("/tmp/cannon".to_string());
    let elf_path = env::var("ELF_PATH").expect("ELF file is missing");
    let block_no = env::var("BLOCK_NO");
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or(format!("{SEGMENT_STEPS}"));
    let seg_size = seg_size.parse::<_>().unwrap_or(SEGMENT_STEPS);
    let args = env::var("ARGS").unwrap_or("".to_string());

    let data = fs::read(elf_path).expect("could not read file");
    let file =
        ElfBytes::<AnyEndian>::minimal_parse(data.as_slice()).expect("opening elf file failed");
    let (mut state, _) = State::load_elf(&file);
    state.patch_go(&file);
    state.patch_stack(&args);

    let block_path = match block_no {
        Ok(no) => {
            let block_path = get_block_path(&basedir, &no, "");
            state.load_input(&block_path);
            block_path
        }
        _ => "".to_string(),
    };

    let mut instrumented_state = InstrumentedState::new(state, block_path);
    instrumented_state.split_segment(false, &seg_path);
    let mut segment_step: usize = seg_size;
    loop {
        if instrumented_state.state.exited {
            break;
        }
        instrumented_state.step();
        segment_step -= 1;
        if segment_step == 0 {
            segment_step = seg_size;
            instrumented_state.split_segment(true, &seg_path);
        }
    }

    instrumented_state.split_segment(true, &seg_path);
    log::info!("Split done");
}

fn prove_single_seg() {
    let basedir = env::var("BASEDIR").unwrap_or("/tmp/cannon".to_string());
    let block = env::var("BLOCK_NO").unwrap_or("".to_string());
    let file = env::var("BLOCK_FILE").unwrap_or(String::from(""));
    let seg_file = env::var("SEG_FILE").expect("Segment file is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or(format!("{SEGMENT_STEPS}"));
    let seg_size = seg_size.parse::<_>().unwrap_or(SEGMENT_STEPS);
    let kernel = segment_kernel(&basedir, &block, &file, &seg_file, seg_size);

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let allstark: AllStark<F, D> = AllStark::default();
    let config = StarkConfig::standard_fast_config();
    let mut timing = TimingTree::new("prove", log::Level::Info);
    zkm::print_mem_usage("before prove");
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
    env_logger::try_init().unwrap_or_default();
    let args: Vec<String> = env::args().collect();
    let helper = || {
        println!(
            "Help: {} split | prove | aggregate_proof | aggregate_proof_all | prove_groth16",
            args[0]
        );
        std::process::exit(-1);
    };
    if args.len() < 2 {
        helper();
    }
    match args[1].as_str() {
        "split" => split_elf_into_segs(),
        "prove" => prove_single_seg(),
        "aggregate_proof" => aggregate_proof().unwrap(),
        "aggregate_proof_all" => aggregate_proof_all().unwrap(),
        "prove_groth16" => prove_groth16(),
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

    zkm::print_mem_usage("new all stark");
    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    // Preprocess all circuits.
    zkm::print_mem_usage("before preprocess all circuit");
    let all_circuits =
        AllRecursiveCircuits::<F, C, D>::new(&all_stark, &select_degree_bits(seg_size), &config);

    zkm::print_mem_usage("before segment kernel");
    let input_first = segment_kernel(&basedir, &block, &file, &seg_file, seg_size);
    let mut timing = TimingTree::new("prove root first", log::Level::Info);
    zkm::print_mem_usage("before prove first");
    let (root_proof_first, first_public_values) =
        all_circuits.prove_root(&all_stark, &input_first, &config, &mut timing)?;

    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(root_proof_first.clone())?;

    let input = segment_kernel(&basedir, &block, &file, &seg_file2, seg_size);
    let mut timing = TimingTree::new("prove root second", log::Level::Info);
    zkm::print_mem_usage("before prove second");
    let (root_proof, public_values) =
        all_circuits.prove_root(&all_stark, &input, &config, &mut timing)?;
    timing.filter(Duration::from_millis(100)).print();

    all_circuits.verify_root(root_proof.clone())?;

    // Update public values for the aggregation.
    let agg_public_values = PublicValues {
        roots_before: first_public_values.roots_before,
        roots_after: public_values.roots_after,
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
    type InnerParameters = DefaultParameters;
    type OuterParameters = Groth16WrapperParameters;

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    let basedir = env::var("BASEDIR").unwrap_or("/tmp/cannon".to_string());
    let block = env::var("BLOCK_NO").unwrap_or("".to_string());
    let file = env::var("BLOCK_FILE").unwrap_or(String::from(""));
    let seg_dir = env::var("SEG_FILE_DIR").expect("segment file dir is missing");
    let seg_file_number = env::var("SEG_FILE_NUM").expect("The segment file number is missing");
    let seg_file_number = seg_file_number.parse::<_>().unwrap_or(2usize);
    let seg_size = env::var("SEG_SIZE").unwrap_or(format!("{SEGMENT_STEPS}"));
    let seg_size = seg_size.parse::<_>().unwrap_or(SEGMENT_STEPS);

    if seg_file_number < 2 {
        panic!("seg file number must >= 2\n");
    }

    let total_timing = TimingTree::new("prove total time", log::Level::Info);
    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    // Preprocess all circuits.
    let all_circuits =
        AllRecursiveCircuits::<F, C, D>::new(&all_stark, &select_degree_bits(seg_size), &config);

    let seg_file = format!("{}/{}", seg_dir, 0);
    let input_first = segment_kernel(&basedir, &block, &file, &seg_file, seg_size);
    let mut timing = TimingTree::new("prove root first", log::Level::Info);
    let (mut agg_proof, mut updated_agg_public_values) =
        all_circuits.prove_root(&all_stark, &input_first, &config, &mut timing)?;

    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(agg_proof.clone())?;

    let mut base_seg = 1;
    let mut is_agg = false;

    if seg_file_number % 2 == 0 {
        let seg_file = format!("{}/{}", seg_dir, 1);
        let input = segment_kernel(&basedir, &block, &file, &seg_file, seg_size);
        timing = TimingTree::new("prove root second", log::Level::Info);
        let (root_proof, public_values) =
            all_circuits.prove_root(&all_stark, &input, &config, &mut timing)?;
        timing.filter(Duration::from_millis(100)).print();

        all_circuits.verify_root(root_proof.clone())?;

        // Update public values for the aggregation.
        let agg_public_values = PublicValues {
            roots_before: updated_agg_public_values.roots_before,
            roots_after: public_values.roots_after,
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
        let input_first = segment_kernel(&basedir, &block, &file, &seg_file, seg_size);
        let mut timing = TimingTree::new("prove root first", log::Level::Info);
        let (root_proof_first, first_public_values) =
            all_circuits.prove_root(&all_stark, &input_first, &config, &mut timing)?;

        timing.filter(Duration::from_millis(100)).print();
        all_circuits.verify_root(root_proof_first.clone())?;

        let seg_file = format!("{}/{}", seg_dir, base_seg + (i << 1) + 1);
        let input = segment_kernel(&basedir, &block, &file, &seg_file, seg_size);
        let mut timing = TimingTree::new("prove root second", log::Level::Info);
        let (root_proof, public_values) =
            all_circuits.prove_root(&all_stark, &input, &config, &mut timing)?;
        timing.filter(Duration::from_millis(100)).print();

        all_circuits.verify_root(root_proof.clone())?;

        // Update public values for the aggregation.
        let new_agg_public_values = PublicValues {
            roots_before: first_public_values.roots_before,
            roots_after: public_values.roots_after,
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
    let wrapped_circuit = WrappedCircuit::<InnerParameters, OuterParameters, D>::build(circuit);
    println!("build finish");

    let wrapped_proof = wrapped_circuit.prove(&block_proof).unwrap();
    wrapped_proof.save(path).unwrap();

    total_timing.filter(Duration::from_millis(100)).print();
    result
}
