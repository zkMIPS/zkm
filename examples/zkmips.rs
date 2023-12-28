use elf::{endian::AnyEndian, ElfBytes};
use std::env;
use std::fs;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;

use mips_circuits::all_stark::AllStark;
use mips_circuits::config::StarkConfig;
use mips_circuits::cpu::kernel::assembler::segment_kernel;
use mips_circuits::generation::GenerationInputs;
use mips_circuits::mips_emulator::state::{InstrumentedState, State, SEGMENT_STEPS};
use mips_circuits::mips_emulator::utils::get_block_path;
use mips_circuits::proof;
use mips_circuits::prover::prove;
use mips_circuits::verifier::verify_proof;

// TODO: handle input
fn split_elf_into_segs() {
    // 1. split ELF into segs
    let basedir = env::var("BASEDIR").unwrap_or("/tmp/cannon".to_string());
    let elf_path = env::var("ELF_PATH").expect("ELF file is missing");
    let block_no = env::var("BLOCK_NO").expect("Block number is missing");
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or(format!("{SEGMENT_STEPS}"));
    let seg_size = seg_size.parse::<_>().unwrap_or(SEGMENT_STEPS);

    let data = fs::read(elf_path).expect("could not read file");
    let file =
        ElfBytes::<AnyEndian>::minimal_parse(data.as_slice()).expect("opening elf file failed");
    let (mut state, _) = State::load_elf(&file);
    state.patch_go(&file);
    state.patch_stack("");

    let block_path = get_block_path(&basedir, &block_no, "");
    state.load_input(&block_path);

    let mut instrumented_state = InstrumentedState::new(state, block_path);
    instrumented_state.split_segment(false, &seg_path);
    let mut segment_step = seg_size;
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
    log::debug!("Split done");
}

fn prove_single_seg() {
    let basedir = env::var("BASEDIR").unwrap_or("/tmp/cannon".to_string());
    let block = env::var("BLOCK_NO").expect("Block number is missing");
    let file = env::var("BLOCK_FILE").unwrap_or(String::from(""));
    let seg_file = env::var("SEG_FILE").expect("Segment file is missing");
    let kernel = segment_kernel(&basedir, &block, &file, &seg_file);

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let allstark: AllStark<F, D> = AllStark::default();
    let mut config = StarkConfig::standard_fast_config();
    config.fri_config.rate_bits = 3;
    let input = GenerationInputs {};
    let mut timing = TimingTree::new("prove", log::Level::Debug);
    let allproof: proof::AllProof<GoldilocksField, C, D> =
        prove(&allstark, &kernel, &config, input, &mut timing).unwrap();
    let mut count_bytes = 0;
    let mut row = 0;
    for proof in allproof.stark_proofs.clone() {
        let proof_str = serde_json::to_string(&proof.proof).unwrap();
        log::trace!("row:{} proof bytes:{}", row, proof_str.len());
        row = row + 1;
        count_bytes = count_bytes + proof_str.len();
    }
    log::trace!("total proof bytes:{}KB", count_bytes / 1024);
    verify_proof(&allstark, allproof, &config).unwrap();
    log::debug!("Prove done");
}

fn main() {
    env_logger::try_init().unwrap_or_default();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        log::warn!("Help: {} split|prove", args[0]);
        return;
    }
    match args[1].as_str() {
        "split" => {
            split_elf_into_segs();
        }
        "prove" => {
            prove_single_seg();
        }
        _ => todo!("Help: {} split|prove", args[0]),
    };
}
