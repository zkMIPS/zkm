use std::env;
use std::fs::File;
use std::io::BufReader;
use std::time::Duration;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;

use zkm_emulator::utils::{load_elf_with_patch, split_prog_into_segs};
use zkm_prover::all_stark::AllStark;
use zkm_prover::config::StarkConfig;
use zkm_prover::cpu::kernel::assembler::segment_kernel;
use zkm_prover::proof;
use zkm_prover::prover::prove;
use zkm_prover::verifier::verify_proof;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

fn prove_single_seg_common(seg_file: &str, basedir: &str, block: &str, file: &str) {
    let seg_reader = BufReader::new(File::open(seg_file).unwrap());
    let kernel = segment_kernel(basedir, block, file, seg_reader);

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

const FIB_ELF: &str = "../program/elf/mips-unknown-linux-musl";

fn prove_fib_example() {
    let seg_path = env::var("SEG_OUTPUT").unwrap_or("/tmp/output".to_string());

    let mut state = load_elf_with_patch(FIB_ELF, vec![]);

    let data = 5u32;
    let n = 4u32;
    state.add_input_stream(&data);
    state.add_input_stream(&n);

    log::info!("public input: {:X?}", data);

    let (_total_steps, seg_num, mut state) = split_prog_into_segs(state, &seg_path, "", 0);

    assert!(seg_num == 1);

    let value = state.read_public_values::<u32>();
    log::info!("public value: {}", value);

    let seg_file = format!("{seg_path}/{}", 0);
    prove_single_seg_common(&seg_file, "", "", "")
}

fn main() {
    env_logger::try_init().unwrap_or_default();
    prove_fib_example();
}
