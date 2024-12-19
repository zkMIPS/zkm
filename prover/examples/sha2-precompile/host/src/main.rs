use std::env;
use std::fs::File;
use std::io::BufReader;
use std::ops::Range;
use std::time::Duration;

use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;

use zkm_emulator::utils::{load_elf_with_patch, split_prog_into_segs};
use zkm_prover::all_stark::AllStark;
use zkm_prover::config::StarkConfig;
use zkm_prover::cpu::kernel::assembler::segment_kernel;
use zkm_prover::fixed_recursive_verifier::AllRecursiveCircuits;
use zkm_prover::generation::state::{AssumptionReceipt, AssumptionReceipts, Receipt};

const DEGREE_BITS_RANGE: [Range<usize>; 6] = [10..21, 12..22, 12..21, 8..21, 6..21, 13..23];

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

const ELF_PATH: &str = "../guest/elf/mips-zkm-zkvm-elf";

fn u32_array_to_u8_vec(u32_array: &[u32; 8]) -> Vec<u8> {
    let mut u8_vec = Vec::with_capacity(u32_array.len() * 4);
    for &item in u32_array {
        u8_vec.extend_from_slice(&item.to_le_bytes());
    }
    u8_vec
}

fn prove_sha_5_precompile(
    elf_path: &str,
    seg_path: &str,
) -> Receipt<<C as GenericConfig<D>>::F, C, D> {
    let mut state = load_elf_with_patch(elf_path, vec![]);
    let n: u32 = 5;
    let public_input: [u8; 32] = [
        37, 148, 182, 169, 46, 191, 177, 195, 49, 45, 235, 125, 1, 192, 21, 251, 149, 233, 251,
        233, 189, 123, 198, 181, 39, 175, 7, 129, 62, 199, 185, 16,
    ];
    state.add_input_stream(&public_input.to_vec());
    state.add_input_stream(&n.to_le_bytes().to_vec());

    let (_total_steps, seg_num, mut state) = split_prog_into_segs(state, seg_path, "", 0);

    let value = state.read_public_values::<[u8; 32]>();
    log::info!("public value: {:?}", value);

    assert!(seg_num == 1);

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    // Preprocess all circuits.
    let all_circuits =
        AllRecursiveCircuits::<F, C, D>::new(&all_stark, &DEGREE_BITS_RANGE, &config);

    let seg_file: String = format!("{}/{}", seg_path, 0);
    log::info!("Process segment {}", seg_file);
    let seg_reader = BufReader::new(File::open(seg_file).unwrap());
    let input_first = segment_kernel("", "", "", seg_reader);
    let mut timing = TimingTree::new("prove root first", log::Level::Info);
    let (agg_proof, updated_agg_public_values) = all_circuits
        .prove_root(&all_stark, &input_first, &config, &mut timing)
        .unwrap();

    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(agg_proof.clone()).unwrap();

    Receipt::<F, C, D> {
        proof: agg_proof,
        root_before: u32_array_to_u8_vec(&updated_agg_public_values.roots_before.root),
        userdata: updated_agg_public_values.userdata.clone(),
    }
}

fn prove_sha2_precompile() {
    // 1. split ELF into segs
    let precompile_path = env::var("PRECOMPILE_PATH").expect("PRECOMPILE ELF file is missing");
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");
    let mut receipts: AssumptionReceipts<F, C, D> = vec![];
    let receipt = prove_sha_5_precompile(&precompile_path, &seg_path);

    log::info!(
        "elf_id: {:?}, data: {:?}",
        receipt.root_before,
        receipt.userdata
    );

    let image_id = receipt.root_before.clone();
    receipts.push(receipt.into());

    let mut state = load_elf_with_patch(&ELF_PATH, vec![]);

    let public_input: [u8; 32] = [
        91, 15, 50, 181, 63, 91, 186, 46, 9, 26, 167, 190, 200, 232, 40, 101, 149, 181, 253, 89,
        24, 150, 142, 102, 14, 67, 78, 221, 18, 205, 95, 28,
    ];
    state.add_input_stream(&public_input.to_vec());
    log::info!("expected public value: {:?}", public_input);

    let private_input: [u8; 32] = [
        37, 148, 182, 169, 46, 191, 177, 195, 49, 45, 235, 125, 1, 192, 21, 251, 149, 233, 251,
        233, 189, 123, 198, 181, 39, 175, 7, 129, 62, 199, 185, 16,
    ];
    log::info!("private input value: {:?}", private_input);
    state.add_input_stream(&private_input.to_vec());

    state.add_input_stream(&image_id);

    let (_total_steps, _seg_num, mut state) = split_prog_into_segs(state, &seg_path, "", 0);

    let value = state.read_public_values::<[u8; 32]>();
    log::info!("public value: {:X?}", value);
    log::info!("public value: {} in hex", hex::encode(value));

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    // Preprocess all circuits.
    let all_circuits =
        AllRecursiveCircuits::<F, C, D>::new(&all_stark, &DEGREE_BITS_RANGE, &config);

    let seg_file: String = format!("{}/{}", seg_path, 0);
    log::info!("Process segment {}", seg_file);
    let seg_reader = BufReader::new(File::open(seg_file).unwrap());
    let kernel = segment_kernel("", "", "", seg_reader);

    let mut timing = TimingTree::new("prove", log::Level::Info);
    let (agg_proof, _updated_agg_public_values, receipts_used) = all_circuits
        .prove_root_with_assumption(&all_stark, &kernel, &config, &mut timing, receipts)
        .unwrap();

    log::info!("Process assumptions");
    timing = TimingTree::new("prove aggression", log::Level::Info);

    for assumption in receipts_used.borrow_mut().iter_mut() {
        let receipt = assumption.1.clone();
        match receipt {
            AssumptionReceipt::Proven(receipt) => {
                all_circuits.verify_root(receipt.proof.clone()).unwrap();
            }
            AssumptionReceipt::Unresolved(assumpt) => {
                log::error!("unresolved assumption: {:X?}", assumpt);
            }
        }
    }
    log::info!("verify");
    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(agg_proof.clone()).unwrap();
}

fn main() {
    env_logger::try_init().unwrap_or_default();
    prove_sha2_precompile();
}
