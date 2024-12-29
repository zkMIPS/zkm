use std::env;

use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use zkm_emulator::utils::{load_elf_with_patch, split_prog_into_segs};
use zkm_prover::generation::state::{AssumptionReceipts, Receipt};
use zkm_utils::utils::prove_segments;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

fn prove_sha_5_precompile(elf_path: &str, seg_path: &str) -> Receipt<F, C, D> {
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

    prove_segments(seg_path, "", "", "", 1, 0, vec![]).unwrap()
}

const ELF_PATH: &str = "../guest/elf/mips-zkm-zkvm-elf";

fn prove_sha2_precompile() {
    // 1. split ELF into segs
    let precompile_path = env::var("PRECOMPILE_PATH").expect("PRECOMPILE ELF file is missing");
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");
    let mut receipts: AssumptionReceipts<F, C, D> = vec![];
    let receipt = prove_sha_5_precompile(&precompile_path, &seg_path);

    log::info!(
        "elf_id: {:?}, data: {:?}",
        receipt.claim().elf_id,
        receipt.claim().commit,
    );

    let image_id = receipt.claim().elf_id;
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
    state.add_input_stream(&private_input);

    state.add_input_stream(&image_id);

    let (_total_steps, _seg_num, mut state) = split_prog_into_segs(state, &seg_path, "", 0);

    let value = state.read_public_values::<[u8; 32]>();
    log::info!("public value: {:X?}", value);
    log::info!("public value: {} in hex", hex::encode(value));

    let _ = prove_segments(&seg_path, "", "", "", 1, 0, receipts);
}

fn main() {
    env_logger::try_init().unwrap_or_default();
    prove_sha2_precompile();
}
