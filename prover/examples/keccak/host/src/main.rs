use alloy_primitives::keccak256;
use std::env;
use zkm_emulator::utils::{load_elf_with_patch, split_prog_into_segs};
use zkm_utils::utils::prove_segments;

const ELF_PATH: &str = "../guest/elf/mips-zkm-zkvm-elf";

fn prove_keccak_rust() {
    // 1. split ELF into segs
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or("65536".to_string());
    let input_length = env::var("INPUT_LEN")
        .unwrap_or("680".to_string())
        .parse::<_>()
        .unwrap();
    let seg_size = seg_size.parse::<_>().unwrap_or(0);

    let mut state = load_elf_with_patch(ELF_PATH, vec![]);
    let private_input: Vec<u8> = vec![0].repeat(input_length);
    let public_input = keccak256(&private_input).to_vec();
    state.add_input_stream(&public_input);
    state.add_input_stream(&private_input);

    let (_total_steps, seg_num, mut state) = split_prog_into_segs(state, &seg_path, "", seg_size);

    let value = state.read_public_values::<[u8; 32]>();
    assert!(value == *public_input);

    let _ = prove_segments(&seg_path, "", "", "", seg_num, 0, vec![]).unwrap();
}

fn main() {
    env_logger::try_init().unwrap_or_default();
    prove_keccak_rust();
}
