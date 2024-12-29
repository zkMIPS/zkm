use std::env;

use zkm_emulator::utils::{load_elf_with_patch, split_prog_into_segs};
use zkm_utils::utils::prove_segments;

const ELF_PATH: &str = "../guest/elf/mips-zkm-zkvm-elf";

fn prove_sha2_rust() {
    // 1. split ELF into segs
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or("65536".to_string());
    let seg_size = seg_size.parse::<_>().unwrap_or(0);

    let mut state = load_elf_with_patch(ELF_PATH, vec![]);
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

    let (_total_steps, seg_num, mut state) = split_prog_into_segs(state, &seg_path, "", seg_size);

    let value = state.read_public_values::<[u8; 32]>();
    log::info!("public value: {:X?}", value);
    log::info!("public value: {} in hex", hex::encode(value));

    let _ = prove_segments(&seg_path, "", "", "", seg_num, 0, vec![]).unwrap();
}

fn main() {
    env_logger::try_init().unwrap_or_default();
    prove_sha2_rust();
}
