use std::env;
use std::fs::File;
use std::io::Read;

use zkm_emulator::utils::{load_elf_with_patch, split_prog_into_segs};
use zkm_utils::utils::prove_segments;

const ELF_PATH: &str = "../guest/elf/mips-zkm-zkvm-elf";

fn prove_revm() {
    // 1. split ELF into segs
    let seg_path = env::var("SEG_OUTPUT").unwrap_or("output".to_owned());
    let seg_size = env::var("SEG_SIZE").unwrap_or("0".to_string());
    let seg_size = seg_size.parse::<_>().unwrap_or(0);

    let data = if let Ok(json_path) = env::var("JSON_PATH") {
        let mut f = File::open(json_path).unwrap();
        let mut data = vec![];
        f.read_to_end(&mut data).unwrap();
        data
    } else {
        guest_std::TEST_DATA.to_vec()
    };

    let encoded = guest_std::cbor_serialize(&data);

    let mut state = load_elf_with_patch(ELF_PATH, vec![]);

    // load input
    state.input_stream.push(encoded);

    let (_total_steps, seg_num, mut _state) = split_prog_into_segs(state, &seg_path, "", seg_size);

    let _ = prove_segments(&seg_path, "", "", "", seg_num, 0, vec![]);
}

fn main() {
    env_logger::try_init().unwrap_or_default();
    prove_revm();
}
