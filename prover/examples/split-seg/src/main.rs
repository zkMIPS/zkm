use std::env;
use zkm_emulator::utils::{
    get_block_path, load_elf_with_patch, split_prog_into_segs, SEGMENT_STEPS,
};

fn split_segments() {
    // 1. split ELF into segs
    let basedir = env::var("BASEDIR").unwrap_or("/tmp/output".to_string());
    let elf_path = env::var("ELF_PATH").expect("ELF file is missing");
    let block_no = env::var("BLOCK_NO").unwrap_or("".to_string());
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or(format!("{SEGMENT_STEPS}"));
    let seg_size = seg_size.parse::<_>().unwrap_or(SEGMENT_STEPS);
    let args = env::var("ARGS").unwrap_or("".to_string());
    // assume the first arg is the hash output(which is a public input), and the others are the input.
    let args: Vec<&str> = args.split_whitespace().collect();
    let mut state = load_elf_with_patch(&elf_path, vec![]);

    if !args.is_empty() {
        let public_input: Vec<u8> = args[0].as_bytes().to_vec();
        log::info!("public input value {:X?}", public_input);
        state.add_input_stream(&public_input);
    }

    if args.len() > 1 {
        for (i, arg) in args.iter().enumerate().skip(1) {
            let private_input = arg.as_bytes().to_vec();
            log::info!("private input value {}: {:X?}", i, private_input);
            state.add_input_stream(&private_input);
        }
    }

    let block_path = get_block_path(&basedir, &block_no, "");
    if !block_no.is_empty() {
        state.load_input(&block_path);
    }
    let _ = split_prog_into_segs(state, &seg_path, &block_path, seg_size);
}

fn main() {
    env_logger::try_init().unwrap_or_default();
    split_segments();
}
