use std::env;
use zkm_emulator::utils::{get_block_path, split_seg_into_segs};
use zkm_utils::utils;

fn prove_large_segment() {
    let basedir = env::var("BASEDIR").unwrap_or("/tmp/cannon".to_string());
    let block = env::var("BLOCK_NO").unwrap_or("".to_string());
    let file = env::var("BLOCK_FILE").unwrap_or(String::from(""));
    let seg_file = env::var("SEG_FILE").expect("big segment file is missing");
    let seg_dir = env::var("SEG_OUTPUT").expect("segment output dir is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or("1024".to_string());
    let seg_size = seg_size.parse::<_>().unwrap_or(1usize);

    let block_path = get_block_path(&basedir, &block, "");
    let (_, seg_num, _) = split_seg_into_segs(&seg_file, &seg_dir, &block_path, seg_size);

    let _ = utils::prove_segments(&seg_dir, &basedir, &block, &file, seg_num, 0, vec![]);
}

fn main() {
    env_logger::try_init().unwrap_or_default();
    prove_large_segment();
}
