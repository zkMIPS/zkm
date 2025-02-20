use std::env;
use zkm_utils::utils;

fn prove_segments() {
    let basedir = env::var("BASEDIR").unwrap_or("/tmp/cannon".to_string());
    let block = env::var("BLOCK_NO").unwrap_or("".to_string());
    let file = env::var("BLOCK_FILE").unwrap_or(String::from(""));
    let seg_dir = env::var("SEG_FILE_DIR").expect("segment file dir is missing");
    let seg_num = env::var("SEG_NUM").unwrap_or("1".to_string());
    let seg_num = seg_num.parse::<_>().unwrap_or(1usize);
    let seg_start_id = env::var("SEG_START_ID").unwrap_or("0".to_string());
    let seg_start_id = seg_start_id.parse::<_>().unwrap_or(0usize);

    let _ = utils::prove_segments(
        &seg_dir,
        &basedir,
        &block,
        &file,
        seg_num,
        seg_start_id,
        vec![],
    );
}

fn main() {
    env_logger::try_init().unwrap_or_default();
    prove_segments();
}
