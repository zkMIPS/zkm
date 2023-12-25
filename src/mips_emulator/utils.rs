/// From the minigeth's rule, the `block` starts with `0_`
pub fn get_block_path(basedir: &str, block: &str, file: &str) -> String {
    format!("{basedir}/0_{block}/{file}")
}
