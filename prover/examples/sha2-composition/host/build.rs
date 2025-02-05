fn main() {
    zkm_build::build_program(&format!("{}/../guest", env!("CARGO_MANIFEST_DIR")));
}
