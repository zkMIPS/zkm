use std::path::PathBuf;
use std::process::Command;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=go");
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = PathBuf::from(&out_dir);
    let lib_name = "zkmgnark";
    let dest = dest_path.join(format!("lib{}.a", lib_name));
    let status = Command::new("go")
        .current_dir("src/snark/libsnark")
        .env("CGO_ENABLED", "1")
        .args(["build", "-tags=debug", "-o", dest.to_str().unwrap(), "-buildmode=c-archive", "."])
        .status()
        .expect("Failed to build Go library");
    if !status.success() {
        panic!("Go build failed");
    }

    // Link the Go library
    println!("cargo:rustc-link-search=native={}", dest_path.display());
    println!("cargo:rustc-link-lib=static={}", lib_name);

    Ok(())
}
