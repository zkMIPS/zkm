use std::process::Command;

use crate::{BuildArgs, HELPER_TARGET_SUBDIR};
use cargo_metadata::camino::Utf8PathBuf;

use super::utils::{get_program_build_args, get_rust_compiler_flags};

/// Get the command to build the program locally.
pub(crate) fn create_local_command(
    args: &BuildArgs,
    program_dir: &Utf8PathBuf,
    program_metadata: &cargo_metadata::Metadata,
) -> Command {
    let mut command = Command::new("cargo");
    let canonicalized_program_dir = program_dir
        .canonicalize()
        .expect("Failed to canonicalize program directory");

    // When executing the local command:
    // 1. Set the target directory to a subdirectory of the program's target directory to avoid
    //    build
    // conflicts with the parent process. Source: https://github.com/rust-lang/cargo/issues/6412
    // 2. Set the rustup toolchain to succinct.
    // 3. Set the encoded rust flags.
    // 4. Remove the rustc configuration, otherwise in a build script it will attempt to compile the
    //    program with the toolchain of the normal build process, rather than the Succinct
    //    toolchain.
    command
        .current_dir(canonicalized_program_dir)
        .env("CARGO_ENCODED_RUSTFLAGS", get_rust_compiler_flags())
        .env(
            "CARGO_TARGET_DIR",
            program_metadata.target_directory.join(HELPER_TARGET_SUBDIR),
        )
        .args(get_program_build_args(args));
    command
}
