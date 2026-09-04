use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().expect("bpfi should live in workspace root");
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    // TODO: rerun-if-changed for the entire _rt subtree
    // TODO: follow the `$TARGET` if specified, and grab bpfi_rt from there.
    let status = Command::new(cargo)
        .current_dir(workspace_root)
        .arg("build-rt")
        .status()
        .expect("failed to invoke cargo build-rt for bpfi_rt");
    assert!(status.success(), "building bpfi_rt failed");
    let artifact = workspace_root.join("target").join("release").join(exe_name("bpfi_rt"));
    println!("cargo:rustc-env=BPFI_RT_IMG={}", artifact.display());
}

fn exe_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}
