//! This build script is as suggested by the Aya cargo template - see https://aya-rs.dev/book/start/development/#prerequisites.
use which::which;
fn main() {
    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}
